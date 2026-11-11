package provider

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func newServer(t *testing.T) tfprotov6.ProviderServer {
	t.Helper()
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestSchemaIsValidAndNamesFollowTheRegistryRule(t *testing.T) {
	resp, err := newServer(t).GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.Diagnostics {
		t.Errorf("schema diagnostic: %s: %s", d.Summary, d.Detail)
	}
	var got []string
	for name := range resp.ResourceSchemas {
		got = append(got, "resource:"+name)
	}
	for name := range resp.DataSourceSchemas {
		got = append(got, "data:"+name)
	}
	sort.Strings(got)
	want := []string{
		"data:reversedock_middleware", "data:reversedock_route", "data:reversedock_service", "data:reversedock_status",
		"resource:reversedock_middleware", "resource:reversedock_route", "resource:reversedock_service",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v\nwant %v", got, want)
	}
	// Every type name starts with the provider's name, the repository is terraform-provider-<name>.
	for _, n := range got {
		if !strings.Contains(n, ":reversedock_") {
			t.Errorf("%s does not start with the provider name", n)
		}
	}
	// The token is sensitive.
	for _, a := range resp.Provider.Block.Attributes {
		if a.Name == "token" && !a.Sensitive {
			t.Error("token must be sensitive")
		}
		if a.Name == "insecure" || a.Name == "skip_tls_verify" {
			t.Errorf("%s must not exist: there is no way to switch certificate verification off", a.Name)
		}
	}
}

func TestResourceConfigValidation(t *testing.T) {
	srv := newServer(t)
	ctx := context.Background()
	schemas, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	typ := schemas.ResourceSchemas["reversedock_service"].ValueType()

	validate := func(name, spec any) []*tfprotov6.Diagnostic {
		cfg, err := tfprotov6.NewDynamicValue(typ, tftypes.NewValue(typ, map[string]tftypes.Value{
			"id":   tftypes.NewValue(tftypes.String, nil),
			"name": tftypes.NewValue(tftypes.String, name),
			"spec": tftypes.NewValue(tftypes.String, spec),
			"etag": tftypes.NewValue(tftypes.String, nil),
		}))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.ValidateResourceConfig(ctx, &tfprotov6.ValidateResourceConfigRequest{TypeName: "reversedock_service", Config: &cfg})
		if err != nil {
			t.Fatal(err)
		}
		return resp.Diagnostics
	}
	text := func(ds []*tfprotov6.Diagnostic) string {
		var b strings.Builder
		for _, d := range ds {
			b.WriteString(d.Summary + ": " + d.Detail + "\n")
		}
		return b.String()
	}

	if ds := validate("app", `{"backends":[{"address":"127.0.0.1:1"}]}`); len(ds) != 0 {
		t.Errorf("valid config: %s", text(ds))
	}
	for _, bad := range []string{"", "a@b", "-x", "has space", "a/b", strings.Repeat("a", 64)} {
		if ds := validate(bad, `{"a":1}`); len(ds) == 0 {
			t.Errorf("name %q was accepted", bad)
		}
	}
	for _, bad := range []string{"[]", `"s"`, "{}", "null"} {
		if ds := validate("ok", bad); len(ds) == 0 {
			t.Errorf("spec %q was accepted", bad)
		}
	}
	// An unknown spec (computed from another resource) is validated when it is known.
	if ds := validate("ok", tftypes.UnknownValue); len(ds) != 0 {
		t.Errorf("unknown spec: %s", text(ds))
	}
}

func TestConfigureNeedsEndpointAndToken(t *testing.T) {
	t.Setenv(envEndpoint, "")
	t.Setenv(envToken, "")
	srv := newServer(t)
	ctx := context.Background()
	schemas, _ := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	typ := schemas.Provider.ValueType()

	configure := func(env map[string]string, attrs map[string]string) []*tfprotov6.Diagnostic {
		for k, v := range env {
			t.Setenv(k, v)
		}
		values := map[string]tftypes.Value{}
		for _, name := range []string{"endpoint", "token", "ca_cert_file", "timeout"} {
			if v, ok := attrs[name]; ok {
				values[name] = tftypes.NewValue(tftypes.String, v)
			} else {
				values[name] = tftypes.NewValue(tftypes.String, nil)
			}
		}
		values["conflict_retries"] = tftypes.NewValue(tftypes.Number, nil)
		values["validate_on_plan"] = tftypes.NewValue(tftypes.Bool, nil)
		cfg, err := tfprotov6.NewDynamicValue(typ, tftypes.NewValue(typ, values))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.ConfigureProvider(ctx, &tfprotov6.ConfigureProviderRequest{Config: &cfg})
		if err != nil {
			t.Fatal(err)
		}
		return resp.Diagnostics
	}

	if ds := configure(nil, nil); len(ds) != 2 {
		t.Errorf("want two diagnostics (endpoint and token), got %d", len(ds))
	}
	if ds := configure(map[string]string{envEndpoint: "http://127.0.0.1:2080", envToken: "rdk_pat_x"}, nil); len(ds) != 0 {
		t.Errorf("environment variables: %v", ds)
	}
	if ds := configure(map[string]string{envEndpoint: "", envToken: ""}, map[string]string{"endpoint": "https://rdock.example.com", "token": "t"}); len(ds) != 0 {
		t.Errorf("attributes: %v", ds)
	}
	if ds := configure(nil, map[string]string{"endpoint": "http://rdock.example.com", "token": "t"}); len(ds) != 1 ||
		!strings.Contains(ds[0].Detail, "plain HTTP") {
		t.Errorf("plain HTTP to a remote host: %v", ds)
	}
	if ds := configure(nil, map[string]string{"endpoint": "https://rdock.example.com", "token": "t", "timeout": "-5s"}); len(ds) != 1 {
		t.Errorf("negative timeout: %v", ds)
	}
}
