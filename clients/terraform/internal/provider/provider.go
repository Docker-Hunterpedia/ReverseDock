// Package provider implements the Terraform and OpenTofu provider for ReverseDock.
//
// It manages the objects of ReverseDock's API provider (routes, services and middlewares
// written through the admin API) with the per-object endpoints
// `/api/v1/{routes,services,middlewares}/{name}`. Objects owned by the configuration file,
// Docker, Swarm or Kubernetes cannot be changed through the API and are read-only here.
package provider

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Environment variables. The token variable is the one `rdock` itself reads for the admin
// listener; the CLI's RDOCK_ADMIN is a host:port, not a URL, so the URL has its own.
const (
	envEndpoint = "RDOCK_ADMIN_URL"
	envToken    = "RDOCK_ADMIN_TOKEN"
)

var _ provider.Provider = (*reverseDockProvider)(nil)

type reverseDockProvider struct {
	version string
}

// New returns the provider factory for the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &reverseDockProvider{version: version} }
}

type providerModel struct {
	Endpoint        types.String `tfsdk:"endpoint"`
	Token           types.String `tfsdk:"token"`
	CACertFile      types.String `tfsdk:"ca_cert_file"`
	Timeout         types.String `tfsdk:"timeout"`
	ConflictRetries types.Int64  `tfsdk:"conflict_retries"`
	ValidateOnPlan  types.Bool   `tfsdk:"validate_on_plan"`
}

func (p *reverseDockProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "reversedock"
	resp.Version = p.version
}

func (p *reverseDockProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the routes, services and middlewares that ReverseDock's admin API owns. " +
			"Objects owned by the configuration file, Docker, Swarm or Kubernetes are read-only through the API and cannot be managed.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional: true,
				Description: "URL of the admin API, for example `https://rdock.example.com:2080`, or `http://127.0.0.1:2080` " +
					"for a loopback address (for example through an SSH tunnel). Plain HTTP is refused for any other address, " +
					"because the token would cross the network unencrypted. May also be set with `" + envEndpoint + "`.",
			},
			"token": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "An API token (`rdk_pat_…`). The `operator` role is needed to change objects, `viewer` is enough to read " +
					"them (data sources, plan and refresh). May also be set with `" + envToken + "`, the variable `rdock` itself reads.",
			},
			"ca_cert_file": schema.StringAttribute{
				Optional: true,
				Description: "PEM file with the certificate authority that signed the admin listener's certificate, added to the " +
					"system roots. There is deliberately no option to skip certificate verification.",
			},
			"timeout": schema.StringAttribute{
				Optional:    true,
				Description: "Time limit for each request to the admin API, as a Go duration such as `10s` or `1m`. Default `30s`.",
			},
			"conflict_retries": schema.Int64Attribute{
				Optional: true,
				Description: "How many times a write is read again and retried after `412 Precondition Failed` (somebody else " +
					"changed the API's objects in between) before it fails. Default 5.",
				Validators: []validator.Int64{int64validator.Between(1, 50)},
			},
			"validate_on_plan": schema.BoolAttribute{
				Optional: true,
				Description: "Dry-run every changed spec against `POST /api/v1/config/validate` during `terraform plan` and report " +
					"the diagnostics as errors on the `spec` attribute. Needs the `operator` role, and sees only the objects that " +
					"exist now: a spec that refers to an object created in the same apply is reported as invalid. Off by default; " +
					"the apply always validates, because the API refuses an invalid configuration as a whole.",
			},
		},
	}
}

func (p *reverseDockProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, v := range map[string]types.String{
		"endpoint": cfg.Endpoint, "token": cfg.Token, "ca_cert_file": cfg.CACertFile, "timeout": cfg.Timeout,
	} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown value",
				fmt.Sprintf("The provider cannot be configured while %s is unknown; set it from a value known at plan time or from the environment.", name))
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := stringOr(cfg.Endpoint, os.Getenv(envEndpoint))
	token := stringOr(cfg.Token, os.Getenv(envToken))
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing admin API endpoint",
			"Set the endpoint attribute or "+envEndpoint+", for example http://127.0.0.1:2080.")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"), "Missing API token",
			"Set the token attribute or "+envToken+". Create one with `rdock tokens create NAME --role operator`.")
	}
	timeout := defaultTimeout
	if s := cfg.Timeout.ValueString(); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			resp.Diagnostics.AddAttributeError(path.Root("timeout"), "Invalid timeout",
				fmt.Sprintf("%q is not a positive duration such as 10s or 1m.", s))
		}
		timeout = d
	}
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := newClient(clientConfig{
		Endpoint:        endpoint,
		Token:           token,
		CACertFile:      cfg.CACertFile.ValueString(),
		Timeout:         timeout,
		ConflictRetries: int(cfg.ConflictRetries.ValueInt64()),
		UserAgent:       fmt.Sprintf("terraform-provider-reversedock/%s", p.version),
		ValidateOnPlan:  cfg.ValidateOnPlan.ValueBool(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	resp.ResourceData = client
	resp.DataSourceData = client
}

func stringOr(v types.String, fallback string) string {
	if !v.IsNull() && v.ValueString() != "" {
		return v.ValueString()
	}
	return fallback
}

func (p *reverseDockProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		func() resource.Resource { return newObjectResource(kindRoutes, "route") },
		func() resource.Resource { return newObjectResource(kindServices, "service") },
		func() resource.Resource { return newObjectResource(kindMiddlewares, "middleware") },
	}
}

func (p *reverseDockProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		func() datasource.DataSource { return newObjectDataSource(kindRoutes, "route") },
		func() datasource.DataSource { return newObjectDataSource(kindServices, "service") },
		func() datasource.DataSource { return newObjectDataSource(kindMiddlewares, "middleware") },
		newStatusDataSource,
	}
}
