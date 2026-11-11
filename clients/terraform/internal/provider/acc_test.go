package provider

// Tests that drive a real Terraform or OpenTofu CLI through terraform-plugin-testing.
//
// They run only with TF_ACC=1 and a CLI (TF_ACC_TERRAFORM_PATH, or the one on PATH):
//
//   - By default they run against fakeAdmin, an in-process stand-in for the admin API.
//   - With RDOCK_ADMIN_URL and RDOCK_ADMIN_TOKEN (an operator token) set they run the same
//     bodies against a real rdock started with testdata/rdock.yaml. Tests that need a fake's
//     hooks (forced conflicts) skip themselves then.

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

var protoV6Factories = map[string]func() (tfprotov6.ProviderServer, error){
	"reversedock": providerserver.NewProtocol6WithError(New("test")()),
}

// admin is what a CLI test talks to.
type admin struct {
	endpoint, token string
	fake            *fakeAdmin // nil against a real rdock
	client          *Client    // for out-of-band changes and cleanup checks
}

func testAdmin(t *testing.T) *admin {
	t.Helper()
	a := &admin{}
	if url := os.Getenv(envEndpoint); url != "" {
		a.endpoint, a.token = url, os.Getenv(envToken)
	} else {
		a.fake = newFakeAdmin(t)
		a.endpoint, a.token = a.fake.Server.URL, fakeOperatorToken
		a.fake.fileObject(kindServices, "file-owned")
	}
	c, err := newClient(clientConfig{Endpoint: a.endpoint, Token: a.token, UserAgent: "acc-test"})
	if err != nil {
		t.Fatal(err)
	}
	a.client = c
	return a
}

// providerBlock is explicit for the fake; against a real rdock the environment variables
// are used, which exercises that path too.
func (a *admin) providerBlock(extra string) string {
	if a.fake == nil {
		return fmt.Sprintf("provider \"reversedock\" {\n%s\n}\n", extra)
	}
	return fmt.Sprintf("provider \"reversedock\" {\n  endpoint = %q\n  token = %q\n%s\n}\n", a.endpoint, a.token, extra)
}

func (a *admin) checkDestroyed(kind string, names ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		doc, err := a.client.getAPI(context.Background())
		if err != nil {
			return err
		}
		for _, n := range names {
			if doc.object(kind, n) != nil {
				return fmt.Errorf("%s/%s still exists", kind, n)
			}
		}
		return nil
	}
}

var backtick = strings.NewReplacer("«", "`")

func hcl(s string) string { return backtick.Replace(s) }

// siteConfig is a service, a middleware and a route that uses both.
func siteConfig(a *admin, n string, priority int, extra string) string {
	return a.providerBlock(extra) + hcl(fmt.Sprintf(`
resource "reversedock_service" "app" {
  name = "%[1]s"
  spec = jsonencode({ backends = [{ address = "127.0.0.1:9" }] })
}

resource "reversedock_middleware" "headers" {
  name = "%[1]s-hdr"
  spec = jsonencode({ type = "headers", response = { set = { "X-Frame-Options" = "DENY" } } })
}

resource "reversedock_route" "web" {
  name = "%[1]s"
  spec = jsonencode({
    match       = "Host(«%[1]s.example.test«)"
    service     = reversedock_service.app.name
    middlewares = [reversedock_middleware.headers.name]
    priority    = %[2]d
  })
}
`, n, priority))
}

func TestAccSiteLifecycle(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	hdr := n + "-hdr"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy: resource.ComposeTestCheckFunc(
			a.checkDestroyed(kindRoutes, n), a.checkDestroyed(kindServices, n), a.checkDestroyed(kindMiddlewares, hdr)),
		Steps: []resource.TestStep{
			{
				Config: siteConfig(a, n, 7, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("reversedock_route.web", "id", n),
					resource.TestCheckResourceAttr("reversedock_route.web", "name", n),
					resource.TestCheckResourceAttrSet("reversedock_route.web", "etag"),
					resource.TestCheckResourceAttrSet("reversedock_service.app", "etag"),
					resource.TestCheckResourceAttr("reversedock_middleware.headers", "name", hdr),
				),
			},
			{
				// Refreshing and planning again changes nothing, although the API stores the
				// object with defaults filled in.
				Config:   siteConfig(a, n, 7, ""),
				PlanOnly: true,
			},
			{
				// The same spec formatted differently is not a change.
				Config: a.providerBlock("") + hcl(fmt.Sprintf(`
resource "reversedock_service" "app" {
  name = "%[1]s"
  spec = <<-EOT
    { "backends": [ { "address": "127.0.0.1:9" } ] }
  EOT
}
resource "reversedock_middleware" "headers" {
  name = "%[1]s-hdr"
  spec = jsonencode({ type = "headers", response = { set = { "X-Frame-Options" = "DENY" } } })
}
resource "reversedock_route" "web" {
  name = "%[1]s"
  spec = jsonencode({
    match       = "Host(«%[1]s.example.test«)"
    service     = reversedock_service.app.name
    middlewares = [reversedock_middleware.headers.name]
    priority    = 7
  })
}
`, n)),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			},
			{
				Config: siteConfig(a, n, 9, ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("reversedock_route.web", plancheck.ResourceActionUpdate),
					plancheck.ExpectResourceAction("reversedock_service.app", plancheck.ResourceActionNoop),
				}},
			},
			{
				ResourceName:            "reversedock_route.web",
				ImportState:             true,
				ImportStateId:           n,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"spec", "etag"},
			},
		},
	})
}

func TestAccImportThenApplyRewritesTheObject(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindServices, n),
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					_, err := a.client.write(context.Background(), kindServices, n, mustObject(t, appService), modeCreate)
					if err != nil {
						t.Fatal(err)
					}
				},
				Config:             a.providerBlock("") + importedService(n),
				ResourceName:       "reversedock_service.imported",
				ImportState:        true,
				ImportStateId:      n,
				ImportStatePersist: true,
			},
			{
				// The imported state holds the server's rendering, which has defaults the
				// configuration lacks: one apply rewrites the object from the configuration.
				Config: a.providerBlock("") + importedService(n),
			},
			{
				Config:   a.providerBlock("") + importedService(n),
				PlanOnly: true,
			},
		},
	})
}

func importedService(n string) string {
	return fmt.Sprintf(`
resource "reversedock_service" "imported" {
  name = %q
  spec = jsonencode({ backends = [{ address = "127.0.0.1:8080" }] })
}
`, n)
}

func TestAccDriftIsDetectedAndRepaired(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	cfg := siteConfig(a, n, 3, "")
	update := []plancheck.PlanCheck{plancheck.ExpectResourceAction("reversedock_route.web", plancheck.ResourceActionUpdate)}
	create := []plancheck.PlanCheck{plancheck.ExpectResourceAction("reversedock_route.web", plancheck.ResourceActionCreate)}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindRoutes, n),
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				// Somebody changes the route in the dashboard.
				PreConfig: func() {
					changed := mustObject(t, hcl(fmt.Sprintf("{\"match\":\"Host(«%s.example.test«)\",\"service\":\"%s\",\"middlewares\":[\"%s-hdr\"],\"priority\":99}", n, n, n)))
					if _, err := a.client.write(context.Background(), kindRoutes, n, changed, modeUpdate); err != nil {
						t.Fatal(err)
					}
				},
				Config:           cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: update},
			},
			{
				// Somebody deletes it.
				PreConfig: func() {
					if _, err := a.client.write(context.Background(), kindRoutes, n, nil, modeDelete); err != nil {
						t.Fatal(err)
					}
				},
				Config:           cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: create},
			},
		},
	})
}

func TestAccErrors(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	routeTo := func(service string) string {
		return a.providerBlock("") + hcl(fmt.Sprintf(`
resource "reversedock_route" "web" {
  name = "%s"
  spec = jsonencode({ match = "Host(«%s.example.test«)", service = %q })
}
`, n, n, service))
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindRoutes, n),
		Steps: []resource.TestStep{
			{
				Config:      routeTo("no-such-service"),
				ExpectError: regexp.MustCompile(`(?s)rejected this configuration.*routes\.` + regexp.QuoteMeta(n) + `\.service.*unknown service`),
			},
			{
				Config:      a.providerBlock("") + "resource \"reversedock_service\" \"bad\" {\n  name = \"has@at\"\n  spec = \"{}\"\n}\n",
				ExpectError: regexp.MustCompile(`(?s)Attribute name must start with a letter or digit`),
			},
			{
				Config:      a.providerBlock("") + "resource \"reversedock_service\" \"bad\" {\n  name = \"ok\"\n  spec = \"[1]\"\n}\n",
				ExpectError: regexp.MustCompile(`the\s+spec\s+must\s+be\s+a\s+JSON\s+object`),
			},
			{
				Config:      a.providerBlock("") + "resource \"reversedock_service\" \"bad\" {\n  name = \"ok\"\n  spec = \"{not json\"\n}\n",
				ExpectError: regexp.MustCompile(`not valid JSON`),
			},
			{
				Config: a.providerBlock("") + `resource "reversedock_service" "f" {
  name = "file-owned"
  spec = jsonencode({ backends = [{ address = "127.0.0.1:9" }] })
}`,
				ExpectError: regexp.MustCompile(`belongs\s+to\s+the\s+configuration\s+file`),
			},
		},
	})
}

func TestAccDeletingAReferencedObjectSurfacesTheAPIsError(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	// The route names its service as a plain string, so Terraform cannot order the destroy.
	both := a.providerBlock("") + hcl(fmt.Sprintf(`
resource "reversedock_service" "app" {
  name = "%[1]s"
  spec = jsonencode({ backends = [{ address = "127.0.0.1:9" }] })
}
resource "reversedock_route" "web" {
  name       = "%[1]s"
  depends_on = [reversedock_service.app]
  spec       = jsonencode({ match = "Host(«%[1]s.example.test«)", service = "%[1]s" })
}
`, n))
	onlyRoute := a.providerBlock("") + hcl(fmt.Sprintf(`
resource "reversedock_route" "web" {
  name = "%[1]s"
  spec = jsonencode({ match = "Host(«%[1]s.example.test«)", service = "%[1]s" })
}
`, n))
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindServices, n),
		Steps: []resource.TestStep{
			{Config: both},
			{
				Config:      onlyRoute,
				ExpectError: regexp.MustCompile(`(?s)refused to delete the service.*routes\.` + regexp.QuoteMeta(n) + `\.service`),
			},
			{Config: both}, // nothing to do, and a complete configuration for the final destroy
		},
	})
}

func TestAccCreateRefusesAnExistingName(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindServices, n),
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					if _, err := a.client.write(context.Background(), kindServices, n, mustObject(t, appService), modeCreate); err != nil {
						t.Fatal(err)
					}
				},
				Config:      a.providerBlock("") + importedService(n),
				ExpectError: regexp.MustCompile(`(?s)already exists.*terraform import`),
			},
			{
				// Cleanup so CheckDestroy passes.
				PreConfig: func() { _, _ = a.client.write(context.Background(), kindServices, n, nil, modeDelete) },
				Config:    a.providerBlock("") + importedService(n),
			},
		},
	})
}

func TestAccDataSources(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	cfg := a.providerBlock("") + importedService(n) + `
data "reversedock_status" "this" {}

data "reversedock_service" "mine" {
  name = reversedock_service.imported.name
}

data "reversedock_service" "from_file" {
  name = "file-owned"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindServices, n),
		Steps: []resource.TestStep{{
			Config: cfg,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.reversedock_status.this", "version"),
				resource.TestCheckResourceAttr("data.reversedock_status.this", "id", "status"),
				resource.TestCheckResourceAttrSet("data.reversedock_status.this", "generation"),
				resource.TestCheckResourceAttr("data.reversedock_service.mine", "owner", "api"),
				resource.TestCheckResourceAttr("data.reversedock_service.mine", "id", n+"@api"),
				resource.TestCheckResourceAttr("data.reversedock_service.from_file", "owner", "file"),
				resource.TestMatchResourceAttr("data.reversedock_service.mine", "spec", regexp.MustCompile(`127\.0\.0\.1:8080`)),
			),
		}},
	})
}

func TestAccDataSourceNotFound(t *testing.T) {
	a := testAdmin(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{{
			Config:      a.providerBlock("") + `data "reversedock_route" "x" { name = "tfacc-no-such-route" }`,
			ExpectError: regexp.MustCompile(`has\s+no\s+route\s+named`),
		}},
	})
}

func TestAccManyResourcesInParallel(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	var b strings.Builder
	b.WriteString(a.providerBlock(""))
	var names []string
	for i := range 15 {
		name := fmt.Sprintf("%s-%d", n, i)
		names = append(names, name)
		fmt.Fprintf(&b, "resource \"reversedock_service\" \"s%d\" {\n  name = %q\n  spec = jsonencode({ backends = [{ address = \"127.0.0.1:%d\" }] })\n}\n", i, name, 9000+i)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindServices, names...),
		Steps: []resource.TestStep{{
			Config: b.String(),
			Check: func(*terraform.State) error {
				if a.fake != nil {
					if m := a.fake.maxInFlight.Load(); m != 1 {
						return fmt.Errorf("writes overlapped (%d at once)", m)
					}
				}
				return nil
			},
		}},
	})
}

func TestAccConflictsWithOtherWritersAreRetried(t *testing.T) {
	a := testAdmin(t)
	if a.fake == nil {
		t.Skip("needs the fake admin API's hooks")
	}
	n := acctest.RandomWithPrefix("tfacc")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindServices, n),
		Steps: []resource.TestStep{{
			PreConfig: func() { a.fake.interfere.Store(3) },
			Config:    a.providerBlock("") + importedService(n),
		}},
	})
}

func TestAccValidateOnPlan(t *testing.T) {
	a := testAdmin(t)
	n := acctest.RandomWithPrefix("tfacc")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		CheckDestroy:             a.checkDestroyed(kindRoutes, n),
		Steps: []resource.TestStep{
			{
				Config: a.providerBlock("  validate_on_plan = true") + hcl(fmt.Sprintf(`
resource "reversedock_route" "web" {
  name = "%[1]s"
  spec = jsonencode({ match = "Host(«%[1]s.example.test«)", service = "missing" })
}
`, n)),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)dry run rejects.*unknown service`),
			},
		},
	})
}

func TestAccProviderConfigurationErrors(t *testing.T) {
	t.Setenv(envEndpoint, "")
	t.Setenv(envToken, "")
	const status = "\ndata \"reversedock_status\" \"s\" {}\n"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{
			{
				Config:      "provider \"reversedock\" {}\n" + status,
				ExpectError: regexp.MustCompile(`Missing admin API endpoint`),
			},
			{
				Config: `
provider "reversedock" {
  endpoint = "http://rdock.example.com:2080"
  token    = "x"
}
` + status,
				ExpectError: regexp.MustCompile(`refusing\s+to\s+send\s+the\s+token\s+over\s+plain\s+HTTP`),
			},
			{
				Config: `
provider "reversedock" {
  endpoint = "https://127.0.0.1:1"
  token    = "x"
  timeout  = "soon"
}
` + status,
				ExpectError: regexp.MustCompile(`Invalid timeout`),
			},
			{
				Config: `
provider "reversedock" {
  endpoint     = "https://127.0.0.1:1"
  token        = "x"
  ca_cert_file = "/nonexistent.pem"
}
` + status,
				ExpectError: regexp.MustCompile(`reading ca_cert_file`),
			},
		},
	})
}
