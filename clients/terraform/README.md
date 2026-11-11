# Terraform and OpenTofu provider for ReverseDock

Manages the **routes, services and middlewares that ReverseDock's admin API owns** (`name@api` in the running configuration) with Terraform or OpenTofu. Requirement F-MGMT-02, [ADR-0030](../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md).

```hcl
terraform {
  required_providers {
    reversedock = { source = "Docker-Hunterpedia/reversedock" }
  }
}

provider "reversedock" {} # RDOCK_ADMIN_URL and RDOCK_ADMIN_TOKEN

resource "reversedock_service" "shop" {
  name = "shop"
  spec = jsonencode({ backends = [{ address = "10.0.0.5:8080" }] })
}

resource "reversedock_route" "shop" {
  name = "shop"
  spec = jsonencode({
    match   = "Host(`shop.example.com`)"
    service = reversedock_service.shop.name
  })
}
```

More in [`examples/`](examples) (a whole small site, an import) and the generated reference in [`docs/`](docs).

## Status: not published

The source lives here and is built and tested here. **It is not on the Terraform or OpenTofu registry.** Publishing needs two things only a maintainer can do:

1. A **separate public repository named `terraform-provider-reversedock`** with this directory as its root. Both registries require the pattern `terraform-provider-{NAME}`, a public repository and lowercase names; the registry's namespace is the GitHub account or organisation that owns it ([Publishing providers](https://developer.hashicorp.com/terraform/registry/providers/publishing), checked 2026-11-11, and [the research note](../../docs/research/v0.8-cache-extensibility.md) section 5.4). The module path `github.com/Docker-Hunterpedia/terraform-provider-reversedock`, the address in `main.go` and the `source` in the examples assume `Docker-Hunterpedia`; change them to the real owner.
2. A **GPG signing key**: "All provider releases are required to be signed". The public key is added to the registry account and the private key to the new repository's secrets (`GPG_PRIVATE_KEY`, `PASSPHRASE`) for the usual GoReleaser workflow. [`.goreleaser.yml`](.goreleaser.yml) and [`terraform-registry-manifest.json`](terraform-registry-manifest.json) (protocol 6) are ready; tags are `vX.Y.Z`.

Also needed for the move: the `replace` line in `go.mod` points at `../go`, the generated Go client in this repository (`github.com/Docker-Hunterpedia/ReverseDock/clients/go`). A standalone repository cannot use a relative path, so that client must be tagged as a Go module in this repository (a tag `clients/go/v0.1.0` makes `go get github.com/Docker-Hunterpedia/ReverseDock/clients/go@v0.1.0` work, because the module lives in a subdirectory) and the `replace` line dropped. The alternative is to vendor the generated file. F-MGMT-02 stays open until the provider is published.

Until then, build it yourself:

```sh
make build                                   # ./terraform-provider-reversedock
```

and tell Terraform or OpenTofu where it is in `~/.terraformrc` (or `~/.tofurc`):

```hcl
provider_installation {
  dev_overrides { "Docker-Hunterpedia/reversedock" = "/path/to/clients/terraform" }
  direct {}
}
```

## What it manages, and what it does not

| Resource | API | Role |
|---|---|---|
| `reversedock_route` | `PUT`/`DELETE /api/v1/routes/{name}` | operator |
| `reversedock_service` | `PUT`/`DELETE /api/v1/services/{name}` | operator |
| `reversedock_middleware` | `PUT`/`DELETE /api/v1/middlewares/{name}` | operator |

| Data source | API | Role |
|---|---|---|
| `reversedock_route`, `reversedock_service`, `reversedock_middleware` | `GET /api/v1/{kind}/{name}` | viewer |
| `reversedock_status` | `GET /api/v1/status` | viewer |

- Each object is `name` plus `spec`, **one JSON object in the shape of the matching section of the configuration file** (`jsonencode({…})`). The provider does not mirror the model attribute by attribute, so it cannot fall behind the Rust model: what `rdock validate` accepts in a `routes`, `services` or `middlewares` entry is accepted in `spec`. Formatting, key order and number spelling never show as a change.
- `etag` is computed and informational: the `ETag` of the API's objects when the resource was last written.
- **Objects owned by the configuration file, Docker, Swarm or Kubernetes are read-only.** The API answers `403` naming the owner, and the provider shows that. The data sources read them (`name = "whoami@docker"`).
- **TCP routes and TCP services are not manageable and have no resources.** The admin API serves only `routes`, `services` and `middlewares` as objects, and its configuration document refuses everything else (`api::parse` in `crates/rdock/src/engine/api.rs`, `SECTIONS` in `crates/rdock-admin/src/resources.rs`). Adding them is an API change (an ADR in this repository), then a few lines here.
- Listeners, certificates, users and tokens are not resources. Create the provider's token on the server.
- Names follow rdock's rule (letter or digit first, then letters, digits, `-`, `_`, `.`; at most 63 characters; no `@`). References between API objects use the bare name.

## Provider settings

| Setting | Environment | Meaning |
|---|---|---|
| `endpoint` | `RDOCK_ADMIN_URL` | URL of the admin API. `https://…`, or `http://` on a loopback address only |
| `token` (sensitive) | `RDOCK_ADMIN_TOKEN` | API token (`rdk_pat_…`); the variable `rdock` itself reads |
| `ca_cert_file` | | PEM file of the CA that signed the admin listener's certificate, added to the system roots |
| `timeout` | | per request, default `30s` |
| `conflict_retries` | | retries after `412`, default 5 |
| `validate_on_plan` | | dry-run changed specs during `plan` (needs operator; off by default) |

There is deliberately **no option to skip certificate verification**, and plain HTTP is refused except to loopback, because the admin API itself only listens in clear text there and the `rdock` CLI sends its token to loopback only. The CLI's `RDOCK_ADMIN` is a `host:port`, not a URL, which is why the URL has its own variable. Redirects are never followed. The user agent is `terraform-provider-reversedock/<version>`.

Create a token on the server (over the admin socket, no token needed): `rdock tokens create terraform --role operator --days 90`. A `viewer` token is enough to plan and to use data sources. With `admin.api_writes: false` (GitOps) every write answers `403`.

## Concurrency

All API-owned objects are one document with one version. The provider handles it:

- A lock per admin endpoint, shared by every provider instance in the process, **serialises writes** although Terraform applies resources in parallel.
- Every write reads `GET /api/v1/config/api` (objects and `ETag`), sends `PUT`/`DELETE` with `If-Match`, and on **`412`** (the dashboard, `curl` or another `terraform apply` wrote in between) reads again and retries, at most `conflict_retries` times with a short back-off, then fails saying another writer is active.
- On **`429`** (the API accepts 5 configuration writes a second across all callers, bursts of 10; 20 requests a second per token) it waits for `Retry-After` and retries, at most 30 times.
- A write the API rejects (`422`: an unknown service, a missing middleware) changes nothing, and the diagnostics are shown on the `spec` attribute. Deleting an object that others refer to is refused the same way, naming the reference, as `terraform destroy` would meet if it deleted in the wrong order; references written as expressions order themselves.
- Every object is one write and one configuration reload on the server. Big configurations apply slowly by design; `-parallelism` does not change that.

## Drift

`plan` and `refresh` read each object back (`GET /api/v1/config/api`). The API returns objects with every default filled in and durations normalised, so the provider never compares your text with the server's. In private state it keeps what the server showed right after its last write: **equal to that is no drift; anything else is drift**, and then the state's `spec` becomes the server's object so the plan shows the difference and proposes your configuration. Without that record (state from an older provider) the object is unchanged when it still says everything the spec says. An object deleted outside Terraform is planned for creation. Import (`terraform import reversedock_route.shop shop`, or an `import` block) takes the bare name; the first apply after an import replaces the object with your `spec`.

Secrets the API masks (`***`, and basic-auth `name:***`) keep the value Terraform wrote, so **changing a secret outside Terraform is not detected**. Write secrets as `${file:…}` or `${env:…}` references: the spec is stored in state as written.

## Tests

```sh
make test       # unit tests, no Terraform/OpenTofu needed
make testacc    # + CLI-driven tests, TF_ACC=1
```

- **Unit tests** (`go test ./...`) cover the JSON handling (semantic equality, defaults, masked secrets, drift decision), endpoint rules, the client against `fakeAdmin`, schema and config validation through the plugin protocol, and that every file in `examples/` parses with the HCL parser and uses only attributes the provider has. `fakeAdmin` (`internal/provider/fake_admin_test.go`) copies the Rust handlers: `ETag` of the form `"g<generation>-<hash>"`, mandatory `If-Match` (`428`/`412` with the current `ETag`), `403` for file- and provider-owned objects, `404` on deleting an absent object, `422` with the reload report's diagnostics, the all-or-nothing validation of references, `429` with `Retry-After`, the role checks, masked secrets restored on write, defaults filled in on read.
- **CLI tests** (`TF_ACC=1`, files `acc_test.go`) run a real `terraform` or `tofu` through `terraform-plugin-testing`: create, update, no-op plans, reformatted specs, import, drift and deletion outside Terraform, errors (rejected spec, file-owned object, existing name, referenced object), data sources, 15 resources in parallel, forced `412`s, `validate_on_plan` and provider configuration errors.

```sh
# Terraform
TF_ACC=1 TF_ACC_TERRAFORM_PATH=$(command -v terraform) go test ./... -count=1
# OpenTofu
TF_ACC=1 TF_ACC_TERRAFORM_PATH=$(command -v tofu) TF_ACC_PROVIDER_HOST=registry.opentofu.org go test ./... -count=1
```

By default they use the in-process fake. **Against a real rdock** the same bodies run when `RDOCK_ADMIN_URL` and `RDOCK_ADMIN_TOKEN` (an operator token) are set; start rdock with [`testdata/rdock.yaml`](testdata/rdock.yaml) (admin API on `127.0.0.1:12080`, plain HTTP listener, one file-owned service called `file-owned` that the tests expect):

```sh
export RDOCK_DATA_DIR=$(mktemp -d)
rdock run --config testdata/rdock.yaml &
until curl -sf http://127.0.0.1:12080/healthz; do sleep 0.5; done
export RDOCK_ADMIN_URL=http://127.0.0.1:12080
export RDOCK_ADMIN_TOKEN=$(rdock tokens create terraform-acc --role operator --days 1 \
  --config testdata/rdock.yaml | head -1)
TF_ACC=1 go test ./... -count=1
```

(`tokens create` goes over the admin socket in `$RDOCK_DATA_DIR`, which needs no token, and prints the token on its first line and a reminder on the second; it needs no user, because the socket's caller is the `cli` administrator, `crates/rdock-admin/src/caller.rs`.) Only the fake can force a `412`; that test skips itself against a real rdock.

Checked with Terraform 1.17.2 and OpenTofu 1.13.9 on 2026-11-11 (fake admin API). The `examples/` also pass `terraform validate` and `tofu validate` with the provider as a development override.

## Documentation

`docs/` is generated by [`tfplugindocs`](https://github.com/hashicorp/terraform-plugin-docs) from the schema, `examples/` and `templates/index.md.tmpl`: `make docs` (needs `terraform` or `tofu` on `PATH`). `make check` is what CI runs: the `terraform-provider` job in `.github/workflows/ci.yml` also validates the examples, runs the CLI tests against the fake with Terraform and OpenTofu, and then against a `rdock` built from the same commit with both.

## Layout

```
main.go                       entry point; the registry address
internal/provider/            provider, resources, data sources, admin API client, JSON helpers, tests
examples/                     provider block, per-resource examples (used by the docs), complete/, import/
docs/, templates/             generated reference and its template
testdata/rdock.yaml           the rdock the tests expect
.goreleaser.yml, terraform-registry-manifest.json, GNUmakefile
```

The module requires Go 1.25.8 (`go` line of `go.mod`: terraform-plugin-testing v1.16.0, used by the tests, needs 1.25.8; the framework v1.19.0 and the generated client need 1.25.0). It uses `github.com/Docker-Hunterpedia/ReverseDock/clients/go` for transport.
