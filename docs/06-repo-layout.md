# ReverseDock — Repository layout and engineering conventions

## 1. Tree

```
reversedock/
├── Cargo.toml                      # workspace: members = crates/*, crates/providers/*
├── Cargo.lock
├── rust-toolchain.toml             # pinned toolchain (1.99.1) + clippy, rustfmt; bumped by PR
├── deny.toml                       # cargo-deny: licenses, advisories, bans, sources
├── justfile                        # dev recipes: just dev | test | e2e | lint | dashboard | bench | release
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # docs (+ actionlint), dco, pr-title, rust (fmt, clippy, nextest, doc), msrv, deny, docker; clients, dashboard; `terraform-provider` (v0.8: provider checks, CLI tests with Terraform and OpenTofu against a fake and a real rdock; not a required check); `waf-example` (v0.8: examples/waf/smoke.sh, the CRS WAF as an agent; not a required check); `openbao` (v0.8: the ignored `e2e_vault` test against OpenBao 2.7.2 in dev mode, pinned by digest, with a root token generated in the job; not a required check); `oidc-dex` (v0.8: the ignored `e2e_oidc` login test against Dex v2.46.1, pinned by digest, with a client secret and a password generated in the job; not a required check); `wasm` (v0.8: `just wasm`, clippy and the WASM tests with the experimental `wasm` feature, the example guest, MSRV with the feature; not a required check); semgrep (report only)
│   │   ├── dashboard.yml           # (M0+) pnpm lint/test/build, bundle-size budget
│   │   ├── e2e.yml                 # (v0.1+) docker compose scenarios, Pebble ACME, toxiproxy
│   │   ├── conformance.yml         # (v0.2+) traefik-label suite
│   │   ├── kubernetes.yml          # (v0.7) chart lint/render/kubeconform and manifests in sync; Gateway API conformance on kind and Helm on k3s (both fail the workflow; passed 2026-11-11; not yet required checks; ADR-0029)
│   │   ├── fuzz.yml                # cargo-fuzz, weekly + on parser changes (tests/fuzz)
│   │   ├── weekly.yml              # RustSec advisories for both lockfiles; tokio canary on the newest 1.x
│   │   ├── bench.yml               # nightly regression check: rdock vs NGINX in one job, artifacts only
│   │   └── release.yml             # build → package (checksums, SBOM; also on PRs) → publish (tags: provenance, cosign, release)
│   ├── ISSUE_TEMPLATE/             # issue forms: bug, compatibility gap, feature, design proposal, docs + config.yml
│   ├── PULL_REQUEST_TEMPLATE.md · CODEOWNERS · dependabot.yml · release.yml (release-note categories)
├── crates/
│   ├── rdock/                      # the binary (clap)
│   ├── rdock-model/                # desired-state types, validation, JSON Schema
│   ├── rdock-rules/                # Traefik-compatible rule grammar
│   ├── rdock-config/               # loaders, merge engine, compile, snapshots, history
│   ├── rdock-proxy/                # Pingora ProxyHttp, router, middleware runtime, L4
│   ├── rdock-tls/                  # resolver, cert store, policies, local CA
│   ├── rdock-acme/                 # ACME client, solvers, DNS providers, scheduler
│   ├── rdock-balancer/             # LB policies, health, retries, breakers
│   ├── rdock-cache/                # HTTP cache: RFC 9111 policy, memory and disk stores, purge, on pingora-cache (ADR-0030)
│   ├── rdock-middleware/           # built-in middlewares; the plugin adapter and `agent` (v0.8)
│   ├── rdock-plugin-api/           # (v0.8) the only crate a native plugin depends on: Plugin trait, http-typed heads, Factory, Registry, testing harness; own 0.x version line (ADR-0030)
│   ├── rdock-wasm/                 # (v0.8, experimental) WASM plugins: digest pin and minisign checks (always built), the wasmtime host and the WIT world `rdock:plugin/filter` behind the `wasm` feature (ADR-0030)
│   ├── rdock-limits/               # rate/concurrency/size limits; per-consumer quotas with persisted counters (v0.8)
│   ├── rdock-credentials/          # (v0.8) credential formats shared by admin and data plane: rdk_pat_ tokens, rdk_ API keys, SHA-256, constant-time compare (ADR-0030)
│   ├── rdock-observability/        # logs, metrics, traces, ring buffer
│   ├── rdock-admin/                # axum API + OpenAPI + embedded dashboard
│   ├── rdock-cloudflare/           # IP sync, DNS-01, Access JWT, Origin CA
│   ├── rdock-dns-providers/        # DNS-01 adapters: Route 53, Google, Azure, DigitalOcean, Hetzner, deSEC, RFC 2136 (ADR-0026)
│   ├── rdock-migrate/              # traefik/nginx → rdock.yaml
│   ├── rdock-testkit/              # test harness (upstreams, Pebble, toxiproxy, containers)
│   └── providers/
│       ├── rdock-provider-file/
│       ├── rdock-provider-docker/
│       ├── rdock-provider-swarm/
│       ├── rdock-provider-kubernetes/ # Gateway API controller + Ingress translation (ADR-0029): api (own types), inventory, translate, gateway/, ingress/, backends, features, runtime/
│       └── rdock-provider-api/
├── apps/
│   ├── website/                    # reversedock.dev: Astro + Starlight, landing + docs (09-website.md, ADR-0017)
│   └── dashboard/                  # Vite + React 19 + TypeScript + Tailwind v4 + shadcn/ui (pnpm)
│       ├── src/
│       │   ├── app/                # router, layout shell, providers
│       │   ├── features/           # overview, routes, services, middlewares, certificates, listeners, providers, security, logs, metrics, config, settings
│       │   ├── components/         # design-system components (Harbor UI)
│       │   ├── api/                # generated from /api/openapi.json (openapi-typescript + openapi-fetch)
│       │   ├── lib/                # utils, i18n (en, ar), formatters
│       │   └── styles/             # tokens.css, globals.css
│       ├── e2e/                    # Playwright
│       ├── package.json · vite.config.ts · tsconfig.json · components.json
│       └── dist/                   # build output (gitignored), embedded by rdock-admin
├── clients/
│   └── terraform/                  # (v0.8) Terraform/OpenTofu provider (Go module, replace to ../go): internal/provider, examples, generated docs, testdata/rdock.yaml; not published (ADR-0030)
├── schema/
│   └── rdock.v1.json               # generated JSON Schema, committed; CI fails if stale
├── Dockerfile                      # build from source: static musl → distroless, non-root
├── Dockerfile.release              # release image from the signed release binaries (GHCR, multi-arch)
├── deploy/
│   ├── docker/                     # compose.yaml + rdock.yaml example
│   ├── helm/reversedock/           # chart (v0.7): templates, values.yaml, values.schema.json, ci/ value sets, README
│   ├── kubernetes/                 # install.yaml (generated from the chart by scripts/render-kubernetes-manifests.sh), namespace.yaml, kustomization.yaml
│   └── systemd/                    # rdock.service (Type=notify, DynamicUser, CAP_NET_BIND_SERVICE; no socket activation)
├── examples/                       # runnable scenarios: config/, kubernetes/ (Gateway, HTTPRoute, GRPCRoute, TLSRoute, Ingress, cert-manager, secrets/), secrets/ (OpenBao Agent in Compose; examples that CI does not run), plugins/ (v0.8: header-rewrite, ip-blocklist, custom-rdock, template; workspace members, `publish = false`, tested by `rust`; wasm-header, the experimental WASM guest for `wasm32-wasip2`, outside the workspace with its own lock file, built and tested by `wasm`), waf/ (v0.8: CRS WAF as a `forward` agent in Compose, `smoke.sh` run by `waf-example`)
├── benchmarks/                     # scenarios/, configs for nginx/traefik/caddy/haproxy, run.sh, results/<version>/
├── tests/
│   ├── e2e/                        # (later) Docker-based scenarios; the v0.1 e2e suites live in crates/rdock/tests
│   ├── conformance/traefik-labels/ # compose files + expected routing tables
│   ├── conformance/gateway-api/    # Gateway API v1.7.0 suite: Go module, options.yaml, run.sh (kind), check-report.py; reports are added by release PRs
│   └── fuzz/                       # own cargo workspace: h1_framing (differential), rules_parser, config_loader, jwt_verify, clienthello, disk_cache_header, json_patch and oidc_cookie (v0.8); label parser later
├── docs/                           # these documents (the engineering plan); the public docs live in apps/website
├── scripts/                        # xlsx2md.py, schema-export, render-kubernetes-manifests.sh, release helpers
├── CONTRIBUTING.md · CODE_OF_CONDUCT.md · SECURITY.md · SUPPORT.md · GOVERNANCE.md
├── CLAUDE.md                       # rules for AI assistants (AGENTS.md is a symlink to it); .claude/ stays local
├── LICENSE (Apache-2.0) · NOTICE · CHANGELOG.md · README.md · .editorconfig · .gitignore
```

## 2. Crate conventions

| Topic | Rule |
|---|---|
| Edition / MSRV | Rust 2024 edition; MSRV = the highest MSRV among our dependencies, **1.89** today (serde-saphyr; Pingora 0.9 needs 1.88), declared once in `[workspace.package] rust-version`, checked by the `msrv` job ([ADR-0011](decisions/0011-yaml-parser-and-msrv.md)) |
| Safety | `[lints.rust] unsafe_code = "forbid"` in the workspace; exceptions need an ADR |
| Clippy | `clippy::all` + selected `pedantic`; `unwrap_used`/`expect_used`/`panic` denied in library crates (allowed in tests and the binary's startup path with a message) |
| Errors | `thiserror` enums in libraries; `miette` diagnostics with source spans for config/label errors; `anyhow` only in the binary |
| Logging | `tracing` only; structured fields, no `println!`; secrets never logged (newtype `Secret<T>` with redacted `Debug`) |
| Async | Tokio 1.x (the `<1.54` cap went with Pingora 0.9.1, which fixed the zero-capacity `BufStream` panic; the weekly `tokio-canary` job tests the newest 1.x ahead of the lockfile); blocking I/O via `spawn_blocking`; no `std::sync::Mutex` across awaits; `ArcSwap` for shared config |
| Build tools | A C compiler and **CMake** (Pingora builds zlib-ng; ring and zstd need C) |
| Public API | `#![warn(missing_docs)]` on lib crates; `pub` surface minimised; `#[non_exhaustive]` on config enums |
| Features | One table (below) is the source of truth; 05 and the ADRs point here |
| Naming | config keys `snake_case`; labels `rdock.dot.case`; CLI flags `--kebab-case`; env `RDOCK_UPPER_SNAKE`; metrics `rdock_snake_case` |
| Dependencies | Every new dependency reviewed against `deny.toml` (allowed licenses: Apache-2.0, MIT, BSD-*, ISC, Zlib, Unicode, MPL-2.0 case-by-case) |
| Docs | Each crate has a `README.md` and a module-level doc comment describing its place in the pipeline |

### Cargo features (source of truth)

| Feature | Default | What it adds |
|---|---|---|
| `docker` | on | Docker provider (`bollard`) |
| `swarm` | on | Swarm provider |
| `kubernetes` | on | Gateway API / Ingress controller (`kube` 5 with rustls and ring, `k8s-openapi`; the Gateway API types are our own, not the `gateway-api` crate); a build without it warns when `providers.kubernetes` is set |
| `dashboard` | on | embedded SPA in `rdock-admin` |
| `mimalloc` | on | `rdock` (the library) sets mimalloc as the global allocator; a custom binary with native plugins turns it off to bring its own (ADR-0030) |
| `wasm` | off, experimental | WASM plugins (`type: wasm`) on wasmtime 36 LTS with Cranelift and the component model (`rdock-wasm`; also a feature of `rdock-middleware` and `rdock-proxy`); about 50 more crates. Without it `type: wasm` is refused with a diagnostic. Tested only in the non-required `wasm` CI job ([ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)) |
| `cache` | none: always built | The HTTP cache (`rdock-cache`, v0.8) is in every build: `pingora-proxy` compiles `pingora-cache` anyway, so a feature would save no dependency ([ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)) |
| `http3` | off, experimental | QUIC ingress; requires the `boringssl` backend |
| `rustls` / `openssl` / `boringssl` | `rustls` | mutually exclusive TLS backends ([ADR-0002](decisions/0002-tls-backend-rustls.md)) |

`cargo build --no-default-features --features rustls` builds the minimal proxy (file provider, no dashboard). The features appear as their crates gain code; M0 has none yet.

## 3. Dashboard conventions

- TypeScript `strict`; ESLint (typescript-eslint, react-hooks, jsx-a11y) + Prettier; Vitest + Testing Library; Playwright e2e against a real `rdock` with fixtures.
- Data layer: client generated by `@hey-api/openapi-ts` from `schema/openapi.json` (openapi-typescript is in maintenance mode, [v0.5 research](research/v0.5-management.md#8-dashboard-frontend)), TanStack Query for caching, typed SSE streams for live data.
- No network calls except the admin API; fonts/icons bundled; CSP `default-src 'self'` served by `rdock-admin`.
- English only ([ADR-0024](decisions/0024-management-api-and-dashboard.md)); no translation layer.
- Bundle budget enforced (initial JS and CSS ≤ 300 kB gzip, lazy chunks ≤ 250 kB); route-level code splitting; production npm licences checked against an allow-list.
- Build: `pnpm build` → `apps/dashboard/dist` → `rdock-admin/build.rs` embeds via `rust-embed` (`RDOCK_SKIP_DASHBOARD=1` builds without it for fast Rust-only iteration).

## 4. Git and release workflow

- `main` is protected by the **Protect main** ruleset: no direct pushes, force pushes or deletion; linear history; squash merges only; PR required with one code-owner approval of the latest push, resolved conversations and an up-to-date branch; required checks `docs`, `dco`, `pr-title` (bound to GitHub Actions). Repository admins may bypass the review requirement only through a PR. Heavier checks (Rust, dashboard, e2e) become required as they land.
- Release tags `v*` are protected by the **Protect release tags** ruleset: only admins create them; nobody can move or delete them.
- Conventional Commits (`feat(docker): …`, `fix(acme): …`); the PR title becomes the squash commit and is checked by `pr-title`. DCO sign-off (`git commit -s`) checked by `dco`; web commits get sign-off automatically. No CLA.
- Versioning: SemVer. `0.x` may break config between minors with a migration note and `rdock config migrate`. Config schema is versioned (`apiVersion`-style `version: 1` optional key).
- Releases come from `.github/workflows/release.yml` when an admin pushes a `v*` tag: static binaries built natively for Linux x86-64 and aarch64 (musl) and macOS arm64, `SHA256SUMS` signed keylessly with cosign, an SPDX SBOM (syft), and GitHub build-provenance attestations; pre-release tags (`-alpha`, `-rc`) become GitHub pre-releases. A hand-written workflow replaced `cargo-dist` so every action is pinned by SHA and signing is under our control. Container images `ghcr.io/docker-hunterpedia/rdock` (multi-arch, non-root) start with v0.1.
- Support policy: last two minor releases get security fixes; `SECURITY.md` with private reporting (GitHub advisories) and a 90-day disclosure target.

## 5. Testing strategy

| Level | Tool | Where | Gate |
|---|---|---|---|
| Unit | `cargo nextest` | per crate | every PR |
| Property / grammar | `proptest` | rules, labels, path normalisation | every PR |
| Integration | `rdock-testkit` (spawns h1/h2c/TLS upstreams, a test CA and the real `rdock` binary; Pebble and toxiproxy later) | `crates/rdock/tests/e2e_*.rs` | every PR |
| Conformance | Traefik-label suite; Gateway API v1.7.0 suite on kind (`kubernetes.yml`; passed 2026-11-11, fails the workflow, not yet a required check) | `tests/conformance` | PRs touching providers; nightly |
| Kubernetes | Translator and status tests on fixtures (`tests/gateway_conformance.rs` transcribes upstream conformance tests); runtime tests against a bare kube-apiserver when `RDOCK_TEST_KUBECONFIG` is set (not wired into CI); chart `helm lint --strict`, `helm template` + kubeconform, manifests in sync; Helm on k3s (fails the workflow; passed 2026-11-11) | `crates/providers/rdock-provider-kubernetes`, `deploy/`, `.github/workflows/kubernetes.yml` | PRs touching them; nightly |
| Fuzz | `cargo-fuzz` (differential HTTP/1 framing vs httparse, rules parser, config loader) | `tests/fuzz` | weekly + parser PRs |
| Load / soak | `oha`, `wrk2`, `k6`, 24 h soak | `benchmarks/` | nightly rdock-vs-NGINX regression check on a shared runner (`bench.yml`); published results from fixed hardware, committed per release |
| Security | `cargo-audit`, `cargo-deny`, Semgrep, dependency review, Trivy on images | CI | every PR |
| UI | Vitest, Playwright (light/dark, 400 px–1440 px, axe, no external requests) | `apps/dashboard` | every PR |
| Website | generated-page freshness, `rdock validate --strict` on every config snippet, status badges vs `rdock`, link check, `astro check`, axe (WCAG 2.2 AA) | `apps/website` | PRs touching the site, schema, CLI or changelog |

## 6. Code graph tooling (Graphify)

Once there is code, contributors (and AI assistants) can build a knowledge graph of the workspace. Verified with `graphify 0.9.95`:

```bash
uv tool install graphifyy                     # package name has two y's; installs `graphify` and `graphify-mcp`
graphify install --platform claude --project  # registers the /graphify skill for this repo (.claude/skills/graphify/)
# inside Claude Code:  /graphify .            # builds graphify-out/{graph.html, GRAPH_REPORT.md, graph.json}
graphify update .                             # re-extract after code changes, no LLM needed
graphify watch .                              # rebuild on change
graphify explain "rdock-config"               # plain-language view of a node and its neighbours
graphify path "rdock-proxy" "rdock-acme"      # shortest dependency path between two nodes
graphify-mcp                                  # stdio MCP server exposing query_graph to any MCP client
```

The hosted endpoint `https://api.graphify.com/mcp` needs an account key (it answers 401 anonymously); the local CLI and its MCP server need nothing. `graphify-out/` is gitignored; a `just graph` recipe will wrap `graphify update .`.
