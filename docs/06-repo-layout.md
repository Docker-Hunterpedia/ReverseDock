# ReverseDock — Repository layout and engineering conventions

## 1. Tree

```
reversedock/
├── Cargo.toml                      # workspace: members = crates/*, crates/providers/*, the native plugin examples, benchmarks/perreq
├── Cargo.lock
├── rust-toolchain.toml             # pinned toolchain (1.99.1) + clippy, rustfmt; bumped by PR
├── deny.toml                       # cargo-deny: licenses, advisories, bans, sources
├── justfile                        # dev recipes: just dev | test | e2e | lint | dashboard | bench | release
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # docs (+ actionlint), dco, pr-title, rust (fmt, clippy, nextest, doc), msrv, deny, docker; clients, dashboard; `terraform-provider` (v0.8: provider checks, CLI tests with Terraform and OpenTofu against a fake and a real rdock; not a required check); `waf-example` (v0.8: examples/waf/smoke.sh, the CRS WAF as an agent; not a required check); `openbao` (v0.8: the ignored `e2e_vault` test against OpenBao 2.7.2 in dev mode, pinned by digest, with a root token generated in the job; not a required check); `oidc-dex` (v0.8: the ignored `e2e_oidc` login test against Dex v2.46.1, pinned by digest, with a client secret and a password generated in the job; not a required check); `wasm` (v0.8: `just wasm`, clippy and the WASM tests with the experimental `wasm` feature, the example guest, MSRV with the feature; not a required check); `http3` (v0.9: `just http3`, clippy, the HTTP/3 unit and end-to-end tests and MSRV with the experimental `http3` feature, then `scripts/http3-curl.sh`, curl over HTTP/3 from a Debian image pinned by digest; not a required check); `chaos` (1.0: `just chaos`, the chaos suite with `RDOCK_CHAOS_DISK=tmpfs`, a real tmpfs filled until `ENOSPC` through passwordless sudo, plus the Docker-based `chaos.rs` (Toxiproxy), `e2e_docker` and `e2e_acme` (Pebble) and `e2e_cluster`; not a required check); `image-scan` (1.0: Grype on the built image, `.grype.yaml` for reviewed exceptions; not a required check); semgrep (fails on any finding; clean on 2026-11-14 and eligible to be required, which is the maintainer's decision)
│   │   ├── dashboard.yml           # (M0+) pnpm lint/test/build, bundle-size budget
│   │   ├── e2e.yml                 # (v0.1+) docker compose scenarios, Pebble ACME, toxiproxy
│   │   ├── conformance.yml         # (v0.2+) traefik-label suite
│   │   ├── kubernetes.yml          # (v0.7) chart lint/render/kubeconform and manifests in sync; Gateway API conformance on kind and Helm on k3s (both fail the workflow; passed 2026-11-11; not yet required checks; ADR-0029)
│   │   ├── cache.yml               # (v0.8) `http-cache`: the public RFC 9111 suite http-tests/cache-tests (pinned by commit, Node.js 24) against the cache at safe defaults, gated by tests/conformance/http-cache/allowlist.json; on PRs touching the cache, weekly; passed its gate 2026-11-12; not a required check (ADR-0030)
│   │   ├── fuzz.yml                # cargo-fuzz, weekly (30 min/target, corpus cached) + on parser changes (tests/fuzz)
│   │   ├── codeql.yml              # CodeQL: Rust, JavaScript/TypeScript, Go, Actions (not required)
│   │   ├── dependency-review.yml   # dependency review on pull requests (not required)
│   │   ├── scorecard.yml           # OpenSSF Scorecard, published to the Security tab (not required)
│   │   ├── weekly.yml              # RustSec advisories for both lockfiles; tokio canary on the newest 1.x
│   │   ├── bench.yml               # nightly regression check: rdock vs NGINX in one job, artifacts only; gates throughput at 0.98× NGINX's, p99, failures and CPU time per request at 2.4× NGINX's (v0.9, `benchmarks/compare.py`)
│   │   ├── soak.yml                # (v0.9) weekly hosted soak, about 5 h 20 min on a GitHub-hosted runner (`benchmarks/soak/hosted`): a stand-in for, not the, 24-hour soak; not a required check; no full run had completed when v0.9 was written (ADR-0031)
│   │   ├── scaling.yml             # (v0.9) hand-run CPU-scaling measurement (rdock on 1, 2 and 4 CPUs of a hosted runner; the 4-CPU row is a lower bound); gates nothing (ADR-0031)
│   │   ├── bench-report.yml        # (v1.0) weekly and by hand: all five proxies plus `direct` on one hosted runner, proxy pinned to 2 of 4 vCPUs, `single`/`tls`/`tls-new`/`h2`, default and tuned configurations; fails on a TLS-parity mismatch; the report states the hosted-runner limit (`benchmarks/hosted_report.py`); not a required check; has not run yet (ADR-0033)
│   │   ├── https-60s.yml           # (v1.0) nightly and on PRs touching ACME/TLS/Docker provider: the release image (Dockerfile.release) with the `https` Compose example against Pebble, fails when valid HTTPS takes 60 s or more after `docker compose up -d` (`tests/https-60s/run.sh`); not a required check; has not run yet (ADR-0033)
│   │   ├── reproducible.yml        # (1.0) weekly rebuild-and-compare: the release recipe built three times (two runners, one other directory), binaries compared by hash; reports, never fails on a difference; not a required check (§4)
│   │   └── release.yml             # build (cargo-auditable) → package (SBOMs read from the binaries, checksums, the `latest` decision; also on PRs) → publish (tags: provenance and SBOM attestations, cosign, release) and image (tags: signed image, per-platform SBOM attestations)
│   ├── ISSUE_TEMPLATE/             # issue forms: bug, compatibility gap, feature, design proposal, docs + config.yml
│   ├── PULL_REQUEST_TEMPLATE.md · CODEOWNERS · dependabot.yml · release.yml (release-note categories)
├── crates/
│   ├── rdock/                      # the binary (clap); `upgrade/` (binary upgrade by handover), `datadir` (the one-process lock), `cluster`/`control` wiring (v0.9)
│   ├── rdock-model/                # desired-state types, validation, JSON Schema
│   ├── rdock-rules/                # Traefik-compatible rule grammar
│   ├── rdock-config/               # loaders, merge engine, compile, snapshots, history
│   ├── rdock-proxy/                # Pingora ProxyHttp, router (host index, v0.9), middleware runtime, L4, listener sockets (`socket2`, v0.9), GeoIP matchers; HTTP/3 ingress (`http3` module, v0.9, experimental, ADR-0032)
│   ├── rdock-tls/                  # resolver, cert store, policies, local CA; shared session tickets and caches per security class (v0.9)
│   ├── rdock-acme/                 # ACME client, solvers, DNS providers, scheduler; orders under a per-name lease on a `ClusterStore`, order journal, certificate storage with `next/` and `meta.json` as the commit (v0.9)
│   ├── rdock-balancer/             # LB policies, health, retries, breakers; `peak_ewma`, outlier detectors, slow start on join, priority tiers, locality (v0.9)
│   ├── rdock-cache/                # HTTP cache: RFC 9111 policy, memory and disk stores, purge, on pingora-cache (ADR-0030)
│   ├── rdock-middleware/           # built-in middlewares; the plugin adapter and `agent` (v0.8)
│   ├── rdock-plugin-api/           # (v0.8) the only crate a native plugin depends on: Plugin trait, http-typed heads, Factory, Registry, testing harness; own 0.x version line (ADR-0030)
│   ├── rdock-wasm/                 # (v0.8, experimental) WASM plugins: digest pin and minisign checks (always built), the wasmtime host and the WIT world `rdock:plugin/filter` behind the `wasm` feature (ADR-0030)
│   ├── rdock-limits/               # rate/concurrency/size limits; per-consumer quotas with persisted counters (v0.8); leased shares for cluster-scoped limits and the adaptive limits of `admission` (v0.9)
│   ├── rdock-credentials/          # (v0.8) credential formats shared by admin and data plane: rdk_pat_ tokens, rdk_ API keys, rdk_join_ join tokens (v0.9), SHA-256, constant-time compare (ADR-0030)
│   ├── rdock-cluster/              # (v0.9) cluster protocol, ClusterStore (CAS, leases with fencing; memory and directory backends), data-plane agent (ADR-0031)
│   ├── rdock-control/              # (v0.9) control plane run by `rdock control run`: cluster CA, join tokens, registry, bundle history, store server, cluster listener (ADR-0031)
│   ├── rdock-observability/        # logs, metrics, traces, ring buffer
│   ├── rdock-admin/                # axum API + OpenAPI + embedded dashboard
│   ├── rdock-cloudflare/           # IP sync, DNS-01, Access JWT, Origin CA
│   ├── rdock-dns-providers/        # DNS-01 adapters: Route 53, Google, Azure, DigitalOcean, Hetzner, deSEC, RFC 2136 (ADR-0026)
│   ├── rdock-migrate/              # traefik/caddy/nginx → rdock.yaml
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
│   ├── go/                         # generated Go client of the admin API (used by the Terraform provider)
│   └── terraform/                  # (v0.8) Terraform/OpenTofu provider (Go module, replace to ../go): internal/provider, examples, generated docs, testdata/rdock.yaml; not published (ADR-0030)
├── schema/
│   ├── rdock.v1.json               # generated JSON Schema, committed; CI fails if stale
│   ├── openapi.json                # generated OpenAPI 3.1 document of the admin API (`just schema`)
│   ├── agent.v1.json               # the agent protocol (hand-kept)
│   ├── migrate-report.v1.json      # (1.0, ADR-0033) generated JSON Schema of `rdock migrate … --report`, with the finding codes (`just schema`; beta)
│   └── compat/                     # (1.0, ADR-0033) public-surface snapshots for the compatibility gate, generated by `just compat`: cli, metrics, access-log, problems, env, labels, image, deprecations (JSON, sorted, no machine paths); exceptions.json is the reviewed exceptions file
├── Dockerfile                      # build from source: static musl → distroless, non-root
├── Dockerfile.release              # release image from the signed release binaries (GHCR, multi-arch)
├── deploy/
│   ├── docker/                     # compose.yaml + rdock.yaml example
│   ├── helm/reversedock/           # chart (v0.7): templates, values.yaml, values.schema.json, ci/ value sets, README
│   ├── kubernetes/                 # install.yaml (generated from the chart by scripts/render-kubernetes-manifests.sh), namespace.yaml, kustomization.yaml
│   └── systemd/                    # rdock.service (Type=notify, DynamicUser, CAP_NET_BIND_SERVICE; no socket activation)
├── examples/                       # runnable scenarios: config/, kubernetes/ (Gateway, HTTPRoute, GRPCRoute, TLSRoute, Ingress, cert-manager, secrets/), secrets/ (OpenBao Agent in Compose; examples that CI does not run), plugins/ (v0.8: header-rewrite, ip-blocklist, custom-rdock, template; workspace members, `publish = false`, tested by `rust`; wasm-header, the experimental WASM guest for `wasm32-wasip2`, outside the workspace with its own lock file, built and tested by `wasm`), waf/ (v0.8: CRS WAF as a `forward` agent in Compose, `smoke.sh` run by `waf-example`)
├── benchmarks/                     # scenarios/, configs for nginx/traefik/caddy/haproxy, run.sh, results/<version>/; perreq/ (v0.9: allocations, system calls and CPU time per request and the CPU-scaling mode, without Docker; a workspace member, `publish = false`), soak/hosted (v0.9: the soak without Docker, with binary upgrades), cpu-ladder.sh; (1.0) configs/tuned/ (each proxy's documented tuning), compose.pinned.yaml (cpusets for hosted runners), hosted_report.py with test_reports.py
├── tests/
│   ├── e2e/                        # (later) Docker-based scenarios; the v0.1 e2e suites live in crates/rdock/tests
│   ├── conformance/traefik-labels/ # container fixtures + expected routing tables; coverage.json (generated from labels/coverage.rs)
│   ├── conformance/traefik-compose/# (1.0) Compose corpus: input, case.json, expected.yaml and report.json of `rdock migrate traefik` (`just migrate-golden`)
│   ├── conformance/caddy-json/     # (1.0) Caddy corpus: Caddyfile, adapted JSON, expected.yaml and report.json of `rdock migrate caddy` (`just caddy-corpus` re-adapts)
│   ├── conformance/nginx/          # (1.0) NGINX corpus: configuration, expected.yaml and report.json of `rdock migrate nginx`
│   ├── conformance/traefik-diff/   # (1.0) differential test against a pinned Traefik: harness.py, test_harness.py, allowlist.json (workflow `traefik-diff`)
│   ├── conformance/http-cache/     # (v0.8) harness for http-tests/cache-tests: rdock.yaml (the cache at safe defaults), summarize.mjs (the gate), allowlist.json (test id → reason), README
│   ├── conformance/gateway-api/    # Gateway API v1.7.0 suite: Go module, options.yaml, run.sh (kind), check-report.py; reports are added by release PRs or a follow-up PR from a run on the release tag
│   ├── https-60s/                  # (1.0) the 60-second HTTPS proof: compose.ci.yaml (override of deploy/docker/examples/https with Pebble), pebble.json, run.sh (workflow `https-60s`)
│   └── fuzz/                       # own cargo workspace: h1_framing (differential), rules_parser, config_loader, jwt_verify, clienthello, disk_cache_header, json_patch and oidc_cookie (v0.8), proxy_header (v0.6), tls_fingerprint and http3_request (v0.9), nginx_parser, and (v1.0) rules_eval, backend_response, acme_answers, admin_input, cluster_protocol, resp_reader, docker_labels, compose_interpolation, migrate_caddy
├── docs/                           # these documents (the engineering plan); the public docs live in apps/website
├── scripts/                        # xlsx2md.py, check-docs.py, compat.py (the compatibility gate, ADR-0033; standard library only) and test_compat.py, render-kubernetes-manifests.sh, http3-curl.sh (curl over HTTP/3, `http3` CI job), https-60s-vps.sh (the 60-second HTTPS proof on a real server against Let's Encrypt, run by hand), release helpers (`release_latest.py` with `test_release_latest.py`: the rule that `latest` never moves backwards; `pin-base-images.sh`: base images by digest)
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
| Cluster crates | `rdock-cluster` depends on no other `rdock-*` crate (the data plane, ACME and the control plane share it); `rdock-control` never depends on `rdock-admin` (`deny.toml`): the binary runs the admin API for the control plane through `rdock_admin::Control` |

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
| `http3` | off, experimental | HTTP/3 ingress on `quinn` and `h3` with the listener's rustls configuration; 7 more crates on Linux (`quinn`, `quinn-proto`, `quinn-udp`, `h3`, `h3-quinn`, `lru-slab`, `rand_pcg`; `web-time` only for wasm targets; `rdock-proxy` itself uses its own adapter of h3's `quic` traits instead of `h3-quinn`, which only the test client uses); not in release binaries ([ADR-0032](decisions/0032-http3-on-quinn-and-h3.md)). Features of the same name on `rdock-proxy` and `rdock-testkit` (the HTTP/3 test client). Without it `http3.enabled: true` is refused with a diagnostic. CI: the non-required `http3` job (`just http3`, then `scripts/http3-curl.sh`) |
| `jemalloc` | off, comparison only | `tikv-jemallocator` as the global allocator, to compare with mimalloc (v0.9, H-PERF-06, ADR-0031); never in a release build; builds on glibc, a musl build was not tried |
| `alloc-count` | off, bench only | `rdock` counts allocations with `stats_alloc` for `benchmarks/perreq` (v0.9, ADR-0031); the system allocator instead of mimalloc; never in a release build or a CI artefact |
| `fault-injection` | off, tests only | faults for the admin API's tests (`RDOCK_FAULT`) and the binary upgrade's (`RDOCK_UPGRADE_FAULT`, also in debug builds); a fault can only make an operation fail; never in a release build |
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
- Versioning: SemVer, with the stability promise, deprecation rules and maturity levels of [10-stability.md](10-stability.md) (ADR-0033). `0.x` may break config between minors with a migration note. Deprecated settings are rewritten by `rdock migrate config`, which will also convert between schema versions once a later one exists. Config schema is versioned (`apiVersion`-style `version: 1` optional key; v1 is additive through 1.x).
- Releases come from `.github/workflows/release.yml` when an admin pushes a `v*` tag: static binaries built natively for Linux x86-64 and aarch64 (musl) and macOS arm64 with `cargo auditable build`, one SPDX SBOM per archive, `SHA256SUMS` over the archives and the SBOMs signed keylessly with cosign, and GitHub build-provenance and SBOM attestations for each archive; pre-release tags (`-alpha`, `-rc`) become GitHub pre-releases. A hand-written workflow replaced `cargo-dist` so every action is pinned by SHA and signing is under our control. Container images `ghcr.io/docker-hunterpedia/rdock` (multi-arch, non-root) start with v0.1; the image job signs the image by digest, attests its provenance, and attests one SBOM per platform (read from the pushed image).
- **SBOMs describe what ships (ADR-0033, F-OSS-03).** `cargo auditable` embeds the exact crate list of the build (the real feature set, no dev dependencies) in a linker section of the binary (cargo-auditable 0.7.7; its README says the data has no timestamps and is sorted so as not to disturb reproducible builds, read 2026-11-14). The `package` job unpacks each archive and runs syft (`anchore/sbom-action`) on the unpacked directory, so the SBOM comes from the binary, never from the source tree; it fails the release when an SBOM lists fewer than 50 crates or not `rdock` itself. Each SBOM is covered twice: by the signed `SHA256SUMS` and by an `actions/attest` SBOM attestation on its archive (`actions/attest-sbom` is marked deprecated in its own repository in favour of `actions/attest`, read 2026-11-14). The image job scans each platform manifest of the pushed image (distroless base packages and the same crates) and attests it to that manifest digest in the registry. **Limits:** the JavaScript libraries bundled into the embedded dashboard are not listed (they are compiled into one asset, not separate packages); the SBOM files themselves are not reproducible (syft writes a document namespace per run); the macOS binary is not codesigned or notarised.
- **Base images are pinned by digest.** Every `FROM` line of `Dockerfile` and `Dockerfile.release` reads `image:tag@sha256:<digest>`: the digest is what Docker pulls, the tag tells people what it is. Dependabot's docker ecosystem (`.github/dependabot.yml`; its file fetcher takes every file name containing "dockerfile" and its parser reads `image:tag@sha256:digest`, dependabot-core at commit `13987a8`, 2026-11-13) updates tag and digest together; the `FROM` lines are literal because Dependabot cannot read build arguments in them. `scripts/pin-base-images.sh` makes a first pin (it reads the digest from the registry over the OCI distribution API, curl only), `--check` compares each pin with what its tag resolves to now, and `--verify` (offline, in the `docs` job and `just ci`) fails when a base image has no digest. The Rust tag in `Dockerfile` must stay in step with `rust-toolchain.toml`; nothing checks that, so a Dependabot bump of the Rust tag needs the same change in `rust-toolchain.toml` and `ARG RUST_VERSION` by hand. Not covered by this change: `apt-get install musl-tools` on the build runners (the runner image is GitHub's) and the images that CI jobs pull for tests (some already pin by digest, see §5; the others are not checked).
- **Reproducibility is tested, and the result is stated here.** `.github/workflows/reproducible.yml` runs weekly (Tuesday, 05:23 UTC) and on pull requests that touch it. It builds the x86_64 Linux release binary three times from one commit with the release recipe (the dashboard, then `cargo auditable build --release --locked`, the same pinned toolchain, the same runner image): twice in the workspace directory on two runners (determinism) and once from a copy of the tree in another directory (path independence), and compares the SHA-256 hashes of the three binaries. **It proves, when the hashes are equal:** this binary, for this target, on this runner image and commit, is the same bit for bit across runners and build directories. **It does not prove:** that the published `.tar.gz` archives are reproducible (tar and gzip headers carry times and owners; the job does not compare archives), anything about the other two targets, the image, a different toolchain or machine, or a rebuild of an older release. It never fails because hashes differ: the run summary and a warning annotation say "not reproducible yet (tracked)" and the two differing binaries are kept as artifacts for 14 days. **Status on 2026-11-14: the job has not run yet; no result exists.** Until a run's result is recorded here, ReverseDock does not claim reproducible builds (F-OSS-03). Adding a reproducibility result to a release's notes, deterministic archives (sorted tar entries, fixed times, `gzip -n`) and a rebuild of the last published release are open.
- **Release branches and the `latest` rule (F-OSS-05).** Fixes land on `main` first and are cherry-picked by pull request to `release/X.Y` (`release/1.4` for the 1.4 line), cut from the tag `vX.Y.0` when the first patch needs it (`git switch -c release/1.4 v1.4.0`, pushed by a maintainer). The branch is protected by a ruleset the maintainer creates (the project never creates rulesets itself); the exact settings are in [10-stability.md](10-stability.md) §6. Release tags for patches are cut from the branch (`v1.4.1` on `release/1.4`); the `package` job already checks that the tag equals the `Cargo.toml` version, and the **Protect release tags** ruleset applies to the tag wherever it points. **`latest` never moves backwards:** the `package` job lists the repository's tags and runs `scripts/release_latest.py <version>`; the `latest` image tag and GitHub's "Latest release" mark go only to a stable version that no higher stable tag outranks by SemVer precedence. A pre-release (`1.0.0-rc.1`) never takes them, and a patch for an older minor (`1.3.5` after `1.4.0`) does not. The tag list is the authority, so a tag that was pushed but never published would hold `latest` back until a maintainer moves it by hand; two releases published within seconds of each other could still race (not handled). The rule has 26 unit tests (`python3 -I scripts/test_release_latest.py`, in the `docs` job and `just ci`). Not done: moving tags `1` and `1.N`.
- Support policy: the two newest minors of the current major get security fixes, and the last minor of the previous major for six months after a new major ([10-stability.md](10-stability.md) §6, F-OSS-05); `SECURITY.md` with private reporting (GitHub advisories) and a 90-day disclosure target.

## 5. Testing strategy

| Level | Tool | Where | Gate |
|---|---|---|---|
| Unit | `cargo nextest` | per crate | every PR |
| Property / grammar | `proptest` | rules, labels, path normalisation | every PR |
| Integration | `rdock-testkit` (spawns h1/h2c/TLS upstreams, a test CA and the real `rdock` binary; Pebble and toxiproxy later) | `crates/rdock/tests/e2e_*.rs` | every PR |
| Conformance | Traefik-label suite; Gateway API v1.7.0 suite on kind (`kubernetes.yml`; GATEWAY-HTTP, -GRPC, -TLS, -TCP passed 2026-11-11 and GATEWAY-UDP 2026-11-12, commit `43d81de`; fails the workflow, not yet a required check); RFC 9111 suite `http-tests/cache-tests` (`cache.yml`; gate passed 2026-11-12, not a required check) | `tests/conformance` | PRs touching providers; nightly |
| Kubernetes | Translator and status tests on fixtures (`tests/gateway_conformance.rs` transcribes upstream conformance tests); runtime tests against a bare kube-apiserver when `RDOCK_TEST_KUBECONFIG` is set (not wired into CI); chart `helm lint --strict`, `helm template` + kubeconform, manifests in sync; Helm on k3s (fails the workflow; passed 2026-11-11) | `crates/providers/rdock-provider-kubernetes`, `deploy/`, `.github/workflows/kubernetes.yml` | PRs touching them; nightly |
| Fuzz | `cargo-fuzz` (libFuzzer): 21 targets, from the differential HTTP/1 framing check to ACME answers, admin request bodies, cluster bundles, the RESP reader, label translation and the migration readers (list and coverage: [11-threat-model.md](11-threat-model.md) §8); each has seeds and a mutation smoke test run by `cargo test` | `tests/fuzz`, `fuzz.yml` | 30 min per target weekly with the corpus kept in the Actions cache (written only by the scheduled run on `main`); 2 min on PRs touching code a target reaches; smoke tests on every fuzz run |
| Load / soak | `oha`, `wrk2`, `k6`, 24 h soak (v0.5, on the retired lab); the hosted soak with binary upgrades (v0.9, `soak.yml`, weekly, about 5 h 20 min: a stand-in for the 24-hour criterion) and the CPU-scaling mode (`scaling.yml`, by hand) | `benchmarks/` | nightly rdock-vs-NGINX regression check on a shared runner (`bench.yml`); all five proxies on a pinned hosted runner with TLS parity and default/tuned configurations (`bench-report.yml`, weekly, results within one run only); published results from fixed hardware, committed per release |
| Compatibility | `scripts/compat.py check` (ADR-0033): the config schema, the OpenAPI document, the Helm values schema and the snapshots in `schema/compat/` against the newest `v*` tag reachable from the commit, and `cargo-semver-checks` 0.51.0 for `rdock-plugin-api`; exceptions in `schema/compat/exceptions.json`. Report mode before `1.0.0-rc.1`, enforce mode from then on (`RDOCK_COMPAT_MODE` forces either); stale snapshots fail in both. Data-directory fixtures of the 0.8 and 0.9 layouts in `crates/rdock/tests/compat_datadir.rs`. What each check covers and misses: [10-stability.md](10-stability.md) §9 | `scripts/`, `schema/compat/`, the `compat` CI job (fetches tags; to be made required) | every PR |
| Chaos (ADR-0033, H-ENG-05) | `rdock-testkit`: an open-model load generator (`load`), a full disk (`disk`: a tmpfs filled until `ENOSPC` with root or passwordless sudo, or the process's file-size limit set to zero, `EFBIG`, rootless), a fake Docker Engine API that disappears, hangs or answers 500 (`fake_docker`), a TCP proxy that resets or blackholes (`fault_proxy`), the fake ACME CA's modes and refused orders (`fake_acme`) | `crates/rdock/tests/chaos_*.rs` (control plane, Docker socket, CA, disk full, flapping, rollback; about 110 s serial, 40 s under nextest) | every PR (rootless variant in `rust`); the tmpfs and Docker variants in the `chaos` job |
| Security | `cargo deny check` (licences, bans, sources and RustSec advisories: the database `cargo audit` reads, so `cargo audit` is not run separately; required `deny` job, weekly also for the fuzz workspace); Semgrep `p/rust`, `p/github-actions`, `p/dockerfile` (fails on any finding; clean on 2026-11-14; not yet required); CodeQL for Rust, JavaScript/TypeScript, Go and Actions (`codeql.yml`; test, bench and example code and the Rust hard-coded-value query, which only finds fixture passwords in unit tests, are left out by `.github/codeql/codeql-config.yml`); GitHub dependency review (`dependency-review.yml`; it covers Go modules and actions: GitHub's dependency graph lists no detection method for `Cargo.lock` and skips our two-document pnpm lockfile, both read 2026-11-14); a Grype scan of the built image failing on high and critical findings unless `.grype.yaml` lists them with a reason (`image-scan`); OpenSSF Scorecard (`scorecard.yml`; Code-Review and Contributors score low for a single-maintainer project). `cargo-vet` is not used: auditing or exempting every dependency is an ongoing review cost one maintainer cannot carry; `cargo deny` and Dependabot's 14-day cooldown are the policy. None of the new jobs is required yet; the threat model is [11-threat-model.md](11-threat-model.md) | CI | every PR (Scorecard weekly and on `main`) |
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
