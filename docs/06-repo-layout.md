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
│   │   ├── ci.yml                  # docs (+ actionlint), dco, pr-title, rust (fmt, clippy, nextest, doc), msrv, deny, docker; semgrep (report only)
│   │   ├── dashboard.yml           # (M0+) pnpm lint/test/build, bundle-size budget
│   │   ├── e2e.yml                 # (v0.1+) docker compose scenarios, Pebble ACME, toxiproxy
│   │   ├── conformance.yml         # (v0.2+) traefik-label suite; gateway-api suite on kind (v0.7)
│   │   ├── fuzz.yml                # cargo-fuzz, weekly + on parser changes (tests/fuzz)
│   │   ├── bench.yml               # (v0.4+) nightly on a dedicated runner, publishes to benchmarks/results
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
│   ├── rdock-middleware/           # built-in middlewares
│   ├── rdock-limits/               # rate/concurrency/size limits
│   ├── rdock-observability/        # logs, metrics, traces, ring buffer
│   ├── rdock-admin/                # axum API + OpenAPI + embedded dashboard
│   ├── rdock-cloudflare/           # IP sync, DNS-01, Access JWT, Origin CA
│   ├── rdock-migrate/              # traefik/nginx → rdock.yaml
│   ├── rdock-testkit/              # test harness (upstreams, Pebble, toxiproxy, containers)
│   └── providers/
│       ├── rdock-provider-file/
│       ├── rdock-provider-docker/
│       ├── rdock-provider-swarm/
│       ├── rdock-provider-kubernetes/
│       └── rdock-provider-api/
├── apps/
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
├── schema/
│   └── rdock.v1.json               # generated JSON Schema, committed; CI fails if stale
├── Dockerfile                      # build from source: static musl → distroless, non-root
├── Dockerfile.release              # release image from the signed release binaries (GHCR, multi-arch)
├── deploy/
│   ├── docker/                     # compose.yaml + rdock.yaml example
│   ├── helm/reversedock/           # chart (P2)
│   ├── kubernetes/                 # raw manifests, kustomize (P2)
│   └── systemd/                    # rdock.service (Type=notify, DynamicUser, CAP_NET_BIND_SERVICE; no socket activation)
├── examples/                       # runnable scenarios: 01-single-app, 02-compose-labels, 03-traefik-migration, 04-cloudflare-tunnel, 05-swarm, 06-kubernetes …
├── benchmarks/                     # scenarios/, configs for nginx/traefik/caddy/haproxy, run.sh, results/<version>/
├── tests/
│   ├── e2e/                        # (later) Docker-based scenarios; the v0.1 e2e suites live in crates/rdock/tests
│   ├── conformance/traefik-labels/ # compose files + expected routing tables
│   ├── conformance/gateway-api/    # upstream suite wiring
│   └── fuzz/                       # own cargo workspace: h1_framing (differential), rules_parser, config_loader; label parser later
├── docs/                           # these documents; docs/site later (Astro Starlight → reversedock.dev)
├── scripts/                        # xlsx2md.py, schema-export, release helpers
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
| Async | Tokio, capped at `<1.54` until Pingora handles tokio 1.54's `BufStream` change (Dependabot ignores it too); blocking I/O via `spawn_blocking`; no `std::sync::Mutex` across awaits; `ArcSwap` for shared config |
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
| `kubernetes` | on | Gateway API / Ingress controller (`kube`, `gateway-api`) |
| `dashboard` | on | embedded SPA in `rdock-admin` |
| `cache` | off until v0.8 | HTTP cache on `pingora-cache` |
| `http3` | off, experimental | QUIC ingress; requires the `boringssl` backend |
| `rustls` / `openssl` / `boringssl` | `rustls` | mutually exclusive TLS backends ([ADR-0002](decisions/0002-tls-backend-rustls.md)) |

`cargo build --no-default-features --features rustls` builds the minimal proxy (file provider, no dashboard). The features appear as their crates gain code; M0 has none yet.

## 3. Dashboard conventions

- TypeScript `strict`; ESLint (typescript-eslint, react-hooks, jsx-a11y) + Prettier; Vitest + Testing Library; Playwright e2e against a real `rdock` with fixtures.
- Data layer: `openapi-typescript` generated types + `openapi-fetch` client, TanStack Query for caching, SSE hooks for live data.
- No network calls except the admin API; fonts/icons bundled; CSP `default-src 'self'` served by `rdock-admin`.
- i18n via ICU messages (`en` source, `ar` first translation); RTL verified in CI with Playwright screenshots.
- Bundle budget enforced (initial JS < 350 kB gzip); route-level code splitting.
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
| Conformance | Traefik-label suite; Gateway API suite (kind) | `tests/conformance` | PRs touching providers; nightly |
| Fuzz | `cargo-fuzz` (differential HTTP/1 framing vs httparse, rules parser, config loader) | `tests/fuzz` | weekly + parser PRs |
| Load / soak | `oha`, `wrk2`, `k6`, 24 h soak | `benchmarks/` | nightly on dedicated runner; results committed per release |
| Security | `cargo-audit`, `cargo-deny`, Semgrep, dependency review, Trivy on images | CI | every PR |
| UI | Vitest, Playwright (light/dark, LTR/RTL, 400 px–1440 px) | `apps/dashboard` | every PR |

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
