# ReverseDock — rules for AI assistants

ReverseDock is an open-source reverse proxy in Rust on Cloudflare Pingora (Apache-2.0, free forever). Milestones M0 (workspace, rule grammar, config model and schema, `rdock validate`) and v0.1 (the HTTP proxy: `rdock run`, file provider with reload, manual TLS, P0 middlewares, admin listener) are implemented; v0.2 adds the Docker provider. Read [docs/README.md](docs/README.md) before proposing changes.

## Working rules

- **Never push to `main`.** It is protected by the "Protect main" ruleset. Every change goes through a branch and a pull request and is squash-merged. Do not merge PRs yourself or use `--admin`/bypass; maintainers merge.
- **Branch names:** `type/short-topic`, e.g. `feat/docker-network-selection`, `fix/acme-ari-retry`, `docs/roadmap-typo`.
- **Sign off every commit:** `git commit -s` (Developer Certificate of Origin). The `dco` check fails without a `Signed-off-by` line matching the commit author.
- **PR titles are Conventional Commits:** `type(scope): summary`. Types: `feat`, `fix`, `docs`, `perf`, `refactor`, `test`, `build`, `ci`, `chore`, `revert`, `security`; add `!` for breaking changes. Scopes are crate or area names without the `rdock-` prefix (`proxy`, `rules`, `config`, `tls`, `acme`, `balancer`, `middleware`, `docker`, `swarm`, `kubernetes`, `cloudflare`, `admin`, `dashboard`, `website`, `observability`, `adr`, `repo`). The `pr-title` check enforces this; the title becomes the commit on `main`.
- **Fill in the PR template:** link the issue (`Closes #123`) and the requirement ID from `docs/04-requirements.md` (e.g. `B-NET-04`). One topic per PR.
- **Required checks:** `docs`, `dco`, `pr-title`, `rust`, `msrv`, `deny`, `docker`. Run `just ci` before pushing (it includes `python3 -I scripts/check-docs.py`); run `just schema` after changing `rdock-model`.
- **No secrets** (tokens, keys, private hostnames, personal data) in code, docs, fixtures or logs. Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Documentation rules

- Architecture, config-model, label-grammar, public-API and security-model changes need an ADR in `docs/decisions/` (copy `0000-template.md`). Accepted ADRs are only changed to mark them superseded.
- Requirement IDs in `docs/04-requirements.md` are stable: never renumber or reuse one. Every ID is scheduled in `docs/07-roadmap.md` or listed there as unscheduled.
- `docs/03-feature-matrix.md` is generated below its `<!-- GENERATED` marker by `scripts/xlsx2md.py` from the workbook in `docs/research/`. Never hand-edit the generated part.
- User-facing behaviour changes update their page in `apps/website/src/content/docs/` in the same PR; run `pnpm gen` there after changing the schema or the CLI ([apps/website/README.md](apps/website/README.md)).
- Facts about third-party projects (Pingora, Traefik, Let's Encrypt, Gateway API) must cite an official source and a date.

## Code conventions

- Toolchain pinned in `rust-toolchain.toml`; MSRV in `Cargo.toml` `rust-version`. Details in [docs/06-repo-layout.md](docs/06-repo-layout.md) §2.
- `unsafe_code = "forbid"`; no `unwrap`/`expect`/`panic` in library crates; `thiserror` in libraries, `miette` for config diagnostics, `anyhow` only in the binary; `tracing` for all logging.
- Names: binary `rdock`, crates `rdock-*`, Docker labels `rdock.*`, config `rdock.yaml`, env `RDOCK_*`, metrics `rdock_*`.
- The data plane never depends on the admin API, dashboard or providers at request time (ADR-0009, ADR-0012). Retries follow ADR-0015; HTTP semantics and the "planned for vX.Y" gate follow ADR-0014.
- Build needs a C compiler and CMake. tokio stays `<1.54` until Pingora fixes its `BufStream` panic.

## Map of the repository

| Path | What it holds |
|---|---|
| [docs/01-vision.md](docs/01-vision.md) | Why, audiences, principles, non-goals, naming, 1.0 criteria |
| [docs/02-research.md](docs/02-research.md) | Verified facts: Pingora 0.9, competitors, ACME, Gateway API, crates, risks |
| [docs/03-feature-matrix.md](docs/03-feature-matrix.md) | 171 capabilities vs NGINX/Traefik/Caddy/HAProxy/Envoy/Pingap/Pingora (generated) |
| [docs/04-requirements.md](docs/04-requirements.md) | Requirement IDs: Basics, Medium, High traffic, Features, Works with |
| [docs/05-architecture.md](docs/05-architecture.md) | The engineering plan: crates, config model, providers, Pingora hooks, TLS/ACME, labels, admin, security |
| [docs/06-repo-layout.md](docs/06-repo-layout.md) | Repo tree, crate rules, Cargo features, CI, releases, testing, Graphify |
| [docs/07-roadmap.md](docs/07-roadmap.md) | Milestones M0 → v1.0 with acceptance criteria |
| [docs/08-design-system.md](docs/08-design-system.md) | Harbor UI dashboard design system |
| [docs/09-website.md](docs/09-website.md) | Public website and docs plan (Astro + Starlight, `apps/website`) |
| [apps/website/](apps/website/README.md) | The website: landing page, docs pages, generators and checks |
| [docs/decisions/](docs/decisions/README.md) | ADR-0001 … ADR-0019 |
| [docs/research/](docs/research/) | Original idea, notes and the feature-matrix workbook |
| [docs/design/](docs/design/) · [docs/assets/](docs/assets/) | Dashboard mock; logo and banner (render with `scripts/render-assets.sh`) |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [GOVERNANCE.md](GOVERNANCE.md) | How changes are proposed, reviewed and merged |

Graphify is optional for contributors (see [CONTRIBUTING.md](CONTRIBUTING.md)). Its hooks are installed per developer in `.claude/settings.local.json`, never committed. The `graphify` section below is generated by `graphify install` and applies only when `graphify` is installed and `graphify-out/` exists.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
