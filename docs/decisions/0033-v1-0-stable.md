# ADR-0033: v1.0 "Stable": the stability promise, maturity levels, migration tools and the proofs

- Status: accepted
- Date: 2026-11-14

## Context

v1.0 is a promise, not a feature set ([roadmap](../07-roadmap.md), [vision §7](../01-vision.md)). [Research](../research/v1.0-stable.md) on 2026-11-13 found:

- **Nothing checks for a breaking change today.** The config schema and the OpenAPI document have drift checks only. Neither contains a `deprecated` keyword, and no deprecation mechanism exists.
- **"Experimental" is marked five different ways** (a Cargo feature, doc comments, `rdock version` text, the "planned for" gate, website badges). Using an experimental feature gives no runtime signal.
- **`rdock config migrate`** is named in `docs/06-repo-layout.md` and does not exist.
- **Traefik conformance is weaker than the 1.0 criterion reads.** The 81 fixtures compare the translator with hand-written expectations; no Traefik process and no real Compose file is involved. `rdock migrate traefik` drops Compose `${VAR}` labels, loses server weights, and ignores static configuration. `rdock run` rejects Traefik's flags, so "changing the image name" does not work literally.
- **Chaos:** of the six scenarios, two are covered, three partly, and disk full has no test. Architecture §20 claims a free-space pre-check for certificate writes that the code does not have.
- **Release integrity** is good (keyless cosign, build-provenance attestations, SHA-pinned actions) with gaps: the SBOM is unsigned and scans the source tree, base images are pinned by tag, reproducibility is claimed and untested, and `docs/06` names scanners CI does not run.
- **Pingora** is still `0.x` and calls its rustls backend and cache integration experimental.
- An independent security review needs an outside party and money. The project has neither a rented benchmark machine nor a budget (maintainer, 2026-11-13).

## Decision

### The promise
- SemVer for the binary, the image and the chart's `appVersion`. A stable surface breaks only in a major, after its deprecation period. Patch releases carry fixes only.
- **Stable surfaces at 1.0**, each with a written definition of "breaking" in `docs/10-stability.md`: the config file (schema v1), the rule grammar, `rdock.*` labels, the documented Traefik label subset, the CLI (commands, flags, exit codes, JSON output; not human-readable text), the admin API `/api/v1`, metric names and labels, JSON access-log fields, problem types, documented `RDOCK_*` variables, the image contract, Helm values, the data-directory format (readable by the next two minors).
- **Not promised:** internal crates (all but `rdock-plugin-api`), performance, log wording, the dashboard's look, error text, anything below stable.
- **Deprecation:** a replacement ships first; a stable element then works for at least two minors and six months and is removed only in a major. It surfaces from one registry as a `rdock validate` warning (`--strict` fails; JSON carries code, since, removal, replacement), one WARN per element at load, the metric `rdock_deprecated_config_in_use{element}`, the admin API and dashboard, `"deprecated": true` in the schema and OpenAPI, and a generated "Deprecations" page.
- **Security exception:** a change that refuses an unsafe configuration may ship in a minor or patch when it fixes a vulnerability, with a "Security" changelog entry and a diagnostic naming the fix.
- **Support (F-OSS-05):** the two newest minors of the current major get security fixes; after a new major, the last minor of the previous one for six months. Fixes land on `main` first and are cherry-picked to `release/X.Y`. The policy page says there is one maintainer and no SLA.
- **MSRV** may rise in a minor, never in a patch, to a Rust release at least six months old.
- **Schema versioning:** v1 is additive through 1.x. `rdock migrate config` rewrites deprecated keys now and converts to a later schema when one exists; it replaces the never-built `rdock config migrate`. The schema `$id` moves to a tag-pinned URL.

### Maturity levels
- Three levels, **experimental / beta / stable**, from one registry in `rdock-model` that feeds validation, `rdock version`, the schema, the website badges and the stability page.
- Experimental features need an explicit opt-in (`experimental: [name, …]` at the top of the config) and are refused without it; using one logs once and sets `rdock_experimental_feature_in_use{feature}`. Beta may change in a minor with a migration note. Promotion needs: tests required in CI, documentation, one release at the lower level, and no open correctness issue.
- **Levels at 1.0.** Stable: the HTTP proxy, file and Docker providers, labels, automatic HTTPS, reliability features, the admin API, users and audit, the dashboard, Swarm, TCP, static files, DNS-01 adapters, the Gateway API controller. Beta: the cache, the plugin SDK and agents, consumers and quotas, OIDC, validation and transformation, UDP, Vault references, the v0.9 balancer and edge-security additions, binary upgrade, the cluster and `rdock control`, distributed limits, admission control and tenants, the Terraform provider and Go client. Experimental: WASM plugins, HTTP/3. TLS and the cache are offered at their level on Pingora parts that Pingora calls experimental; the page says so and we carry upstream breaks.

### Compatibility checks (required in CI)
A schema-diff script of our own, `oasdiff` for the OpenAPI document, snapshot tests for metric names, CLI `--help` structure and JSON outputs and access-log fields, and `cargo-semver-checks` for `rdock-plugin-api`. Each compares with the last release tag and fails on a change that the stability page calls breaking, unless the element is below stable.

### Migration
- **Traefik:** fix the gaps found (Compose interpolation with `--env-file`, `$$`, weights, `usersFile`, the plain-HTTP note), map the cheap unmapped options, add `--static` (reads `traefik.yml` and `command:` flags for entry points, ACME and Docker provider settings) and `--full`. "Conformance-tested" means three layers: the translation fixtures, a Compose corpus with golden output, and a differential CI job that runs a pinned Traefik and rdock on the same labels and compares status, answering backend, forwarded request and redirects; agreement must be total for options marked supported, apart from a reviewed allow-list. The subset is pinned to Traefik v3.7.
- **The 1.0 criterion is reworded:** a Traefik-on-Docker user changes the image, removes Traefik's flags (or runs `rdock migrate traefik --static`) and keeps their labels. `rdock run` does not accept Traefik's flags. When a Docker setup has only `traefik.*` labels and no `rdock.expose`, validation says that containers are not exposed by default.
- **Caddy:** `rdock migrate caddy` reads adapted JSON (`caddy adapt … | rdock migrate caddy -`), not the Caddyfile.
- **NGINX:** `rdock migrate nginx` with our own small parser for the faithful subset; constructs without a faithful translation (`if`, `map`, `rewrite … last`, named locations, variables) are refused per construct and written as disabled routes. It ships as beta.
- **One report** for all three: four levels (exact, approximate, manual, dropped), stable codes, `--report`, `--strict` (exit 2), and the invariant that every source item is accounted for. Guides list the defaults that change.
- Later: `acme.json` import, Caddyfile input, TOML dynamic files, NGINX `limit_req`, `stream {}` and `proxy_cache`.

### Proofs
- **Chaos suite** as a CI workflow on Toxiproxy and tmpfs: control plane down, Docker socket down (also at boot and hanging), CA down during renewal, disk full, backend flapping, config rollback under load. Pass: no failed request, a stated recovery bound, an intact data directory and audit chain. Disk-full rules: a configuration write that cannot be stored is refused; a mutating admin call whose audit record cannot be written fails; certificate writes check free space first.
- **Benchmarks:** competitor images updated, an HTTP/2 scenario, TLS parity rules, and a default and a tuned configuration per proxy, run on free hosted runners with pinned cores and published with that limit stated. The report says what a dedicated three-machine run would add; that run stays open.
- **60-second HTTPS:** a CI test with the release image, Compose and one label against Pebble, and a script for a fresh-VPS run against Let's Encrypt staging that a maintainer can run.
- **Security review:** the project prepares (threat model, an internal review per surface with fixes, fuzz targets for HTTP/2 frames, ACME responses, response framing and admin bodies, longer fuzz runs, Scorecard and CodeQL, docs aligned with what CI runs). The independent review itself needs a funder or a grant and is the maintainer's to commission; **1.0 is not tagged as final without it**. Until then releases are `1.0.0-rc.N`.
- **Release integrity:** SBOM built from the binaries and signed, base images pinned by digest, a weekly rebuild-and-compare job, release branches with their ruleset and a `latest` rule that never moves backwards.
- **Playground:** the shipped schema-driven one stands; exact diagnostics through a WebAssembly build of the validator are later work.

## Consequences

- A new document `docs/10-stability.md` and website pages for the policy, deprecations and maturity. `SECURITY.md`, `docs/06` and F-OSS-02/03/05 are aligned with what exists.
- `experimental:` is a config-model change: `type: wasm` and `http3.enabled` need the opt-in from this release on.
- New requirement IDs for the Caddy migration and the chaos suite; none is renumbered.
- The order: registry and maturity levels → deprecation plumbing and `rdock migrate config` → compatibility checks → migration report and Traefik work → Caddy → NGINX → chaos suite and the disk-full rules → security preparation → benchmarks and the 60-second proof → release integrity → documents. The result is released as `1.0.0-rc.1`.
- Open, and outside what the project can do alone: the independent security review, a dedicated-hardware benchmark, a 24-hour soak, a real-world 60-second run, the Best Practices badge registration, publishing `rdock-plugin-api` to crates.io.
