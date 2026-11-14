# Stability, deprecation and support

What ReverseDock promises from 1.0 on, decided in [ADR-0033](decisions/0033-v1-0-stable.md) after the [v1.0 research](research/v1.0-stable.md) (Part A, sections 2, 3 and 5). The public version of this page is [Stability and support](../apps/website/src/content/docs/docs/project/stability.mdx) on the website; the generated lists are [Maturity levels](../apps/website/src/content/docs/docs/project/maturity.mdx) and [Deprecations](../apps/website/src/content/docs/docs/project/deprecations.mdx).

Before 1.0 (`0.x`, the current `0.9.0-alpha.1`), configuration may still break between minor releases with a migration note; the mechanisms below already work, so 1.0 starts with them tested.

## 1. Versions

- [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) for the `rdock` binary, the container image and the Helm chart's `appVersion`.
- **Patch** (`1.2.3` → `1.2.4`): fixes only. No new configuration keys, metrics or default changes, except what a security fix needs (section 5).
- **Minor** (`1.2` → `1.3`): additions and new deprecations; beta features may change with a migration note; experimental features may change freely.
- **Major** (`1.x` → `2.0`): the only release where a stable surface may break, and only after its deprecation period.
- Separate version lines: `rdock-plugin-api` (its own `0.x` version), the WASM ABI (the WIT package version), the configuration schema (`v1`), the admin API (`/api/v1`), the cluster protocol and the data-directory format (integers), and the Helm chart's `version`.

## 2. The promise, per surface

A **stable** surface breaks only in a major release, after its deprecation period (section 4). "Breaking" means:

| Surface | Breaking (only in a major, after a deprecation) | Not breaking |
|---|---|---|
| Configuration file (schema v1) | Removing or renaming a key; changing a type; making an optional key required; removing an enum value; refusing a file that validated before; changing a default that changes behaviour; changing the meaning of a value | New optional keys; new enum values (tools that read the schema must accept unknown values); new warnings; refusing a configuration that was unsafe (section 5); the wording of diagnostics |
| Rule grammar | A rule that parsed no longer parses or matches differently; a change of priority order | New matchers and functions |
| `rdock.*` labels | As for the configuration file | New labels |
| Traefik label subset (documented, pinned to Traefik v3.7) | Dropping a label listed as supported | Following Traefik's own deprecations with the warning Traefik gives; moving the supported Traefik range forward in a minor |
| CLI | Removing or renaming a command, flag or documented `RDOCK_*` variable; changing what exit codes `0`, `1` and `2` mean; changing JSON output fields or their types (`validate --format json`, `version --json`, `status --json`, the admin commands' JSON); changing a default | New commands, flags and JSON fields; **all human-readable output**, `--help` included |
| Admin API `/api/v1` | Removing a path, method, field or enum value; making a request field required; changing types, status codes or the roles an operation needs | New paths, optional request fields, response fields, and enum values in responses (clients must ignore unknown fields and values) |
| Metrics | Removing or renaming a metric or label; changing a stable metric's type, unit or histogram buckets | New metrics and label values. A new label name on an existing metric counts as a new metric |
| JSON access-log fields | Removing or renaming a field; changing its type | New fields. The text format is not stable |
| Problem types (RFC 9457) | Removing a `type` URI or changing its status | New types; the wording of `title` and `detail` |
| Documented `RDOCK_*` environment variables | Removing or renaming one | New variables. `RDOCK_BUILD_*`, `RDOCK_*_TESTS`, `RDOCK_FAULT*`, `RDOCK_UPGRADE_FAULT`, `RDOCK_TEST_DEPRECATIONS` and `RDOCK_UPDATE_GOLDEN` are internal |
| Container image | Entrypoint, default command, user id (65532), data path (`/var/lib/rdock`), exposed ports, health check | Base image updates |
| Helm values | As for the configuration file, on `values.schema.json`; renaming the resources the chart creates | New values |
| Data directory | A release that cannot read the directory of either of the two minors before it; a format bump without a documented downgrade statement | New files. A downgrade across a format bump is refused (the code refuses a newer format) |
| `rdock-plugin-api` | What the [Cargo SemVer reference](https://doc.rust-lang.org/cargo/reference/semver.html) calls major | Additions behind `#[non_exhaustive]` and defaulted trait items |

**Not promised:** the internal crates (every workspace crate but `rdock-plugin-api` and the `rdock::run` entry point), performance characteristics, the wording of logs, errors and diagnostics, the dashboard's look and URLs, undocumented behaviour, and anything below stable (section 7).

**Checked by CI** (planned as the next step of ADR-0033): a schema-compatibility script for `schema/rdock.v1.json`, `oasdiff` for the OpenAPI document, snapshots of metric names, CLI structure, JSON outputs and access-log fields, and `cargo-semver-checks` for `rdock-plugin-api`, each against the last release tag.

## 3. Configuration schema versions

- `version: 1` is optional and means schema v1, the only one. A file with another `version` is refused by `rdock validate`, `rdock run` and `rdock migrate config`.
- v1 changes only by additions and deprecations through 1.x.
- A v2, if one is ever needed, comes in a minor release as an opt-in (`version: 2`, `schema/rdock.v2.json`); both are read for at least two minors, through one internal model with two front ends. The next major makes v2 the default and still reads v1 for one more major, with a deprecation warning.
- `rdock migrate config` rewrites deprecated v1 keys now, and is where a v1 → v2 conversion will live: a conversion is a list of the same rewrite rules the deprecations use (`SCHEMA_MIGRATIONS` in `crates/rdock-model/src/deprecation.rs`, empty today).
- The schema's `$id` moves to a tag-pinned URL before 1.0 (ADR-0033); today it points at `main`.

## 4. Deprecation

- **A replacement first.** Nothing is deprecated before its replacement is in a release, and never in favour of something less stable.
- **Period.** A stable element keeps working for at least **two minor releases and six months** after the release that deprecates it, whichever is longer, and is removed only in a major. A beta element: one minor and three months, and it may go in a minor. Experimental: no period.
- **One registry** (`crates/rdock-model/src/deprecation.rs`) lists every deprecated element: a configuration key or value, a label, a CLI flag or command, an API operation or field, or a metric, with the release that deprecated it, the release that removes it, the replacement, a note, and the rewrite `rdock migrate config` applies. Everything below reads it:
  1. `rdock validate`: a warning at the path, with the replacement and the removal release. `--strict` fails on it; `--deprecations error` fails on deprecations only, to check a file against the release that removes them. `--format json` carries `code: "deprecated"`, `element`, `since`, `removal` and `replacement`.
  2. At load and every reload: one `WARN` per element (not per use), and the gauge `rdock_deprecated_config_in_use{element}`.
  3. `GET /api/v1/status` lists them under `deprecations_in_use`; the reload report's diagnostics carry the same fields; the dashboard's overview shows a notice.
  4. Labels: the same warning in the provider's diagnostics; a renamed label is read under its new name during the overlap.
  5. The JSON Schema: `"deprecated": true`, `x-rdock-deprecated` and a sentence in the description, so editors strike the key through. A key the model no longer reads is added back under its old name.
  6. The OpenAPI document: `deprecated: true` on the operation, and the answers carry `Deprecation` ([RFC 9745](https://www.rfc-editor.org/rfc/rfc9745), a Structured Field Date) and, when a date is promised, `Sunset` ([RFC 8594](https://www.rfc-editor.org/rfc/rfc8594), an HTTP-date); both read 2026-11-14.
  7. The CLI: a warning on standard error when a deprecated command or flag is used.
  8. The website's [Deprecations](../apps/website/src/content/docs/docs/project/deprecations.mdx) page, generated, and a `Deprecated` section in `CHANGELOG.md` for the release that deprecates something.
- **During a rename's overlap** the model drops the old key and the loader rewrites it to the new one before reading (the registry entry says `read_by_model: false`), so there is one model.
- **`rdock migrate config <file>`** applies the rewrites: it prints the result, `--diff` prints a unified diff, `--write` replaces the file after copying it to `<file>.bak` (`.bak.1`, … when taken), `-o` writes elsewhere, `-` reads standard input. Exit codes as `rdock migrate traefik`: `0` done (whether or not anything changed), `1` the input cannot be migrated (not YAML or JSON, an unknown `version`), `2` an I/O error. It edits the text where it can (a renamed key, a replaced value, a block mapping moved elsewhere change only those lines), so comments, blank lines, quoting, key order and anchors elsewhere stay; the edited text is parsed again and must equal the rewritten document. Where that is not possible (flow style around a moved mapping, a move in a JSON file), it writes the whole document out again through serde-saphyr, which keeps the content but loses comments and formatting, and says so. Uses that need a decision are reported, never guessed.
- The first deprecation is `observability.alerts.webhook` (deprecated in 1.0, removed in 2.0): the single v0.3 webhook, a channel named `webhook` since v0.5, replaced by a `type: webhook` channel under `observability.alerts.channels`.

## 5. Security exception

A change that refuses an unsafe configuration may ship in a minor or a patch release, without the deprecation period, when it fixes a vulnerability. It needs a "Security" entry in the changelog (and the advisory), a diagnostic that names the fix, and where possible one minor of warnings first. Everything else waits for the period.

## 6. Support (F-OSS-05)

- **Supported:** the two newest minor releases of the current major get security fixes. When `1.N` comes out, `1.N-2` ends.
- **After a new major:** the last minor of the previous major gets security fixes for six months.
- **Backported:** security fixes, and fixes for crashes, data loss and failed certificate issuance. Other fixes go to the newest minor only; fixes to experimental features are never backported.
- **How:** fixes land on `main` first and are cherry-picked by pull request to `release/X.Y`, which has the same ruleset as `main`; releases are tagged from that branch. Embargoed fixes go through a private GitHub security advisory.
- **Skew:** data planes may be up to two minors older than their control plane, never newer; the data directory is readable by the next two minors.
- **Pre-releases** (`-alpha`, `-rc`) and `0.x`: the latest release only.
- **One maintainer, no SLA.** The response times in [SECURITY.md](../SECURITY.md) are targets, not guarantees.

## 7. Maturity levels

Every feature has one level, from one registry (`crates/rdock-model/src/maturity.rs`) that feeds `rdock validate`, `rdock version`, the JSON Schema (`x-rdock-maturity`), the website's badges and its generated [Maturity levels](../apps/website/src/content/docs/docs/project/maturity.mdx) page.

| | Experimental | Beta | Stable |
|---|---|---|---|
| Promise | None: may change or be removed in any release | Not removed without a deprecation; details may change in a minor, with a migration note | Sections 2 and 4 |
| Opt-in | Named in the top-level `experimental: [name, …]`; refused without it | None | None |
| Release binaries | May be left out (a cargo feature) | Always in | Always in |
| `rdock validate` | Without the opt-in: an error (`code: experimental_not_enabled`) naming the key to add; an unknown name is an error, a name not in use or not experimental a warning | Nothing | Nothing |
| Run time | One `WARN` per feature at load and reload; `rdock_experimental_feature_in_use{feature}` is 1 (0 for the others) | One `INFO` per feature, no metric | Nothing |
| Status | `GET /api/v1/status` `features_in_use.experimental`, dashboard notice | `features_in_use.beta`, dashboard notice | — |
| Security fixes | `main` only | Backported | Backported |

**Levels at 1.0** (ADR-0033; the concrete settings are in the registry and in ADR-0033's "As implemented" note):

- *Stable:* the HTTP proxy, the file and Docker providers, labels, automatic HTTPS, the reliability features, the admin API, users and audit, the dashboard, Swarm, TCP routes, static files, the DNS-01 adapters, the Gateway API controller.
- *Beta:* the cache, the plugin SDK and agents, consumers and quotas, OIDC, validation and transformation, UDP, Vault references, the v0.9 balancing and edge-security additions, binary upgrade, the cluster and `rdock control`, distributed limits, admission control and tenants, the Terraform provider and the Go client.
- *Experimental:* WASM plugins (`wasm`) and HTTP/3 (`http3`). Both also need their cargo feature, which release builds leave off; the opt-in and the build are checked separately, and each diagnostic says what the other needs.
- TLS and the cache run on parts of Pingora that Pingora calls experimental (its rustls backend, its cache integration); they are offered at the levels above and ReverseDock carries upstream breaks.

**Promotion** needs tests in a required CI job, documentation, one release at the lower level, and no open correctness issue (an ADR or ADR note for experimental → beta). Beta → stable also needs one full minor and three months without an incompatible change, fuzzing where the feature parses untrusted input, and the surface in the compatibility checks. **Demotion** never happens silently: a stable feature can only be deprecated; an experimental feature with no progress for two minors is removed.

The "planned for" gate ([ADR-0014](decisions/0014-http-semantics-v0-1.md)) is separate: it marks settings the schema accepts that are not implemented yet, which is not a maturity level. A test keeps the website's planned list (`apps/website/src/data/status.json`) and the registry from contradicting each other.

## 8. MSRV and toolchain

- The MSRV (`rust-version` in `Cargo.toml`, 1.89 today) is checked by the required `msrv` job. Release binaries are built with the pinned toolchain (`rust-toolchain.toml`).
- The MSRV may rise in a **minor** release, never in a patch, to a Rust release at least **six months old** (unless a security fix in a dependency forces it), and the rise is listed under "Changed" in the changelog.
- `rdock-plugin-api` keeps its own, lower where possible, `rust-version`. A supported minor keeps the MSRV it was released with.
