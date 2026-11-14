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
| Metrics | Removing or renaming a metric or label; adding a label name to an existing metric (it changes every series, so it needs a new metric instead); changing a stable metric's type, unit or histogram buckets | New metrics and label values |
| JSON access-log fields | Removing or renaming a field; changing its type | New fields. The text format is not stable |
| Problem types (RFC 9457) | Removing a `type` URI or changing its status | New types; the wording of `title` and `detail` |
| Documented `RDOCK_*` environment variables | Removing or renaming one | New variables. `RDOCK_BUILD_*`, `RDOCK_*_TESTS`, `RDOCK_TEST_*` (such as `RDOCK_TEST_DEPRECATIONS`), `RDOCK_FAULT*`, `RDOCK_UPGRADE_FAULT`, `RDOCK_UPDATE_GOLDEN`, `RDOCK_ALLOC_COUNT_SOCKET` and the compatibility gate's `RDOCK_COMPAT_*` are internal |
| Container image | Entrypoint, default command, user id (65532), data path (`/var/lib/rdock`), exposed ports, health check | Base image updates |
| Helm values | As for the configuration file, on `values.schema.json`; renaming the resources the chart creates | New values |
| Data directory | A release that cannot read the directory of either of the two minors before it; a format bump without a documented downgrade statement | New files. A downgrade across a format bump is refused (the code refuses a newer format) |
| `rdock-plugin-api` | What the [Cargo SemVer reference](https://doc.rust-lang.org/cargo/reference/semver.html) calls major | Additions behind `#[non_exhaustive]` and defaulted trait items |

**Not promised:** the internal crates (every workspace crate but `rdock-plugin-api` and the `rdock::run` entry point), performance characteristics, the wording of logs, errors and diagnostics, the dashboard's look and URLs, undocumented behaviour, and anything below stable (section 7).

**Checked by CI:** the `compat` job compares every surface it can read by machine with the last release tag and names the rule above that a change breaks; section 9 says what each check covers and what it cannot see.

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

## 9. How the promise is checked

The `compat` CI job runs `scripts/compat.py check` (ADR-0033; Python standard library only). It compares the tree with a **baseline**, the newest tag matching `v*` reachable from the commit (`git describe --tags --abbrev=0 --match 'v*'`), and fails when a change is breaking by section 2, unless the element is below stable (section 7), is deprecated and its removal release is reached (section 4), or a reviewed exception accepts it.

- **Modes.** While the tree's version is below `1.0.0-rc.1` the promise is not yet in force: the gate runs in **report** mode, prints every finding and passes. From `1.0.0-rc.1` on it runs in **enforce** mode and fails on a finding. `RDOCK_COMPAT_MODE=report|enforce` (or `--mode`) forces either, so the gate can be tried now; `RDOCK_COMPAT_BASELINE` (or `--baseline`) names another baseline. In both modes it fails on a stale or missing snapshot, an invalid exceptions file, or a clone without the baseline tag (a shallow checkout has none: the job checks out with `fetch-depth: 0` and `fetch-tags: true`, and the gate says so rather than comparing with nothing).
- **Snapshots.** Surfaces without a machine-readable definition of their own are generated from the code that defines them into `schema/compat/` (`just compat`), so a pull request's diff shows every public-surface change; a test and the `compat` job fail when a snapshot is stale. A surface whose snapshot the baseline tag does not have yet is reported as not compared; the first release that ships it becomes its baseline (the image contract is read from the baseline's `Dockerfile.release` instead).
- **Exceptions.** `schema/compat/exceptions.json` lists accepted findings, each with the surface, element and rule as the gate prints them, a `reason` (an entry without one is an error) and the `release` that ships the change. An entry counts only while the baseline is older than its release, then expires and the gate asks for its removal. An exception is for a reviewed case (a security fix under section 5, a beta feature that the registry listed wrongly); the usual way is a deprecation.

| Surface | Compared | What breaks the check | What it cannot detect |
|---|---|---|---|
| Configuration file | `schema/rdock.v1.json` with the baseline's, by our own JSON Schema differ (no maintained tool handles our 2020-12 schema; research §2.3). It follows `$ref`, matches `oneOf`/`anyOf` alternatives by their `type` constant, definition name or kind, and reads `x-rdock-maturity` on either side and the registry's locations for older baselines that had no marks | A removed or renamed key, a narrowed type, a newly required key, a removed enum value or tagged variant, a tightened bound (`minimum`, `maximum`, lengths, item counts, `pattern`, `format`, `uniqueItems`), `additionalProperties` becoming `false`, a changed default (a default object that gains keys is not a change). A pattern that only gains top-level alternatives counts as looser. A change it cannot classify (a changed pattern, an ambiguous alternative, `not`/`if`/`dependentRequired` and the like, a default no longer stated) is **needs review**, which fails like a break until an exception records why it is not one | A changed meaning of a value, a default applied in code rather than declared in the schema, validation done in code (cross-field rules, `rdock validate` errors), anything inside a string the schema leaves free (rule expressions, durations) |
| Rule grammar | Not machine-checked yet | — | Everything: the parser's tests and fuzz target guard it, not the gate |
| `rdock.*` labels | `schema/compat/labels.json` (the shorthand labels and the full-form sections, from the Docker provider's constants); the full form's fields are configuration paths, checked with the schema | A shorthand label or a section no longer read | How a label's value is translated |
| Traefik label subset | The same file: every Traefik label the conformance fixtures use that the translation takes without a warning | A label dropped from that set | A label nobody wrote a fixture for; a change in translation that the fixtures do not assert |
| CLI | `schema/compat/cli.json`, from clap's own command tree: every visible command and flag with its short form, value names, defaults, `env`, possible values, whether it is required or repeatable; the exit-code table; the JSON Schemas of `validate --format json` and `version --json` (from the types that print them); `status --json` and `routes explain --json` print API answers and are checked with the API | A removed command, flag, short form, alias, `env` or possible value; a changed default; a flag that became required or stopped taking or repeating values; a new required argument; a removed exit code (a changed meaning is needs review); a removed JSON field, a field that may now be absent, a wider or changed type | Human-readable output and `--help` text (not promised); behaviour behind a flag; hidden flags |
| Admin API | `schema/openapi.json` by our own differ on the same engine: requests compared as input, responses as output. `oasdiff` 1.37.0 was tried and not adopted (see ADR-0033's note on step 3) | A removed path or method; a removed parameter, request field, media type or response field; a parameter or request field that became required; a changed type; a removed enum value in a request; a removed status code; a security requirement a caller can no longer meet. New enum values in responses are allowed. The configuration model inside the document is left to the configuration check | **The roles an operation needs**: they are enforced in the handlers and not stated in the document; headers; behaviour |
| Metrics | `schema/compat/metrics.json`, from the metric registry itself (`Metrics::catalogue`, plus the admin API's own table): name, type, unit (by the name's suffix), help, label names, buckets, feature | A removed or renamed metric or label, a new label name on an existing metric, a changed type, unit or bucket list. Help text changes are allowed | Label values, and what a metric counts |
| JSON access log | `schema/compat/access-log.json`, the JSON Schema of `AccessRecord`, compared as output | A removed field, a field that may now be absent, a wider or changed type | The text format; the meaning of a value |
| Problem types | `schema/compat/problems.json` from `ProblemKind::ALL` | A removed type URI or a changed status | `title` and `detail` (not promised) |
| `RDOCK_*` variables | `schema/compat/env.json`: every variable a flag reads plus the documented others; a test fails when the code reads an `RDOCK_*` variable that is neither listed nor internal | A variable no longer read | How a value is interpreted |
| Container image | `schema/compat/image.json` from `Dockerfile.release`'s final stage (entrypoint, command, user, the uid of the data directory, data path, exposed ports, health check); the gate also checks that `Dockerfile` states the same contract | Any change of those, a port no longer exposed | The built image itself (the `docker` job's smoke test runs it); base-image changes (not promised) |
| Helm values | `deploy/helm/reversedock/values.schema.json` with the configuration differ | As for the configuration file | Renamed resources the chart creates; values the templates read without a schema entry |
| Data directory | Tests that start the current binary on directories in the 0.8 and 0.9 layouts (`crates/rdock/tests/compat_datadir.rs`: last-known-good copy, history, users, audit chain, format marker; certificates in `rdock-acme`, quota counters in `rdock-limits`) | A release that cannot read them | Layouts of releases without a fixture; files the fixtures do not write |
| `rdock-plugin-api` | `cargo-semver-checks` 0.51.0 with `--baseline-rev <tag>` (beta today, so its findings are reported and exempt) | What its lints call major | By its own documentation: type changes of fields and parameters, changes of generics and lifetimes, and breaks that appear only with some features; these need review by hand |

Nothing above checks **semantic behaviour**: a changed meaning, a default applied in code, a different routing decision for the same rule, different retry or timeout behaviour, a different status for the same request. The end-to-end tests guard those where they pin the behaviour, and the changelog has to say so.

