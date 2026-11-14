# Caddy corpus

Golden cases for `rdock migrate caddy` ([ADR-0033](../../../docs/decisions/0033-v1-0-stable.md)). The test is `crates/rdock-migrate/tests/corpus_caddy.rs`; it runs in `cargo test` and needs no Caddy.

Each directory holds:

| File | What it is |
|---|---|
| `Caddyfile` | The source the case stands for. Its header comment says what the case exercises. |
| `caddy.json` | The input: the JSON `caddy adapt --config Caddyfile` makes of it. |
| `case.json` | `input`, `exercises`, `source` (where the JSON shapes come from), `full` and `expect_invalid`. |
| `expected.yaml` | The exact output. |
| `report.json` | The exact report (`--report`), with `rdock_version` replaced by `<version>`. |

The test fails when an output or report differs, when a source item is not accounted for exactly once, when a finding's level is not its code's, when the output does not read as rdock.yaml or does not validate (other than as `expect_invalid` says), or when a credential from an input (`not-copied-example-value`) reaches the output. After a deliberate change, `just migrate-golden` rewrites the goldens; review the diff before committing.

## Where the JSON comes from

**The `caddy.json` files are written by hand; they were not produced by running Caddy.** Caddy cannot run in the development sandbox (no `caddy` binary, no image pulls). Each file follows the shapes of Caddy v2.11.9's Caddyfile adapter, read on 2026-11-14 from:

- the adapter's own tests at the `v2.11.9` tag, which pair a Caddyfile with the JSON it adapts to: `caddytest/integration/caddyfile_adapt/*.caddyfiletest` in [caddyserver/caddy](https://github.com/caddyserver/caddy/tree/v2.11.9/caddytest/integration/caddyfile_adapt) (each case's `source` names the ones it follows);
- the adapter's source (`caddyconfig/httpcaddyfile/`, and the `UnmarshalCaddyfile` methods under `modules/caddyhttp/`) for directives those tests do not show, such as `basic_auth` and `try_files`;
- the [JSON reference](https://caddyserver.com/docs/json/) for field names and defaults.

Nothing is copied from those files; host names use `example.com`, `.example`, `.dev` and `.localhost`, and addresses use private ranges.

To check the hand-written JSON against Caddy itself, a maintainer (or CI) runs `just caddy-corpus`: it re-adapts every `Caddyfile` with `caddy:2.11.9` pinned by digest (`adapt.sh`, no network inside the container) and overwrites `caddy.json`. Review the diff (key order and `hide` lists may differ without changing the meaning), then run `just migrate-golden`. Case `18-plugins-and-apps` uses plugins (`layer4`, `rate_limit`) that the standard image lacks; the script keeps its hand-written JSON.

## Coverage and what is left

20 cases. Not yet covered as their own cases: `handle_errors`, `intercept`, `map` with `vars` matchers, `copy_response`, dynamic SRV upstreams, client certificate connection policies, `log` per site, several servers with their own `automatic_https`, large real-world configurations. Add a case for each bug found in the migration.
