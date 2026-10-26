# ADR-0011: YAML is parsed with serde-saphyr; MSRV is 1.89

- Status: accepted · Date: 2026-10-26

## Context
The configuration (and later Docker Compose-style inputs) is YAML. The usual crate, `serde_yaml`, was archived in 2024 and is flagged by RustSec; `serde_yml` has a RustSec advisory; the forks `serde_yaml_ng` (last release 2024-05) and `serde_norway` (2024-12) are thinly maintained and depend on `unsafe-libyaml`, which RustSec also lists. `serde-saphyr` (2.0.0, 2026-10-13) is pure Rust on the `saphyr` parser, actively maintained, rejects duplicate keys by default, enforces budgets against YAML bombs, supports anchors and merge keys, and reports errors with line, column and a snippet. Its 1.2+ releases need Rust 1.89.

YAML 1.1 turns `yes`, `on` and `off` into booleans. With that behaviour `tls: off` would become `false` and fail to load.

## Decision
- Parse YAML with `serde-saphyr` (deserialize feature only) into a `serde_json::Value`, then into the model. Use `strict_booleans: true`: only `true` and `false` are booleans; `off`, `on`, `yes` stay strings.
- The minimum supported Rust version is the highest MSRV among our dependencies, today **1.89** (serde-saphyr; Pingora 0.9 needs 1.88). It is declared once in `[workspace.package] rust-version` and checked by the `msrv` CI job.

## Consequences
- No C or `unsafe` YAML parser in the binary; duplicate keys (for example two `routes:` sections) are load errors instead of silent overrides.
- `tls: off` works; `redirect_http_to_https: yes` is a type error with a clear path instead of a guess.
- Users building from source need Rust 1.89 or newer; the pinned development toolchain (`rust-toolchain.toml`) is newer anyway.
