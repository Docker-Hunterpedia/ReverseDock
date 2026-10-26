# rdock-config

Turns configuration sources into a validated `rdock_model::Config`, and keeps applied configurations on disk.

- **Loading:** `load_file`, `load_str` and `load_value` parse YAML (with [serde-saphyr](https://crates.io/crates/serde-saphyr): pure Rust, anchors and merge keys, duplicate keys rejected, YAML 1.2 booleans so `off` stays a string) or JSON, deserialise into the model with precise error paths, report **unknown keys as errors** with "did you mean" hints (keys starting with `x-` are extension fields and are ignored), and run the model's semantic validation. Unknown keys are found by comparing the input with the model serialised back to JSON, so typos are caught everywhere, including inside tagged middlewares and untagged `match`/`tls` values.
- **References** ([ADR-0016](../../docs/decisions/0016-config-references-and-secrets.md)): `${NAME}`, `${env:NAME}` and `${file:/abs/path}` in string values. Secret fields keep the reference and are resolved where they are used; regular-expression `replacement` fields are taken literally. `Loaded::source` is the document as written, so history and the last-known-good copy never contain resolved secrets, and errors never quote a resolved value.
- **State** (`state` module): the last-known-good copy and a bounded history under `$RDOCK_DATA_DIR/state`, written atomically with owner-only permissions.

**Next:** the provider registry and the merge engine with ownership rules ([ADR-0009](../../docs/decisions/0009-provider-ownership-and-merge.md)) arrive with the Docker provider in v0.2.
