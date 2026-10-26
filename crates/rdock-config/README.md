# rdock-config

Turns configuration sources into a validated `rdock_model::Config`.

**Today (M0):** `load_file` and `load_str` parse YAML (with [serde-saphyr](https://crates.io/crates/serde-saphyr): pure Rust, anchors and merge keys, duplicate keys rejected, YAML 1.2 booleans so `off` stays a string) or JSON, deserialise into the model with precise error paths, report **unknown keys** as warnings (errors with `strict`, see [ADR-0003](../../docs/decisions/0003-config-model-superset-of-traefik.md)) with "did you mean" hints, and run the model's semantic validation.

Unknown keys are found by comparing the input with the model serialised back to JSON, so typos are caught everywhere, including inside tagged middlewares and untagged `match`/`tls` values.

**Next (v0.1):** `${VAR}` and `${file:…}` interpolation, the provider registry, the merge engine with ownership rules ([ADR-0009](../../docs/decisions/0009-provider-ownership-and-merge.md)), compilation into the runtime snapshot, history and last-known-good ([architecture §4–§5](../../docs/05-architecture.md)).
