# rdock

The ReverseDock binary, and since v0.8 a library: `rdock::run(registry)` is the whole command line, so a binary with native plugins is a `Registry` and one call (F-EXT-02, [ADR-0030](../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md)). The stock binary (`src/main.rs`) is `rdock::run(rdock::Registry::new())`. The library re-exports the plugin API as `rdock::plugin_api` and, with the default feature `mimalloc`, sets mimalloc as the global allocator. Examples: [`examples/plugins`](../../examples/plugins/README.md).

| Command | Since | What it does |
|---|---|---|
| `rdock validate <files>… [--strict] [--format text\|json]` | M0 | Loads and validates configuration files; exit code 1 when any has errors |
| `rdock schema` | M0 | Prints the JSON Schema of `rdock.yaml` |
| `rdock version [--json]` | M0 | Prints version, commit, compiler and target; since v0.8 also the plugin API version and the registered plugins |
| `rdock run`, `reload`, `status`, `config`, `cert`, `migrate`, `trust` | v0.1+ | See [requirements B-CFG-04](../../docs/04-requirements.md) |
