# Native plugin examples

The plugin SDK (F-EXT-02, F-EXT-05; [ADR-0030](../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md)): a plugin is a Rust crate that depends only on [`rdock-plugin-api`](../../crates/rdock-plugin-api/README.md); a binary depends on `rdock` and on its plugins, lists them in a `Registry` and calls `rdock::run(registry)`. There is no dynamic loading: plugins are compiled in.

**A plugin runs inside the proxy with its privileges.** Treat a plugin's code like the proxy's own.

| Directory | What it is |
|---|---|
| [`header-rewrite/`](header-rewrite/README.md) | Sets and removes request and response headers from configuration. Two phases, typed configuration with validation. |
| [`ip-blocklist/`](ip-blocklist/README.md) | Refuses client addresses from a list of networks with `403`. Configuration errors with paths, per-request state, a `log` phase. |
| [`custom-rdock/`](custom-rdock/README.md) | The binary that registers both, with an end-to-end test that starts it and sends real requests. |
| [`template/`](template/README.md) | A minimal plugin, its binary and its tests, to copy. |
| [`wasm-header/`](wasm-header/README.md) | **Experimental.** A sandboxed WASM plugin (a `no_std` Rust component for `wasm32-wasip2`), loaded from a signed file by an `rdock` built with `--features wasm`. Not a workspace member; built and tested in the `wasm` CI job. |

The first four are members of this repository's Cargo workspace, so `cargo test --workspace` (the `rust` CI job) builds and tests them. Their manifests use path dependencies; outside this repository use git dependencies pinned to a tag, because the crates are not published on crates.io:

```toml
[dependencies]
rdock = { git = "https://github.com/Docker-Hunterpedia/ReverseDock", tag = "v1.0.0-rc.1" }
rdock-plugin-api = { git = "https://github.com/Docker-Hunterpedia/ReverseDock", tag = "v1.0.0-rc.1" }
```

Guide: [Plugins](../../apps/website/src/content/docs/guides/plugins.mdx).
