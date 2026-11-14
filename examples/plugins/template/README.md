# Plugin template

A minimal native plugin (`src/lib.rs`: adds `X-Greeting` from its configuration), the binary that registers it (`src/main.rs`, `my-rdock`) and tests on the SDK harness. Copy this directory to start your own:

1. Copy it out of the repository and rename the package, the library and the binary in `Cargo.toml`.
2. Replace the two path dependencies with git dependencies pinned to one tag (the crates are not published on crates.io):
   ```toml
   rdock = { git = "https://github.com/Docker-Hunterpedia/ReverseDock", tag = "v1.0.0-rc.1" }
   rdock-plugin-api = { git = "https://github.com/Docker-Hunterpedia/ReverseDock", tag = "v1.0.0-rc.1" }
   ```
3. Copy the repository's `rust-toolchain.toml` (and, if you like, `deny.toml` for `cargo deny check`).
4. `cargo test`, then `cargo build --release`. Building needs a C compiler and CMake.

Keep the release profile unwinding (do not set `panic = "abort"`): the proxy catches a panicking plugin and answers `500` for that request only, which needs unwinding.

```yaml
middlewares:
  hello: { type: plugin, name: greeting, config: { text: "hello from my plugin" } }
```

Inside this repository the template is a workspace member, so CI builds and tests it. Guide: [Plugins](../../../apps/website/src/content/docs/guides/plugins.mdx).
