# wasm-header (experimental)

An example **WASM plugin** ([ADR-0030](../../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md)): a WebAssembly component for the world `rdock:plugin/filter@0.1.0` ([`crates/rdock-wasm/wit/filter.wit`](../../../crates/rdock-wasm/wit/filter.wit)). It answers `403` for the path `/blocked`, adds `x-wasm: yes` to other requests, and `x-wasm-response: yes` and `x-wasm-request-id` to responses.

WASM plugins are experimental and need an `rdock` built with `--features wasm`; the ABI may change in any release.

```sh
rustup target add wasm32-wasip2
cargo build --release --locked --target wasm32-wasip2
# -> target/wasm32-wasip2/release/rdock_wasm_header.wasm (about 8 KB)
minisign -S -s minisign.key -m target/wasm32-wasip2/release/rdock_wasm_header.wasm
sha256sum target/wasm32-wasip2/release/rdock_wasm_header.wasm
```

```yaml
middlewares:
  header:
    type: wasm
    path: /etc/rdock/plugins/rdock_wasm_header.wasm
    sha256: "<the digest sha256sum printed>"
    trusted_keys: ["<the second line of minisign.pub>"]
```

The crate is `no_std` because Rust's standard library on `wasm32-wasip2` imports WASI, which rdock does not give plugins; it brings a bump allocator (each request gets a fresh instance, so nothing is freed), a panic handler and `cabi_realloc`. It is not a member of the repository's workspace (it is never built for the host) and has its own `Cargo.lock`.

Tests: the `wasm` CI job (`just wasm`) builds it, signs it with a test key and runs it through `rdock-wasm`'s checks (`crates/rdock-wasm/tests/example.rs`) and through the real binary (`crates/rdock/tests/e2e_wasm.rs`). Guide: [WASM plugins](../../../apps/website/src/content/docs/docs/guides/wasm-plugins.mdx).
