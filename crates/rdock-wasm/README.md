# rdock-wasm

Sandboxed WebAssembly plugins for ReverseDock (F-EXT-03, F-EXT-05; [ADR-0030](../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md)). **Experimental.**

- `artifact`: reads a module and checks, before anything parses it, its size, its pinned SHA-256 and its minisign signature against trusted keys. Always built.
- `minisign`: minisign public keys and signatures on ring's Ed25519 and BLAKE2b-512 (`ED` and legacy `Ed`; the trusted comment is checked). Always built.
- Feature **`wasm`** (off by default): the wasmtime 36 host. One engine with fuel metering and an epoch thread; components are checked against the world [`wit/filter.wit`](wit/filter.wit) (`rdock:plugin/filter@0.1.0`) and the granted capabilities when loaded; each request gets a fresh instance with a memory limit and no WASI.
- Feature `testing`: a deterministic signing key and WAT test components, for tests in other crates.

The middleware that uses it is `type: wasm` in `rdock-middleware`. Guide: [WASM plugins](../../apps/website/src/content/docs/docs/guides/wasm-plugins.mdx). Tests: `cargo test -p rdock-wasm --features wasm,testing` (the example guest needs `rustup target add wasm32-wasip2`).
