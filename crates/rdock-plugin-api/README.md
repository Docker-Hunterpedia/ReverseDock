# rdock-plugin-api

The API a native ReverseDock plugin is written against (F-EXT-02, F-EXT-05, [ADR-0030](../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md)). It is the only crate a plugin depends on: its public types are `http`-crate types, `bytes` and std, never Pingora's or the proxy's internal ones.

**Stability: `0.x`.** This crate has its own version line, separate from the proxy's. Until 1.0 any release may change it; enums and structs that will grow are `#[non_exhaustive]`, and new phases arrive as trait methods with default bodies. `rdock version` prints the API version a binary was built with.

**Security: a plugin runs inside the proxy, with its privileges.** It sees every header and body it asks for and can reach whatever the process can. Review a plugin as you would the proxy's own code. A panic in a hook is caught and answers that request with `500`; nothing else limits what a plugin does.

## What is in it

- `Plugin`: hooks for the phases `request`, `upstream_request`, `request_body` (async) and `response`, `response_body`, `log` (`response` async, the last two synchronous), and `capabilities()`, which declares the phases, per-request state and a body hold (`BodyLimit`).
- `RequestHead` and `ResponseHead`: typed views that allow reading and bounded changes (headers, method, path and query; status and headers). Framing headers (`Content-Length`, `Transfer-Encoding`, `Connection`…) belong to the proxy.
- `Decision` (`Continue` or `Respond(Response)`), `BodyDecision` (also `Replace`), `RequestBody`.
- `Ctx`: request facts (client address, route, request id, TLS, consumer and groups when set, the chosen backend in later phases) and typed per-request `State`.
- `Factory`, `typed` and `ConfigError`: build a plugin from its `config` object and report problems with paths, which `rdock validate` prints under `middlewares.<name>.config`.
- `Registry`: names mapped to factories, built explicitly by the binary that embeds the proxy.
- `testing`: a harness that runs a plugin through its phases without a proxy.

## A plugin and its binary

```rust
use std::sync::Arc;
use rdock_plugin_api::{
    typed, Capabilities, ConfigError, Ctx, Decision, Phases, Plugin, Registry, RequestHead,
    async_trait,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    header: String,
    value: String,
}

struct SetHeader(Config);

#[async_trait]
impl Plugin for SetHeader {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::REQUEST)
    }

    async fn request(&self, req: &mut RequestHead, _cx: &mut Ctx<'_>) -> Decision {
        let _ = req.set_header(self.0.header.as_str(), self.0.value.as_str());
        Decision::Continue
    }
}

let registry = Registry::new().plugin(
    "set_header",
    typed(|config: Config| -> Result<SetHeader, ConfigError> { Ok(SetHeader(config)) }),
);
assert!(registry.check().is_ok());
// In the binary's `main`: `rdock::run(registry)`.
```

The binary depends on `rdock` (the proxy as a library) and on its plugins, then calls `rdock::run(registry)`; every subcommand (`run`, `validate`, `schema`…) behaves as in the stock binary, with the plugins available. The crates are not published on crates.io: outside this repository depend on them through git (`rdock-plugin-api = { git = "https://github.com/Docker-Hunterpedia/ReverseDock", tag = "…" }`). Examples and a template: [`examples/plugins/`](../../examples/plugins/README.md). Guide: [Plugins](../../apps/website/src/content/docs/guides/plugins.mdx).
