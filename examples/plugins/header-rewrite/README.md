# header-rewrite

An example plugin: sets and removes request and response headers from its configuration. It declares only the phases it needs (`request`, `response` or both), refuses invalid or framing header names (`Content-Length`, `Transfer-Encoding`…) when the configuration is validated, and refuses a header that is both set and removed.

```yaml
middlewares:
  tidy:
    type: plugin
    name: header_rewrite        # the name the binary registered it under
    config:
      request:
        set: { X-Team: core }
        remove: [X-Debug]
      response:
        set: { X-Frame-Options: DENY }
        remove: [Server]
```

`rdock validate` reports problems inside `config` with their path, e.g. `error: middlewares.tidy.config.request.set.Content-Length: ...`. Tests: `cargo test -p header-rewrite` (the SDK's `testing` harness, no proxy). Register it with `Registry::new().plugin("header_rewrite", header_rewrite::factory())`; see [`custom-rdock`](../custom-rdock/README.md).

The built-in `headers` middleware does this job too; this plugin shows how one is written.
