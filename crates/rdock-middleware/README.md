# rdock-middleware

Built-in middlewares: headers, redirects, rewrites, basic and forward auth, IP filters, rate limits, CORS, compression, error pages, maintenance mode and static files.

**v0.1:** the P0 set — `headers` (with HSTS), `redirect`, `rewrite`, `strip_prefix`, `add_prefix`, `replace_path`, `basic_auth` (argon2id, bcrypt; legacy Apache MD5 and SHA-1 with a warning), `forward_auth`, `ip_allow`, `ip_deny`, `rate_limit`, `cors`, `compress` (streaming gzip), `errors` and `maintenance`. Each implements the `Middleware` trait (`request`, `response`, `error_page`); `build` creates them from the `rdock-model` types. Brotli and zstd follow later. Design: [architecture §8](../../docs/05-architecture.md).

**v0.6:** `static` (F-WEB-01) serves files from a directory opened once with cap-std: strong `ETag`s, RFC 9110 conditionals and ranges, precompressed sidecars and an SPA fallback. A `Reply` body is in memory (`Body::Bytes`) or ranges of an open file (`Body::File`) that the proxy reads chunk by chunk.
