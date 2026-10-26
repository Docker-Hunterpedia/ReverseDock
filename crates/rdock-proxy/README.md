# rdock-proxy

The data plane: the Pingora `ProxyHttp` implementation, listeners, router, middleware runtime, forwarded headers, error pages and layer-4 proxies.

**v0.1:** our own accept loops hand each connection to Pingora's HTTP engine ([ADR-0012](../../docs/decisions/0012-own-listeners-pingora-http-engine.md)), so listeners are added, changed and removed in-process on reload. `compile` turns a validated `Config` into an immutable runtime (routes, services, certificates, middlewares) that is swapped atomically; `gate` refuses settings planned for later versions ([ADR-0014](../../docs/decisions/0014-http-semantics-v0-1.md)). It also holds the router, path normalisation, trusted-proxy handling, upstream DNS cache and peer selection, connection hardening (header deadline, bare-LF rejection) and the error pages. TCP/SNI passthrough lands in v0.6. Design: [architecture §6–§8 and §17](../../docs/05-architecture.md).
