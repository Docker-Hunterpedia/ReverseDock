# rdock-provider-docker

Docker provider: container discovery through the Engine API, `rdock.*` labels and the Traefik label subset. Design: [ADR-0018](../../../docs/decisions/0018-docker-provider-and-merge.md) and [architecture §11](../../../docs/05-architecture.md).

- **`labels`** (done): `translate` turns what the Engine API reports about running containers into the provider's routes, services and middlewares, with diagnostics. No I/O, so the conformance suite and `rdock migrate traefik` call it directly.
  - Opt-in: `rdock.enable`, `traefik.enable` (when `traefik_labels` is on), or `expose_by_default`.
  - Native shorthand (`rdock.host`, `rdock.path`, `rdock.port`, `rdock.tls`, `rdock.middlewares`) and full form (`rdock.routes.<name>.<field>`, `rdock.services.<name>.<field>`, `rdock.middlewares.<name>.<field>`, fields as in YAML; `[a, b]` for lists).
  - Traefik v3 subset: routers, load-balancer services and the common middlewares; every other `traefik.*` label is a warning that names it.
  - Network: `rdock.network` / `traefik.docker.network` > `providers.docker.network` > the only network. Port: label > the only exposed port > a warning listing the ports.
  - Replicas with the same labels share one service. Containers whose health check is `starting` or `unhealthy` leave the pool, unless none is healthy (then all stay, with a warning).
  - Label values are literal: `${…}` is rejected, and labels cannot name files on the proxy's host.
- **`watch`** (next, #18): the Engine API loop on `bollard`.
