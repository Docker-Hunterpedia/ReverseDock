# Traefik label conformance suite

Each `*.yaml` file here describes running containers as the Docker Engine API reports them, and the routing table and diagnostics the Docker provider must produce from their labels (W-DKR-03, [ADR-0018](../../../docs/decisions/0018-docker-provider-and-merge.md)). The suite runs in `cargo test` (`crates/providers/rdock-provider-docker/tests/conformance.rs`) and needs no Docker daemon.

```yaml
description: One sentence: what the case shows.
settings: { network: proxy }          # optional providers.docker settings
containers:
  - name: app                         # container name
    labels: { traefik.enable: "true", traefik.http.routers.app.rule: "Host(`app.example.com`)" }
    networks: { web: "172.18.0.2" }   # network → IP
    ports: [80]                       # exposed ports
    health: healthy                   # none | starting | healthy | unhealthy (default none)
    stopping: false                   # Docker sent the stop signal (kill event)
    host_network: false
expect:
  routes:      { app: { service: app } }   # exactly these objects; fields compared as a subset
  services:    { app: { backends: [{ address: "172.18.0.2:80", weight: 1 }] } }
  middlewares: {}
  diagnostics: []                          # one text per diagnostic, in order, contained in "path: message"
```

Known differences from Traefik, on purpose:

- Containers are opt-in (`exposedByDefault` is `true` in Traefik, `expose_by_default` is `false` here).
- Several exposed ports and no port label is a warning; Traefik picks the lowest port.
- A router without entrypoints uses `defaults.listeners`; Traefik attaches it to every entrypoint.
- No default router for containers without router labels (Traefik's `defaultRule`).
- The `retry` middleware is a warning: retries are a service setting (`rdock.services.<name>.retries`).

Add a fixture for every label you add to the subset, and for every bug found in label handling.
