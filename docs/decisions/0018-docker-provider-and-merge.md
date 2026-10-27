# ADR-0018: The Docker provider, label translation and the provider merge

- Status: accepted
- Date: 2026-10-28

## Context
v0.2 adds the first dynamic provider: Docker containers and their labels (B-DKR-01, W-DKR-01…08), extra configuration files (`providers.file.paths`), zero-config mode (B-CFG-11) and `rdock migrate traefik` (F-MGMT-03). ADR-0009 fixed the ownership rules (`name@provider`, complete snapshots, keep the previous valid snapshot) but not how snapshots enter the v0.1 engine, which loads, validates and compiles one `Config`. Three questions are open:

1. How objects from several providers become one configuration that the existing validator and compiler accept.
2. How one bad container is kept from rejecting everything (ADR-0009: "partial failure produces diagnostics and skips that object").
3. What labels mean, especially Traefik's, and what happens with automatic HTTPS before ACME exists (v0.3).

## Decision

**Snapshots.** The `Snapshot` type and the merge live in `rdock-config` (architecture §2: provider registry and merge). A provider runs as a task that publishes complete snapshots on a `tokio::sync::watch` channel (a shared `Provider` trait arrives with the second dynamic provider): a `Fragment` (routes, services and middlewares by bare name; TCP objects join in v0.6) and its diagnostics. Providers never see each other or the data plane (ADR-0009, ADR-0012).

**Translation is pure.** `rdock-provider-docker` has two halves: `labels`, which turns container facts (name, labels, networks and addresses, exposed ports, state, health) into a `Fragment` with no I/O, and `watch`, which talks to the Engine API through `bollard`. The conformance suite (`tests/conformance/traefik-labels`) and `rdock migrate traefik` both drive `labels` directly, so the suite needs no Docker daemon.

**The merge.** The engine starts from the file configuration, which alone owns listeners, defaults, certificates, ACME, security, admin, observability and lifecycle. Each provider object is added under the key `name@provider`. References inside provider objects resolve same-provider first: a bare `x` becomes `x@docker` when the Docker snapshot defines `x`, otherwise it stays `x` (a file object); `x@file` and `x@docker` are taken as written. The merged configuration then runs through the **existing** validator and compiler. The validator accepts `name@<provider>` keys and checks references to them like any other; the compiler resolves `name@file` to `name` and every other reference to the key as written.

**Isolation.** After validation and compilation, every error whose path lies under a provider-owned key (`routes["app@docker"]…`) removes that object, then everything that references it, and the merged configuration is checked again (at most four rounds; then that provider's whole snapshot is dropped and its previous valid snapshot used). Removed objects are reported as warnings naming the original error, in logs, `rdock status` and the admin status. Errors in file-owned objects reject the reload as in v0.1.

**Debounce and triggers.** File changes, `SIGHUP`, `rdock reload` and provider snapshots all feed one apply loop, coalesced over 250 ms (architecture §5). History and the last-known-good copy store the file as written plus each provider's fragment, so a restart while Docker is down serves the last routes (architecture §5, LKG).

**The Docker loop.** `bollard` 0.21 (Engine API 1.53, negotiated; Podman serves the 1.40 API, so health comes from inspect, not the list) without its TLS features. List running containers, inspect each, then stream `container` and `network` events; each relevant event re-lists (coalesced), and a full re-list runs every 60 s. Socket loss keeps the last snapshot in service, marks the provider degraded and reconnects with backoff from 1 s to 30 s; traffic never stops because Docker did.

**Eligibility and safety.** Containers are opt-in (B-SEC-10; Traefik's `exposedByDefault` is `true`, ours is `false`): `rdock.enable=true`, `traefik.enable=true` when `traefik_labels` is on, or `expose_by_default: true` and not disabled. Label values are taken literally: `${…}` in a label is rejected for that object (ADR-0009 rule 7, ADR-0016), so secrets never come from labels.

**Backends.** Address: the network named by `rdock.network` / `traefik.docker.network`, else `providers.docker.network`, else the container's only network, else a diagnostic; host-network containers use `providers.docker.host_address` and need an explicit port. Port: label > the single exposed port > a diagnostic listing the ports. Traefik picks the lowest exposed port instead ([Docker provider reference](https://doc.traefik.io/traefik/reference/install-configuration/providers/docker/), checked 2026-10-28); we keep the diagnostic, because a wrong guess sends traffic to a metrics or admin port, and the conformance suite documents the difference. A container whose Docker health check reports `starting` or `unhealthy` stays in the snapshot but is left out of its pool (W-DKR-06); a pool with no healthy backend answers 503. Stopped containers leave the pool on the next snapshot; requests already in flight finish on the configuration they started with.

**Labels.** Native `rdock.*` labels and the Traefik v3 subset of architecture §11. The shorthand (`rdock.host`, `rdock.port`, `rdock.path`, `rdock.tls`, `rdock.middlewares`) makes one route and one service named after the container. Traefik semantics are followed where they are defined (a router with no service uses the container's only service; a router with no entrypoints uses every listener; entrypoint names map through `providers.docker.entrypoints`, unmapped names are used as listener names). A label outside the subset is a warning with the exact label, never silently ignored. Automatic routes for containers that have no router labels (Traefik's `defaultRule`) are not created in v0.2.

**HTTPS before ACME.** Label routes follow `defaults.tls` like file routes. Until v0.3, a route asking for automatic HTTPS needs a manual or default certificate; without one, that route is removed by isolation with the existing "planned for v0.3" diagnostic, and the rest of the configuration still applies. `rdock.tls=off` serves the route on plain listeners.

**Zero-config mode (v0.2 form).** `rdock run` with no configuration file and a reachable Docker socket uses: listener `web` on `:80`, `defaults.listeners: [web]`, `defaults.tls: off`, the Docker provider with its defaults, and the admin listener on `127.0.0.1:9900`. v0.3 adds `websecure` and automatic certificates to it.

## Consequences
- The validator, compiler and diagnostics of v0.1 are reused unchanged in substance; provider objects are just keys with `@provider`.
- One bad container never blocks other containers or the file configuration, and the reason is visible.
- The translator is a pure function, so label behaviour is fixed by fixtures, and `rdock migrate traefik` shares the exact code path.
- Until v0.3, Docker users either run plain HTTP, provide certificates, or set a default certificate; the docs say so on every Docker page.
- `bollard` becomes a dependency of the `docker` feature only; `--no-default-features` builds stay Docker-free.
