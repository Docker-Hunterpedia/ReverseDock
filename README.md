<p align="center">
  <img src="docs/assets/banner.png" alt="ReverseDock — one reverse proxy for every dock" width="100%">
</p>

# ReverseDock

[![ci](https://github.com/Docker-Hunterpedia/ReverseDock/actions/workflows/ci.yml/badge.svg)](https://github.com/Docker-Hunterpedia/ReverseDock/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-F58F0A.svg)](LICENSE)
[![Status: v0.2 alpha](https://img.shields.io/badge/status-v0.2%20Docker--native%20·%20alpha-78716C.svg)](docs/07-roadmap.md)
[![DCO](https://img.shields.io/badge/DCO-required-1C1917.svg)](CONTRIBUTING.md#branches-and-commits)

> One reverse proxy for a laptop, a VPS, a Docker Swarm, or a Kubernetes cluster.
> Rust, built on [Cloudflare Pingora](https://github.com/cloudflare/pingora). 100 % free and open source (Apache-2.0). No account, no telemetry, no paid tier.

**Status: v0.2 "Docker-native" (alpha, [`0.2.0-alpha.1`](https://github.com/Docker-Hunterpedia/ReverseDock/releases/tag/v0.2.0-alpha.1)).** ReverseDock routes Docker containers from their labels, `rdock.*` or your existing `traefik.*` labels, with no restart when containers start, stop or change health; `rdock run` with no configuration file serves labelled containers on port 80, and `rdock migrate traefik` turns Traefik labels into an `rdock.yaml`. It also replaces NGINX for host and path routing with your own certificates: HTTP/1.1, HTTP/2, h2c, WebSocket, server-sent events and gRPC; TLS with SNI and named policies; the Traefik rule grammar; headers, redirects, path rewrites, basic and forward authentication, IP filters, rate limits, CORS, gzip, error pages and maintenance mode; reloads on file change, `SIGHUP` or `rdock reload` without dropping requests (listener changes included); JSON access logs and Prometheus metrics. Automatic HTTPS arrives in v0.3 ([roadmap](docs/07-roadmap.md)).

```bash
# With Docker: the example serves traefik/whoami on http://localhost
cd deploy/docker && docker compose up -d
curl -H 'Host: whoami.localhost' http://localhost/
docker compose exec rdock rdock status

# Docker labels: rdock.* and traefik.* labels on http://whoami.localhost
cd deploy/docker/examples/labels && docker compose up -d

# From source (Rust 1.89+, a C compiler and CMake)
cargo run -p rdock -- run -c examples/config/rdock.quickstart.yaml --data-dir ./data
cargo run -p rdock -- validate examples/config/rdock.full.yaml   # also lists what is not supported yet
just ci                                                           # everything CI checks
```

On a server, [`deploy/systemd/rdock.service`](deploy/systemd/rdock.service) runs it unprivileged with `CAP_NET_BIND_SERVICE`; `systemctl reload rdock` re-reads the configuration.

Editors with the YAML language server get completion and validation from the first line of any `rdock.yaml`:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/Docker-Hunterpedia/ReverseDock/main/schema/rdock.v1.json
```

## Where it is going

- **Traefik's discovery:** Docker, Compose, Swarm, Kubernetes Gateway API — with `rdock.*` labels *and* your existing `traefik.*` labels.
- **Caddy's HTTPS:** automatic certificates by default (HTTP-01, TLS-ALPN-01, DNS-01 with Cloudflare first), ARI-aware renewals ready for 45-day certificates.
- **NGINX's HTTP features:** rewrites, redirects, headers, compression, static files, caching, TCP/UDP.
- **HAProxy's reliability:** health checks, load-balancing policies, retries with budgets, circuit breakers, limits.
- **A Cloudflare-style dashboard** embedded in the single binary, plus a REST API with history and rollback.
- **Cloudflare-aware:** trusted IP sync, `CF-Connecting-IP`, Origin CA, Authenticated Origin Pulls, Tunnel examples, Access JWT.

```yaml
# docker-compose.yml — one label is enough
services:
  app:
    image: ghcr.io/me/app
    labels:
      rdock.host: app.example.com      # route + service + automatic HTTPS
```

## Documentation

| | |
|---|---|
| [Vision](docs/01-vision.md) | why, audiences, principles, non-goals |
| [Research](docs/02-research.md) | verified facts and competitor landscape (Oct 2026) |
| [Feature matrix](docs/03-feature-matrix.md) | 171 capabilities vs NGINX, Traefik, Caddy, HAProxy, Envoy, Pingap, Pingora |
| [Requirements](docs/04-requirements.md) | Basics · Medium traffic · High traffic · Features · Works with |
| [Architecture](docs/05-architecture.md) | the engineering plan |
| [Repo layout](docs/06-repo-layout.md) | crates, conventions, CI, releases |
| [Roadmap](docs/07-roadmap.md) | M0 → v1.0 with acceptance criteria |
| [Design system](docs/08-design-system.md) | Harbor UI · dashboard mock `docs/design/dashboard-mock.html` ([preview](https://claude.ai/artifact/Svy4mzFgfqoWie4aGmHrxB)) · banner & logo sources in `docs/assets/` ([canvas](https://claude.ai/artifact/Kg8V5vPCPyYbokXwYEH8iu)); the in-repo files are canonical, the links are private previews |
| [Decisions](docs/decisions/README.md) | ADRs |

## Roadmap at a glance

`M0 foundations → v0.1 hello proxy → v0.2 Docker-native → v0.3 automatic HTTPS → v0.4 production reliability → v0.5 management (dashboard + API) → v0.6 Swarm + L4 + static → v0.7 Kubernetes → v0.8 cache + plugins → v0.9 scale + HTTP/3 (experimental) → v1.0`

## Contributing

v0.2 reads Docker labels: bug reports from real setups, Traefik labels that route differently than expected, and real-world label sets from Dokploy, Coolify or your own Compose files are the most valuable contributions right now.

- [CONTRIBUTING.md](CONTRIBUTING.md): issues, PR rules, Conventional Commits, DCO sign-off (`git commit -s`)
- [Code of Conduct](CODE_OF_CONDUCT.md) · [Governance](GOVERNANCE.md) · [Support](SUPPORT.md)
- Security problems: [SECURITY.md](SECURITY.md), never a public issue
- Questions: [Discussions](https://github.com/Docker-Hunterpedia/ReverseDock/discussions)

`main` is protected: every change goes through a reviewed pull request with green checks.

## License

[Apache-2.0](LICENSE). Free forever: no CLA, no open-core, no telemetry ([ADR-0005](docs/decisions/0005-license-apache2-dco.md)).
