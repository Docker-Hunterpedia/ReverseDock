# ReverseDock — Vision

> **One reverse proxy for a laptop, a VPS, a Docker Swarm, or a Kubernetes cluster.**
> Rust, built on Cloudflare Pingora. 100 % free and open source (Apache-2.0). No account, no telemetry, no paid tier, ever.

## 1. Why another proxy

| Existing tool | What it does best | Where it hurts |
|---|---|---|
| **NGINX OSS** | Mature HTTP server, caching, static files, TCP/UDP | Static config, no service discovery, ACME is external, dashboard is paid (Plus), C codebase |
| **Traefik OSS** | Docker/Swarm/K8s discovery, labels, middlewares | No cache or static files, read-only dashboard, JWT and distributed rate-limit live in paid *Hub* |
| **Caddy** | Automatic HTTPS, simplest config, JSON API | Docker discovery is a third-party plugin, L4 is a plugin, no built-in dashboard |
| **HAProxy CE** | Fastest L4/L7 balancing, stick tables, health checks | Hardest config, ACME still experimental, no container/orchestrator discovery, no dashboard editing |
| **Envoy** | Everything, dynamic xDS, HTTP/3, WASM | Needs a control plane; not meant to be run alone on a VPS |
| **Pingap / Zentinel / River** (Pingora-based) | Pingap: UI + plugins + ACME; Zentinel: security agents; River: stalled (v0.5.0, 2024) | None has Traefik-label compatibility, Swarm, Kubernetes Gateway API, HTTP/3, or a full management plane |

Nobody ships, in one free binary: **Traefik's discovery + Caddy's HTTPS + NGINX's HTTP features + HAProxy's reliability + an editable dashboard.** That is the gap ReverseDock fills.

## 2. Positioning

> *ReverseDock is an open-source, Rust-powered reverse proxy that combines NGINX's flexibility, Traefik's service discovery, Caddy's automatic HTTPS, and HAProxy's reliability — built on Cloudflare Pingora, with a Cloudflare-style dashboard, and free for everyone.*

The developer experience is as important as raw performance. A user should be able to go from `docker compose up` to a valid HTTPS site with **one label**.

## 3. Audiences

| Audience | Typical setup | What they need from us first |
|---|---|---|
| **Self-hoster / developer** | 2–20 containers on one box: Compose, Dokploy, Coolify, Portainer, Proxmox VM, home lab | Labels, automatic HTTPS (incl. behind Cloudflare), dashboard, zero config files |
| **Team in production** | Dozens of services on Swarm or several VMs, SaaS/API/e-commerce | Health checks, load balancing, rate limits, metrics, REST API, config history, GitOps |
| **Platform / high traffic** | Kubernetes, multiple proxy instances, multi-region | Gateway API, distributed state, control plane, cache, WAF, HTTP/3, published benchmarks |

Every feature is designed so the first audience never pays (in complexity) for the third.

## 4. Principles (non-negotiable)

1. **Single binary, zero required dependencies.** No database, no Redis, no Node runtime, no Kubernetes. The dashboard is embedded in the binary.
2. **The data plane never waits for the control plane.** Dashboard, admin API, Docker socket, Kubernetes API or ACME CA can all be down; existing routes keep serving from the last-known-good snapshot.
3. **One internal model.** File, Docker, Swarm, Kubernetes, API: every provider translates into the same desired-state model. No provider has its own routing engine.
4. **Deterministic configuration.** Each object has one owner (provider). Conflicts are rejected with a diagnostic, never silently overwritten. Every apply is atomic and reversible.
5. **Secure by default.** Admin API bound to localhost; containers are opt-in; forwarded headers only trusted from configured proxies; secrets never in labels or logs; request-smuggling hardening on; on-demand certificates require authorization.
6. **Compatibility is tested, not claimed.** Traefik-label support means a conformance suite that runs real Compose files. Gateway API support means the upstream conformance tests.
7. **Everything is observable.** Every state (route, backend, certificate, provider) is visible in the dashboard, the API, the CLI and Prometheus.
8. **Honest performance.** Published, reproducible benchmark scripts and results. No numbers without hardware, TLS and request-mix details.
9. **Free forever.** Apache-2.0, DCO instead of a CLA (nobody can relicense it), no open-core split, no "enterprise" edition.

## 5. Non-goals (through 1.0)

- Not a CDN and not a replacement for network-level DDoS protection (we do application-layer controls only).
- Not an identity provider: we validate tokens (JWT/OIDC/mTLS); we do not manage users for your apps.
- Not a billing or API-monetization platform (we export usage events; we don't invoice).
- Not a forward proxy by default (`CONNECT` is disabled; an explicit, isolated forward mode may come later).
- Not a mail proxy in the core binary.

## 6. Naming conventions

| Thing | Name |
|---|---|
| Product | **ReverseDock** |
| Binary / CLI | `rdock` |
| Crates | `rdock-*` (e.g. `rdock-proxy`, `rdock-acme`) |
| Docker labels | `rdock.*` (plus `traefik.*` compatibility) |
| Config file | `rdock.yaml` (JSON accepted; canonical schema is JSON Schema) |
| Data directory | `/var/lib/rdock` (`RDOCK_DATA_DIR`) |
| Admin listener (default) | `127.0.0.1:2080` |
| Container image | `ghcr.io/reversedock/rdock` |
| Kubernetes GatewayClass | `reversedock` (controller name `reversedock.dev/gateway-controller`) |
| Domain (schema URL, docs site) | `reversedock.dev` — **to be registered**; until then the schema ships inside the repo (`schema/rdock.v1.json`) |

## 7. What "done" means for 1.0

- A Traefik-on-Docker user switches by changing the image name and keeping their labels (documented subset, conformance-tested).
- Fresh VPS, DNS pointed, `docker compose up` → valid HTTPS in under 60 seconds with one label.
- Kubernetes Gateway API conformance profiles `GATEWAY-HTTP`, `GATEWAY-GRPC` and `GATEWAY-TLS` pass (TCP/UDP route tests as they leave provisional status).
- Benchmarks vs NGINX, Traefik, Caddy and HAProxy published with identical hardware, TLS settings and request mix.
- Independent security review of HTTP parsing, TLS/ACME and the admin surface.
- Chaos suite passes: control plane down, Docker socket down, CA down, disk full, backend flapping, config rollback under load.
