# ReverseDock — Feature-Parity Matrix

Comparison of **NGINX OSS, Traefik Proxy OSS, Caddy, HAProxy CE, Envoy, Pingap** and the **Pingora framework** against the 171 capabilities ReverseDock targets. Source of truth is the workbook [`research/feature-parity-matrix-2026-10-26.xlsx`](research/feature-parity-matrix-2026-10-26.xlsx); the tables below are generated from it with [`scripts/xlsx2md.py`](../scripts/xlsx2md.py) (workbook modules mapped to the crates in [05 §2](05-architecture.md#2-crate-map)).

## Highlights

### Protocols and routing

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| HTTP/1.1 proxy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTTP/2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTTP/3 frontend | 🧪 | ✅ | ✅ | ✅ | ✅ | — | — (PR closed 2026-09) |
| WebSockets | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| gRPC proxy | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ |
| TCP proxy | ✅ | ✅ | 🔌 | ✅ | ✅ | — | 🛠️ |
| UDP proxy | ✅ | ✅ | 🔌 | ◐ | ✅ | — | 🛠️ |

### HTTPS, reliability, caching

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Automatic ACME HTTPS | 🔌 | ✅ | ✅ | 🧪 | 🔌 | ✅ | 🛠️ |
| DNS-01 / wildcard | 🔌 | ✅ | 🔌 | 🧪 | 🔌 | ✅ | 🛠️ |
| Active health checks | 🔌 (Plus) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Passive health checks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ |
| Response caching | ✅ | 🔌 | 🔌 | ✅ (memory) | ✅ | ✅ | 🧪 (alpha) |
| Circuit breaking | ◐ | ✅ | ◐ | ✅ | ✅ | ✅ | 🛠️ |

### Infrastructure integrations

| Integration | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Docker container discovery | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | ✅ (own labels) | 🛠️ |
| Traefik-label compatibility | — | ✅ | — | — | — | — | 🛠️ |
| Docker Swarm | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ |
| Kubernetes Ingress | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ |
| Kubernetes Gateway API | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ |
| Cloudflare DNS-01 | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | ✅ | 🛠️ |

### Security and management

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| JWT validation | 🔌 | 🔌 (Hub) | 🔌 | 🔌 | ✅ | ✅ | 🛠️ |
| WAF | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | ◐ | 🛠️ |
| Editable web dashboard | 🔌 | ◐ (read-only) | 🔌 | 🔌 | 🔌 | ✅ | 🛠️ |
| Live config REST API | 🔌 | 🔌 | ✅ | ◐ | ◐ | ◐ | 🛠️ |
| Third-party extensions | ✅ | ✅ | ✅ | ◐ | ✅ (WASM) | ✅ | 🛠️ |

**Reading:** the only column that matters for effort is *Pingora*. Everything marked 🛠️ is ours to build — that is ~80 % of the matrix, which is why the roadmap is milestone-driven rather than feature-driven.

## Highest-value priorities

| Priority | Capability | Why it matters |
|---|---|---|
| P0 | Routing engine on Pingora | Core of the project |
| P0 | Docker + Compose discovery | Immediate adoption |
| P0 | Traefik-label compatibility | Zero-effort migration |
| P0 | Automatic ACME HTTPS (ARI-aware) | Caddy-class experience, survives 45-day certs |
| P0 | Cloudflare trusted IPs + DNS-01 | Reliable HTTPS and real client IPs behind Cloudflare |
| P1 | Health checks + load balancing | Production reliability |
| P1 | REST API + dashboard | Day-2 operations |
| P1 | Docker Swarm, TCP/SNI passthrough | Multi-node Docker |
| P2 | Kubernetes Gateway API v1.6 | Cloud-native adoption |
| P2 | Production HTTP cache | Compete with NGINX caching |
| P3 | Distributed control plane, HTTP/3 | Multi-region and edge |

## Phase overrides

The workbook phases are a research snapshot. Where [04-requirements.md](04-requirements.md) and the [roadmap](07-roadmap.md) decided differently, **04/07 win**:

| Capability | Workbook | ReverseDock | Why |
|---|:-:|:-:|---|
| HTTP/3 / QUIC frontend | P2 | P3 (v0.9, experimental) | Pingora has no h3; needs a BoringSSL variant and an h3→h2c hop (ADR-0006) |
| ACME TLS-ALPN-01 | P1 | P0 (v0.3) | Needed when :80 is not reachable (Cloudflare Tunnel, port 80 blocked) |
| Local development CA | P1 | P0 (v0.3) | Part of the Caddy-class HTTPS promise |
| Client / upstream mTLS | P1 | P1 (v0.4, M-TLS-01) | Unchanged; identity *policies* and SPIFFE are P3 (H-SEC-05) |
| JWT verification / JWKS | P1 | P1 (v0.4, M-SEC-01) | Unchanged; OIDC login and API keys are P2 (F-GW-01) |
| Regex / header / method routing | P1 | P0 (v0.1, B-NET-04) | The Traefik rule grammar must be complete for label compatibility in v0.2 |
| Zero-downtime binary upgrade | P2 | P3 (v0.9, H-PERF-04) | Requires the supervisor/worker model (ADR-0008) |
| Forward auth middleware | P1 | P0 (v0.1, B-SEC-12) | Authelia/Authentik setups are the norm on Dokploy/Coolify |
| Safe retries | P1 | P1 (v0.4) but transport-only | Status-code retries wait for an upstream Pingora hook (ADR-0010) |


<!-- GENERATED from docs/research/feature-parity-matrix-2026-10-26.xlsx by scripts/xlsx2md.py — edit the workbook, not this section -->

## Legend

| Symbol | Meaning | Engineering implication |
|---|---|---|
| ✅ Native | Official built-in / packaged support | Still requires config and tests |
| ◐ Partial | Limited features or different semantics | Read notes; cannot claim full parity |
| 🔌 External | Plugin / controller / other process | Extra dependencies / maintenance |
| 🧪 Experimental | Documented experimental feature | Not a stable compatibility guarantee |
| — Not native | No documented built-in support in this scope | May be possible via custom code |
| 🛠️ Build needed | Pingora gives building blocks, product feature absent | ReverseDock must implement it |

Scope rules: free/open-source distributions only (NGINX Plus and Traefik Hub do not count). Running inside Docker ≠ Docker service discovery. HTTP/3 downstream ≠ HTTP/3 upstream. P0–P3 are **requirements for ReverseDock, not implementation claims**.

## Counts by phase (171 capabilities)

| Phase | Count | Milestones |
|---|---|---|
| P0 | 59 | v0.1 – v0.3 (Foundations: protocols, routing, TLS + ACME, Docker labels) |
| P1 | 58 | v0.4 – v0.6 (Production: LB & health, observability, management, Swarm, L4) |
| P2 | 35 | v0.7 – v0.8 (Advanced: Kubernetes, cache, extensibility) |
| P3 | 19 | v0.9 + (Scale: clustering, HTTP/3, specialised edge policy) |

## Full matrix

Columns: NGINX OSS · Traefik OSS · Caddy · HAProxy CE · Envoy · Pingap · Pingora framework · target phase (workbook) · ReverseDock crate/module · effort. Phases in **04-requirements.md win** where they differ (see Phase overrides above).

### Basics · HTTP

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [HTTP/1.1 reverse proxy](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Low | Pingora already offers HTTP reverse proxy APIs. |
| [HTTP/2 frontend](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Low | Supports HTTP/2 over TLS; align frame/stream limits. |
| [HTTP/2 upstream](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Low | Test protocol negotiation and connection reuse. |
| [HTTP/3 / QUIC frontend](https://nginx.org/en/docs/http/ngx_http_v3_module.html) | 🧪 | ✅ | ✅ | ✅ | ✅ | — | — | P2 | `rdock-proxy (http3 feature)` | Very high | NGINX module remains experimental; Pingora doesn't include full HTTP/3 product support. |
| [HTTP/3 upstream](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) | — | ◐ | 🧪 | ◐ | ✅ | — | — | P3 | `rdock-proxy (http3 feature)` | Very high | Caddy upstream HTTP/3 is documented experimental; Envoy supports it. |
| [WebSocket upgrades](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Low | Include fragmented frames, idle timeouts, and streaming tests. |
| [gRPC upstream proxy](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ | P0 | `rdock-proxy` | Medium | Distinguish native gRPC-over-HTTP/2 from gRPC-Web translation. |
| [gRPC-Web translation](https://pingap.io/) | — | ✅ | ◐ | ◐ | ✅ | ✅ | 🛠️ | P1 | `rdock-middleware (grpc-web)` | Medium | Requires translation middleware when browser clients use gRPC-Web. |
| [SSE / chunked streaming](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Medium | Critical for LLM token streaming and long-lived connections. |
| [Streaming uploads with bounded memory](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P0 | `rdock-proxy` | High | Add backpressure and memory-budget tests; framework alone isn't a guarantee. |
| [HTTP proxy to HTTPS upstream](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Low | Validate origin certificates and hostnames by default. |
| [Unix-socket HTTP upstream](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P0 | `rdock-proxy` | Low | Useful for native services, sockets and self-hosted deployments. |
| [IPv6 listeners and upstreams](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Low | Ensure dual-stack resolution and IPv6 CIDR coverage. |
| [Host / domain routing](https://pingap.io/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-rules + rdock-proxy (router)` | Medium | Core route matcher owned by project, not upstream library. |
| [Host wildcard routing](https://pingap.io/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-rules + rdock-proxy (router)` | Medium | Define wildcard collision rules and exact-host priority. |
| [Path prefix routing](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-rules + rdock-proxy (router)` | Medium | Normalize paths defensively to avoid bypasses. |
| [Regex / header / method routing](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-rules + rdock-proxy (router)` | Medium | Avoid pathological regex and keep matcher semantics deterministic. |
| [Header mutations](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-rules + rdock-proxy (router)` | Medium | Filter hop-by-hop headers; prevent spoofed forwarded headers. |
| [URL rewrite and redirects](https://nginx.org/en/docs/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-rules + rdock-proxy (router)` | Medium | Test canonicalization and redirect loops. |
| [Custom error pages](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-proxy` | Low | Useful for TLS, timeout, 429, maintenance and 5xx responses. |
| [Graceful reload / connection draining](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Medium | Ensure existing HTTP/2 streams and WebSockets survive as intended. |
| [Connection pooling / keep-alive](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Medium | Expose per-backend limits and idle eviction. |
| [Request / response timeout tuning](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-proxy` | Low | Support route, upstream, read, write, connect timeouts. |

### TLS · Certificates

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [TLS termination, SNI, ALPN](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-tls` | Medium | TLS backend choice affects build, FIPS and platform support. |
| [Client mTLS](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-tls` | Medium | Validate client cert chain, identity and revocations. |
| [Upstream mTLS](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-tls` | Medium | Support distinct upstream trust roots. |
| [Automatic ACME HTTPS](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/ssl-tls/acme/) | 🔌 | ✅ | ✅ | 🧪 | 🔌 | ✅ | 🛠️ | P0 | `rdock-acme` | High | HAProxy 3.2+ native ACME is experimental; NGINX typically external. |
| [Automatic renewal / CA failover](https://caddyserver.com/docs/automatic-https) | 🔌 | ✅ | ✅ | 🧪 | 🔌 | ✅ | 🛠️ | P0 | `rdock-acme` | High | Crash-safe storage, backoff, rate-limit awareness. |
| [ACME HTTP-01](https://caddyserver.com/docs/automatic-https) | 🔌 | ✅ | ✅ | 🧪 | 🔌 | ✅ | 🛠️ | P0 | `rdock-acme` | Medium | Ensure 80/tcp challenge and redirects cooperate. |
| [ACME TLS-ALPN-01](https://caddyserver.com/docs/automatic-https) | 🔌 | ✅ | ✅ | ◐ | 🔌 | ◐ | 🛠️ | P1 | `rdock-acme` | Medium | Avoid claiming support when a provider only implements HTTP-01/DNS-01. |
| [ACME DNS-01 / wildcards](https://pingap.io/) | 🔌 | ✅ | 🔌 | 🧪 | 🔌 | ✅ | 🛠️ | P0 | `rdock-acme` | High | Implement provider adapters; Cloudflare first. |
| [Certificate import / BYO certificate](https://caddyserver.com/docs/automatic-https) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-tls` | Low | PEM/key, encrypted key support and atomic replacement. |
| [Local development CA / HTTPS](https://caddyserver.com/docs/automatic-https) | 🔌 | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | 🛠️ | P1 | `rdock-acme` | High | Caddy has built-in local CA and trust management. |
| [On-demand TLS for customer domains](https://caddyserver.com/docs/automatic-https) | 🔌 | ◐ | ✅ | 🔌 | 🔌 | ◐ | 🛠️ | P2 | `rdock-acme` | Very high | MUST include authorization to avoid certificate-issuance abuse. |
| [HSTS / secure TLS profiles](https://caddyserver.com/docs/automatic-https) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-tls` | Low | HSTS opt-in rather than blindly forcing preload. |
| [Certificate status / expiry alerts](https://pingap.io/crates/) | 🔌 | ✅ | ✅ | 🔌 | 🔌 | ✅ | 🛠️ | P0 | `rdock-observability` | Medium | Expiration and renewal failures need clear alerts. |

### Layer 4 & transport

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [Generic TCP proxying](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | 🔌 | ✅ | ✅ | — | 🛠️ | P1 | `rdock-proxy (l4)` | High | Requires dedicated L4 listener, not an HTTP route workaround. |
| [Generic UDP proxying](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | 🔌 | ◐ | ✅ | — | 🛠️ | P2 | `rdock-proxy (l4)` | Very high | Do not conflate QUIC listener with arbitrary UDP relay. |
| [TLS passthrough by SNI](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | ✅ | ✅ | 🔌 | ✅ | ✅ | — | 🛠️ | P1 | `rdock-proxy (l4)` | High | Pass encrypted streams without terminating TLS. |
| [PROXY protocol incoming](https://www.haproxy.org/) | ✅ | ✅ | ◐ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-proxy (l4)` | Medium | Trust only configured upstreams; v1/v2 parsing. |
| [PROXY protocol to upstream](https://www.haproxy.org/) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-proxy (l4)` | Medium | Useful for preserving client source address. |
| [TCP service health checks](https://pingap.io/crates/) | ✅ | ✅ | ◐ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-proxy (l4)` | Medium | Share checker framework with HTTP but separate protocol parsing. |
| [HTTP CONNECT / forward-proxy mode](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | 🔌 | 🔌 | ◐ | ✅ | ◐ | 🛠️ | P3 | `unscheduled (F-WEB-05)` | Very high | Isolate from reverse-proxy and guard SSRF / open-proxy risks. |
| [SMTP/IMAP/POP3 proxy options](https://nginx.org/en/docs/) | ✅ | — | 🔌 | ◐ | ◐ | — | 🛠️ | P3 | `out of scope (F-WEB-06)` | Very high | Separate optional component; not an early product differentiator. |

### Medium · Routing / balancing

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [Weighted round-robin](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-balancer` | Low | Pingora offers LB primitives; verify exact weighted semantics or implement explicitly. |
| [Least connections / least requests](https://www.haproxy.org/) | ✅ | ◐ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-balancer` | Low | Algorithms differ: NGINX least_conn, Envoy least_request; Traefik primarily weighted round-robin; implement / test per algorithm. |
| [Consistent hashing / affinity](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P1 | `rdock-balancer` | Medium | Pingora ketama primitives are available. |
| [IP affinity](https://www.haproxy.org/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-balancer` | Medium | Hash correctly behind trusted reverse proxies. |
| [Sticky cookie affinity](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) | 🔌 | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-balancer` | Medium | Cookie signing, key rotation, backup routing. |
| [Active HTTP health probes](https://docs.nginx.com/nginx-gateway-fabric/overview/nginx-plus/) | 🔌 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P1 | `rdock-balancer (health)` | Medium | NGINX Plus provides extra commercial probes; OSS passive/other checks. |
| [Passive backend health detection](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-balancer (health)` | Medium | Classify upstream errors and enforce sample thresholds. |
| [Automatic failover / backups](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P1 | `rdock-balancer` | Medium | Define fail-closed and fail-open behavior. |
| [Safe retries / replay protection](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-balancer (retry)` | High | Never blindly replay non-idempotent requests. |
| [Circuit breaking](https://pingap.io/crates/) | ◐ | ✅ | ◐ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-balancer / rdock-limits` | High | Be explicit about breaker circuit scope, state and recovery. |
| [Outlier detection / eviction](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ◐ | ◐ | ◐ | ✅ | ✅ | ◐ | 🛠️ | P2 | `rdock-balancer / rdock-limits` | High | Detect persistent errors and support slow-start recovery. |
| [Backpressure / queue limits](https://www.haproxy.org/) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-balancer / rdock-limits` | High | Bound all queues; test overload response paths. |
| [Canary / weighted traffic split](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-rules + rdock-proxy (router)` | Medium | Keep weights deterministic and health-aware. |
| [Request mirroring / shadowing](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | ◐ | ✅ | ✅ | ◐ | 🛠️ | P2 | `rdock-rules + rdock-proxy (router)` | High | Sanitize tokens and PII before mirroring. |
| [Backend DNS service discovery](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-balancer (dns discovery)` | Medium | DNS TTL respect; avoid silent staleness. |
| [Blue/green deployment switching](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-rules + rdock-proxy (router)` | Medium | Atomic upstream cutover with draining. |
| [Connection draining during rolling deploy](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ◐ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-balancer / rdock-limits` | High | Schedule health and graceful disruption windows. |
| [Adaptive latency-aware routing](https://www.haproxy.org/) | 🔌 | ◐ | ◐ | ✅ | ✅ | ◐ | 🛠️ | P3 | `rdock-balancer` | Very high | Requires observability, fairness, and control-loop tests. |
| [Locality / zone-aware routing](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | ◐ | ◐ | ◐ | ✅ | — | 🛠️ | P3 | `rdock-balancer` | High | Deploy only when user has multi-AZ infra. |
| [Global distributed rate limits](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/distributed-ratelimit/) | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | — | 🛠️ | P3 | `rdock-control (P3)` | Very high | External backend/coordination required; Traefik Hub separate. |

### Traffic · Middleware

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [Per-IP local rate limiting](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | 🔌 | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-limits` | Medium | Per-instance only; correctly interpret real IP. |
| [Per-route / identity quotas](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ◐ | ✅ | 🔌 | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-limits` | High | Keys from auth context, deny spoofed identities. |
| [Burst / token bucket limits](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | 🔌 | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-limits` | Medium | Memory bounded cardinality and cleanup. |
| [Concurrent request caps](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | ◐ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-limits` | Medium | Distinct from rate limits; include queue timeout. |
| [Request body size limits](https://nginx.org/en/docs/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-limits` | Low | Enforce early, including streaming/chunked bodies. |
| [Header / URL length limits](https://nginx.org/en/docs/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-limits` | Medium | Reject ambiguous/malformed requests consistently. |
| [Traffic shaping / bandwidth caps](https://www.haproxy.org/) | ✅ | ◐ | ◐ | ✅ | ✅ | ◐ | 🛠️ | P2 | `rdock-limits` | High | Per-client, per-route throughput limiting. |
| [Configurable response compression](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-middleware (compress)` | Medium | gzip baseline; br/zstd depend on modules/providers. |
| [CORS middleware](https://pingap.io/plugins/) | 🔌 | ✅ | ✅ | ◐ | ✅ | ✅ | 🛠️ | P0 | `rdock-middleware` | Low | CORS is not an authentication mechanism. |
| [Custom security headers](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-middleware` | Low | CSP, frame protection, referrer, X-Content-Type-Options. |
| [Forward auth middleware](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | ✅ | ◐ | ✅ | ✅ | 🛠️ | P1 | `rdock-middleware (auth)` | Medium | Timeouts, failure policy and trust boundary essential. |
| [Request / response header rewrite](https://nginx.org/en/docs/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-middleware` | Low | Match priority and normalise case/hop-by-hop headers. |
| [Conditional route policy chains](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-middleware` | High | Ordered execution with explicit side effects. |
| [WASM middleware/plugins](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | 🔌 | 🔌 | 🔌 | ✅ | — | 🛠️ | P3 | `rdock-plugins (P2/P3)` | Very high | Sandbox, capabilities, fuel and ABI stability. |
| [Native third-party plugin API](https://pingap.io/plugins/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P2 | `rdock-plugins (P2/P3)` | High | Different runtime models; design stable, safe extension interface. |

### Cache · Content serving

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [HTTP response caching](https://github.com/cloudflare/pingora) | ✅ | 🔌 | 🔌 | ✅ | ✅ | ✅ | 🧪 | P2 | `rdock-cache (P2)` | Very high | Pingora proxy cache integration experimental; audit RFC semantics. |
| [Memory response cache](https://github.com/cloudflare/pingora) | ◐ | 🔌 | 🔌 | ✅ | ✅ | ✅ | ✅ | P2 | `rdock-cache (P2)` | High | Fast but bounded; test stampede conditions. |
| [Disk-backed HTTP cache](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/cache_filter) | ✅ | 🔌 | 🔌 | — | ✅ | ✅ | 🧪 | P2 | `rdock-cache (P2)` | Very high | Eviction, corruption recovery and disk quotas. |
| [Cache-Control and Vary semantics](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/performance/caching/) | ✅ | 🔌 | 🔌 | ◐ | ✅ | ✅ | 🧪 | P2 | `rdock-cache (P2)` | Very high | HAProxy has restricted Vary cases; test private response safety. |
| [Stale-while-revalidate / stale-if-error](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) | ✅ | 🔌 | 🔌 | ◐ | ◐ | ◐ | 🧪 | P2 | `rdock-cache (P2)` | High | Clear consistency and background revalidation rules. |
| [Conditional ETag / Last-Modified](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) | ✅ | 🔌 | 🔌 | ◐ | ✅ | ◐ | 🧪 | P2 | `rdock-cache (P2)` | High | Conditional request flow must preserve origin semantics. |
| [Cache purge API](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) | 🔌 | 🔌 | 🔌 | 🔌 | ◐ | ◐ | 🛠️ | P2 | `rdock-cache (P2)` | High | Granular purge and authenticated admin access. |
| [Request coalescing / cache lock](https://github.com/cloudflare/pingora) | ✅ | 🔌 | 🔌 | 🔌 | ◐ | ◐ | ✅ | P2 | `rdock-cache (P2)` | Medium | Pingora has memory caching locks; HTTP integration still needed. |
| [Static files / SPA fallback](https://pingap.io/plugins/) | ✅ | 🔌 | ✅ | — | ◐ | ✅ | 🛠️ | P1 | `rdock-middleware (static)` | Medium | Static MIME, ranges and traversal prevention. |
| [Directory listing / file browsing](https://nginx.org/en/docs/) | ✅ | 🔌 | ✅ | — | — | ◐ | 🛠️ | P3 | `rdock-middleware (static)` | Medium | Disabled by default, hardened path resolution. |
| [Conditional byte range static files](https://nginx.org/en/docs/) | ✅ | 🔌 | ✅ | — | ◐ | ◐ | 🛠️ | P2 | `rdock-middleware (static)` | Medium | Check for large asset and partial content behavior. |
| [Custom 404/maintenance page](https://nginx.org/en/docs/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-middleware` | Low | Static or upstream error views, no sensitive leaks. |
| [Brotli + Zstd compression](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | ✅ | ◐ | 🔌 | ✅ | ◐ | 🛠️ | P2 | `rdock-middleware (compress)` | Medium | Availability varies by module and build; negotiate correctly. |

### Security · Identity

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [Basic auth](https://pingap.io/plugins/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-middleware (auth)` | Low | Hash passwords, never plaintext files by default. |
| [IP allow/deny CIDR](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-proxy (security) / rdock-limits` | Low | Parse CIDRs and IPv6 consistently. |
| [Trusted forwarding chain / real client IP](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-proxy (security) / rdock-limits` | High | Critical behind Cloudflare and Docker NAT; reject untrusted forwarded headers. |
| [JWT verification / JWKS](https://doc.traefik.io/traefik/secure/secure-api-access-with-jwt/) | 🔌 | 🔌 | 🔌 | 🔌 | ✅ | ✅ | 🛠️ | P1 | `rdock-middleware (auth)` | High | Traefik Hub JWT is not Traefik OSS core. |
| [OIDC login / access policies](https://doc.traefik.io/traefik/secure/secure-api-access-with-jwt/) | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | ◐ | 🛠️ | P2 | `rdock-middleware (auth)` | High | Can integrate external auth; distinguish JWT validator from full login. |
| [API key validation](https://pingap.io/plugins/) | 🔌 | 🔌 | 🔌 | ◐ | 🔌 | ✅ | 🛠️ | P2 | `rdock-middleware (auth)` | Medium | Avoid persistent user DB in data plane; use auth service. |
| [Client certificate access control](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P1 | `rdock-tls` | Medium | mTLS identities and policies. |
| [HTTP request smuggling hardening](https://nginx.org/en/docs/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-proxy (security) / rdock-limits` | Very high | Differential parser tests; strict CL/TE and HTTP/2 normalization. |
| [Application WAF / OWASP CRS](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | ◐ | 🛠️ | P3 | `external agent via rdock-plugins (P3)` | Very high | Choose engine separately; do not imply rate limits equal WAF. |
| [Bot / JA4 / behavioral mitigation](https://pingap.io/) | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | ◐ | 🛠️ | P3 | `rdock-proxy (security) / rdock-limits` | Very high | JA4 observable in Pingap; mitigation needs rules and tuning. |
| [GeoIP or region policies](https://www.haproxy.org/) | 🔌 | 🔌 | 🔌 | ✅ | 🔌 | ◐ | 🛠️ | P2 | `rdock-proxy (security) / rdock-limits` | Medium | Prefer external MaxMind-style DB; keep freshness verified. |
| [Cloudflare connecting-IP validation](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | 🛠️ | P0 | `rdock-cloudflare` | Medium | Only trust CF-Connecting-IP from verified Cloudflare hop. |
| [Per-tenant RBAC for management API](https://caddyserver.com/docs/api) | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | ◐ | 🛠️ | P2 | `rdock-admin` | High | Control-plane only; tenant isolation not implicit in proxy. |
| [Audit logs of admin changes](https://caddyserver.com/docs/api) | 🔌 | ◐ | ◐ | 🔌 | ◐ | ◐ | 🛠️ | P1 | `rdock-admin` | Medium | Recorded actor, old/new hash, timestamp and outcome. |
| [Secrets encryption / external secrets](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | ◐ | ◐ | 🔌 | ✅ | ◐ | 🛠️ | P2 | `rdock-config (secrets)` | High | Avoid secrets in labels and logs; support file / Vault. |

### Observability · Admin

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [Structured access logs](https://pingap.io/crates/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-observability` | Low | JSON with request ID, backend, status, latency. |
| [Real-time status / connections stats](https://www.haproxy.org/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-observability` | Medium | Export active/idle connections, upstream states. |
| [Prometheus metrics endpoint](https://pingap.io/) | 🔌 | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-observability` | Medium | Caddy and Envoy expose native Prometheus-compatible metrics; NGINX OSS generally exporter integration. |
| [OpenTelemetry tracing](https://pingap.io/crates/) | 🔌 | ✅ | 🔌 | 🔌 | ✅ | ✅ | 🛠️ | P1 | `rdock-observability` | High | Trace sampling + W3C propagation; avoid sensitive data. |
| [Configurable log sampling/redaction](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ◐ | ✅ | ◐ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-observability` | Medium | User PII, API keys, cookies must be redacted. |
| [p50 / p95 / p99 latency visibility](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ◐ | ✅ | ◐ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-observability` | Medium | Instrument route, backend, status; avoid uncontrolled label cardinality. |
| [Per-route and upstream metrics](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | ◐ | ✅ | ◐ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-observability` | High | Metrics label controls needed for multi-tenant deployment. |
| [OpenTelemetry log/trace correlation](https://pingap.io/crates/) | 🔌 | ✅ | 🔌 | 🔌 | ✅ | ✅ | 🛠️ | P2 | `rdock-observability` | Medium | Same request-id / trace-id across layers. |
| [Backend health UI / topology](https://pingap.io/) | 🔌 | ✅ | 🔌 | ◐ | 🔌 | ✅ | 🛠️ | P1 | `rdock-admin` | High | Traefik dashboard shows config; Pingap has editable admin UI. |
| [Editable web UI for routes / domains](https://pingap.io/) | 🔌 | ◐ | 🔌 | 🔌 | 🔌 | ✅ | 🛠️ | P1 | `apps/dashboard` | High | Traefik OSS dashboard mostly informational, not route editor. |
| [REST API for live config mutation](https://caddyserver.com/docs/api) | 🔌 | 🔌 | ✅ | ◐ | ◐ | ◐ | 🛠️ | P1 | `rdock-admin (api)` | Very high | Envoy uses xDS for most dynamic config; avoid confusing admin API with control API. |
| [Role based login / multi-user admin](https://pingap.io/) | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | ◐ | 🛠️ | P2 | `apps/dashboard` | High | Use standard identity provider integration; admin controls isolated. |
| [Configuration history and rollback](https://github.com/cloudflare/pingora) | 🔌 | 🔌 | ◐ | 🔌 | 🔌 | ◐ | 🛠️ | P1 | `rdock-config` | High | Atomic snapshots and last-known-good config. |

### Config · Delivery

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [Human-friendly YAML/TOML config](https://pingap.io/crates/) | 🔌 | ✅ | ◐ | 🔌 | ✅ | ✅ | 🛠️ | P0 | `rdock-config` | Medium | Canonical JSON schema plus YAML importer; Pingap supports TOML/HCL/KDL. |
| [Canonical JSON config](https://caddyserver.com/docs/api) | 🔌 | ◐ | ✅ | 🔌 | ✅ | ◐ | 🛠️ | P0 | `rdock-config` | Medium | Strongly typed with schema and migrations. |
| [Single binary deployment](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock (binary)` | Low | Rust binary with config and data plane in one deploy unit. |
| [Standalone Docker image / Compose](https://pingap.io/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `deploy/` | Low | Non-root images, read-only option, multi-arch. |
| [Hot reload without dropping traffic](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-config` | High | Atomic state swap and lifecycle tests. |
| [Dry-run configuration validation](https://nginx.org/en/docs/) | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P0 | `rdock-config` | Medium | Return structured errors, collision diagnostics. |
| [Atomic config rollback](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | 🔌 | ◐ | ◐ | ✅ | ◐ | 🛠️ | P1 | `rdock-config` | High | Rollback on bind failure, invalid cert and backend mismatch. |
| [Versioned management REST API](https://caddyserver.com/docs/api) | 🔌 | 🔌 | ✅ | ◐ | ◐ | ◐ | 🛠️ | P1 | `rdock-admin (api)` | High | No public admin exposure by default. |
| [GitOps and declarative files](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-config` | Medium | Controller should reconcile, not imperatively override ownership. |
| [Multiple providers merged deterministically](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | 🔌 | ✅ | 🔌 | 🔌 | ✅ | ◐ | 🛠️ | P1 | `rdock-config` | Very high | Source ownership, namespaces, priorities and conflicts. |
| [CLI lint/status/reload commands](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock (binary)` | Low | Exit statuses and actionable diagnostics. |
| [Terraform/OpenTofu provider](https://caddyserver.com/docs/api) | 🔌 | 🔌 | 🔌 | 🔌 | 🔌 | — | 🛠️ | P2 | `rdock-admin (api)` | High | Versioned API is a prerequisite. |
| [Traefik label/config migration assistant](https://doc.traefik.io/traefik/providers/docker/) | — | — | — | — | — | — | 🛠️ | P1 | `rdock-migrate` | High | Parse subset of Traefik v3 labels and flag unsupported semantics. |
| [NGINX config migration assistant](https://nginx.org/en/docs/) | — | — | — | — | — | — | 🛠️ | P3 | `rdock-migrate` | Very high | NGINX grammar + directive compatibility needs explicit coverage. |
| [Plugin loading / versioned SDK](https://pingap.io/plugins/) | ✅ | ✅ | ✅ | ◐ | ✅ | ✅ | 🛠️ | P2 | `rdock-plugins (P2/P3)` | Very high | Plugin policy should not jeopardize data-plane stability. |

### Providers · Ecosystem

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [Docker container discovery](https://doc.traefik.io/traefik/providers/docker/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | ✅ | 🛠️ | P0 | `rdock-provider-docker` | High | Read-only events plus full reconciliation, multi-network selection. |
| [Docker Compose label routing](https://doc.traefik.io/traefik/providers/docker/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | ✅ | 🛠️ | P0 | `rdock-provider-docker` | High | Container label parsing and router/service relation. |
| [Traefik Docker-label compatibility](https://doc.traefik.io/traefik/providers/docker/) | — | ✅ | — | — | — | — | 🛠️ | P0 | `rdock-provider-docker` | Very high | Pingap has Docker discovery/labels, but full Traefik-label semantic compatibility is not documented. |
| [Docker Swarm service discovery](https://doc.traefik.io/traefik/reference/install-configuration/providers/swarm/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ | P1 | `rdock-provider-swarm` | High | Service labels in deploy.labels; overlay and task vs VIP modes. |
| [Kubernetes Ingress controller](https://doc.traefik.io/traefik/reference/install-configuration/providers/kubernetes/kubernetes-gateway/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ | P2 | `rdock-provider-kubernetes` | Very high | Dedicated controller; nginx and Envoy usually external controllers. |
| [Kubernetes Gateway API controller](https://gateway-api.sigs.k8s.io/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ | P2 | `rdock-provider-kubernetes` | Very high | Target conformance, especially HTTPRoute core profile. |
| [Kubernetes EndpointSlice watch](https://gateway-api.sigs.k8s.io/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ | P2 | `rdock-provider-kubernetes` | High | Controller owns watch, data plane consumes snapshots. |
| [K3s / RKE2 integration](https://gateway-api.sigs.k8s.io/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ | P2 | `rdock-provider-kubernetes` | Medium | Should follow conformant Kubernetes API, not separate backend. |
| [Nomad service discovery](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ | P3 | `unscheduled (W-PLAT-06)` | High | Traefik native provider advantage. |
| [Consul Catalog discovery](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ | P3 | `unscheduled (W-PLAT-06)` | High | Distinct catalog vs KV configuration models. |
| [Consul / etcd KV config](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | 🔌 | ✅ | 🔌 | 🔌 | ✅ | — | 🛠️ | P3 | `unscheduled (W-PLAT-07)` | High | Avoid control plane availability becoming data-plane dependency. |
| [Amazon ECS discovery](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | — | 🛠️ | P3 | `unscheduled (W-PLAT-08)` | High | Traefik native provider; model portability. |
| [Cloudflare CDN as upstream edge](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P0 | `rdock-cloudflare` | Medium | All can run behind CDN; project needs strong trusted proxy logic. |
| [Cloudflare DNS-01 ACME provider](https://pingap.io/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | ✅ | 🛠️ | P0 | `rdock-cloudflare` | Medium | Use scoped API token; CA challenge correctness. |
| [Cloudflare Tunnel / cloudflared](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `deploy/` | Low | Cloudflared tunnels HTTP to origin; not embedded runtime. |
| [Cloudflare Origin CA TLS / Authenticated Origin Pull](https://caddyserver.com/docs/automatic-https) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-tls` | Medium | Origin validation, client cert check and trust store. |
| [Cloudflare Access JWT validator](https://doc.traefik.io/traefik/secure/secure-api-access-with-jwt/) | 🔌 | 🔌 | 🔌 | 🔌 | ✅ | ◐ | 🛠️ | P2 | `rdock-cloudflare` | Medium | Verify token signature, audience, issuer, timestamps. |
| [Dokploy-compatible deployment / networks](https://doc.traefik.io/traefik/providers/docker/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | ◐ | 🛠️ | P0 | `deploy/` | Medium | Infrastructure compatibility ≠ native Dokploy provider; support Compose and labels. |
| [Coolify / Portainer Docker compatibility](https://doc.traefik.io/traefik/providers/docker/) | 🔌 | ✅ | 🔌 | 🔌 | 🔌 | ◐ | 🛠️ | P1 | `deploy/` | Medium | Do not assume official platform endorsement. |
| [Prometheus + Grafana dashboards](https://pingap.io/) | 🔌 | ✅ | 🔌 | ✅ | 🔌 | ✅ | 🛠️ | P1 | `rdock-observability` | Medium | Metrics and reusable Grafana dashboard templates. |
| [Vault / secret stores integration](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | 🔌 | 🔌 | 🔌 | ✅ | ◐ | 🛠️ | P2 | `rdock-config (secrets)` | High | Secure adapter, no secret interpolation in public labels. |
| [DNS A/AAAA/SRV upstream discovery](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🛠️ | P1 | `rdock-balancer (dns discovery)` | High | Use TTL, resolver errors and stale cache policy. |

### High traffic · Operations

| Capability | NGINX | Traefik | Caddy | HAProxy | Envoy | Pingap | Pingora | Phase | Crate / module | Effort | Build notes |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|---|
| [Multithreaded asynchronous processing](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `rdock-proxy` | Medium | Pingora async Rust and Tokio runtime tuning. |
| [Connection / concurrency safeguards](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P1 | `rdock-limits` | High | Hard per-host/per-worker limits needed for safety. |
| [Resource-aware overload protection](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ◐ | ✅ | ◐ | ✅ | ✅ | ◐ | 🛠️ | P2 | `rdock-balancer / rdock-limits` | Very high | Global budgets, shedding, priority and queue bounds. |
| [Config version rollout / ACK / NACK](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | 🔌 | ◐ | 🔌 | ✅ | — | 🛠️ | P3 | `rdock-control (P3)` | Very high | xDS-style ACK/NACK is reference model, not necessarily adopt xDS. |
| [Control plane independent data plane](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | ◐ | ✅ | ✅ | ◐ | ✅ | ◐ | 🛠️ | P1 | `rdock-config` | High | Use last-good snapshot, survive dashboard outage. |
| [Multi-proxy centrally managed cluster](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | 🔌 | 🔌 | 🔌 | ✅ | — | 🛠️ | P3 | `rdock-control (P3)` | Very high | External orchestrator needed, never required for single binary. |
| [Distributed certificate coordination](https://caddyserver.com/docs/automatic-https) | 🔌 | ◐ | ✅ | 🔌 | 🔌 | ◐ | 🛠️ | P3 | `rdock-acme` | High | Avoid duplicate issuances and reconcile storage. |
| [Dynamic service weights from control plane](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | ✅ | ✅ | ✅ | ✅ | ◐ | 🛠️ | P2 | `rdock-balancer` | High | Make updates atomic, observable and bounded. |
| [Regional routing / locality preferences](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | 🔌 | ◐ | ◐ | ◐ | ✅ | — | 🛠️ | P3 | `rdock-balancer` | High | Cannot infer region without metadata. |
| [Zero-downtime binary upgrade](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P2 | `rdock-proxy` | High | Validate live sockets, long-lived connections and TLS handoffs. |
| [Published reproducible benchmark suite](https://github.com/cloudflare/pingora) | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ | 🛠️ | P1 | `benchmarks/` | Very high | Same TLS, request mix, hardware and memory budget for comparisons. |
| [Sustained fault-injection / fuzz testing](https://github.com/cloudflare/pingora) | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ | 🛠️ | P1 | `tests/` | Very high | HTTP differential fuzz, chaos network and soaking. |
| [Rust memory-safe default codebase](https://github.com/cloudflare/pingora) | — | — | — | — | — | ✅ | ✅ | P0 | `workspace` | Low | Pingora/Pingap primarily Rust, not a guarantee that all TLS and extension code is memory-safe. |
| [Open-source product/core (licenses vary)](https://github.com/cloudflare/pingora) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | P0 | `repo governance` | Medium | Proposed project targets Apache-2.0; competitors use differing licenses. Check obligations before reusing code. |

## Backlog by crate / module

| Crate / module | Total | P0 | P1 | P2 | P3 |
|---|:-:|:-:|:-:|:-:|:-:|
| `apps/dashboard` | 2 | 0 | 1 | 1 | 0 |
| `benchmarks/` | 1 | 0 | 1 | 0 | 0 |
| `deploy/` | 4 | 2 | 2 | 0 | 0 |
| `external agent via rdock-plugins (P3)` | 1 | 0 | 0 | 0 | 1 |
| `out of scope (F-WEB-06)` | 1 | 0 | 0 | 0 | 1 |
| `rdock (binary)` | 2 | 2 | 0 | 0 | 0 |
| `rdock-acme` | 8 | 4 | 2 | 1 | 1 |
| `rdock-admin` | 3 | 0 | 2 | 1 | 0 |
| `rdock-admin (api)` | 3 | 0 | 2 | 1 | 0 |
| `rdock-balancer` | 10 | 0 | 6 | 1 | 3 |
| `rdock-balancer (dns discovery)` | 2 | 0 | 2 | 0 | 0 |
| `rdock-balancer (health)` | 2 | 0 | 2 | 0 | 0 |
| `rdock-balancer (retry)` | 1 | 0 | 1 | 0 | 0 |
| `rdock-balancer / rdock-limits` | 5 | 0 | 3 | 2 | 0 |
| `rdock-cache (P2)` | 8 | 0 | 0 | 8 | 0 |
| `rdock-cloudflare` | 4 | 3 | 0 | 1 | 0 |
| `rdock-config` | 9 | 4 | 5 | 0 | 0 |
| `rdock-config (secrets)` | 2 | 0 | 0 | 2 | 0 |
| `rdock-control (P3)` | 3 | 0 | 0 | 0 | 3 |
| `rdock-limits` | 8 | 4 | 3 | 1 | 0 |
| `rdock-middleware` | 5 | 4 | 1 | 0 | 0 |
| `rdock-middleware (auth)` | 5 | 1 | 2 | 2 | 0 |
| `rdock-middleware (compress)` | 2 | 0 | 1 | 1 | 0 |
| `rdock-middleware (grpc-web)` | 1 | 0 | 1 | 0 | 0 |
| `rdock-middleware (static)` | 3 | 0 | 1 | 1 | 1 |
| `rdock-migrate` | 2 | 0 | 1 | 0 | 1 |
| `rdock-observability` | 10 | 4 | 5 | 1 | 0 |
| `rdock-plugins (P2/P3)` | 3 | 0 | 0 | 2 | 1 |
| `rdock-provider-docker` | 3 | 3 | 0 | 0 | 0 |
| `rdock-provider-kubernetes` | 4 | 0 | 0 | 4 | 0 |
| `rdock-provider-swarm` | 1 | 0 | 1 | 0 | 0 |
| `rdock-proxy` | 16 | 15 | 0 | 1 | 0 |
| `rdock-proxy (http3 feature)` | 2 | 0 | 0 | 1 | 1 |
| `rdock-proxy (l4)` | 6 | 0 | 5 | 1 | 0 |
| `rdock-proxy (security) / rdock-limits` | 5 | 3 | 0 | 1 | 1 |
| `rdock-rules + rdock-proxy (router)` | 9 | 5 | 3 | 1 | 0 |
| `rdock-tls` | 7 | 3 | 4 | 0 | 0 |
| `repo governance` | 1 | 1 | 0 | 0 | 0 |
| `tests/` | 1 | 0 | 1 | 0 | 0 |
| `unscheduled (F-WEB-05)` | 1 | 0 | 0 | 0 | 1 |
| `unscheduled (W-PLAT-06)` | 2 | 0 | 0 | 0 | 2 |
| `unscheduled (W-PLAT-07)` | 1 | 0 | 0 | 0 | 1 |
| `unscheduled (W-PLAT-08)` | 1 | 0 | 0 | 0 | 1 |
| `workspace` | 1 | 1 | 0 | 0 | 0 |

## Workbook sheet "20 Critical Decisions" (as authored, phase-ordered)

| # | Capability | Phase | Crate / module | Build note |
|:-:|---|:-:|---|---|
| 1 | [HTTP/1.1 reverse proxy](https://github.com/cloudflare/pingora) | P0 | `rdock-proxy` | Pingora already offers HTTP reverse proxy APIs. |
| 2 | [HTTP/2 upstream](https://github.com/cloudflare/pingora) | P0 | `rdock-proxy` | Test protocol negotiation and connection reuse. |
| 3 | [TLS termination, SNI, ALPN](https://github.com/cloudflare/pingora) | P0 | `rdock-tls` | TLS backend choice affects build, FIPS and platform support. |
| 4 | [Host / domain routing](https://pingap.io/) | P0 | `rdock-rules + rdock-proxy (router)` | Core route matcher owned by project, not upstream library. |
| 5 | [Path prefix routing](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | P0 | `rdock-rules + rdock-proxy (router)` | Normalize paths defensively to avoid bypasses. |
| 6 | [Graceful reload / connection draining](https://github.com/cloudflare/pingora) | P0 | `rdock-proxy` | Ensure existing HTTP/2 streams and WebSockets survive as intended. |
| 7 | [Trusted forwarding chain / real client IP](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | P0 | `rdock-proxy (security) / rdock-limits` | Critical behind Cloudflare and Docker NAT; reject untrusted forwarded headers. |
| 8 | [Automatic ACME HTTPS](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/ssl-tls/acme/) | P0 | `rdock-acme` | HAProxy 3.2+ native ACME is experimental; NGINX typically external. |
| 9 | [ACME DNS-01 / wildcards](https://pingap.io/) | P0 | `rdock-acme` | Implement provider adapters; Cloudflare first. |
| 10 | [Docker container discovery](https://doc.traefik.io/traefik/providers/docker/) | P0 | `rdock-provider-docker` | Read-only events plus full reconciliation, multi-network selection. |
| 11 | [Traefik Docker-label compatibility](https://doc.traefik.io/traefik/providers/docker/) | P0 | `rdock-provider-docker` | Pingap has Docker discovery/labels, but full Traefik-label semantic compatibility is not documented. |
| 12 | [Request body size limits](https://nginx.org/en/docs/) | P0 | `rdock-limits` | Enforce early, including streaming/chunked bodies. |
| 13 | [Per-IP local rate limiting](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | P0 | `rdock-limits` | Per-instance only; correctly interpret real IP. |
| 14 | [Active HTTP health probes](https://docs.nginx.com/nginx-gateway-fabric/overview/nginx-plus/) | P1 | `rdock-balancer (health)` | NGINX Plus provides extra commercial probes; OSS passive/other checks. |
| 15 | [Safe retries / replay protection](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | P1 | `rdock-balancer (retry)` | Never blindly replay non-idempotent requests. |
| 16 | [Weighted round-robin](https://github.com/cloudflare/pingora) | P1 | `rdock-balancer` | Pingora offers LB primitives; verify exact weighted semantics or implement explicitly. |
| 17 | [Configurable log sampling/redaction](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | P1 | `rdock-observability` | User PII, API keys, cookies must be redacted. |
| 18 | [REST API for live config mutation](https://caddyserver.com/docs/api) | P1 | `rdock-admin (api)` | Envoy uses xDS for most dynamic config; avoid confusing admin API with control API. |
| 19 | [Kubernetes Gateway API controller](https://gateway-api.sigs.k8s.io/) | P2 | `rdock-provider-kubernetes` | Target conformance, especially HTTPRoute core profile. |
| 20 | [HTTP/3 / QUIC frontend](https://nginx.org/en/docs/http/ngx_http_v3_module.html) | P2 | `rdock-proxy (http3 feature)` | NGINX module remains experimental; Pingora doesn't include full HTTP/3 product support. |

## Source library (official references used for the matrix)

| Ref | Document | What it substantiates |
|---|---|---|
| PINGORA | [Pingora official repository](https://github.com/cloudflare/pingora) | Pingora core APIs, protocols, caching maturity |
| PINGAP | [Pingap project website](https://pingap.io/) | Pingap product features and integrations |
| PINGAP_CRATES | [Pingap crate inventory](https://pingap.io/crates/) | Discovery, health checks, ACME, cache, observability |
| PINGAP_PLUGINS | [Pingap plugin inventory](https://pingap.io/plugins/) | Auth, rate limits, static files, plugins |
| NGINX | [NGINX documentation](https://nginx.org/en/docs/) | Official NGINX OSS modules and functionality |
| NGINX_V3 | [NGINX HTTP/3 module](https://nginx.org/en/docs/http/ngx_http_v3_module.html) | Experimental module; build flag required |
| NGINX_PROXY | [NGINX HTTP proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) | Proxy caching and purge license boundary |
| NGINX_PLUS | [NGINX Plus differentiators](https://docs.nginx.com/nginx-gateway-fabric/overview/nginx-plus/) | Plus-only dashboard, active health checks, JWT, dynamic upstream control |
| TRAEFIK | [Traefik provider overview](https://doc.traefik.io/traefik/reference/install-configuration/providers/overview/) | Docker, Swarm, K8s, Consul, Nomad, ECS, etc. |
| TRAEFIK_MW | [Traefik OSS middleware overview](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | OSS auth, routing, rate limits, rewrites, observability |
| TRAEFIK_DOCKER | [Traefik Docker provider](https://doc.traefik.io/traefik/providers/docker/) | Container labels and service discovery |
| TRAEFIK_SWARM | [Traefik Swarm provider](https://doc.traefik.io/traefik/reference/install-configuration/providers/swarm/) | Swarm deploy-level labels |
| TRAEFIK_GATEWAY | [Traefik Gateway API provider](https://doc.traefik.io/traefik/reference/install-configuration/providers/kubernetes/kubernetes-gateway/) | Gateway API feature coverage |
| TRAEFIK_HUB | [Traefik Hub-only JWT](https://doc.traefik.io/traefik/secure/secure-api-access-with-jwt/) | Separates paid Hub JWT from OSS |
| TRAEFIK_DRL | [Traefik Hub-only distributed rate limit](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/distributed-ratelimit/) | Hub-specific global rate limiter |
| CADDY | [Caddy reverse proxy documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) | Routing, health checks, transports, LB |
| CADDY_TLS | [Caddy Automatic HTTPS](https://caddyserver.com/docs/automatic-https) | ACME, local CA, automatic renewals, on-demand TLS |
| CADDY_API | [Caddy API documentation](https://caddyserver.com/docs/api) | Live JSON config API |
| HAPROXY | [HAProxy official site](https://www.haproxy.org/) | HAProxy Community version and features |
| HAPROXY_HC | [HAProxy health checks](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/) | Active & passive checks |
| HAPROXY_CACHE | [HAProxy caching](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/performance/caching/) | Native memory caching limitations |
| HAPROXY_ACME | [HAProxy ACME support](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/ssl-tls/acme/) | Experimental in 3.2+ |
| ENVOY | [Envoy architecture overview](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview) | Data plane, filters, xDS, discovery |
| ENVOY_H3 | [Envoy HTTP/3](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http3) | Downstream and upstream HTTP/3 |
| ENVOY_CACHE | [Envoy HTTP cache filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/cache_filter) | Native filter and backends |
| GATEWAY | [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) | Gateway, Route and conformance |
