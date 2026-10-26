# ReverseDock — Research (verified 2026-10-26)

This document replaces the original research notes (kept verbatim in [`research/`](research/)). Every claim below was checked against the official source on the date above. Items that changed since the original notes are marked **(changed)**.

## 1. Pingora reality check

**Current release: Pingora 0.9.0 (2026-09-04).** Release cadence in 2026: 0.7.0 (Jan 30), 0.8.0 (Mar 2), 0.8.1 (Jun 4), 0.9.0 (Sep 4). License Apache-2.0. MSRV 1.85 (some crates 1.88). Linux is the only tier-1 platform; x86-64 and aarch64 both supported.

| Area | What Pingora 0.9 gives us | What we must build |
|---|---|---|
| HTTP/1.1, HTTP/2, h2c, WebSocket, gRPC, SSE | End-to-end proxying, connection pooling (sharded + global LRU), keep-alive, HTTP/1.1 pipelining, bounded HTTP/2 defaults | Routing, middleware, config, everything product-level |
| HTTP hardening | 0.9 centralised request-target parsing, rejects ambiguous authorities and CR/LF in `:path`, strips hop-by-hop headers to upstream by default, never reuses HTTP/1 connections after incomplete responses | Differential fuzzing against hyper/h2, strict-mode policy, limits |
| TLS | Backends: **OpenSSL (default), BoringSSL (FIPS), rustls (experimental), s2n-tls**. 0.9 adds `Acceptor::from_server_config` (runtime-built rustls `ServerConfig` + in-memory keys), TLS handshake offload thread pool, per-peer CA, pre-TLS callback for PROXY protocol, mTLS client-cert verification (0.8) | Our SNI certificate resolver, cert store, policies, ACME |
| Load balancing | `pingora-load-balancing`: round-robin, random, consistent hashing (ketama), FNV hashing, `Weighted<_>` selection honouring backend weights; TCP/HTTP active health checks; backends shared across selectors (0.9) | Verify weighted semantics; least-connections, P2C, passive health, retries with budget, circuit breaking, outlier detection |
| Graceful upgrade | Zero-downtime binary upgrade via fd transfer; 0.9 adds old↔new process signalling and close-on-exec fixes | Listener-change orchestration (see architecture) |
| Modules | 0.9 **upstream module system** (modules can act after upstream response headers, before upstream compression); built-in compression modules | Our middleware pipeline on top |
| Caching | `pingora-cache` is **alpha, "APIs highly volatile"** (0.9: deferred admission, dictionary compression, purge-but-keep-body, LRU ops). `pingora-memory-cache` with stampede lock is stable | A production HTTP cache is its own track (P2) |
| HTTP/3 / QUIC | **Not available (changed).** PR #514 (quiche h3 server) was **closed unmerged on 2026-09-12**; the client PR #524 was closed too. Maintainers pointed at `tokio-quiche` (open-sourced 2025-11-06) as the future direction | A separate HTTP/3 track on `tokio-quiche`, behind a feature flag, requiring a BoringSSL build |
| L4 | 0.7 `ConnectionFilter` (early TCP filtering) and a "virtual L4 stream" abstraction; `CONNECT` disabled by default since 0.8 | TCP/UDP proxy listeners, SNI passthrough, PROXY protocol in/out |
| Observability | Prometheus moved to optional `pingora-prometheus` crate (0.9); Tokio poll-time histograms; TCP/TLS timing fields on sessions | Access logs, OTel, per-route metrics with bounded cardinality |

**Conclusion unchanged:** Pingora is a framework, not a product. ~80 % of the matrix is "build needed".

## 2. Competitor landscape (OSS editions only)

| Project | Base | Config | Discovery | HTTPS | Dashboard | Notes (verified) |
|---|---|---|---|---|---|---|
| **Traefik 3.7.x** | Go | YAML/TOML/labels/CRDs | Docker, Swarm, K8s Ingress + Gateway API, Consul, Nomad, ECS, KV | ACME HTTP/TLS-ALPN/DNS | Read-only OSS dashboard | JWT + distributed rate-limit are *Hub* (paid); 3.7.x is the current line (patch releases through Oct 2026) |
| **Caddy 2** | Go | Caddyfile / JSON API | Plugins (`caddy-docker-proxy`) | Best-in-class ACME, local CA, on-demand TLS with `ask` | None (API only) | Reference for HTTPS DX and JSON admin API |
| **NGINX OSS** | C | nginx.conf | None | External (certbot) | None (Plus only) | Reference for cache/static/TCP/UDP/mail; HTTP/3 module still experimental |
| **HAProxy CE 3.2+** | C | haproxy.cfg | DNS/SRV | ACME **experimental** since 3.2 | Stats page (read-only) | Reference for stick tables, health checks, queueing |
| **Envoy** | C++ | xDS / YAML | Via control plane | External | Admin page | Reference for outlier detection, retries/budgets, overload manager, HTTP/3 |
| **Pingap** | Rust/Pingora | **TOML/HCL/KDL** (`servers` → `locations` → `upstreams` + `plugins`), etcd | DNS, **own** Docker labels | ACME HTTP-01/DNS-01 | **Editable web UI** in binary, history/restore, API tokens | 30+ plugins, OpenSSL or rustls, JA4. ~1.4k stars. No Traefik labels, no Swarm/K8s, no HTTP/3, no TCP/UDP |
| **Zentinel** | Rust/Pingora **fork of 0.9.0** | KDL | – | mTLS, JWT/OIDC/SAML agents | – | "Agent" architecture (WAF, auth as isolated processes). Patched Pingora for full rustls `ServerConfig` on listeners (now upstream in 0.9) and status-code retries (`should_retry_response`) |
| **River** (ISRG/Prossimo) | Rust/Pingora | KDL | – | – | – | **Stalled: v0.5.0 (2024-08-30), "no expectation of stability"** |
| **Nginx Proxy Manager** | Node + NGINX | UI/SQLite | None | Certbot | Yes (popular) | Shows demand for a visual manager among self-hosters |

**Lessons we adopt**

- From **Traefik**: entrypoints/routers/services/middlewares model and the label grammar — our internal model is a *superset* of it, so label compatibility is a translation, not a reinterpretation.
- From **Caddy**: automatic HTTPS as a default, not a feature; `ask`-style authorization for on-demand TLS; JSON config API with atomic replace; local CA for dev.
- From **HAProxy**: queueing with deadlines, stick-table-style abuse counters, deterministic health-check state machine.
- From **Envoy**: outlier detection, retry budgets, overload manager, ACK/NACK config rollout (reference, not xDS).
- From **Pingap**: embed the UI in the binary; 15-minute in-memory traffic view without Prometheus; config dry-run with diff.
- From **Zentinel**: keep heavy security engines (WAF) out-of-process; status-code-aware retries.

## 3. Ecosystem facts that shape the design

### Certificates (changed since the original notes)
- **Let's Encrypt OCSP ended 2025-08-06.** Revocation is CRL-only. `OCSP Must-Staple` requests fail. → We never request Must-Staple; OCSP stapling is optional and only when the CA publishes an OCSP URL.
- **Lifetimes shrink** ([Let's Encrypt, 2025-12-02](https://letsencrypt.org/2025/12/02/from-90-to-45)): default stays 90 days today, drops to **64 days in February 2027** and **45 days in February 2028**; the CA/B Forum cap is 47 days by 2029-03-15.
- **Profiles:** `classic` (90 d, default), `tlsserver` (45 d, no CN/SKI, max 25 names, 7-hour authz reuse), `shortlived` (~6 d, **the only profile allowing IP-address identifiers**), `tlsclient` retired 2026-07-08.
- **ARI (RFC 9773)** tells clients when to renew; Let's Encrypt recommends ARI first, otherwise renewing at ⅔ of lifetime. → Renewal scheduling must be ARI-driven and cheap enough to run hourly.
- Rust client: **`instant-acme` 0.8.x (0.8.5, 2026)** supports ARI, profiles, EAB, device-attest-01; pure Rust, tokio, rustls.

### Kubernetes
- **Gateway API v1.6.0 (2026-06-30):** `TCPRoute` and `UDPRoute` graduated to Standard/v1 (joining HTTPRoute, GRPCRoute, TLSRoute); `ListenerSet` is on its way to Standard (v1.7 is at release-candidate stage, Oct 2026). Experimental resources live in `gateway.networking.x-k8s.io` with an `X` prefix. Rust bindings: `gateway-api` 0.22 (2026-10-21) on `kube` 4.2. Conformance profiles are named `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS`; TCP/UDP tests left provisional status in v1.6.3.

### Docker / Swarm
- Docker Engine 29.x; Engine API `GET /containers/json`, `/events`, `/networks` is all the Docker provider needs (read-only). Podman exposes a compatible socket. Traefik's own docs warn that mounting the Docker socket is a host-security risk → we document socket-proxy setups and need only read scopes.
- Swarm service labels live under `deploy.labels` and are read from `GET /services`, `/tasks`.

### HTTP/3
- `tokio-quiche` (Cloudflare, 2025-11) is "not a standalone HTTP/3 server" but the supported async driver; it requires BoringSSL. A rustls build cannot host QUIC via quiche; a rustls + `quic-boringssl` combination is possible (per PR #514 notes), an OpenSSL + BoringSSL combination is not (duplicate symbols).

## 4. Rust building blocks (candidate crates, verified versions)

| Need | Crate | Why |
|---|---|---|
| Proxy core | `pingora` 0.9 (`pingora-core`, `pingora-proxy`, `pingora-http`, `pingora-load-balancing`, `pingora-timeout`, `pingora-prometheus`) | The foundation |
| TLS | `rustls` 0.23 + `aws-lc-rs` (FIPS-capable) via Pingora's `rustls` feature; `rcgen` for local CA / self-signed | No OpenSSL/Perl; `aws-lc-rs` still needs a C compiler + CMake (Go for FIPS), `ring` provider for pure-Rust builds; dynamic `ServerConfig` |
| ACME | `instant-acme` 0.8 | ARI, profiles, EAB |
| Docker | `bollard` | Async Docker Engine API, events stream |
| Kubernetes | `kube` 4.x, `gateway-api` 0.22, `k8s-openapi` | Controller-runtime style watches |
| Admin API | `axum` + `utoipa` (OpenAPI) + `tower-http` | Separate listener, typed, documented |
| Config | `serde`, `serde-saphyr` (YAML, pure Rust, [ADR-0011](decisions/0011-yaml-parser-and-msrv.md)) / `serde_json`, `schemars` 1.x (JSON Schema 2020-12), `jsonschema` (tests), `serde_path_to_error` | Canonical schema, IDE autocomplete, precise error paths |
| Rule grammar | hand-written `nom`/`winnow` parser for the Traefik v3 rule language | Deterministic, no regex backtracking for the grammar itself |
| Regex | `regex` (linear-time; no catastrophic backtracking) | Safe `PathRegexp`/`HostRegexp` |
| Runtime state swap | `arc-swap` | Lock-free config snapshots |
| Rate limiting | own token-bucket on `dashmap` with bounded cardinality (+ `governor` reference) | Memory-bounded |
| Compression | Pingora modules (`gzip`, `brotli`, `zstd` features) | Already integrated |
| Logging/metrics/tracing | `tracing`, `tracing-subscriber` (JSON), `prometheus`/`pingora-prometheus`, `opentelemetry-otlp` | Standard stack |
| WASM plugins (later) | `wasmtime` component model | Sandbox + fuel |
| Dashboard | Vite, React 19, TypeScript, Tailwind v4, shadcn/ui, TanStack Query/Table, CodeMirror 6, uPlot; embedded via `rust-embed` | One binary |
| Release | `cargo-dist`, `cargo-deny`, `cargo-audit`, `syft` (SBOM), `cosign` | Supply-chain hygiene |

## 5. Risks and how we handle them

| Risk | Mitigation |
|---|---|
| Pingora API churn (0.x, breaking changes every release) | Thin adapter layer in `rdock-proxy`; pin minor version; upgrade in one PR per release with the e2e suite |
| rustls is "experimental" in Pingora | It is the backend Zentinel and Pingap ship; we add our own TLS test matrix; OpenSSL stays a build-time fallback feature |
| HTTP/3 needs BoringSSL while the rest uses rustls | Separate feature flag and build variant; never on the critical path of v0.x |
| Cache crate instability | Cache track starts P2 against a pinned Pingora version with our own storage abstraction |
| Traefik label semantics are large | Explicit supported subset + conformance suite; unsupported labels produce warnings, never silent ignores |
| Certificate rate limits / shorter lifetimes | ARI, per-CA rate-limit awareness, staging mode, persistent account/order state, alerting |
| Docker socket exposure | Read-only scopes, documented socket-proxy, no exec/create calls ever |
| Scope creep | Roadmap milestones each have acceptance criteria; P3 items stay out of the core binary unless feature-gated |

## 6. Sources

Pingora: [repo](https://github.com/cloudflare/pingora) · [releases](https://github.com/cloudflare/pingora/releases) · [CHANGELOG](https://github.com/cloudflare/pingora/blob/main/CHANGELOG.md) · [PR #514 (h3 server, closed)](https://github.com/cloudflare/pingora/pull/514) · [PR #524 (h3 client, closed)](https://github.com/cloudflare/pingora/pull/524) · [tokio-quiche announcement](https://www.phoronix.com/news/Cloudflare-OSS-Tokio-Quiche)
Competitors: [Pingap](https://github.com/vicanso/pingap) · [pingap.io](https://pingap.io/) · [Zentinel](https://zentinelproxy.io/) · [Zentinel on Pingora](https://docs.zentinelproxy.io/concepts/pingora/) · [River](https://github.com/memorysafety/river) · [River initiative](https://www.memorysafety.org/initiative/reverse-proxy) · [Traefik docs](https://doc.traefik.io/traefik/) · [Traefik Docker provider](https://doc.traefik.io/traefik/providers/docker/) · [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https) · [Caddy API](https://caddyserver.com/docs/api) · [HAProxy ACME](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/ssl-tls/acme/) · [NGINX HTTP/3 module](https://nginx.org/en/docs/http/ngx_http_v3_module.html) · [Envoy architecture](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/arch_overview)
Certificates: [LE certificate lifetimes](https://letsencrypt.org/docs/cert-lifetimes/) · [LE profiles](https://letsencrypt.org/docs/profiles/) · [LE OCSP end of life](https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life.html) · [instant-acme](https://docs.rs/instant-acme/latest/instant_acme/)
Kubernetes: [Gateway API](https://gateway-api.sigs.k8s.io/) · [Gateway API v1.6 release](https://kubernetes.io/blog/2026/08/03/gateway-api-v1-6-release/) · [gateway-api crate](https://docs.rs/crate/gateway-api/)
Design reference: [Cloudflare site tokens (third-party analysis)](https://www.shadcn.io/design/cloudflare)
