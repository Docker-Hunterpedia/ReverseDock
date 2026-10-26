# ReverseDock — Requirements

Checklists grouped the way the idea was framed: **Basics → Medium traffic → High traffic → Features → Works with**. Each item has an ID (used by the [roadmap](07-roadmap.md)) and a phase that matches the [feature matrix](03-feature-matrix.md): **P0** = v0.1–v0.3, **P1** = v0.4–v0.6, **P2** = v0.7–v0.8, **P3** = v0.9+.

A ticked box means the requirement is delivered in full on `main` (or in the release being prepared); partly delivered items stay open.

Corrections versus the original notes are marked **(fixed)**. Where this file and the generated matrix disagree on a phase, **this file wins**; the deltas are listed in [03 § Phase overrides](03-feature-matrix.md#phase-overrides).

---

## B — Basics (P0): a proxy that replaces NGINX/Traefik for a self-hosted stack

### B-NET · Networking and proxying
- [x] B-NET-01 HTTP/1.1 and HTTP/2 listeners (TLS and cleartext), h2c upstreams
- [x] B-NET-02 Reverse proxy to HTTP and HTTPS upstreams, with certificate + hostname verification on by default
- [x] B-NET-03 Unix-domain-socket upstreams; IPv4/IPv6 dual stack
- [x] B-NET-04 Routing by host (exact, wildcard), path (exact, prefix, regex), method, headers, query, client IP; Traefik v3 rule grammar
- [x] B-NET-05 Request/response header set/add/remove; hop-by-hop headers stripped
- [x] B-NET-06 Rewrites and redirects (301/302/307/308, scheme, regex), query preservation
- [x] B-NET-07 WebSocket, SSE/chunked streaming, gRPC (incl. streaming) without buffering
- [x] B-NET-08 Forwarded headers: `Forwarded`, `X-Forwarded-For/Proto/Host/Port`, `X-Real-IP`; **trusted-proxy list required before any are honoured**
- [x] B-NET-09 Timeouts: connect, read, write, idle, request-header; per route and per service
- [x] B-NET-10 Graceful reload (SIGHUP/CLI/API/file-watch) without dropping requests; graceful shutdown with drain timeout
- [x] B-NET-11 Custom error pages (403/404/429/502/503/504) and maintenance mode
- [x] B-NET-12 HTTP→HTTPS redirect on by default for TLS hosts
- [ ] B-NET-13 Streaming uploads/downloads with bounded memory (backpressure tests)

### B-TLS · HTTPS and certificates
- [ ] B-TLS-01 TLS termination with SNI and ALPN; TLS 1.2 + 1.3 with named policies (`modern`, `intermediate`, `custom`)
- [ ] B-TLS-02 Automatic HTTPS on by default for routable public hosts (opt-out per route)
- [ ] B-TLS-03 ACME: Let's Encrypt + any RFC 8555 CA (ZeroSSL, Buypass, Google, internal step-ca) incl. External Account Binding
- [ ] B-TLS-04 HTTP-01 and TLS-ALPN-01 challenges built in; DNS-01 via provider adapters (Cloudflare first)
- [ ] B-TLS-05 **(fixed)** ARI-driven renewal (RFC 9773), fallback at ⅔ lifetime; works with 90/64/45/6-day certificates
- [ ] B-TLS-06 **(fixed)** Certificate profiles (`classic`, `tlsserver`, `shortlived`), IP-address certificates via `shortlived`
- [ ] B-TLS-07 **(fixed)** No OCSP Must-Staple; OCSP stapling only when the CA publishes an OCSP URL
- [ ] B-TLS-08 CA rate-limit awareness, exponential backoff, staging mode, persistent account/order state
- [x] B-TLS-09 Manual certificates (PEM, encrypted keys, atomic replacement, file-watch reload)
- [x] B-TLS-10 Multiple certificates per listener (SNI); default certificate; wildcard match rules
- [x] B-TLS-11 HSTS opt-in (never forced preload)
- [ ] B-TLS-12 Expiry / renewal-failure alerts (log, metric, dashboard, webhook)
- [ ] B-TLS-13 Local development CA (`rdock trust`) and self-signed fallback for `.localhost`/private hosts

### B-CFG · Configuration and developer experience
- [x] B-CFG-01 One static binary (musl), Linux x86-64 + ARM64; macOS for development
- [x] B-CFG-02 YAML config with JSON equivalence; published JSON Schema (IDE autocomplete, `$schema` line)
- [x] B-CFG-03 Environment interpolation `${VAR}` and file secrets `${file:/run/secrets/x}`; never interpolate in labels
- [ ] B-CFG-04 CLI: `run`, `validate`, `reload`, `status`, `config show|diff`, `cert list|renew`, `migrate traefik|nginx`, `version`, `trust`
- [x] B-CFG-05 Actionable errors (path, line, hint); `--strict` to reject unknown keys
- [ ] B-CFG-06 Atomic apply with validation; automatic rollback to last-known-good on bind/cert/backend failure
- [x] B-CFG-07 Config auto-reload on file change (debounced), with diff in logs
- [x] B-CFG-08 Logs to stdout/stderr, JSON by default in containers
- [x] B-CFG-09 `/healthz` (liveness), `/readyz` (readiness: config applied, listeners bound)
- [x] B-CFG-10 Official multi-arch Docker image (non-root, read-only FS), Compose examples, systemd unit (`AmbientCapabilities=CAP_NET_BIND_SERVICE`; socket activation is not supported — Pingora adopts fds only through its own upgrade protocol)
- [ ] B-CFG-11 Zero-config mode: with no file, `rdock run` uses Docker provider + defaults

### B-SEC · Baseline security
- [x] B-SEC-01 Basic auth (argon2id/bcrypt hashes; never plaintext)
- [x] B-SEC-02 IP allow/deny lists (CIDR, IPv6), per route
- [x] B-SEC-03 Per-IP rate limiting (token bucket, bounded memory)
- [x] B-SEC-04 Header, URI and body size limits enforced early, also for chunked bodies
- [x] B-SEC-05 Security response headers middleware (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [x] B-SEC-06 Request-ID generation/propagation
- [x] B-SEC-07 Admin API bound to localhost by default, token-authenticated, never auto-exposed on proxy listeners
- [x] B-SEC-08 Request-smuggling hardening (strict CL/TE, HTTP/2 pseudo-header validation) + differential fuzz tests
- [x] B-SEC-09 Runs as non-root with `CAP_NET_BIND_SERVICE` (image and systemd unit set it); a privileged user is never required
- [ ] B-SEC-10 Containers opt-in by default (`rdock.enable=true` or `expose_by_default`)
- [x] B-SEC-11 CORS middleware (origins, methods, headers, credentials, preflight short-circuit)
- [x] B-SEC-12 Forward-auth middleware (Authelia/Authentik style: subrequest with timeout, copied headers, fail-closed)

### B-OBS · Baseline observability
- [x] B-OBS-01 JSON access logs (request id, client ip, route, service, upstream, status, bytes, timings, tls, cf-ray)
- [x] B-OBS-02 Prometheus `/metrics` (requests, status classes, latency histograms, upstream health, TLS, certs)
- [x] B-OBS-03 Redaction of secrets/headers in logs by default

### B-DKR · Docker (P0, see W-DKR for the full list)
- [ ] B-DKR-01 Docker provider with `rdock.*` labels and Traefik-label subset (details in W-DKR)

---

## M — Medium traffic (P1): production workloads

### M-LB · Load balancing and health
- [ ] M-LB-01 Round-robin, weighted round-robin, random, power-of-two-choices, least-connections, least-requests
- [ ] M-LB-02 Consistent hashing (ketama) and IP-hash; header/cookie hashing
- [ ] M-LB-03 Sticky sessions (signed cookie, key rotation, fallback when backend gone)
- [ ] M-LB-04 Active health checks: HTTP(S) (status/body match), TCP, gRPC health protocol; configurable interval/timeout/thresholds
- [ ] M-LB-05 Passive health: error/timeout counting, ejection, slow recovery (slow-start)
- [ ] M-LB-06 Retries only for safe/idempotent or replayable requests; per-route retry budget; `Retry-After` awareness
- [ ] M-LB-07 Circuit breaker per backend/service with explicit states and half-open probes
- [ ] M-LB-08 Connection limits per upstream; connection-pool sizing and idle eviction
- [ ] M-LB-09 Backup/failover pools; fail-open vs fail-closed policy
- [ ] M-LB-10 DNS (A/AAAA/SRV) upstream discovery honouring TTL

### M-TLS · TLS and identity in production
- [ ] M-TLS-01 Client mTLS: CA-pinned verification per listener/route (`optional`/`required`), identity exposed as headers; upstream mTLS with distinct trust roots
- [ ] M-SEC-01 JWT validation middleware (JWKS with caching and rotation, issuer/audience/expiry checks, claims → headers, per route)

### M-RT · Production routing
- [ ] ~~M-RT-01~~ merged into B-NET-04 (regex/header/query routing is needed for Traefik-label compatibility in v0.2)
- [ ] M-RT-02 Deterministic priorities (explicit > rule length), shadowed-route diagnostics
- [ ] M-RT-03 Weighted traffic split, canary, blue/green atomic cutover with draining
- [ ] M-RT-04 Request mirroring (sanitised, percentage-based)
- [ ] M-RT-05 Per-route middleware chains with explicit order
- [ ] M-RT-06 Multi-tenant host routing; API version routing (path/header)
- [ ] M-RT-07 gRPC-Web ↔ gRPC translation for browser clients

### M-TM · Traffic management
- [ ] M-TM-01 Rate limits keyed by IP, header, cookie, JWT claim, route; burst + sustained
- [ ] M-TM-02 Concurrency limits with queue and queue deadline
- [ ] M-TM-03 Load shedding / overload protection (CPU, inflight, memory watermarks)
- [ ] M-TM-04 Bandwidth limits per route/client
- [ ] M-TM-05 Buffering controls (request/response, upload streaming)
- [ ] M-TM-06 Compression: gzip, brotli, zstd (negotiated, min size, content types)
- [ ] M-TM-07 Per-route timeouts and body limits override

### M-OBS · Observability and administration
- [ ] M-OBS-01 OpenTelemetry traces (OTLP), W3C `traceparent`, sampling
- [ ] M-OBS-02 Per-route/service metrics with bounded labels; p50/p95/p99
- [ ] M-OBS-03 Log sampling, structured export (Loki/OpenSearch via stdout or OTLP logs)
- [ ] M-OBS-04 Alert rules (cert expiry, backend down, error-rate) → webhook, email (SMTP), Slack/Discord-compatible webhooks
- [ ] M-OBS-05 Grafana dashboard JSON shipped in repo

### M-ADM · Management
- [ ] M-ADM-01 Versioned REST API (`/api/v1`) with OpenAPI, scoped tokens, audit log
- [ ] M-ADM-02 Config history, diff, rollback; dry-run validation endpoint
- [ ] M-ADM-03 Embedded dashboard (see F-UI)
- [ ] M-ADM-04 Import/export full config; GitOps reconciliation mode (file provider wins)

### M-L4 · Layer 4
- [ ] M-L4-01 TCP proxy listeners with `HostSNI` routing (SNI passthrough, no termination)
- [ ] M-L4-02 TLS termination for TCP routes (databases, MQTT, SMTP-with-TLS)
- [ ] M-L4-03 PROXY protocol v1/v2 inbound (trusted sources only) and outbound
- [ ] M-L4-04 UDP relay with session idle timeouts (P2)
- [ ] M-L4-05 TCP health checks shared with HTTP checker framework

### M-SWM · Docker Swarm
Tracked as W-SWM-01…03 below.

---

## H — High traffic (P2–P3): platform and edge

### H-PERF · Performance
- [ ] H-PERF-01 Tunable Tokio runtime (threads per listener, pinning), `SO_REUSEPORT`, socket buffers
- [ ] H-PERF-02 TLS handshake offload pool, session resumption/tickets with key rotation
- [ ] H-PERF-03 HTTP/2 stream/window tuning; bounded queues and backpressure end-to-end
- [ ] H-PERF-04 Zero-downtime binary upgrade **and** listener-set changes: supervisor/worker model on Pingora's fd transfer, admin socket handed over, verified with long-lived connections (until then listener changes need a restart — ADR-0008)
- [ ] H-PERF-05 **HTTP/3 track** (ingress first) on `tokio-quiche`, feature-gated, BoringSSL build variant
- [ ] H-PERF-06 NUMA/worker/buffer sizing guidance; allocator choice (`mimalloc`/`jemalloc`) benchmarked
- [ ] H-PERF-07 eBPF/kernel-assisted experiments only with benchmark evidence

### H-HA · Distributed high availability (P3)
- [ ] H-HA-01 Multiple independent data planes; optional central control plane (`rdock-control`)
- [ ] H-HA-02 Config rollout with ACK/NACK, versioning, rollback; data planes survive control-plane outage from last-known-good
- [ ] H-HA-03 Shared certificate storage/coordination (no duplicate issuance; lock per name)
- [ ] H-HA-04 Distributed rate limiting (Redis-compatible or built-in gossip counters)
- [ ] H-HA-05 Locality/zone-aware routing, regional preferences, progressive draining

### H-LB · Advanced balancing (P3)
- [ ] H-LB-01 Peak-EWMA latency-aware selection; adaptive weights from observed health
- [ ] H-LB-02 Outlier detection with ejection and slow-start
- [ ] H-LB-03 Priority tiers / disaster-recovery pools; hedged requests under strict safety rules
- [ ] H-LB-04 Per-tenant quotas, admission control

### H-SEC · Security at scale
- [ ] H-SEC-01 Abuse counters (stick-table-like) per client/route with TTL
- [ ] H-SEC-02 Optional WAF (OWASP CRS-compatible engine) out-of-process or WASM
- [ ] H-SEC-03 Bot heuristics, JA3/JA4 fingerprint exposure (log/metric/route key)
- [ ] H-SEC-04 GeoIP rules (MaxMind-format DB, freshness check)
- [ ] H-SEC-05 Identity policies on top of mTLS (M-TLS-01): per-route subject/SAN rules, SPIFFE/SPIRE workload identity (P3)
- [ ] H-SEC-06 OAuth2/OIDC policies, external authorization (ext-authz style), Cloudflare Access JWT
- [ ] H-SEC-07 Tenant isolation for config, API scopes and metrics

### H-ENG · Reliability and performance engineering (P1 onward, continuous)
- [ ] H-ENG-01 Benchmarks: sustained/burst, connection churn, long-lived WS/SSE, TLS handshakes, tail latency; same hardware vs NGINX/Traefik/Caddy/HAProxy; published scripts + results
- [ ] H-ENG-02 Soak tests (24h+), fault injection (toxiproxy), backend failure/recovery, reload under load
- [ ] H-ENG-03 Memory-leak and resource-exhaustion tests; HTTP parsing fuzzing (differential)
- [ ] H-ENG-04 Rule: control plane and dashboard are never on the request path

---

## F — Features and differentiators

### F-UI · Dashboard (P1) — see [design system](08-design-system.md)
- [ ] F-UI-01 Embedded, responsive, light/dark, **RTL-ready (Arabic)**, keyboard-navigable, no external calls
- [ ] F-UI-02 Overview: traffic, error rate, p95, backend health, certificate status, provider status
- [ ] F-UI-03 CRUD for routes/services/middlewares/certificates owned by the API provider; read-only view of file/Docker/K8s-owned objects with "where it comes from"
- [ ] F-UI-04 Live request log (SSE) with filters; live traffic charts without Prometheus (15-minute ring buffer)
- [ ] F-UI-05 Config editor (YAML, schema-validated), preview diff, apply, history, rollback
- [ ] F-UI-06 Users, roles (viewer/operator/admin), API tokens, audit log
- [ ] F-UI-07 Multi-instance view (P3, with control plane)

### F-EXT · Extensibility (P2–P3)
- [ ] F-EXT-01 Middleware pipeline with phases (`request`, `upstream_request`, `response`, `response_body`, `log`) and explicit ordering
- [ ] F-EXT-02 Native Rust plugin trait (compile-time) with stability policy from v1.0
- [ ] F-EXT-03 WASM plugins (component model, sandbox, fuel, capability allow-list) — experimental
- [ ] F-EXT-04 Out-of-process "agents" over gRPC/HTTP for heavy engines (WAF, custom auth), with timeouts and fail policy
- [ ] F-EXT-05 Plugin SDK, examples, signature verification for distributed plugins

### F-GW · API gateway features (P2)
- [ ] F-GW-01 API-key validation (hashed keys, external store) and OIDC login/policies (plain JWT validation is M-SEC-01)
- [ ] F-GW-02 Per-consumer rate limits and quotas
- [ ] F-GW-03 Request validation against OpenAPI/JSON Schema
- [ ] F-GW-04 Consistent JSON error envelope; request/response transformation
- [ ] F-GW-05 Usage metering events export (OTLP/webhook) — no billing in core

### F-WEB · Web server and legacy compatibility
- [ ] F-WEB-01 Static files: MIME, ranges, conditional requests, cache headers, SPA fallback, precompressed assets (P1)
- [ ] F-WEB-02 Directory listing (off by default, hardened path resolution) (P3)
- [ ] F-WEB-03 HTTP cache: memory + disk, RFC 9111, `Vary`, SWR/SIE, purge API (URL/tag), coalescing (P2)
- [ ] F-WEB-04 FastCGI (PHP) gateway (P3, optional crate)
- [ ] F-WEB-05 Explicit forward-proxy/CONNECT mode, isolated config, off by default (P3)
- [ ] F-WEB-06 Mail proxy — out of scope for core (separate project if ever)

### F-MGMT · Management and automation
- [ ] F-MGMT-01 CLI/API parity; OpenAPI published; typed clients generated (TS, Go)
- [ ] F-MGMT-02 Terraform/OpenTofu provider (P2)
- [ ] F-MGMT-03 Migration assistants: `rdock migrate traefik` (labels + dynamic YAML, P0), `rdock migrate nginx` (directive subset, P3)
- [ ] F-MGMT-04 Webhooks for config/cert/health events
- [ ] F-MGMT-05 Docs site with interactive config playground (schema-driven)

### F-OSS · Open-source quality
- [x] F-OSS-01 Apache-2.0, DCO, public roadmap, issue/PR templates, CODE_OF_CONDUCT, SECURITY.md with private reporting
- [x] F-OSS-02 `cargo-deny`/`cargo-audit`, SAST (Semgrep), dependency review in CI
- [x] F-OSS-03 Signed releases (cosign), SBOM (SPDX), checksums, reproducible builds where possible
- [x] F-OSS-04 Non-root, distroless/static images; read-only root FS; no mandatory account, telemetry or activation
- [ ] F-OSS-05 Support policy: last two minor versions receive security fixes

---

## W — Works with

### W-CF · Cloudflare (P0/P1)
- [ ] W-CF-01 Auto-sync Cloudflare IP ranges (`api.cloudflare.com/client/v4/ips`, daily, cached) → `trusted_proxies: [cloudflare]`
- [ ] W-CF-02 `CF-Connecting-IP` honoured only from verified Cloudflare hops; `CF-Ray` logged
- [ ] W-CF-03 DNS-01 via scoped API token (Zone:DNS:Edit) for wildcards
- [ ] W-CF-04 Origin CA certificates and Full (strict) guidance
- [ ] W-CF-08 Authenticated Origin Pulls: client-certificate verification against Cloudflare's origin-pull CA (needs M-TLS-01)
- [ ] W-CF-05 Cloudflare Tunnel: documented deployment with `cloudflared` sidecar, no inbound ports
- [ ] W-CF-06 Cloudflare Access JWT validation middleware (P2)
- [ ] W-CF-07 Compatible with Cloudflare Load Balancer origin pools (health endpoints, PROXY-less)

### W-DKR · Docker and Compose (P0, highest priority)
- [ ] W-DKR-01 Engine API discovery (events + periodic full reconcile), read-only scopes, socket-proxy documented, Podman socket compatible
- [ ] W-DKR-02 Native labels (`rdock.host`, `rdock.port`, `rdock.path`, `rdock.tls`, `rdock.middlewares`, full `rdock.routes.*` form)
- [ ] W-DKR-03 Traefik v3 label subset with conformance tests; unsupported labels → warnings in logs and dashboard
- [ ] W-DKR-04 Network-aware IP selection (`rdock.network`/`traefik.docker.network`, default shared network), multiple networks
- [ ] W-DKR-05 Port detection: label > single exposed port > error with hint
- [ ] W-DKR-06 Container health-aware routing (Docker HEALTHCHECK), draining on stop
- [ ] W-DKR-07 Docker secrets (`${file:/run/secrets/..}`), rootless Docker where networking permits
- [ ] W-DKR-08 Dokploy / Coolify / Portainer compatibility examples (labels + networks)

### W-SWM · Docker Swarm (P1)
- [ ] W-SWM-01 Separate provider: services + `deploy.labels`; task vs VIP endpoint modes
- [ ] W-SWM-02 Overlay networks; replica scale events; task health/readiness; rolling-update draining
- [ ] W-SWM-03 Swarm secrets/configs; multi-node replicated proxies (global mode)

### W-K8S · Kubernetes (P2)
- [ ] W-K8S-01 Gateway API controller targeting the latest Standard channel (v1.6+; v1.7 at rc as of Oct 2026): GatewayClass, Gateway, HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, UDPRoute, ReferenceGrant, ListenerSet once Standard; upstream conformance profiles `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS` in CI
- [ ] W-K8S-02 Ingress controller (networking.k8s.io/v1) for migration
- [ ] W-K8S-03 EndpointSlice watches, Secrets for TLS, cert-manager compatibility
- [ ] W-K8S-04 Leader election, RBAC, namespace scoping, readiness probes
- [ ] W-K8S-05 Helm chart, Kustomize, raw manifests; k3s/RKE2/kind tested

### W-PLAT · Other platforms

| ID | Platform | Integration | Phase |
|---|---|---|---|
| W-PLAT-01 | Bare-metal / VM (systemd) | static binary, unit file with `CAP_NET_BIND_SERVICE` | P0 |
| W-PLAT-02 | Dokploy, Coolify, Portainer | Docker labels + networks examples | P0/P1 |
| W-PLAT-03 | Proxmox / home lab | Docker or native | P0 |
| W-PLAT-04 | Cloudflare Tunnel | `cloudflared` sidecar example | P1 |
| W-PLAT-05 | AWS EC2 / GCP / Azure VMs | binary or container | P1 |
| W-PLAT-06 | HashiCorp Nomad / Consul catalog | providers | P3 |
| W-PLAT-07 | etcd / Consul KV | config provider | P3 |
| W-PLAT-08 | Amazon ECS | provider | P3 |

### W-DNS · DNS providers for DNS-01
- [ ] W-DNS-01 `DnsProvider` trait, propagation check with retries, Cloudflare adapter (P0)
- [ ] W-DNS-02 Exec/webhook provider for anything else (P1)
- [ ] W-DNS-03 Route 53, Google Cloud DNS, Azure DNS, DigitalOcean, Hetzner, deSEC, RFC 2136 adapters (P1–P2)

### W-OBS · Monitoring, config and secrets
- [ ] W-OBS-01 Prometheus, Grafana, OTLP (Tempo/Jaeger), Loki/OpenSearch via stdout or OTLP, syslog (P0–P1)
- [ ] W-OBS-02 Secrets: env, files, Docker/Swarm/K8s secrets (P0); Vault/External Secrets (P2)
- [x] W-OBS-03 GitOps: file provider + `rdock validate` in CI (P0); Terraform (P2)
