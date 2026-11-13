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
- [x] B-TLS-13 Local development CA (`rdock trust`) and self-signed fallback for `.localhost`/private hosts

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
- [x] M-LB-01 Round-robin, weighted round-robin, random, power-of-two-choices, least-connections, least-requests
- [x] M-LB-02 Consistent hashing (ketama) and IP-hash; header/cookie hashing
- [x] M-LB-03 Sticky sessions (signed cookie, key rotation, fallback when backend gone)
- [x] M-LB-04 Active health checks: HTTP(S) (status/body match), TCP, gRPC health protocol; configurable interval/timeout/thresholds
- [x] M-LB-05 Passive health: error/timeout counting, ejection, slow recovery (slow-start)
- [x] M-LB-06 Retries only for safe/idempotent or replayable requests; per-route retry budget; `Retry-After` awareness
- [x] M-LB-07 Circuit breaker per backend/service with explicit states and half-open probes
- [x] M-LB-08 Connection limits per upstream; connection-pool sizing and idle eviction
- [x] M-LB-09 Backup/failover pools; fail-open vs fail-closed policy
- [x] M-LB-10 DNS (A/AAAA/SRV) upstream discovery honouring TTL

### M-TLS · TLS and identity in production
- [x] M-TLS-01 Client mTLS: CA-pinned verification per listener/route (`optional`/`required`), identity exposed as headers; upstream mTLS with distinct trust roots
- [x] M-SEC-01 JWT validation middleware (JWKS with caching and rotation, issuer/audience/expiry checks, claims → headers, per route)

### M-RT · Production routing
- [ ] ~~M-RT-01~~ merged into B-NET-04 (regex/header/query routing is needed for Traefik-label compatibility in v0.2)
- [x] M-RT-02 Deterministic priorities (explicit > rule length), shadowed-route diagnostics
- [x] M-RT-03 Weighted traffic split, canary, blue/green atomic cutover with draining
- [x] M-RT-04 Request mirroring (sanitised, percentage-based)
- [x] M-RT-05 Per-route middleware chains with explicit order
- [x] M-RT-06 Multi-tenant host routing; API version routing (path/header)
- [x] M-RT-07 gRPC-Web ↔ gRPC translation for browser clients

### M-TM · Traffic management
- [x] M-TM-01 Rate limits keyed by IP, header, cookie, JWT claim, route; burst + sustained
- [x] M-TM-02 Concurrency limits with queue and queue deadline
- [x] M-TM-03 Load shedding / overload protection (CPU, inflight, memory watermarks)
- [x] M-TM-04 Bandwidth limits per route/client
- [ ] M-TM-05 Buffering controls (request/response, upload streaming). *Open (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)):* the `hold_body` middleware holds a request body until it is complete (memory up to 64 KiB, then a spool file; `413`/`408` on a limit) but is not full pre-buffering: the request head and backend connection exist while the body is held, so slow uploads still occupy a backend worker, and the head reaches the backend before an agent or `validate` verdict on the body (Pingora 0.9.1 limitation; it needs an upstream early-body hook). The box stays unticked.
- [x] M-TM-06 Compression: gzip, brotli, zstd (negotiated, min size, content types)
- [x] M-TM-07 Per-route timeouts and body limits override

### M-OBS · Observability and administration
- [x] M-OBS-01 OpenTelemetry traces (OTLP), W3C `traceparent`, sampling
- [x] M-OBS-02 Per-route/service metrics with bounded labels; p50/p95/p99
- [x] M-OBS-03 Log sampling, structured export (Loki/OpenSearch via stdout or OTLP logs)
- [x] M-OBS-04 Alert rules (cert expiry, backend down, error-rate) → webhook, email (SMTP), Slack/Discord-compatible webhooks
- [x] M-OBS-05 Grafana dashboard JSON shipped in repo

### M-ADM · Management
- [x] M-ADM-01 Versioned REST API (`/api/v1`) with OpenAPI, scoped tokens, audit log
- [ ] M-ADM-02 Config history, diff, rollback; dry-run validation endpoint
- [ ] M-ADM-03 Embedded dashboard (see F-UI)
- [ ] M-ADM-04 Import/export full config; GitOps reconciliation mode (file provider wins)

### M-L4 · Layer 4
- [x] M-L4-01 TCP proxy listeners with `HostSNI` routing (SNI passthrough, no termination)
- [x] M-L4-02 TLS termination for TCP routes (databases, MQTT, SMTP-with-TLS)
- [x] M-L4-03 PROXY protocol v1/v2 inbound (trusted sources only) and outbound
- [x] M-L4-04 UDP relay with session idle timeouts (P2). *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `udp` listeners, `udp_routes`, `udp_services`, per-client sessions with idle timeouts, `responses`/`requests`, session caps on by default, passive and TCP health.
- [x] M-L4-05 TCP health checks shared with HTTP checker framework

### M-SWM · Docker Swarm
Tracked as W-SWM-01…03 below.

---

## H — High traffic (P2–P3): platform and edge

### H-PERF · Performance
- [ ] H-PERF-01 Tunable Tokio runtime (threads per listener, pinning), `SO_REUSEPORT`, socket buffers. *In progress (v0.9 step 1, [ADR-0031](decisions/0031-v0-9-scale.md), unreleased):* `listeners.<l>.socket` (backlog 4096 by default instead of 128, `reuse_port`, buffers, keep-alive, `user_timeout`, `fast_open`, `ipv6_only`, `dscp`) bound through `socket2`, `runtime.worker_threads` and `runtime.max_blocking_threads`, `tls.max_handshakes` on `https` listeners; CPU pinning, per-thread acceptors and `tls.max_handshakes` on `tcp` listeners are planned.
- [ ] H-PERF-02 TLS handshake offload pool, session resumption/tickets with key rotation. *In progress (v0.9 step 2, ADR-0031, unreleased):* one ticketer (ChaCha20-Poly1305, current and previous key, rotation `tls.tickets.rotate`) and one session cache per security class, kept across reloads and handed over in a binary upgrade; `tls.tickets.key_file` for several instances; 0-RTT stays off. The handshake offload pool waits for a benchmark.
- [ ] H-PERF-03 HTTP/2 stream/window tuning; bounded queues and backpressure end-to-end. *In progress (v0.9 step 2, ADR-0031, unreleased):* `listeners.<l>.http2` (streams, windows, frame and header-list size, reset-flood limits spelled `unlimited` to remove, send buffer) with the previous values as defaults; a test shows a slow HTTP/2 reader does not grow proxy memory. A downstream keep-alive PING is planned (needs a Pingora change).
- [ ] H-PERF-04 Zero-downtime binary upgrade: the running process hands its listening sockets and admin sockets to the new binary (peer handover, ADR-0031), verified with long-lived connections; listener-set changes already apply in process (ADR-0012). *In progress (v0.9 step 2, ADR-0031, unreleased):* `rdock upgrade` (admin Unix socket only) and `SIGUSR2` on Linux, with binary checks, optional minisign signature, `validate`, rollback when the new process fails, a bounded drain (`upgrade.drain`, 10 minutes), metrics and an audit record; one process per data directory (`rdock.lock`) and a spool per process. `e2e_upgrade` proves zero failed new connections at about 1,400 per second on a shared 4-vCPU sandbox (the ADR asks for 1,000), held WebSocket, SSE, upload, HTTP/2, TLS-passthrough and UDP traffic, and the failure cases. Not yet tested under real systemd; UDP sessions end at the handover (migration planned).
- [ ] H-PERF-05 **HTTP/3 track** (ingress first) on `quinn` and `h3` with our rustls configuration, feature-gated and experimental (ADR-0032)
- [ ] H-PERF-06 NUMA/worker/buffer sizing guidance; allocator choice (`mimalloc`/`jemalloc`) benchmarked
- [ ] H-PERF-07 eBPF/kernel-assisted experiments only with benchmark evidence

### H-HA · Distributed high availability (P3)
- [ ] H-HA-01 Multiple independent data planes; optional central control plane (`rdock-control`). *In progress (v0.9 step 5, [ADR-0031](decisions/0031-v0-9-scale.md), unreleased):* `rdock control run` (the same binary; crates `rdock-control` and `rdock-cluster`), a cluster CA (P-256), single-use join tokens hashed at rest, enrolment over TLS pinned to the CA (`ca_file` or `ca_pin`), 30-day client certificates renewed with a third left, every later call mutual TLS over HTTP/2, revocation; `cluster` and `control` in the model; the cluster API (`/api/v1/cluster/…`) and `rdock control publish | revisions | rollback | instances | revoke | token create`. Proof 1 (`e2e_cluster`) passes. Planned: the instance dashboard page, rollout waves, a highly available control plane.
- [ ] H-HA-02 Config rollout with ACK/NACK, versioning, rollback; data planes survive control-plane outage from last-known-good. *In progress (v0.9 step 5, ADR-0031, unreleased):* bundles with revision, SHA-256 and cluster id, zstd-compressed, pulled by long poll, stored before the ACK, NACK with diagnostics, origin `control` with the instance's own sections, boot from the stored bundle; another cluster's, a lower or an empty bundle is refused; rollback publishes an earlier revision as a new one. Canary waves, halt on NACK across waves and automatic rollback are the next step.
- [ ] H-HA-03 Shared certificate storage/coordination (no duplicate issuance; lock per name). *In progress (v0.9 step 5, ADR-0031, unreleased):* the `ClusterStore` (compare-and-swap, leases with a fencing token) on the control plane (fencing enforced) or a shared directory (best effort); per-name lease, re-check after taking it, order journal resumed by the next holder, shared ACME account and renewal time, HTTP-01 and TLS-ALPN-01 answers replicated with a barrier; `allow_acme` is no longer needed with the Kubernetes provider on a control-plane store. Proof 2 passes without Docker against the testkit's ACME CA (one order per name, one renewal, a killed holder's order resumed); the Pebble variant runs in CI. The Helm chart keeps `allowAcme` as it was (per-replica join tokens are not modelled yet).
- [ ] H-HA-04 Distributed rate limiting (Redis-compatible or built-in gossip counters)
- [ ] H-HA-05 Locality/zone-aware routing, regional preferences, progressive draining. *In progress (v0.9 step 3, ADR-0031, unreleased):* `zone` and `for_zones` on backends, `locality { zone, mode: prefer | off }` (zone also from `RDOCK_ZONE`), off by default; the Kubernetes provider keeps EndpointSlice zones and `hints.forZones` with kube-proxy's safeguard. Open: progressive draining (`drain.duration`), zones from Docker/Swarm labels, the pod's zone from the Helm chart.

### H-LB · Advanced balancing (P3)
- [ ] H-LB-01 Peak-EWMA latency-aware selection; adaptive weights from observed health. *In progress (v0.9 step 3, ADR-0031, unreleased):* `policy: peak_ewma` (P2C over `latency × (in_flight + 1) / weight`, `decay`, `measure: first_byte | last_byte`). "Adaptive weights" is read as Peak-EWMA plus the outlier detectors of H-LB-02; a continuous success-rate weight is not planned.
- [ ] H-LB-02 Outlier detection with ejection and slow-start. *In progress (v0.9 step 3, ADR-0031, unreleased):* `passive.outlier.success_rate` and `.failure_percentage` with Envoy's defaults, `ejection_jitter`, slow start long form with `on: [recovery, join]`, refused with hash policies.
- [ ] H-LB-03 Priority tiers / disaster-recovery pools; hedged requests under strict safety rules. *In progress (v0.9 step 3, ADR-0031, unreleased):* `priority: 0..7` with `failover: strict | spill` and `overprovisioning`; `retries.per_try_timeout`. Hedging is refused as planned: Pingora 0.9 cannot race two upstream attempts of a request.
- [ ] H-LB-04 Per-tenant quotas, admission control

### H-SEC · Security at scale
- [ ] H-SEC-01 Abuse counters (stick-table-like) per client/route with TTL. *In progress (v0.9 step 4, ADR-0031, unreleased):* `type: abuse` (events: statuses, classes, `auth_failure`; keys `client_ip` with IPv6 by /64, `consumer`, `ja4`, `header:`; `threshold`, `window`, `ban`; `action: deny | tarpit | tag`; `exempt` with loopback and the trusted proxies); bounded counters and a separate bounded ban list that is never evicted (new bans refused when full); bans persisted across restarts and binary upgrades; `GET`/`DELETE /api/v1/abuse/bans`, `rdock bans`. Per instance; cluster-shared counters come with H-HA-04. Challenge actions are not planned in core.
- [ ] H-SEC-02 Optional WAF (OWASP CRS-compatible engine) out-of-process or WASM. *Closed by reference to ADR-0030 (decided in ADR-0031; ticked in the v0.9 release PR):* `type: agent` with the `examples/waf` Coraza/CRS image and the experimental `type: wasm`. Open items: agents over gRPC `ext_proc` and HAProxy SPOP (refused as planned), a body verdict before the request head is sent (a Pingora limit).
- [ ] H-SEC-03 Bot heuristics, JA3/JA4 fingerprint exposure (log/metric/route key). *In progress (v0.9 step 4, ADR-0031, unreleased):* JA4 (FoxIO spec at commit 8eda4ce4, BSD 3-Clause; no JA4+) and optional JA3 from our ClientHello parser: `listeners.<l>.tls.fingerprint`, access-log fields, `Context.fingerprint`, header to backends, `ClientFingerprint(…)` in HTTP and TCP rules, `key: ja4` for limits and `abuse`. Not a metric label (unbounded). Bot heuristics (`verified_bot` by forward-confirmed reverse DNS) are planned, not in v0.9.
- [ ] H-SEC-04 GeoIP rules (MaxMind-format DB, freshness check). *In progress (v0.9 step 4, ADR-0031, unreleased):* `geoip` (`database`, `asn_database`, `max_age` 30 d, `on_stale: warn | refuse`, opt-in log fields), `maxminddb` 0.32.0 without `mmap`, files watched; `ClientCountry`, `ClientContinent`, `ClientASN` in HTTP, TCP and UDP rules; unknown addresses never match; `rdock_geoip_database_age_seconds`. No database bundled or downloaded; a `geoip` middleware with header injection is not planned (rules cover it).
- [ ] H-SEC-05 Identity policies on top of mTLS (M-TLS-01): per-route subject/SAN rules, SPIFFE/SPIRE workload identity (P3). *In progress (v0.9 step 4, ADR-0031, unreleased):* `client_cert` typed lists (`subjects`, `organizations`, `dns`, `uris`, `emails`, `serials`, `sha256`) and `spiffe { trust_domains, ids, id_prefixes, consumer }` with the X.509-SVID rules; SPIFFE ID in `Context`, the access log and optionally as an issuer-keyed consumer; client CA bundles and upstream TLS files watched, mismatched cert/key pairs refused until both files land. Planned: the SPIFFE Workload API (needs `tonic`), per-trust-domain bundles on one listener, checking a backend's SPIFFE ID (Pingora 0.9.1 offers no verifier hook).
- [ ] H-SEC-06 OAuth2/OIDC policies, external authorization (ext-authz style), Cloudflare Access JWT. *Closed by reference to ADR-0030 (decided in ADR-0031; ticked in the v0.9 release PR):* `oidc`, `jwt`, `forward_auth`, `agent`, `cloudflare_access`. Open items: OIDC back-channel logout, token introspection (RFC 7662), gRPC `ext_authz`.
- [ ] H-SEC-07 Tenant isolation for config, API scopes and metrics

### H-ENG · Reliability and performance engineering (P1 onward, continuous)
- [x] H-ENG-01 Benchmarks: sustained/burst, connection churn, long-lived WS/SSE, TLS handshakes, tail latency; same hardware vs NGINX/Traefik/Caddy/HAProxy; published scripts + results
- [x] H-ENG-02 Soak tests (24h+), fault injection (toxiproxy), backend failure/recovery, reload under load
- [ ] H-ENG-03 Memory-leak and resource-exhaustion tests; HTTP parsing fuzzing (differential)
- [x] H-ENG-04 Rule: control plane and dashboard are never on the request path

---

## F — Features and differentiators

### F-UI · Dashboard (P1) — see [design system](08-design-system.md)
- [x] F-UI-01 Embedded, responsive, light/dark, English only (ADR-0024; RTL/Arabic dropped), keyboard-navigable, no external calls
- [ ] F-UI-02 Overview: traffic, error rate, p95, backend health, certificate status, provider status
- [ ] F-UI-03 CRUD for routes/services/middlewares/certificates owned by the API provider; read-only view of file/Docker/K8s-owned objects with "where it comes from"
- [ ] F-UI-04 Live request log (SSE) with filters; live traffic charts without Prometheus (15-minute ring buffer)
- [ ] F-UI-05 Config editor (YAML, schema-validated), preview diff, apply, history, rollback
- [ ] F-UI-06 Users, roles (viewer/operator/admin), API tokens, audit log
- [ ] F-UI-07 Multi-instance view (P3, with control plane)

### F-EXT · Extensibility (P2–P3)
- [x] F-EXT-01 Middleware pipeline with phases (`request`, `upstream_request`, `response`, `response_body`, `log`) and explicit ordering. *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* the phases `request`, `upstream_request`, `request_body`, `response`, `response_body` and `log` with list order in and reverse order out.
- [x] F-EXT-02 Native Rust plugin trait (compile-time) with stability policy from v1.0. *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `rdock-plugin-api` (own `0.x` line, so the stability policy starts at 1.0), `type: plugin` with panic isolation and `rdock::run(registry)`.
- [ ] F-EXT-03 WASM plugins (component model, sandbox, fuel, capability allow-list) — experimental. *Open:* in the source of 0.8.0-alpha.1 behind the cargo feature `wasm` (off by default, not in the stock binary or images): `type: wasm` runs a component for the WIT world `rdock:plugin/filter@0.1.0` (request and response heads, no bodies) on wasmtime 36 LTS, a fresh instance per request, fuel, epoch deadline and memory limits, no WASI, capabilities `log`, `clock`, `random` granted per middleware, fail closed with `on_error`; tested (limits, traps, imports, a `no_std` Rust example guest, the real binary with a reload) in the non-required `wasm` CI job only; the ABI is `0.x`; the box stays open while the release binaries and images leave WASM out ([ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md))
- [ ] F-EXT-04 Out-of-process "agents" over gRPC/HTTP for heavy engines (WAF, custom auth), with timeouts and fail policy. *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `type: agent` over HTTP (`rdock` JSON and `forward` protocols; timeouts, fail closed by default, circuit breaker) and the CRS WAF example (`examples/waf`, `waf-example` CI job). *Open:* gRPC agents (`ext_proc`, `ext_authz`) and SPOP, refused as planned; the request head reaches the backend before a body verdict (Pingora 0.9.1 limitation).
- [ ] F-EXT-05 Plugin SDK, examples, signature verification for distributed plugins. *Open:* the SDK half (`rdock-plugin-api`, `testing`, two native examples, a template) and the signature half (WASM modules: a mandatory `sha256` pin and a minisign Ed25519 signature by a pinned key, checked before compilation; `allow_unsigned: true` is the warned exception) are in 0.8.0-alpha.1; signatures apply to WASM modules only, which need the experimental `wasm` feature that the release binaries and images leave out, so the box stays open

### F-GW · API gateway features (P2)
- [ ] F-GW-01 API-key validation (hashed keys, external store) and OIDC login/policies (plain JWT validation is M-SEC-01). *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* the API-key half: `consumers`, `api_key` with `rdk_` keys stored as ID and SHA-256 (inline, keys file, admin API); OIDC login: `oidc` (authorization code with PKCE, stateless encrypted session cookie, refresh, RP-initiated logout, claims to headers and to the consumer; tested against a fake provider and Dex in CI), and `jwt.consumer_claim`. The external store (RFC 7662) and server-side sessions, early session revocation, OIDC back-channel logout and a dashboard UI for consumers, keys and quotas are open.
- [x] F-GW-02 Per-consumer rate limits and quotas. *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `rate_limit.key: consumer` with group overrides, the `quota` middleware with persisted per-instance counters.
- [x] F-GW-03 Request validation against OpenAPI/JSON Schema. *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `type: validate` with inline JSON Schema 2020-12 or an OpenAPI 3.1 document; non-default OpenAPI parameter styles are refused as planned.
- [x] F-GW-04 Consistent JSON error envelope; request/response transformation. *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* the envelope half (`errors.format`, RFC 9457 problem details) and the transformation half (`type: transform`: header rules and JSON Patch on request bodies and, up to a cap, JSON response bodies).
- [x] F-GW-05 Usage metering events export (OTLP/webhook) — no billing in core. *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `observability.metering` (CloudEvents webhook, OTLP logs, bounded queue, at least once).

### F-WEB · Web server and legacy compatibility
- [x] F-WEB-01 Static files: MIME, ranges, conditional requests, cache headers, SPA fallback, precompressed assets (P1)
- [x] F-WEB-02 Directory listing (off by default, hardened path resolution) (P3). *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `static.listing: true` (off by default; escaped names, restrictive CSP, existing `hidden`/`symlinks` policy, at most 10,000 entries).
- [ ] F-WEB-03 HTTP cache: memory + disk, RFC 9111, `Vary`, SWR/SIE, purge API (URL/tag), coalescing (P2). *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `rdock-cache` with memory and disk stores, RFC 9111 storability, freshness, revalidation, `Vary`, `stale-if-error`, coalescing, invalidation, tags and the admin purge API (one instance); the stampede test passes; the RFC 9111 suite `http-tests/cache-tests` (commit `7e2c537`, Node.js 24, job `http-cache`, not a required check) passed its gate on commit `c292639` with 205 tests passing and 2 required failures allow-listed in `tests/conformance/http-cache/allowlist.json` (`other-date-update`, `other-date-update-expires`: Pingora 0.9.1 rewrites `Date`, an upstream change is needed). *Open:* background refresh for `stale-while-revalidate` (served as plain staleness; refused as planned). The box stays open until background refresh lands, because the requirement names SWR.
- [ ] F-WEB-04 FastCGI (PHP) gateway (P3, optional crate)
- [ ] F-WEB-05 Explicit forward-proxy/CONNECT mode, isolated config, off by default (P3)
- [ ] F-WEB-06 Mail proxy — out of scope for core (separate project if ever)

### F-MGMT · Management and automation
- [x] F-MGMT-01 CLI/API parity; OpenAPI published; typed clients generated (TS, Go)
- [ ] F-MGMT-02 Terraform/OpenTofu provider (P2). *Open (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)):* the provider source (`reversedock_route`, `reversedock_service`, `reversedock_middleware`, data sources, import) is in `clients/terraform` and tested in the `terraform-provider` CI job; publishing needs a separate public repository `terraform-provider-reversedock` and a signing key (maintainer actions), so the box stays unticked.
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
- [x] W-CF-08 Authenticated Origin Pulls: client-certificate verification against Cloudflare's origin-pull CA (needs M-TLS-01)
- [ ] W-CF-05 Cloudflare Tunnel: documented deployment with `cloudflared` sidecar, no inbound ports
- [x] W-CF-06 Cloudflare Access JWT validation middleware (P2). *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* `type: cloudflare_access`, a preset over `jwt`.
- [x] W-CF-07 Compatible with Cloudflare Load Balancer origin pools (health endpoints, PROXY-less)

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
- [x] W-SWM-01 Separate provider: services + `deploy.labels`; task vs VIP endpoint modes
- [x] W-SWM-02 Overlay networks; replica scale events; task health/readiness; rolling-update draining
- [x] W-SWM-03 Swarm secrets/configs; multi-node replicated proxies (global mode)

### W-K8S · Kubernetes (P2)
- [x] W-K8S-01 Gateway API controller targeting the latest Standard channel (v1.7.0, released 2026-10-29; every kind below is `v1` in Standard): GatewayClass, Gateway, HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, UDPRoute, ReferenceGrant, ListenerSet; upstream conformance profiles `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS` in CI. *Released in 0.8.0-alpha.1:* GatewayClass, Gateway, HTTPRoute, GRPCRoute, TLSRoute (passthrough), TCPRoute, ReferenceGrant and ListenerSet are implemented; UDPRoute is implemented with UDP routes (v0.8, ADR-0030), its nine upstream tests transcribed and passing against the translator, and `GATEWAY-UDP` added to the conformance job, where it passes on kind (2026-11-12, commit `43d81de`: core 21 passed, extended 7 passed); the upstream Gateway API v1.7.0 conformance suite passes in CI on kind for `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS` and `GATEWAY-TCP` (all core tests and every claimed extended feature; 2026-11-11, commit `19e88cc`, [run](https://github.com/Docker-Hunterpedia/ReverseDock/actions/runs/43046671411)); all five profiles pass; no report has been submitted upstream ([ADR-0029](decisions/0029-kubernetes-gateway-api.md), [roadmap](07-roadmap.md))
- [x] W-K8S-02 Ingress controller (networking.k8s.io/v1) for migration. *Released in 0.8.0-alpha.1:* tested on fixtures; no cluster job exercises Ingress (the `helm-k3s` job, which passed on 2026-11-11, uses a Gateway and an HTTPRoute only)
- [x] W-K8S-03 EndpointSlice watches, Secrets for TLS, cert-manager compatibility. *Released in 0.8.0-alpha.1:* tested on fixtures and against a bare API server; cert-manager compatibility is not exercised in a cluster job (the k3s job uses a self-made TLS Secret, not cert-manager)
- [x] W-K8S-04 Leader election, RBAC, namespace scoping, readiness probes. *Released in 0.8.0-alpha.1:* tested without a cluster; the chart's RBAC and readiness probes ran on kind and k3s in CI on 2026-11-11 (the controller wrote status through the conformance suite, and `helm install --wait` and `helm upgrade --wait` returned); leader election is not checked by any job; the namespaced mode (`watchNamespaces`) is not exercised in a cluster job
- [ ] W-K8S-05 Helm chart, Kustomize, raw manifests; k3s/RKE2/kind tested. *Open:* released in 0.8.0-alpha.1: the chart, manifests, Kustomize base and examples exist and are checked offline in CI; the kind (conformance) and k3s (install, example, upgrade, uninstall) jobs passed in CI on 2026-11-11 (commit `19e88cc`); RKE2 has no job and is untested, so the box stays open; the chart is not published to a chart registry

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
- [x] W-DNS-03 Route 53, Google Cloud DNS, Azure DNS, DigitalOcean, Hetzner, deSEC, RFC 2136 adapters (P1–P2)

### W-OBS · Monitoring, config and secrets
- [ ] W-OBS-01 Prometheus, Grafana, OTLP (Tempo/Jaeger), Loki/OpenSearch via stdout or OTLP, syslog (P0–P1)
- [x] W-OBS-02 Secrets: env, files, Docker/Swarm/K8s secrets (P0); Vault/External Secrets (P2). *Implemented (v0.8, [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md)), released in 0.8.0-alpha.1:* External Secrets Operator, the CSI driver and Vault Agent documented as file and Secret producers; `${vault:…}` for KV v2 with token and Kubernetes login, tested against OpenBao.
- [x] W-OBS-03 GitOps: file provider + `rdock validate` in CI (P0); Terraform (P2)
