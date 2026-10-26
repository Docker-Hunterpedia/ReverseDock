Open-Source Reverse Proxy — Complete Project Requirements
Research and feature specification • October 2026
1. Project vision
Build a modern, high-performance, open-source reverse proxy based on Cloudflare Pingora, combining the strongest capabilities of:
- NGINX: Reverse proxying, HTTP serving, caching, rewriting, compression, and flexible configuration.
- Traefik: Docker labels, automatic service discovery, Kubernetes integrations, routing rules, and middleware.
- Caddy: Automatic HTTPS, simple configuration, certificate management, and developer experience.
- HAProxy: High-performance load balancing, traffic controls, health checks, and reliability.
- Envoy: Extensibility, dynamic configuration, observability, and distributed infrastructure.
The goal is not another basic reverse proxy. It is one proxy that works for a developer running two Docker containers, a company operating dozens of services, or a platform handling very high traffic.

It should remain fully usable without a dashboard, database, Kubernetes, or an external control plane.
2. What the research tells us
I reviewed the official documentation and repositories for Pingora, NGINX, Traefik, Caddy, HAProxy, and Envoy.
Pingora is a strong foundation.

It already provides asynchronous networking in Rust, HTTP/1.1 and HTTP/2 proxying, connection pooling, graceful restarts, load-balancing primitives, TLS integrations, and WebSocket/gRPC proxy support. 

GitHub





Pingora is not a complete reverse-proxy product.

We must implement the configuration experience, certificate automation, Docker/Kubernetes discovery, provider management, middleware, management APIs, and other product-level features ourselves.


HTTP/3 and QUIC are a significant gap.

Pingora maintainers have described HTTP/3 integration through Cloudflare's Quiche as a future goal. We should treat HTTP/3 as a separate engineering milestone, not as an existing Pingora capability. 

GitHub
+1





Caching needs substantial work.

Pingora contains caching components, but its public proxy-caching integration remains experimental. A stable production cache needs dedicated implementation and testing. 

GitHub
+1







3. Existing open-source projects we must consider
This is an important finding: the Pingora-based reverse-proxy idea already exists in several projects. Our project needs a stronger, clearly differentiated scope.









Pingap
GitHubAlready offers a built-in web interface, hot reloads, 30+ plugins, automatic certificates, load balancing, metrics, and Docker-label discovery. It's the closest existing competitor and an important architectural reference. 

GitHub















Zentinel
GitHub organizationFocuses on security, programmable agents, and extensible traffic protection, including a ModSecurity-related project. Worth studying for the middleware and security architecture. 

Zentinel Documentation
+1






Proposed differentiation: A fully open-source, multi-environment proxy with first-class Docker/Swarm/Kubernetes support, NGINX-class HTTP features, Caddy-like HTTPS automation, HAProxy-like traffic management, and a unified API and configuration system. The developer experience should be as important as raw performance.

The following is a target specification, not a claim that Pingora already implements everything.

4. Basics — Minimum viable reverse proxy
Phase 1 · Essential
The first release should already be capable of replacing NGINX or Traefik for straightforward self-hosted applications.
Core networking and proxying
- \[ \] HTTP/1.1 and HTTP/2 listeners.
- \[ \] HTTP-to-HTTPS redirects.
- \[ \] Reverse proxy to HTTP and HTTPS backends.
- \[ \] TLS termination with SNI and ALPN.
- \[ \] Upstream TLS certificate and hostname verification.
- \[ \] Multiple domains and subdomains.
- \[ \] Wildcard hostname routing.
- \[ \] Routing by hostname, path, path prefix, and HTTP method.
- \[ \] Request and response header modifications.
- \[ \] URL rewrites and redirects, including permanent and temporary redirects.
- \[ \] Query string preservation and manipulation.
- \[ \] WebSocket proxying.
- \[ \] Server-Sent Events (SSE) and streaming responses without unnecessary buffering.
- \[ \] gRPC and gRPC streaming.
- \[ \] HTTP/2 cleartext upstreams (h2c).
- \[ \] Unix-domain socket upstreams.
- \[ \] IPv4 and IPv6.
- \[ \] Correct forwarded-header handling: Forwarded, X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host.
- \[ \] Trusted-proxy configuration to prevent client-IP spoofing.
- \[ \] Configurable connection, read, write, and idle timeouts.
- \[ \] Graceful shutdown and connection draining.
HTTPS and certificates
- \[ \] Automatic HTTPS enabled by default for eligible public domains.
- \[ \] Let's Encrypt ACME support.
- \[ \] Support for other ACME certificate authorities.
- \[ \] HTTP-01 and TLS-ALPN-01 challenges.
- \[ \] DNS-01 challenges for wildcard certificates.
- \[ \] Automatic certificate renewal and storage.
- \[ \] Manually provided certificates and private keys.
- \[ \] Multiple certificates per listener through SNI.
- \[ \] TLS 1.2 and TLS 1.3 policies.
- \[ \] HTTP Strict Transport Security (HSTS), configurable.
- \[ \] Certificate expiry and renewal failure alerts.
- \[ \] Support for local development certificates.
Automatic HTTPS, including renewals and safe defaults, is one of Caddy's major advantages and should be part of the core product rather than an optional afterthought. 

Caddy Documentation



Configuration and developer experience
- \[ \] Single, self-contained executable.
- \[ \] Human-readable YAML configuration.
- \[ \] JSON configuration and API representation.
- \[ \] Environment variable interpolation.
- \[ \] File-based secrets and mounted secret volumes.
- \[ \] CLI commands: start, stop, reload, validate, version, and status.
- \[ \] Configuration schema and autocomplete support.
- \[ \] Clear, actionable configuration errors.
- \[ \] Live config updates without dropping existing requests.
- \[ \] Atomic configuration validation and rollback.
- \[ \] Automatic config reload when watched files change.
- \[ \] Logs to stdout/stderr, suitable for Docker.
- \[ \] JSON structured access logs.
- \[ \] Basic health and readiness endpoints.
- \[ \] Basic Prometheus metrics.
- \[ \] Linux x86-64 and ARM64 builds.
- \[ \] Official Docker images and Docker Compose examples.
- \[ \] systemd deployment support.
Basic security
- \[ \] HTTP Basic authentication.
- \[ \] IP allowlists and denylists.
- \[ \] CIDR-based access rules.
- \[ \] Basic per-IP rate limiting.
- \[ \] Request size and header size limits.
- \[ \] Security response headers.
- \[ \] Request ID generation and propagation.
- \[ \] Restricted admin API, disabled from public interfaces by default.
- \[ \] Safe handling of malformed HTTP requests and ambiguous message framing.
- \[ \] No privileged user requirement after port binding, where supported.
5. Medium traffic — Production workloads
Phase 2 · Production Ready
This stage is intended for SaaS products, busy APIs, e-commerce systems, multi-service infrastructure, and production deployments that need reliable scaling.
Load balancing
- \[ \] Round-robin.
- \[ \] Weighted round-robin.
- \[ \] Least connections.
- \[ \] Least requests / least outstanding work.
- \[ \] Random and power-of-two-choices.
- \[ \] Consistent hashing.
- \[ \] IP-hash routing.
- \[ \] Sticky sessions using cookies.
- \[ \] Header- and cookie-based upstream selection.
- \[ \] Active health checks (HTTP, HTTPS, TCP).
- \[ \] Passive health checks using observed failures.
- \[ \] Automatic removal and recovery of unhealthy backends.
- \[ \] Retry policies restricted by request safety and replayability.
- \[ \] Circuit breakers.
- \[ \] Connection limits per upstream.
- \[ \] Failover and backup server pools.
- \[ \] Configurable health check intervals, thresholds, and timeouts.
Production routing
- \[ \] Regex path matching.
- \[ \] Header, cookie, and query parameter routing.
- \[ \] Route priorities and deterministic rule evaluation.
- \[ \] Request mirroring to a secondary backend.
- \[ \] Weighted traffic splitting.
- \[ \] Canary deployments.
- \[ \] Blue-green deployments.
- \[ \] API version-based routing.
- \[ \] Domain-based multi-tenant routing.
- \[ \] Maintenance mode with configurable responses.
- \[ \] Custom error pages.
- \[ \] Health-aware service discovery.
- \[ \] Per-route middleware configuration.
Traffic management
- \[ \] Rate limiting by IP, API key, user, or custom identity.
- \[ \] Burst limits and token-bucket algorithms.
- \[ \] Concurrent request limits.
- \[ \] Request queuing and queue deadlines.
- \[ \] Backend overload protection and load shedding.
- \[ \] Bandwidth limits per route or client.
- \[ \] Request and response buffering controls.
- \[ \] Gzip, Brotli, and Zstandard compression where negotiated.
- \[ \] Configurable header/body transformation limits.
- \[ \] Timeout policies per route and backend.
- \[ \] Upload and download streaming controls.
- \[ \] Retry budgets to avoid amplification during outages.
Caching
- \[ \] HTTP response caching respecting applicable HTTP cache semantics.
- \[ \] Configurable memory cache.
- \[ \] Persistent disk cache.
- \[ \] Cache TTL and override rules.
- \[ \] Cache-control and Vary handling.
- \[ \] Conditional revalidation with ETag and Last-Modified.
- \[ \] stale-while-revalidate and stale-if-error.
- \[ \] Cache bypass rules for authenticated/private traffic.
- \[ \] Cache invalidation and purge API.
- \[ \] Cache locking / request coalescing to prevent stampedes.
- \[ \] Cache hit, miss, stale, and bypass metrics.
- \[ \] Bounded cache sizes and eviction policies.
Monitoring and administration
- \[ \] Prometheus /metrics.
- \[ \] OpenTelemetry tracing and context propagation.
- \[ \] Real-time request counts, response codes, and latency.
- \[ \] Request duration p50, p95, p99 histograms.
- \[ \] Backend health and error rate reporting.
- \[ \] CPU, memory, connections, and bandwidth statistics.
- \[ \] Structured log export and sampling.
- \[ \] Configurable sensitive-header and token redaction.
- \[ \] Alert rules and notification integrations.
- \[ \] Administrative REST API.
- \[ \] Config version history, diffs, and rollback.
- \[ \] Optional web dashboard.
Caddy's documented production features include active/passive health checks, retry policies, dynamic upstream discovery, buffering controls, and streaming-specific behavior. These are useful reference cases for compatibility tests. 

Caddy Documentation



6. High traffic — Enterprise and distributed infrastructure
Phase 3 · Advanced Scaling
These capabilities should make the proxy competitive in demanding edge, platform, and large-scale API environments. The designation refers to architectural complexity, not a guaranteed requests-per-second figure.
Extreme performance
- \[ \] Tunable multithreaded asynchronous runtime.
- \[ \] Efficient per-core connection handling.
- \[ \] Adaptive upstream connection pooling.
- \[ \] HTTP/2 multiplexing and resource limits.
- \[ \] Memory allocation optimization.
- \[ \] Bounded queues and backpressure across the entire request pipeline.
- \[ \] Streaming large uploads/downloads with bounded memory.
- \[ \] HTTP/3 and QUIC support through a dedicated integration.
- \[ \] TLS session resumption and session ticket management.
- \[ \] TLS handshake optimization and concurrency limits.
- \[ \] Linux socket tuning, including SO\_REUSEPORT where appropriate.
- \[ \] NUMA-aware configuration for large servers.
- \[ \] Configurable worker and buffer sizing.
- \[ \] Efficient handling of large numbers of idle and long-lived connections.
- \[ \] Optional eBPF or kernel-assisted networking experiments, only where benchmarks justify them.
Distributed high availability
- \[ \] Multiple proxy instances with independent data planes.
- \[ \] Centralized, optional control plane.
- \[ \] Cluster-wide dynamic configuration.
- \[ \] Safe configuration rollout with acknowledgement, rejection, and rollback.
- \[ \] Cross-node service discovery.
- \[ \] Distributed rate limiting.
- \[ \] Shared certificate coordination.
- \[ \] Cluster-aware session affinity where required.
- \[ \] Health-based traffic removal and failover.
- \[ \] Regional backend preferences.
- \[ \] Zone-aware and locality-aware routing.
- \[ \] Progressive draining for rolling deployments.
- \[ \] Disaster recovery and persisted last-known-good configuration.
- \[ \] Operation during temporary control-plane outages.
Advanced load balancing
- \[ \] Peak exponentially weighted moving average (peak EWMA) latency-aware routing.
- \[ \] Least-loaded and adaptive backend selection.
- \[ \] Outlier detection and automatic ejection.
- \[ \] Slow-start traffic ramp-up for recovered instances.
- \[ \] Priority tiers and disaster-recovery backends.
- \[ \] Weighted locality routing.
- \[ \] Hedged requests under carefully defined, safe conditions.
- \[ \] Dynamic backend weights based on observed health.
- \[ \] Per-tenant traffic quotas.
- \[ \] Traffic shaping and admission control.
Security at scale
- \[ \] Distributed abuse counters similar in purpose to HAProxy stick tables.
- \[ \] Optional Web Application Firewall (WAF).
- \[ \] OWASP Core Rule Set integration or equivalent tested rule engine.
- \[ \] Bot and scraper mitigation mechanisms.
- \[ \] Request anomaly scoring.
- \[ \] GeoIP-based rules.
- \[ \] JA3/JA4-style TLS fingerprint information, where technically available and appropriate.
- \[ \] HTTP request smuggling detection and prevention.
- \[ \] TLS passthrough with SNI routing.
- \[ \] Mutual TLS for clients and upstreams.
- \[ \] SPIFFE/SPIRE workload identity integration.
- \[ \] OAuth2/OIDC authorization policies.
- \[ \] External authorization service support.
- \[ \] Distributed denial-of-service mitigation controls at the application layer, without claiming to replace upstream network-level protection.
- \[ \] Tenant isolation for configuration, access, and metrics.
HAProxy's stick tables are particularly useful to study for efficient per-client counters, behavioral rules, and abuse controls. 

HAProxy config tutorials



Reliability and performance engineering
- \[ \] Stress tests for sustained and burst traffic.
- \[ \] Connection-churn benchmarks.
- \[ \] Long-lived WebSocket and SSE benchmarks.
- \[ \] TLS handshake throughput benchmarks.
- \[ \] Latency-under-load measurements, including tail latency.
- \[ \] Comparisons against equivalent NGINX, Traefik, Caddy, and HAProxy configurations.
- \[ \] Soak tests lasting many hours or days.
- \[ \] Network fault injection (packet loss, latency, partial outages).
- \[ \] Backend failure and recovery tests.
- \[ \] Graceful-reload tests under active connections.
- \[ \] Memory leak and resource exhaustion testing.
- \[ \] Compatibility and fuzz testing for HTTP parsing.
- \[ \] Published, reproducible benchmark scripts and results.
Key engineering rule: The control plane and dashboard must never sit on the request-critical path. Existing routes must continue working when the database, dashboard, or configuration controller is temporarily unavailable.

7. Features — Product capabilities and differentiators
This section covers functionality beyond simply proxying traffic. These are the features that could make the project easier to adopt and extend than competing proxies.
A. Web dashboard









Traefik — service and route visibility









NGINX Proxy Manager — visual management

The dashboard should be optional and separate from the proxy's critical networking processes.
- \[ \] Clean, responsive web interface.
- \[ \] Overview of domains, routes, services, and listeners.
- \[ \] Create, edit, enable, and disable routes.
- \[ \] Certificate management and renewal status.
- \[ \] Live service health visualization.
- \[ \] Real-time traffic charts.
- \[ \] Request logs with filters.
- \[ \] Middleware management.
- \[ \] Rate-limit and access-rule management.
- \[ \] Configuration validator and visual diff.
- \[ \] Preview of a change before applying it.
- \[ \] Configuration audit history and rollback.
- \[ \] Export and import configuration.
- \[ \] Multi-user management and RBAC.
- \[ \] Optional multi-instance management.
- \[ \] Dark/light themes.
B. Extensible middleware and plugins
- \[ \] Middleware pipeline with explicit execution order.
- \[ \] Native Rust plugin interfaces.
- \[ \] WebAssembly plugins with sandboxing, capability restrictions, and resource limits.
- \[ \] Plugins for request, response, authentication, and traffic phases.
- \[ \] External authorization middleware.
- \[ \] API-key authentication.
- \[ \] JWT validation using JWKS.
- \[ \] OAuth2 / OIDC authentication.
- \[ \] Forward authentication.
- \[ \] CORS middleware.
- \[ \] CSRF-related policies for applicable applications.
- \[ \] Security headers.
- \[ \] Request and response transformation.
- \[ \] Redirect and rewrite plugins.
- \[ \] Request mirroring and logging plugins.
- \[ \] Plugin versioning and compatibility checks.
- \[ \] Official plugin SDK and examples.
- \[ \] Plugin registry with signatures and provenance verification.
- \[ \] Per-route plugin enablement.
For the initial design, keep common middleware built in. Add a stable third-party plugin API only after the core request/response lifecycle is proven.
C. API gateway features
- \[ \] API key creation, validation, and revocation integrations.
- \[ \] External JWT/OIDC validation.
- \[ \] Per-consumer rate limits.
- \[ \] Per-route and per-tenant quotas.
- \[ \] API request transformation.
- \[ \] Request schema validation using OpenAPI or JSON Schema.
- \[ \] API version routing.
- \[ \] External policy decision support.
- \[ \] Consistent error responses.
- \[ \] Usage metering and billing event export.
- \[ \] Developer-facing API analytics.
- \[ \] API request and response size policies.
- \[ \] Request ID and distributed trace propagation.
This makes the proxy usable as an API gateway without requiring the core project to become a full billing or identity platform.
D. Web server and legacy compatibility
These features bring it closer to NGINX beyond conventional reverse proxying.
- \[ \] Static file serving.
- \[ \] Directory indexes, optional directory listings, and default documents.
- \[ \] MIME type handling.
- \[ \] Range requests and conditional requests.
- \[ \] Configurable file cache headers.
- \[ \] SPA fallback routing.
- \[ \] Custom 403, 404, 429, 502, 503, and 504 pages.
- \[ \] Response compression and content negotiation.
- \[ \] Content security policy and other header policies.
- \[ \] Optional CGI/FastCGI gateway support.
- \[ \] Optional HTTP CONNECT and explicit forward-proxy mode, strictly separated from reverse-proxy configuration.
- \[ \] Generic TCP proxying.
- \[ \] Generic UDP proxying.
- \[ \] PROXY protocol v1/v2 support.
- \[ \] TCP SNI passthrough routing.
- \[ \] Optional mail proxy support (SMTP, IMAP, POP3) in a separate module.
NGINX supports static serving, HTTP caching, TCP/UDP proxying, and optional mail proxy functionality. Those are separate implementation areas, not capabilities automatically inherited from Pingora's HTTP proxy. 

nginx.org
+1



E. Management and automation
- \[ \] Versioned REST management API.
- \[ \] OpenAPI specification.
- \[ \] Secure admin authentication and authorization.
- \[ \] API tokens with narrowly scoped permissions.
- \[ \] Configuration as code / GitOps.
- \[ \] Declarative configuration reconciliation.
- \[ \] Configuration backups and restores.
- \[ \] Safe dry-run mode.
- \[ \] Webhooks for changes and alerts.
- \[ \] Audit logs for administration.
- \[ \] CLI and API parity.
- \[ \] Terraform/OpenTofu provider or integration.
- \[ \] NGINX configuration migration helper for supported directives.
- \[ \] Traefik configuration and Docker-label migration helper.
- \[ \] Documentation site and interactive playground.
F. Security and open-source quality
- \[ \] Apache-2.0 or similarly permissive open-source licensing.
- \[ \] Public roadmap, issue templates, and contribution guidelines.
- \[ \] Security disclosure policy and private vulnerability reporting.
- \[ \] Dependency and license auditing.
- \[ \] Automated SAST and dependency scanning.
- \[ \] Signed releases and Software Bill of Materials (SBOM).
- \[ \] Container images with minimal dependencies, non-root execution, and read-only filesystem compatibility.
- \[ \] Published release checksums.
- \[ \] Unit, integration, and end-to-end testing.
- \[ \] Protocol fuzzing and regression tests.
- \[ \] Reproducible benchmark infrastructure.
- \[ \] Supported-version and security-fix policy.
- \[ \] No mandatory account, telemetry, or license activation.

8. Works with — Integrations and environments
The most important design principle: all infrastructure providers should translate their configurations into one consistent internal model rather than each provider implementing its own routing engine.
YAML / JSON


Docker / Swarm


Kubernetes


Cloud APIs


Consul / etcd


Admin REST API



Unified Configuration Engine
Normalization · Validation · Priorities · Snapshots
Pingora-Based Data Plane
Listeners · Routers · Middleware · Load Balancers

A. Cloudflare









Cloudflare integration

High priority


- \[ \] Work behind Cloudflare's HTTP reverse proxy and CDN.
- \[ \] Cloudflare DNS API integration.
- \[ \] Automatic DNS-01 certificate challenges using scoped Cloudflare API tokens.
- \[ \] Automatic synchronization of trusted Cloudflare IP ranges.
- \[ \] Safe restoration of the visitor IP through CF-Connecting-IP only for verified/trusted upstream connections.
- \[ \] Correct handling of Cloudflare forwarded headers.
- \[ \] Support for Cloudflare Origin CA certificates.
- \[ \] Authenticated Origin Pulls (Cloudflare-to-origin mTLS).
- \[ \] Cloudflare Full (strict) TLS configurations.
- \[ \] Cloudflare Tunnel integration through cloudflared.
- \[ \] Cloudflare Access JWT validation.
- \[ \] Cloudflare API integration for DNS records and optional zone operations.
- \[ \] Compatibility with Cloudflare Load Balancing origin pools.
- \[ \] Preserve and optionally log Cloudflare Ray IDs.
- \[ \] Support for private deployments without public inbound ports when used with Cloudflare Tunnel.
Cloudflare documentation confirms the original-client-IP header behavior and its outbound-only tunnel architecture. The origin TLS connection is separate from Cloudflare's visitor-facing TLS connection, so both sides must be configured correctly. 

Cloudflare Support docs
+2



B. Docker and Docker Compose









Docker integration

Highest priority


- \[ \] Docker Engine API service discovery.
- \[ \] Docker Compose support.
- \[ \] Automatic detection of container creation, updates, restarts, and removal.
- \[ \] Native project-specific Docker labels.
- \[ \] Compatibility with commonly used Traefik Docker labels.
- \[ \] Automatic domain-to-container routing.
- \[ \] Network-aware container IP selection.
- \[ \] Configurable internal service ports.
- \[ \] Multiple routers and backends per container.
- \[ \] Automatic detection of eligible containers.
- \[ \] Opt-in exposure of containers by default.
- \[ \] Container health-aware routing.
- \[ \] Support for multiple Docker networks.
- \[ \] Support for Docker secrets.
- \[ \] Docker events watcher with periodic reconciliation.
- \[ \] Docker API socket proxy / restricted API access.
- \[ \] Rootless Docker support where networking permits.
A highly useful feature would be accepting existing labels like these:
services:
  app:
    image: myapp:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(\`app.example.com\`)"
      - "traefik.http.routers.app.tls=true"
      - "traefik.http.services.app.loadbalancer.server.port=3000"


Goal: A user migrating from Traefik should initially be able to retain their existing Docker Compose services and supported labels. Unsupported label semantics should produce explicit warnings rather than silent misconfiguration.

Traefik documents these label conventions and warns that unrestricted access to the Docker API is a host-security risk. 

Traefik
+1



C. Docker Swarm
- \[ \] Native Swarm service discovery.
- \[ \] Support service-level labels through deploy.labels.
- \[ \] Discover individual service tasks or virtual IP endpoints.
- \[ \] Support overlay networks.
- \[ \] Automatic updates as replicas scale up or down.
- \[ \] Task health and readiness handling.
- \[ \] Rolling-deployment-aware traffic draining.
- \[ \] Node-aware routing and service affinity.
- \[ \] Swarm secrets and configuration objects.
- \[ \] Support multi-node deployment with replicated proxies.
- \[ \] Traefik-compatible Swarm label subset.
Swarm must have a distinct provider from standalone Docker because service-level labels and task discovery behave differently. 

v3.5



D. Kubernetes









Kubernetes integration

High priority after Docker


- \[ \] Kubernetes Service and EndpointSlice discovery.
- \[ \] Kubernetes Ingress controller support.
- \[ \] Kubernetes Gateway API controller support.
- \[ \] GatewayClass, Gateway, and HTTPRoute.
- \[ \] GRPCRoute.
- \[ \] TLSRoute, TCPRoute, and UDPRoute as their associated protocol support matures.
- \[ \] Weighted traffic splitting.
- \[ \] Hostname and path matching.
- \[ \] Cross-namespace access controls and ReferenceGrant.
- \[ \] Gateway API conformance testing.
- \[ \] Kubernetes Secrets for TLS.
- \[ \] cert-manager compatibility.
- \[ \] Kubernetes readiness/liveness probes.
- \[ \] RBAC and namespace-scoped permissions.
- \[ \] Watch-based updates without constant API polling.
- \[ \] Leader election and high-availability controller replicas.
- \[ \] Helm chart.
- \[ \] Kustomize examples.
- \[ \] Standard deployment manifests.
- \[ \] Support for K3s, RKE2, and other conformant Kubernetes distributions.
- \[ \] Kubernetes NetworkPolicy-compatible deployment guidance.
Target the standard Kubernetes Gateway API rather than inventing a proprietary routing model first. Its conformance tests cover core features including weighted backends, host/path matching, redirects, and cross-namespace references. 

Gateway API



E. Other platforms and orchestration
Platform	Target integration	Priority
Dokploy	Docker labels, networks, Compose deployments	P0/P1
Coolify	Docker-aware routing, migration support	P1
Portainer	Docker/Swarm compatibility	P1
HashiCorp Nomad	Nomad service discovery	P2
HashiCorp Consul	Service discovery and KV configuration	P2
etcd	Distributed configuration	P2
Amazon ECS	ECS service discovery	P2
AWS EC2 / traditional VMs	Binary, systemd, Docker	P0
Google Cloud / Azure VMs	Binary and container deployment	P1
Bare-metal Linux	Native executable, systemd	P0
Home labs / Proxmox VMs	Docker and native Linux	P0
k3s / RKE2	Kubernetes standard APIs	P1
Cloudflare Workers	Compatible upstream, not a Pingora deployment target	P2

P0 = first release, P1 = production expansion, P2 = longer-term integration. These are proposed targets, not currently implemented capabilities.F. DNS and certificate providers
- \[ \] Cloudflare DNS.
- \[ \] AWS Route 53.
- \[ \] Google Cloud DNS.
- \[ \] Azure DNS.
- \[ \] DigitalOcean DNS.
- \[ \] Hetzner DNS.
- \[ \] RFC 2136 dynamic DNS updates.
- \[ \] DNS provider plugin interface.
- \[ \] DNS propagation checks and retry controls.
- \[ \] Certificate storage using local files initially.
- \[ \] Optional shared storage or secret-manager integration for clustered deployments.
G. Monitoring, configuration, and secrets
- \[ \] Prometheus.
- \[ \] Grafana.
- \[ \] OpenTelemetry collectors.
- \[ \] Jaeger and Tempo.
- \[ \] Loki and Elasticsearch/OpenSearch log pipelines.
- \[ \] Syslog.
- \[ \] HashiCorp Vault.
- \[ \] Kubernetes Secrets.
- \[ \] Docker Secrets.
- \[ \] External Secrets Operator.
- \[ \] Consul and etcd.
- \[ \] HTTP configuration provider.
- \[ \] GitOps deployment workflows.
- \[ \] Terraform / OpenTofu.
Traefik's provider architecture is a useful baseline: it already supports Docker, Swarm, Kubernetes, Consul, Nomad, ECS, file-based configuration, and multiple KV backends. 

Traefik




9. Recommended technical architecture
I would divide the repository into independent Rust crates and optional supporting services.
Management Layer
CLI · REST API · Optional Web Dashboard
Configuration &amp; Discovery Layer
Files · Docker · Swarm · Kubernetes · KV Stores
Proxy Core — Pingora
Routing · TLS · Middleware · Load Balancing · Caching
Backend Services
Containers · APIs · Virtual Machines · Clusters

Suggested repository structure:
proxy/
├── crates/
│   ├── proxy-core/
│   ├── proxy-config/
│   ├── proxy-routing/
│   ├── proxy-tls/
│   ├── proxy-balancer/
│   ├── proxy-cache/
│   ├── proxy-middleware/
│   ├── proxy-observability/
│   ├── proxy-api/
│   └── providers/
│       ├── file/
│       ├── docker/
│       ├── swarm/
│       ├── kubernetes/
│       ├── cloudflare/
│       └── consul/
├── apps/
│   ├── cli/
│   └── dashboard/
├── deployments/
│   ├── docker/
│   ├── helm/
│   └── systemd/
├── benchmarks/
├── examples/
├── docs/
└── tests/


The dashboard can use Next.js, React, and Tailwind, while the proxy and its main configuration components remain in Rust. A small deployment should run using just the Rust binary.
10. Suggested release roadmap
Release	Main goal	Key deliverables
v0.1	Working reverse proxy	HTTP/1.1, HTTP/2, TLS, host/path routing, YAML, CLI, logs
v0.2	Docker-native	Docker Compose, Docker discovery, native labels, Traefik label subset
v0.3	Automatic HTTPS	ACME, DNS-01, Cloudflare DNS, renewal, certificate storage
v0.4	Production reliability	Load balancing, health checks, retries, rate limits, metrics
v0.5	Management	REST API, optional dashboard, config history and rollback
v0.6	Extended proxy	TCP/UDP, caching, advanced routing and middleware
v0.7	Orchestration	Docker Swarm and Kubernetes Gateway API
v0.8	Extensibility	Plugin SDK, authentication, API gateway modules
v0.9	Distributed infrastructure	Cluster config, rate-limit coordination, advanced failover
v1.0	Stable release	Protocol conformance, audits, performance validation, stable APIs

The release numbers are a proposed sequence rather than fixed commitments. HTTP/3 and advanced L4 support should have separate engineering tracks and only enter a release when their implementation is validated.
11. Critical decisions before development
There are five especially important decisions.

1. Build on Pingora directly or extend Pingap?

Pingap already implements a significant part of the basic roadmap. We should evaluate its internal architecture, extensibility, upstream activity, and test coverage before deciding whether to create an entirely new Rust project or contribute to/fork an existing one. Its Apache-2.0 license permits that, subject to license requirements.

2. Define real compatibility, not just similar functionality.

For Docker, for example, supporting traefik.http.routers.\* labels is more meaningful than merely providing a separate label format. But compatibility must be implemented and tested feature by feature.

3. Make configuration deterministic.

When file, Docker, Kubernetes, and API providers define conflicting routes, the system needs clear ownership, source priorities, conflict rejection, and rollback. No provider should silently overwrite another provider's configuration.

4. Keep the core independent.

A single-VPS installation should not require Redis, PostgreSQL, a dashboard, or a cluster. Distributed state, shared certificates, and a central control plane should be optional extensions.

5. Define measurable acceptance criteria.

A release should only be described as production-ready when it passes correctness, security, failure recovery, and performance tests. For high-traffic claims, publish hardware details, request profiles, TLS settings, concurrency, throughput, and latency distributions.
12. What I would prioritize

First: Docker and Traefik compatibility

A developer should be able to replace their existing Traefik deployment with minimal changes. This gives the project an immediately useful migration path.




Second: Caddy-level HTTPS simplicity

Automatic certificate issuance, renewals, Cloudflare DNS challenges, and safe TLS defaults should work without complicated configuration.




Third: HAProxy-class reliability

Strong health checks, effective load balancing, strict limits, predictable failures, and verifiable performance.




Fourth: Kubernetes and extensibility

Gateway API conformance, distributed infrastructure support, and a plugin system that won't compromise the stability of the proxy core.



My suggested product positioning:
An open-source, Rust-powered reverse proxy that combines NGINX's flexibility, Traefik's service discovery, Caddy's automatic HTTPS, and HAProxy's reliability — built on Cloudflare Pingora.