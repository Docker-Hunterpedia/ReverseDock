# ReverseDock — Roadmap

Milestones, not dates. Each milestone ships a usable binary and has acceptance criteria that CI can verify. Requirement IDs refer to [04-requirements.md](04-requirements.md); P-levels to the [feature matrix](03-feature-matrix.md). Every ID in 04 appears in exactly one milestone below or in the *Unscheduled* list at the end.

| Milestone | Theme | You can… |
|---|---|---|
| **M0** | Foundations | build, lint, test, release; model + schema exist |
| **v0.1** | Hello proxy | replace NGINX for host/path routing with manual certs |
| **v0.2** | Docker-native | replace Traefik on a Compose/Dokploy box using existing labels |
| **v0.3** | Automatic HTTPS | go from DNS → HTTPS with one label; survive 45-day certs |
| **v0.4** | Production reliability | run busy APIs: LB, health, retries, limits, mTLS, JWT, compression |
| **v0.5** | Management | operate it from a dashboard and REST API with history/rollback |
| **v0.6** | Swarm + L4 + static | multi-node Docker, TCP/SNI passthrough, static sites, more DNS providers |
| **v0.7** | Kubernetes | run it as a Gateway API controller |
| **v0.8** | Cache + extensibility | cache like NGINX, extend with plugins/agents, API-gateway features |
| **v0.9** | Scale | multi-instance control plane, distributed limits, zero-downtime listener changes, HTTP/3 (experimental) |
| **v1.0** | Stable | stability guarantees, audit, conformance, docs site |

---

## M0 — Foundations
**Status:** implemented; first published pre-release `0.1.0-alpha.2`: workspace, `rdock-rules`, `rdock-model` + schema, `rdock-config` loader, `rdock validate|schema|version`, CI, release pipeline, Dockerfile.
**Scope:** workspace skeleton (all crates with READMEs), `rdock-model` + JSON Schema export, `rdock-rules` parser with property tests, CI (fmt/clippy/nextest/deny/audit/Semgrep), release pipeline (`cargo-dist`, checksums, SBOM, cosign — empty releases are fine), `justfile`, Dockerfile skeleton, CONTRIBUTING/SECURITY/CoC/issue templates, ADRs 0001–0010. IDs: F-OSS-01, F-OSS-02, F-OSS-03.
**Done when:** `just ci` is green; `schema/rdock.v1.json` is generated and validated against the YAML examples in `docs/05-architecture.md`; a tagged pre-release produces signed artifacts.

## v0.1 — Hello proxy (P0 core)
**Status:** implemented on `feat/v0.1-hello-proxy`, to be released as `0.1.0-alpha.3`. Listener changes apply in-process without a restart ([ADR-0012](decisions/0012-own-listeners-pingora-http-engine.md), superseding ADR-0008); settings planned for later versions are reported by `rdock validate` and refused by `rdock run` ([ADR-0014](decisions/0014-http-semantics-v0-1.md)).
**Scope:** B-NET-01…13, B-TLS-01/09/10/11, B-CFG-01…10, B-SEC-01…09, B-SEC-11, B-SEC-12, B-OBS-01…03, F-OSS-04, W-PLAT-01/03/05, W-OBS-01…03 (P0 parts). File provider with watch, SIGHUP/CLI reload, LKG, history, `restart required` path for listener changes (ADR-0008). Middlewares: headers, redirect, rewrite/strip/add prefix, basic_auth, forward_auth, ip_allow/deny, rate_limit, cors, compress (gzip), errors, maintenance. Error pages. `rdock validate|run|reload|status|version`. Official image + Compose example + systemd unit.
**Done when:** e2e suite proves h1/h2/h2c/WebSocket/SSE/gRPC proxying, forwarded-header rules, reload under load (no failed requests in a 60 s `oha` run during 20 reloads), listener-change restart path under Docker and systemd, smuggling test vectors rejected, differential fuzz target exists.

## v0.2 — Docker-native (P0 providers)
**Scope:** W-DKR-01…08, B-DKR-01, B-SEC-10, B-CFG-11, W-PLAT-02 (zero-config mode), F-MGMT-03 (`rdock migrate traefik`: labels → YAML preview), Traefik subset table in architecture §11, diagnostics for unsupported labels, Compose examples (basic, Dokploy, Coolify, Portainer), socket-proxy docs. The provider merge of [ADR-0018](decisions/0018-docker-provider-and-merge.md), which also brings extra configuration files (`providers.file.paths`). Plan and issues: the [v0.2 milestone](https://github.com/Docker-Hunterpedia/ReverseDock/milestone/3).
**Done when:** `tests/conformance/traefik-labels` (≥ 40 Compose fixtures) produce the expected routing tables; container start/stop/health events reflected within 1 s; Docker socket loss does not drop traffic.

## v0.3 — Automatic HTTPS (P0 TLS)
**Scope:** B-TLS-02…08/12/13, W-CF-01…05, W-DNS-01, W-PLAT-04 (Tunnel example), ACME HTTP-01/TLS-ALPN-01/DNS-01, ARI scheduler, profiles, storage, alerts, local CA (`rdock trust`), HSTS, http→https defaults, Cloudflare IP sync + `CF-Connecting-IP`, Origin CA guidance, Tunnel example. Docs site (F-MGMT-05) starts here as an out-of-band track.
**Done when:** e2e against Pebble: issue, renew via ARI, recover from CA outage, wildcard via mocked DNS-01; fresh-VPS scenario script reaches valid HTTPS < 60 s; cert metrics and alerts fire in tests.

## v0.4 — Production reliability (P1 traffic)
**Scope:** M-LB-01…10, M-TLS-01, M-SEC-01, M-RT-02…07, M-TM-01…07, M-OBS-01/02/03, M-L4-05, W-CF-07, W-CF-08, H-ENG-01…03 (first benchmark publication). Retries per ADR-0010 (transport failures before response headers).
**Done when:** chaos suite (toxiproxy: latency, resets, partial outages; backend flapping) passes with documented behaviour; retry budget prevents amplification in a simulated outage; mTLS and JWT suites pass; published benchmark report vs NGINX/Traefik/Caddy/HAProxy with identical configs.

## v0.5 — Management (P1 admin)
**Scope:** M-ADM-01…04, F-UI-01…06, M-OBS-04, M-OBS-05 (Grafana dashboards), F-MGMT-01/04/05 (docs site v1), H-ENG-04, audit log, tokens/RBAC, SSE logs/events, ring-buffer charts, config editor with schema validation + diff + rollback, OpenAPI + generated TS client.
**Done when:** Playwright suite covers all pages in light/dark/LTR/RTL at 400–1440 px; API conformance tests against OpenAPI; admin never on request path (verified by killing the admin task under load — H-ENG-04); security review checklist for the admin surface complete.

## v0.6 — Swarm, L4, static (P1 breadth)
**Scope:** W-SWM-01…03, M-L4-01…03, F-WEB-01, W-DNS-02, W-DNS-03, Traefik `tcp.*` label subset, PROXY protocol, SNI passthrough, static files with SPA fallback.
**Done when:** 3-node Swarm e2e (scale up/down, rolling update without 5xx); passthrough of a TLS database connection; static-file suite (ranges, conditionals, traversal attempts); every DNS adapter has a mocked-API test.

## v0.7 — Kubernetes (P2)
**Scope:** W-K8S-01…05, Helm chart, Ingress translation, leader election, status conditions.
**Done when:** upstream Gateway API conformance profiles `GATEWAY-HTTP`, `GATEWAY-GRPC`, `GATEWAY-TLS` pass on kind in CI (TCP/UDP tests as they leave provisional status); Helm install on k3s documented and tested.

## v0.8 — Cache and extensibility (P2)
**Scope:** F-WEB-02, F-WEB-03 cache (memory + disk, purge API, SWR/SIE), F-EXT-01…05 (stable native trait, WASM experimental, out-of-process agents, plugin SDK + signatures), F-GW-01…05, W-CF-06 (Cloudflare Access JWT), M-L4-04 UDP, F-MGMT-02 Terraform provider (W-OBS-03 P2 part), W-OBS-02 Vault/External Secrets, status-code retries if the upstream Pingora hook landed (ADR-0010).
**Done when:** cache conformance against an RFC 9111 test-suite subset; stampede test shows a single origin fetch; plugin SDK with two example plugins; WAF agent example (CRS-compatible engine) wired as an agent.

## v0.9 — Scale (P3)
**Scope:** H-HA-01…05 (`rdock-control`, ACK/NACK rollout, shared cert storage, distributed rate limits), H-LB-01…04, H-SEC-01…07, H-PERF-01…06 (supervisor/worker model with fd transfer: zero-downtime upgrades and listener changes), F-UI-07, **HTTP/3 ingress experimental** (feature-gated BoringSSL build, ADR-0006).
**Done when:** 3-instance cluster survives control-plane outage; no duplicate certificate issuance across instances; fd-transfer e2e keeps WebSocket/SSE connections alive across an upgrade and a listener change; HTTP/3 interop with h3i/curl; 24 h soak at target RPS without memory growth.

## v1.0 — Stable
**Scope:** API/config stability guarantees, deprecation policy, F-OSS-05 support policy, third-party security audit (HTTP parsing, TLS/ACME, admin), full docs site with schema-driven playground, migration guides (Traefik, Caddy; NGINX directive subset from F-MGMT-03), signed releases + SBOM in place since M0.
**Done when:** the 1.0 success criteria in [01-vision.md §7](01-vision.md) are all met.

---

### Unscheduled / out of scope for 1.0
F-WEB-04 (FastCGI), F-WEB-05 (forward-proxy mode), F-WEB-06 (mail proxy), H-PERF-07 (eBPF experiments), W-PLAT-06/07/08 (Nomad/Consul, KV config, ECS providers). They are tracked in 04 so nobody re-proposes them by accident; each needs its own ADR before it enters a milestone.

### Out-of-band tracks (never block a milestone)
- **HTTP/3** (BoringSSL variant; depends on `tokio-quiche` maturity and the h3→h2c hop measurements).
- **Cache** (depends on `pingora-cache` API stability; we pin and adapt).
- **Benchmarks** (nightly job, results published per release).
- **Website and docs** (Astro + Starlight, [09-website](09-website.md), [ADR-0017](decisions/0017-website-astro-starlight.md)): W0 launches before v0.2, and every later milestone ships with its docs (W1 with v0.2, W2 with v0.3, W3 from v0.5 to v1.0).
