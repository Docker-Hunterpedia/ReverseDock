# ReverseDock threat model

- Status: living document, first written 2026-11-14 (v1.0 step 8, [ADR-0033](decisions/0033-v1-0-stable.md))
- Tree: `1.0.0-rc.1`, that is `0.9.0-alpha.1` plus the v1.0 work (release builds: default features `docker`, `swarm`, `kubernetes`, `mimalloc`; **not** `wasm`, `http3`, `fault-injection`, `alloc-count`, `jemalloc`)
- Audience: an external security auditor, first; contributors changing a surface listed here, second

This document says what ReverseDock protects, from whom, where the trust boundaries are, and for each entry point which threats were considered, what mitigates them **with the code and the test that proves it**, what is left (residual risk) and what is out of scope. Every claim names a file or a test so that it can be checked; a mitigation without a test is marked **untested**. It complements, and does not replace, the control table in [architecture §15](05-architecture.md#15-security-model), the [ASVS 5.0 Level 2 review of the admin surface](security/asvs-5.0-l2-admin.md) (v0.5), the review notes in [ADR-0025](decisions/0025-admin-limits-and-review-fixes.md), [ADR-0030](decisions/0030-v0-8-cache-extensibility-gateway.md) (v0.8 security review, 2026-11-12), [ADR-0031](decisions/0031-v0-9-scale.md) and [ADR-0032](decisions/0032-http3-on-quinn-and-h3.md) (v0.9 reviews), and the smuggling catalogue in [research/v0.1-security.md](research/v0.1-security.md).

Test names are written `file::test`; `e2e_*` files are in `crates/rdock/tests/`, others in the named crate. Fuzz targets are in `tests/fuzz/` ([§8](#8-how-the-project-tests-itself)).

## Contents

1. [Scope of a first audit](#1-scope-of-a-first-audit)
2. [System and upstream components](#2-system-and-upstream-components)
3. [Assets](#3-assets)
4. [Actors](#4-actors)
5. [Trust boundaries](#5-trust-boundaries)
6. [Entry points, threats and mitigations](#6-entry-points-threats-and-mitigations)
7. [Residual risks](#7-residual-risks)
8. [How the project tests itself](#8-how-the-project-tests-itself)
9. [Out of scope](#9-out-of-scope)
10. [Before commissioning an audit (maintainer checklist)](#10-before-commissioning-an-audit-maintainer-checklist)

## 1. Scope of a first audit

The 1.0 criterion ([vision §7](01-vision.md)) asks for an independent review of **HTTP parsing, TLS/ACME and the admin surface**. The proposed first scope:

| In the first scope | Crates (lines of non-test Rust, 2026-11-14) |
|---|---|
| HTTP/1.1 and HTTP/2 data plane as far as it is ours: request checks, routing, path normalisation, forwarding headers, hop-by-hop handling, own answers, PROXY protocol, the ClientHello peek and TLS listener setup, session resumption | `rdock-proxy` (20,229), `rdock-rules` (1,887), `rdock-tls` (2,832), the request-phase middlewares that authenticate (`rdock-middleware`, 18,577, of which `auth`, `jwt`, `oidc`, `api_key`, `forward_auth`, `client_cert`) |
| ACME client, certificate storage and renewal, the local CA, DNS-01 adapters | `rdock-acme` (5,363), `rdock-dns-providers` (4,053) |
| Admin API, dashboard serving, users, sessions, tokens, TOTP, audit log, configuration API | `rdock-admin` (11,431), `rdock-credentials` (586), the admin parts of `rdock` (`crates/rdock/src/admin_cli.rs`, `engine.rs`) |

Proposed for a second scope: providers (Docker, Swarm, Kubernetes), the cluster (`rdock-cluster`, `rdock-control`), the cache, static files, TCP/UDP, plugins and agents.

**Outside the first scope unless the maintainer includes them:** the experimental HTTP/3 ingress (`http3` feature, ADR-0032) and WASM plugins (`wasm` feature, ADR-0030). Both are off in release builds and refused by configuration without the `experimental:` opt-in (ADR-0033). The Terraform provider and the Go client (`clients/`) are beta tools that run on an operator's machine, not in the proxy.

## 2. System and upstream components

```
                  Internet clients                           Operators
                         |                                       |
          HTTP/1.1, HTTP/2, TLS, PROXY, TCP, UDP          CLI over the Unix socket,
          (HTTP/3: experimental, off in releases)         browser/API over the admin listener
                         |                                       |
  +----------------------|---------------------------------------|----------------------+
  |  rdock process       v                                       v                      |
  |  +-------------------------------+   ArcSwap snapshot   +---------------------+    |
  |  | data plane (Pingora runtime)  | <------------------- | engine (config,     |    |
  |  | listeners, routes,            |   one-way: the data  | reload, providers,  |    |
  |  | middlewares, balancer, cache  |   plane never calls  | ACME manager)       |    |
  |  +-------------------------------+   the admin side     +---------------------+    |
  |        |            |                                     ^     |        ^          |
  |        |            | outbound calls                      |     |        |          |
  |        |            +--> forward-auth, agents, JWKS/OIDC, |     |   +----------+    |
  |        |                 Vault, webhooks, DNS APIs,      |     |   | admin    |    |
  |        |                 Redis (cluster limits)          |     |   | runtime  |    |
  |        v                                                  |     |   +----------+    |
  |   backends (upstream trust: X-Forwarded-*, identity hdrs) |     v                   |
  |                                                           |  data directory          |
  |                                                           |  (keys, ACME account,    |
  |                                                           |   users, tokens, audit,  |
  |                                                           |   config history)        |
  +-----------------------------------------------------------|--------------------------+
          ^                         ^                          |
   Docker / Swarm socket     Kubernetes API             ACME CA (directory, orders, ARI)
   (labels from containers)  (routes from namespaces)   control plane (cluster bundles,
                                                         store, join and enrolment)
```

The data plane is Pingora's HTTP engine behind our own accept loops (ADR-0012); everything that decides about a request (routing, middlewares, selection, own answers) is ours. Facts below about upstream components are from the pinned versions in `Cargo.lock`:

| Upstream component | Version | What it does for us | Their security posture |
|---|---|---|---|
| Pingora (`pingora-core`, `-proxy`, `-cache`) | 0.9.1 | HTTP/1.1 parsing and framing (on `httparse` 1.10.1), HTTP/2 via `h2`, connection pools, cache state machine | Cloudflare fixed three request-smuggling issues in 0.8.0 (CVE-2026-2833, -2835, -2836; https://blog.cloudflare.com/pingora-oss-smuggling-vulnerabilities, read 2026-11-13); 0.9.1 is after the fix. Pingora calls its rustls backend and cache experimental |
| `h2` | 0.4.20 | HTTP/2 frames, HPACK, flow control, reset limits | — |
| rustls / ring | 0.23.46 / 0.17.14 | TLS 1.2/1.3 handshake and record layer, crypto (ADR-0013) | rustls is fuzzed upstream on OSS-Fuzz (its `SECURITY.md`) |
| `instant-acme` | 0.8.5 | ACME protocol: JWS, directory, orders, authorisations, problem documents, ARI requests | — |
| hyper | 1.12.0 | Outbound HTTP clients (ACME, webhooks, JWKS, Vault, DNS APIs, cluster) and the admin server under axum 0.8.9 | — |
| argon2 | 0.6.0 | Admin password hashes | — |
| bollard / kube | 0.21.1 / 5.0.0 | Docker Engine API and Kubernetes API clients | — |

## 3. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| TLS private keys of served certificates | `<data dir>/acme/certs/*/key.pem` (`0600`), operator files named in `certificates`, cluster store | Impersonation of every served name |
| ACME account key | `<data dir>/acme/accounts/*` (`0600`), cluster store | Revocation and issuance under the operator's account; rate-limit exhaustion |
| Local CA root key (`pki/`) | `<data dir>/pki` | Trusted by clients that installed it for private names |
| Admin credentials and sessions | `users.json` (argon2 hashes, TOTP secrets), `tokens.json` (SHA-256 of secrets), session cookies, the bootstrap token | Full control of the proxy |
| Audit log | `<data dir>/audit/*.jsonl`, hash-chained; optional forwarding over syslog/TLS | Accountability for every admin change |
| Configuration and its history | the operator's files, `<data dir>/config/` (API snapshot, history) | Decides what is exposed and to whom |
| Secrets referenced by configuration | files, environment, Vault (`${file:…}`, `${env:…}`, `${vault:…}`), resolved only in memory | Backend credentials, DNS API keys, OIDC client secrets, API-key material |
| Upstream trust | headers rdock sets for backends: `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, identity headers from authentication middlewares, client-certificate headers | Backends trust them to make access decisions |
| Client traffic | requests and responses in transit, cached objects, held bodies, logs | Confidentiality and integrity for every user |
| Cluster CA and join tokens | control plane's store (`rdock-control`), data-plane identities | A rogue instance could join and receive configuration and keys |
| Tenant boundaries | tenant prefixes and host claims in the configuration (ADR-0031) | One tenant must not read or route another's traffic |
| Availability of the data plane | the process | A reverse proxy outage is everyone's outage |

## 4. Actors

| Actor | Capabilities assumed | Trusted for |
|---|---|---|
| A1 Unauthenticated Internet client | Any bytes to any public listener (HTTP/1.1, HTTP/2, TLS, PROXY header if the source is not trusted, TCP/UDP routes); many connections; slow reads and writes | Nothing |
| A2 Authenticated low-privilege admin user | A viewer or operator account or token; the admin API and dashboard within that role | What the role allows; never more (no escalation, no reading secrets) |
| A3 Tenant | A user or token scoped to a tenant prefix (ADR-0031) | Its own objects and host claims only |
| A4 Container on a Docker host | Sets any label on its own container; reaches other containers on shared networks | Nothing by default (containers are not exposed without `rdock.enable`/`traefik.enable` or `expose_by_default`); once exposed, the routes its labels declare |
| A5 Kubernetes namespace user | Creates Gateway API routes, Ingresses, Services, Secrets in its namespaces | Routes in its namespace attached where the Gateway's `allowedRoutes` permit; cross-namespace references only with a `ReferenceGrant` |
| A6 Compromised backend | Any response bytes, slow or none; `Retry-After`; status codes that drive retries and ejection | Response content for its own routes |
| A7 Compromised cluster member (data plane) | A valid client certificate and the channel to the control plane | Its own reports and store operations within its lease |
| A8 Compromised control plane | Publishes bundles, answers store calls, issues certificates | Configuration of the whole cluster (by design; this is a full compromise) |
| A9 Local unprivileged user on the host | Connects to loopback ports; reads world-readable files; cannot read `0600` files owned by rdock's user | Nothing |
| A10 Malicious upstream CA or DNS | Arbitrary ACME answers (directory, order, `Retry-After`, ARI windows, certificate chains); arbitrary DNS answers to resolutions rdock makes | The CA is trusted to issue only to the account holder; its answers are parsed defensively |
| A11 Supply-chain attacker | A malicious crate version, GitHub Action or base image | Nothing |

The operator (who writes the configuration file and runs the binary) and admins with the `admin` role are trusted. An operator's configuration that is unsafe is refused with a diagnostic where we can tell ([CLAUDE.md design rule](../CLAUDE.md#design-rule)), but a malicious operator is out of scope.

## 5. Trust boundaries

| # | Boundary | Crossed by | Direction of trust |
|---|---|---|---|
| B1 | Network → listeners | A1, A6 (responses) | Untrusted bytes in; parsed by Pingora/h2/rustls and our checks before routing |
| B2 | rdock → backends | Forwarded requests; backend responses | Backends trust rdock's forwarding and identity headers; rdock does not trust responses |
| B3 | Network/loopback → admin listener; local user → admin Unix socket | A2, A3, A9 | Authenticated by token or session (listener), by socket file mode (socket) |
| B4 | Providers → engine | Docker/Swarm labels (A4), Kubernetes objects (A5), file provider (operator) | Provider objects are less trusted than the file: they cannot use references, read files, run commands or claim another provider's names (namespaced keys) |
| B5 | rdock → outbound services | ACME CA (A10), DNS providers, forward-auth, agents, JWKS/OIDC, Vault, webhooks, Redis | Answers are parsed with size and time limits; private targets refused unless allowed |
| B6 | Control plane ↔ data planes | mTLS with enrolled identities; bundles with digests; store calls with leases | Data planes trust the control plane (A8 is a full compromise); the control plane trusts a data plane only for its own reports and leases |
| B7 | Process ↔ data directory | The process (single writer, lock file), A9 | `0700`/`0600` modes; another local user cannot read keys |
| B8 | Old ↔ new process during a binary upgrade | Socket handover over the admin socket | Only the same user's process with access to the socket |
| B9 | Build → release | CI, dependencies, actions, base images (A11) | Pinned and signed (§8) |

## 6. Entry points, threats and mitigations

Each subsection lists threats (STRIDE letter in brackets: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege), the mitigation with code and test, and what is left.

### 6.1 HTTP/1.1 listeners (B1)

| Threat | Mitigation (code) | Proof (test) |
|---|---|---|
| [T] Request smuggling: conflicting or duplicate `Content-Length`, obfuscated `Transfer-Encoding`, HTTP/1.0 with `Transfer-Encoding`, bare LF, chunk-size overflow, bad chunk terminators | Pingora 0.9.1 parser and re-framing of every forwarded body; `check_request` in `crates/rdock-proxy/src/proxy.rs` adds `Host` for HTTP/1.1 and refuses obfuscated `Expect` | `e2e_security::content_length_and_transfer_encoding_vectors`, `e2e_security::cl_te_conflict_cannot_smuggle`; fuzz `h1_framing` (differential: what is forwarded is exactly one request) |
| [T] Smuggling through an `Upgrade` before the backend's `101` (the Pingora 0.8.0 class) | Pingora 0.9.1 | `e2e_security::content_length_and_transfer_encoding_vectors` (vector 30) |
| [T][S] Header syntax: duplicate `Host`, missing `Host`, userinfo in authority, absolute-form mismatch, space before colon, obs-fold, CR in a value | Pingora and `check_request` | `e2e_security::target_authority_and_header_syntax_vectors` |
| [T][S] A `Host` that is not `host[:port]` (a path, query, `\`, space, non-numeric port) passing wildcard and `HostRegexp` routes and reaching the backend and `forward_auth` (review 10, M3) | `proxy.rs::valid_authority` in `check_request`: 400 | `proxy::tests::host_must_be_a_host_and_port`; `e2e_security::target_authority_and_header_syntax_vectors` |
| [T] `Connection` naming a header that rdock sets later (`X-Real-IP`, `X-Request-Id`, `X-Forwarded-Port`, identity and fingerprint headers); Pingora removes nominated fields only after the request phase and protects only four names (review 10, M1) | `proxy.rs::strip_connection_nominations` removes the client's nominated fields and the nominations in `early_request_filter`, before any header is set; nominations Pingora refuses (its protected names, malformed tokens, too many) are left for it | `proxy::tests::connection_cannot_remove_headers_rdock_sets_later`; `e2e_security::connection_cannot_strip_headers_rdock_sets`; vector 31 still refused |
| [T] A body hidden from `validate`, `agent`, `transform` and plugins behind an `Upgrade` header that Pingora removes (or a WebSocket handshake the backend declines) (review 10, H1) | `proxy.rs::is_upgrade` counts only `CONNECT` and an HTTP/1.1 `Upgrade: websocket` handshake, as Pingora forwards them; such a handshake that declares a body gets 400 | `proxy::tests::only_websocket_handshakes_and_connect_are_upgrades`, `websocket_handshakes_with_a_body_are_refused`; `e2e_security::an_upgrade_header_does_not_hide_a_body_from_validation` |
| [S] Client-IP spoofing via `X-Forwarded-For`, `Forwarded`, `X-Real-IP` | Only from `trusted_proxies`; untrusted copies replaced (`crates/rdock-proxy/src/forwarded.rs`, `ClientIpPolicy::client_ip`) | Unit tests in `crates/rdock-proxy/src/forwarded.rs`; `e2e_proxy_protocol::*` for the PROXY-protocol address |
| [S] Client-supplied identity headers (user, groups, client certificate, fingerprint) reaching the backend | Authentication middlewares remove client copies before setting their own (`crates/rdock-middleware/src/auth.rs`, `oidc/`, `jwt/`, `client_cert.rs`, `fingerprint` headers) | `e2e_oidc::the_login_flow_admits_browsers_and_refuses_api_requests_without_a_session`, `e2e_mtls::optional_listeners_let_routes_decide_and_forward_the_identity`, `e2e_api_keys::keys_authenticate_revoke_within_one_reload_and_never_leak` |
| [T] Route-match versus forward mismatch through path encoding (`%2F`, dot segments, double slashes) | `rdock_rules::path::normalize`: the forwarded path is the normalised one, routing uses its decoded form with reserved characters kept encoded (ADR-0014) | Unit tests in `crates/rdock-rules/src/path.rs`; fuzz `rules_eval` (the forwarded path normalises to itself; a rule decides the same as its explanation, its negation and its canonical form) |
| [T][E] Paths a backend resolves outside the routed prefix (`/..;/`, `..%2F`, `%2e%2e%5C`, `\..\`, `%00`) getting past a `PathPrefix` rule; the router keeps `%2F` and `%5C` encoded (review 10, M6) | `rdock_rules::path::ambiguous`, refused with 400 by `request_filter` unless `security.paths.ambiguous: forward`; other encoded separators pass as sent unless `security.paths.encoded_separators: reject` (`path::has_encoded_separator`) | `path::tests::ambiguous_spellings_are_found`, `encoded_separators_are_found`, `encoded_separators_are_routed_and_forwarded_as_sent`; `e2e_security::target_authority_and_header_syntax_vectors`, `ambiguous_paths_can_be_forwarded_on_request`, `encoded_separators_without_a_dot_segment_pass_unchanged_by_default`, `encoded_separators_can_be_refused` |
| [T][D] Cache poisoning through the parts of `Host` routing ignores (port, trailing dot) and through trusted forwarding headers (review 10, M2); cache busting with port spellings (`:00080`, `:99999`, `:`) and empty labels (review 10 fixes, M4) | `cache.rs::cache_key` keys on the authority as sent (lower case, IPv6 canonical) and the `X-Forwarded-Proto/-Host/-Port` the backend gets; `proxy.rs::valid_authority` refuses ports in any but their canonical spelling and names with an empty label (400), so a host and port have at most two keys (with and without one trailing dot) | `e2e_cache::the_authority_the_backend_sees_is_part_of_the_key`; `proxy::tests::authorities_are_accepted_only_in_their_canonical_spelling`, `host_must_be_a_host_and_port`; `cache::tests::spellings_of_one_authority_are_one_key` |
| [D] Oversized URI, headers, header count, body | `check_request` (`security.limits`), route `max_body` | `e2e_security::size_limits_are_enforced`, `e2e_limits::a_route_can_allow_larger_bodies_than_the_default` |
| [D] Slowloris and idle connections | Header deadline, idle timeout | `e2e_security::slow_headers_are_cut_off`, `e2e_security::idle_connections_without_bytes_are_closed` |
| [D][E] Rate limits evaded by rotating IPv6 addresses, flushing other clients' buckets (review 10, M4) | `limits.rs::key_of`: an IPv6 client counts by its /64 (`client_ip` and the per-IP fallbacks) | `limits::tests::ipv6_clients_are_keyed_by_their_64` |
| [D][I] `basic_auth`: one client taking every verification slot; user names told apart by timing (review 10, M5); people behind one NAT queued into 429 and an `auth_failure` ban (review 10 fixes, M3) | `auth.rs`: at most `PER_CLIENT` (2) verifications at a time per client (/64 for IPv6), the others wait their turn then get 429, which is not an authentication failure; unknown names verified against a configured hash | `auth::tests::one_client_cannot_take_every_verification_slot`, `turns_are_given_back_however_a_wait_ends`, `unknown_users_cost_a_verification_and_are_refused` |
| [T] A body replayed on another connection after a pooled one failed, counted twice against `max_body`, appended twice to a mirror copy or a held body (review 10 fixes, M1); unbounded attempts on stale pooled connections outside `retries` (fixes L5) | `proxy.rs::upstream_peer` resets the body count, the mirror copy and the held body on every attempt after the first; `error_while_proxy` tries again after a failed pooled connection once per request (`pooled_retried`), then follows `retries` | `e2e_retries::a_replayed_body_on_another_connection_is_counted_once`, `an_idempotent_request_on_a_dropped_pooled_connection_gets_another_connection`; the mirror and held-body cases and the one-extra-attempt bound are **untested** |
| [I] Error answers that leak internals (backend addresses, stack traces) | One renderer for every own answer (`crates/rdock-proxy/src/errorpage.rs`), problem details without addresses | `e2e_errors::rdock_answers_render_as_problem_details_where_configured` (502 detail without the backend address) |
| [I] Content sniffing of rdock's own answers | `X-Content-Type-Options: nosniff` on every answer rdock writes itself (`proxy.rs::reply`, `fail_to_proxy`); never added to proxied responses (v1.0 step 8) | `e2e_errors::own_answers_say_nosniff_and_proxied_ones_are_left_alone` |

Residual: Pingora's parser is upstream code; differences between Pingora's view and a backend's view of a request that both accept are found by fuzzing the forwarded form, not by a second parser of the backend's kind. Header-name case and underscore handling follow Pingora (underscores are passed; Envoy refuses them at the edge by default). A backend that decodes `%2F` or `%5C` into separators and then makes its own access decision sees a different path than the router for spellings without a dot segment (`group%2Fproject`); `encoded_separators: reject` is the strict option. The bare-LF check covers the header block at the start of each read; a pipelined request in the same read is parsed by Pingora alone (rdock re-serialises what it forwards). `basic_auth` still lets many clients together hold every verification slot; put `rate_limit` or `abuse` in front of it. **Untested:** a request after an aborted body on a reused connection (pipelining after an error) has no dedicated test.

### 6.2 HTTP/2 listeners (B1)

HTTP/2 framing, HPACK and flow control are `h2`'s and Pingora's. What is ours: the per-listener settings and their validation (`crates/rdock-model/src/listener.rs`, `listeners.<l>.http2`), mapped onto Pingora's `H2Options`, and everything after the request head (shared with HTTP/1.1).

| Threat | Mitigation | Proof |
|---|---|---|
| [D] Rapid Reset (CVE-2023-44487), MadeYouReset (CVE-2025-8671) | `max_pending_accept_reset_streams`, `max_local_error_reset_streams` with bounded defaults; the validator names "unlimited" explicitly | `e2e_http2::http2_settings_reach_the_client`, `e2e_http2::a_flood_limit_above_the_ceiling_names_unlimited` |
| [D] Memory growth from a slow reader | `max_send_buffer`, stream windows | `e2e_http2::a_slow_http2_reader_does_not_grow_proxy_memory` |
| [D] CONTINUATION flood, HPACK bomb, header count | `max_header_list_size`; `security.limits.max_headers` applies to the decoded request (`check_request`) | **Untested** as floods: no test sends CONTINUATION without END_HEADERS or an HPACK amplification; relies on `h2` 0.4.20 |
| [T] HTTP/2 → HTTP/1 translation: pseudo-headers, CR/LF or colons in names and values, connection-specific headers, `content-length` against DATA | `h2` validates fields; Pingora builds the HTTP/1 request; `HeaderValue` cannot hold CR/LF | **Untested** by a project test; no h2→h1 differential target exists (the HTTP/3 mapping, which is ours, has one: `http3_request`) |

Residual: HTTP/2 denial-of-service resistance is as good as `h2` 0.4.20's limits and our defaults; the 2026 "HTTP/2 bomb" class (press reports only, see research Part C 3.4) is not tested.

### 6.3 TLS listeners and the ClientHello peek (B1)

| Threat | Mitigation | Proof |
|---|---|---|
| [T][D] Malformed or fragmented ClientHello in our own peek (SNI routing, fingerprints) | `crates/rdock-tls/src/clienthello.rs`: 16 KiB, 128 extensions, duplicates refused, reassembly across records, rewind | Fuzz `clienthello`, `tls_fingerprint`; unit tests in the same file |
| [D] Handshake floods | `tls.max_handshakes`, handshake timeout | `e2e_sockets::the_handshake_bound_keeps_established_connections_served` |
| [S][E] A session resumed on a listener that requires client certificates from one that does not | Ticket keys per security class (`crates/rdock-tls/src/tickets.rs`) | `e2e_tls_resumption::a_session_without_client_authentication_never_resumes_where_it_is_required` |
| [S] Client certificate checks, SPIFFE identities | rustls `WebPkiClientVerifier` per listener; typed field rules (`crates/rdock-middleware/src/client_cert.rs`) | `e2e_mtls::a_required_client_certificate_is_verified`, `e2e_mtls::validate_refuses_client_auth_without_roots` |
| [I] TLS-ALPN-01 validation certificates served to ordinary clients | Served only for `acme-tls/1` | `e2e_acme::issues_through_tls_alpn01_and_hides_validation_certificates` |
| [S] Upstream TLS without verification | Verification on by default; `insecure` explicit and diagnosed | `e2e_mtls::services_present_a_client_certificate_to_backends`; validation tests in `crates/rdock-model/src/validate/tests.rs` (`flags_risky_security_and_admin_settings`) |

Residual: no revocation checking of client certificates (CRL/OCSP) is offered; this is documented as absent. Private keys are not zeroised in memory (rustls holds them).

### 6.4 PROXY protocol (B1)

| Threat | Mitigation | Proof |
|---|---|---|
| [S] A client sends a PROXY header to claim another address | Read only from the listener's `trusted` sources; required once a source is trusted; an untrusted sender is closed and counted | `e2e_proxy_protocol::untrusted_sender_of_a_header_is_closed_and_counted`, `e2e_proxy_protocol::listener_without_proxy_protocol_never_looks_for_a_header` |
| [T][D] Malformed headers | `proxy-header` 0.1.3 parser, prefix-safe | Fuzz `proxy_header`; `e2e_proxy_protocol::haproxy_send_proxy_interop` |

### 6.5 TCP and UDP routes (B1)

| Threat | Mitigation | Proof |
|---|---|---|
| [D] Connection and session exhaustion | `in_flight` per client, UDP session caps (`sessions.max`, `max_per_client`), idle timeouts | `e2e_tcp::in_flight_limits_connections_per_client`, `e2e_tcp::an_idle_relay_is_closed`, `e2e_udp::session_caps_drop_and_count_without_answering` |
| [S] Spoofed UDP sources (reflection) | Nothing answers before a route, filters and caps admit a session; drops are never answered | `e2e_udp::ip_deny_and_unmatched_clients_are_dropped_silently` |

Residual: UDP is connectionless; source addresses cannot be verified. Use `ip_allow` for UDP services exposed to the Internet.

### 6.6 Backend responses (B2, actor A6)

| Threat | Mitigation | Proof |
|---|---|---|
| [T] Connection-specific response headers (`Connection`-nominated, `Keep-Alive`, `Proxy-Connection`, `Upgrade`) passed to the client | `proxy.rs::strip_response_hop_by_hop` (Pingora only cleans requests); a `101` keeps them | Fuzz `backend_response` (v1.0 step 8: nominated headers gone, others kept, one response head written back) |
| [D] A backend pausing itself for long with `Retry-After` | Pause capped at 60 s (`MAX_PAUSE` in `proxy.rs`) | Fuzz `backend_response` |
| [D] A failing backend taking the service down | Passive ejection, active checks, retries with a budget (ADR-0015), panic routing when nothing is available (v1.0 step 8) | `e2e_health::*`, `chaos_flapping::*`, `crates/rdock-proxy/tests/selection.rs::panic_mode_prefers_ejected_backends_whose_checks_pass` |
| [T] Cache poisoning through unkeyed inputs | Key: store, route, client scheme, lower-cased host, path and query rules, `Vary` (§19); authenticated routes need an explicit statement | `e2e_cache::two_routes_sharing_a_store_never_see_each_others_objects`, `e2e_cache::vary_keeps_one_variant_per_value`, `e2e_cache::caching_an_authenticated_route_needs_an_explicit_statement` |
| [T] Corrupt stored cache entries | Header decoder with limits | Fuzz `disk_cache_header`; `e2e_cache::the_disk_store_survives_restarts_streams_large_objects_and_drops_damage` |

Residual: response-side framing (a backend's `Content-Length` against its body, `HEAD`/`204`/`304` bodies) is Pingora's; no project fuzz target drives Pingora's response parser (the `backend_response` target starts from a parsed head).

### 6.7 Providers (B4)

| Threat | Mitigation | Proof |
|---|---|---|
| [E] A container exposes itself without the operator's consent | Not exposed by default; `rdock.enable`/`traefik.enable` or `expose_by_default` | Fuzz `docker_labels` (a container without an enable label contributes no route, whatever its other labels); provider conformance fixtures |
| [I][E] Labels that read secrets or files (`${file:…}`, `${env:…}`, `${vault:…}`) | `${…}` refused in labels (`crates/providers/rdock-provider-docker/src/labels.rs`); provider objects hold no references in secret fields; Vault references only from the file | `rdock-provider-docker` `labels::tests::unsupported_and_unsafe_labels_are_warnings`; `rdock-model` `validate::tests::provider_objects_hold_no_references_in_secret_fields`; `e2e_vault::provider_objects_cannot_make_rdock_read_vault` |
| [E] A container claims a hostname another service serves | Provider objects are namespaced (`name@docker`); a provider route that conflicts with the file is left out with a diagnostic | `rdock-config` `merge::tests::provider_objects_get_qualified_keys_and_same_provider_references` |
| [S][E] A container requests certificates for arbitrary names | Any exposed container can name any host; certificates are requested for configured names only; a name that failed keeps its back-off when its route leaves and returns, per name, so a new set of names around it starts no new order (`rdock-acme` `state.rs::Backoffs`, review 10 admin M3 and fixes L1) | `state::tests::a_name_that_leaves_and_returns_keeps_its_back_off`, `a_name_that_returns_with_other_names_keeps_its_back_off`; **residual risk** (§7): no per-provider allow-list of names |
| [E][I] Labels that make rdock reach its own machine: a `unix://` backend (the admin socket), loopback, `localhost`, link-local (cloud metadata), numeric spellings, URL-parser spellings (`\@`, `%31`, full-width digits) and DNS names that resolve to such addresses; files named by `*_file` and `openapi`, `wasm` modules (review 10, M7 and admin L5; fixes H2, L4) | `labels.rs::local_backend_refusal`, `local_url_refusal` (URLs parsed as `HttpUrl`; opt-in `allow_local_backends`, never sockets); at connect time, `BackendPolicy::NotLocal` on every resolved address of a label service (`compile.rs::label_guard`, HTTP, TCP and UDP) and of a label middleware's requests (`HttpClient::guarded`); `native.rs::no_file` | `labels::tests::labels_cannot_reach_the_proxys_own_machine_unless_allowed`, `middleware_urls_from_labels_are_judged_by_the_host_the_url_parser_sees`, `labels_cannot_name_files_on_the_proxys_host`; `tenant_addresses::label_services_never_reach_the_machine_through_a_name`; `client::tests::a_guarded_client_never_connects_to_the_machine_however_a_name_resolves`; `addresses::tests::labels_reach_private_networks_but_not_the_machine_or_its_link` |
| [E][I] A label `static` middleware with `symlinks: all` escaping `static_roots` (review 10, admin H2) | `compile.rs::check_label_root` refuses it | `compile::tests::label_middlewares_cannot_follow_links_out_of_their_root` |
| [I] Docker socket abuse | Read-only Engine API calls (`list`, `inspect`, `events`); socket-proxy documented | `e2e_docker::docker_containers_are_routed_and_socket_loss_keeps_traffic`; the call list is in `crates/providers/rdock-provider-docker/src/watch.rs` (no test asserts the absence of write calls: **untested**) |
| [E] Kubernetes cross-namespace references | Only with a matching `ReferenceGrant` | `rdock-provider-kubernetes` `gateway::grants::tests::a_grant_must_match_every_field`, `same_namespace_needs_no_grant`; Gateway API conformance suite v1.7.0 in CI |
| [D] Malformed objects from the API | Typed decoding (`kube`, `bollard`), label translation never panics | Fuzz `docker_labels`; Kubernetes decoding is **not fuzzed** (kube's own types) |

### 6.8 Admin API, dashboard and Unix socket (B3)

| Threat | Mitigation | Proof |
|---|---|---|
| [S] Default credentials | None; first admin through a one-time bootstrap token | `rdock-admin` `server::the_bootstrap_token_creates_one_admin_who_can_log_in` |
| [S] Credential guessing, user enumeration | Rate-limited logins per name and address, same answer for unknown users, argon2 hashes | `server::logins_hide_which_users_exist_and_are_rate_limited` |
| [S] Second factor bypass, code replay | TOTP with `last_step` (each code once) | `server::an_admin_enrols_totp_then_logs_in_with_a_second_factor`; fuzz `admin_input` (a code is accepted for one step at most, only after the last one) |
| [E] Role escalation, missing checks on an endpoint | Every operation needs a role; tokens cannot mint tokens; tenant matrix fails closed | `server::roles_limit_tokens_and_metrics_needs_one`, `tests/tenants.rs::the_matrix_of_role_tenant_and_operation_fails_closed`, `e2e_openapi::every_documented_operation_answers_as_documented` |
| [T] CSRF on cookie sessions | CSRF token on writes, `SameSite`, cross-site writes refused | `server::the_api_needs_the_token_and_refuses_cross_site_writes` |
| [S] DNS rebinding, foreign `Host` | Host allow-list | `server::health_answers_with_security_headers_and_foreign_hosts_are_refused` |
| [I] Admin API on the network without TLS | Validation error unless loopback or `admin.tls` | `rdock-model` `validate::tests::a_network_admin_listener_needs_tls_and_known_hosts` |
| [I] Secrets in API answers, history, audit | Masked as `***`; written-back `***` keeps the value | `rdock-admin` `config_api::tests::secrets_are_masked_unless_they_are_references`, `basic_auth_hashes_and_the_old_webhook_url_are_masked`, `masked_values_written_back_keep_the_current_secret`; `e2e_api_keys::keys_authenticate_revoke_within_one_reload_and_never_leak` |
| [T] Lost updates, unvalidated writes | `If-Match` required, validation before apply, dry runs | `server::configuration_writes_are_conditional_dry_run_and_audited` |
| [D] Admin floods taking the data plane down | Own runtime, connection cap, per-caller and global write rates (ADR-0025) | `server::each_caller_has_its_own_request_budget`, `server::configuration_work_is_rate_limited_for_everyone`, `server::bodies_over_a_mebibyte_are_refused`, `chaos_admin::*` |
| [T][D] Malformed request bodies and query strings | Typed bodies with `deny_unknown_fields`; axum `Query` extractor | Fuzz `admin_input` (every body type, every query struct), `json_patch`, `config_loader` |
| [R] Unaudited changes | Reserve audit space first, change second, record third; a lost record leaves an `audit.gap` record (ADR-0033 step 7) | `server::logins_writes_and_refusals_land_in_an_intact_audit_chain`, `chaos_disk::*` |
| [I][E] Local user on the Unix socket | Socket file `0600` (`crates/rdock-admin/src/server.rs`); no token needed by design | `server::the_socket_is_owner_only_needs_no_token_and_is_removed_on_stop` |
| [E] An operator reaching the admin socket or the process's files and secrets through API objects: a `unix://` backend, `static`/`wasm`/`plugin`, file fields, `${…}` references (review 10, admin H1; fixes L4) | `config_api.rs::admit` → `operator_refusal` on every object a non-admin or any tenant-scoped caller adds or changes (422), on every write route | `config_api::tests::operators_cannot_write_objects_that_use_the_process_authority`; `tenants::a_tenant_administrator_cannot_name_a_file_on_the_proxys_machine` |
| [I] An operator redirecting a masked secret by changing the fields around it (review 10, admin M4), or reading or redirecting it through `PATCH`, which patched the unmasked document (JSON Patch `copy`, `move`, `test`) (review 10 fixes, H1) | `config_api.rs::editable`: every write route starts from the masked document; `restore_secrets`: `***` is kept only in an otherwise unchanged object; `secret_operation`: a JSON Patch that copies, moves or tests a secret is refused | `config_api::tests::a_kept_secret_cannot_be_sent_somewhere_else`, `json_patches_cannot_take_or_compare_a_secret`; `server::patches_can_neither_read_nor_redirect_a_kept_secret` |
| [I] Viewers and operators reading audit records on the events stream (review 10, admin M1) | `stream.rs::keeps`: `type: admin` entries only for unscoped admins, re-checked every minute | `stream::tests::admin_records_reach_administrators_only` |
| [D] Unauthenticated refusals filling the audit disk (then 507 on every change) and raising one alert each (review 10, admin H3, M2); one client crowding out other clients' refusals and every new alert with names it chooses (review 10 fixes, M2, L3) | `audit.rs::Audit::coalesce` (one record per minute per action and client, with `repeated`; a per-client entry past the table; `summary:` records for counts with no later record, also at shutdown); alert keys by action and client, and a full alert table drops its oldest entry, never a new alert (`alerts/mod.rs::decide`) | `audit::tests::refusals_from_one_client_are_written_once_per_window`, `one_client_cannot_crowd_out_other_clients_refusals`, `counts_of_refusals_not_written_are_summarised_when_their_entry_ends`, `repeated_refusals_share_an_alert_key`; `alerts::tests::alerts_that_are_never_resolved_do_not_pile_up` |
| [I] XSS in the dashboard through names from labels or objects | Content-Security-Policy `default-src 'self'` without inline styles (ADR-0025), framework escaping | CSP header: `server::health_answers_with_security_headers_and_foreign_hosts_are_refused`; output encoding of hostile names is **untested** by an end-to-end browser test |

Residual: the audit chain is unkeyed; whoever can write the files can rewrite the tail, remove the newest records or files, or rewrite the whole chain, and `rdock audit verify` cannot tell (ADR-0025). Forwarding to a remote syslog over TLS is the tamper-resistant copy. Retention is by age only: authenticated activity can still grow the log. Any process that can open the admin socket (the same user, or a container sharing the data directory) is an admin.

### 6.9 Cluster listener and control plane (B6)

| Threat | Mitigation | Proof |
|---|---|---|
| [S] A rogue instance joins | Join tokens single-use with an expiry; enrolment issues a client certificate bound to the CSR key | `rdock-control` `tokens::tests::tokens_are_single_use_and_expire`, `ca::tests::issues_client_certificates_that_name_the_instance` |
| [S] A revoked or renewed-away identity keeps working | Certificate registry checked per call | `rdock-control` `plane::tests::a_renewed_away_certificate_stops_working` |
| [T] A tampered or foreign bundle | Cluster id, newer revision, non-empty document and SHA-256 of the canonical JSON checked (`crates/rdock-cluster/src/agent.rs::refuse`); zstd capped at 64 MiB | Fuzz `cluster_protocol` (v1.0 step 8); `e2e_cluster::*` |
| [T] Redis (cluster limits) answering out of step | RESP reader with size, depth and type checks (`crates/rdock-cluster/src/resp.rs`) | Fuzz `resp_reader`; `rdock-cluster` `resp::tests::*` (the target found a panic on a reply starting with a multi-byte character, fixed in step 8: `a_reply_starting_with_a_multi_byte_character_is_refused`) |
| [E] A compromised data plane writes into another's state | Store operations fenced by leases | `crates/rdock-cluster/tests/leases.rs` |

Residual: a compromised control plane (A8) controls every data plane: bundles are integrity-checked by digest, not signed by an offline key.

### 6.10 ACME client and certificate storage (B5, actor A10)

| Threat | Mitigation | Proof |
|---|---|---|
| [D][T] Hostile CA answers: `Retry-After` values, ARI windows | Our parsing in `crates/rdock-acme/src/client.rs::retry_after` (capped at a day) and `state.rs::apply_window` (clamped, saturating); the protocol documents themselves are `instant-acme`'s | Fuzz `acme_answers` (v1.0 step 8 found that an out-of-range year in a `Retry-After` date overflowed `http_date`'s arithmetic: a panic in debug builds, a wrong time in release builds; fixed with RFC 9110's ranges, `client::tests::dates_out_of_range_are_refused`, `state::tests::extreme_windows_do_not_overflow`) |
| [D] A CA that hangs | 30 s deadline per request (`TimedClient`, ADR-0033 step 7) | `chaos_acme::*` |
| [T] Corrupt stored metadata, chains, order journals | `meta.json` names the chain's SHA-256; unreadable metadata is ignored and replaced at the next renewal | Fuzz `acme_answers` (records read back through the storage layer); `e2e_cluster_acme::the_lease_holder_killed_mid_order_leaves_one_order` |
| [I] Account and certificate keys readable by others | `write_private` with mode `0600` (`crates/rdock-acme/src/storage.rs`) | `rdock-acme` `storage::tests::writes_private_files` |
| [E] DNS-01 hook argument injection | The hook runs without a shell, the name as one argument (`crates/rdock-acme/src/dns.rs`) | `rdock-acme` `dns::tests::exec_runs_without_a_shell_and_reports_failures` |
| [D] Issuance loops that exhaust CA rate limits | Backoff with jitter up to a day, ARI-coordinated renewals, one order per name across a cluster, free-space check before an order | `e2e_acme::failures_show_in_metrics_and_status`, `e2e_cluster_acme::three_instances_on_a_shared_directory_order_once_per_name_and_renew_once`, `chaos_disk::*` |

Not implemented, so not a risk today: on-demand TLS (issuing at handshake time for unknown names). Architecture §15 listed controls for it; the feature does not exist (v1.0 step 8 corrected the row).

### 6.11 Outbound calls (B5)

Forward-auth, agents, webhooks and alert channels, JWKS/OIDC discovery, Vault, DNS provider APIs.

| Threat | Mitigation | Proof |
|---|---|---|
| [I] SSRF to private or metadata addresses through configuration from providers or tenants | Private targets refused unless `allow_private_targets`; tenant backends never loopback, link-local or Unix sockets | `e2e_tenants::tenant_backends_never_reach_local_or_metadata_addresses`; `rdock-observability` `alerts::deliver::tests::private_ip_literals_in_urls_are_recognised` |
| [D] A slow authorisation service | Timeouts; forward-auth fails closed | `e2e_middleware::forward_auth_allows_refuses_and_fails_closed` |
| [T] Forged tokens and JWKS confusion | Algorithms configured ∩ advertised, never `none`; HMAC only when listed | `e2e_jwt::*`, `e2e_oidc::id_tokens_that_fail_a_check_are_refused`; fuzz `jwt_verify`, `oidc_cookie` |

### 6.12 Plugins (native SDK, agents) and WASM

Native plugins are compiled into a custom binary by its builder and are trusted like the binary. Agents are external services reached over HTTP with the outbound protections above. WASM plugins (experimental, outside the first scope) run in wasmtime with signed artefacts and fail closed: `e2e_wasm::a_signed_wasm_plugin_serves_reloads_and_fails_closed`.

### 6.13 The CLI, the data directory and binary upgrades (B7, B8)

| Threat | Mitigation | Proof |
|---|---|---|
| [T] Two processes writing one data directory | Lock file | `e2e_upgrade::a_second_run_on_one_data_directory_is_refused` |
| [D] A failed upgrade | The old process keeps serving | `e2e_upgrade::a_failed_upgrade_leaves_the_old_process_serving` |
| [E] Debug-only test hooks in production | `RDOCK_TEST_*` variables read only by debug builds | `crates/rdock/tests/compat.rs` (environment inventory); the release build reading none of them is **untested** beyond `cfg!(debug_assertions)` in code review |
| [I] The CLI sending a token over the network in clear | Tokens only to loopback (ADR-0025) | `e2e_config_api::the_cli_manages_users_tokens_backends_and_history` |

## 7. Residual risks

Stated plainly; each is a choice or a known gap, not an oversight.

1. **Audit window on I/O errors.** Admin calls reserve room for their audit record before the change, so lack of space cannot leave a change unrecorded; an I/O error other than lack of space between a change and its record still can. Such a loss is counted (`rdock_admin_audit_write_failures_total`) and the next call first writes an `audit.gap` record (ADR-0033, step 7).
2. **Unkeyed audit chain.** Someone who can write the audit files can rewrite the tail undetectably; remote forwarding over TLS is the protection (ADR-0025).
3. **Labels can claim any hostname** once a container is exposed, and cause certificate orders for it. Their backends and middleware URLs may reach any private network the proxy can (containers live there); only the proxy's own machine, its link and cloud metadata addresses are refused, also after DNS resolution. Operators who run untrusted containers on a Docker host must keep `expose_by_default` off, review `rdock.enable`, and use the socket proxy (`deploy/docker/examples/socket-proxy`).
4. **HTTP/2 denial-of-service classes** beyond reset floods (CONTINUATION, HPACK amplification) rely on `h2` 0.4.20 and are not tested here (§6.2).
5. **No client-certificate revocation** (CRL/OCSP); short-lived client certificates are the mitigation.
6. **Stateless OIDC sessions cannot be revoked early**; keep `ttl` short (architecture §15).
7. **A compromised control plane** controls the cluster; bundles carry digests, not signatures (§6.9).
8. **Panic routing** (v1.0 step 8) sends requests to backends that are out of rotation when none is available, by design (a broken health check must not cause an outage); `when_all_down: fail_closed` turns it off.
9. **Private keys are not zeroised** in memory; a process memory dump exposes them.
10. **Upstream code** (Pingora, h2, rustls, instant-acme) is in our trust base; we fuzz our side of each boundary and track their advisories with `cargo deny`.
11. **Single maintainer.** Code review is by the maintainer and AI assistants; the OpenSSF Scorecard's Code-Review check reflects it.

## 8. How the project tests itself

- **Fuzzing** (`tests/fuzz`, cargo-fuzz/libFuzzer, `.github/workflows/fuzz.yml`): 21 targets. Network-facing: `h1_framing`, `clienthello`, `tls_fingerprint`, `proxy_header`, `http3_request`, `backend_response`, `rules_eval`, `rules_parser`, `jwt_verify`, `oidc_cookie`. Outbound and stored: `acme_answers`, `resp_reader`, `cluster_protocol`, `disk_cache_header`. Admin and configuration: `admin_input`, `json_patch`, `config_loader`. Providers and migration: `docker_labels`, `compose_interpolation`, `migrate_caddy`, `nginx_parser`. Each has seeds and a deterministic mutation smoke test that runs under plain `cargo test`. Weekly 30 minutes per target with a corpus kept between scheduled runs; 2 minutes on pull requests.
- **End-to-end suites** in `crates/rdock/tests/` (the tests named in §6), the chaos suite (`chaos_*.rs`), the Gateway API conformance suite, the cache-tests suite, the Traefik differential job.
- **Static analysis**: `clippy -D warnings` with `unwrap`/`expect`/`panic` denied in library crates, `unsafe_code = "forbid"`, Semgrep (`p/rust`, `p/github-actions`, `p/dockerfile`; clean on 2026-11-14), CodeQL (Rust, JavaScript/TypeScript, Go, Actions).
- **Supply chain**: `cargo deny` (licences, RustSec advisories, bans, sources; required), dependency review on pull requests, a Grype scan of the built image, OpenSSF Scorecard, Dependabot, actions pinned by commit SHA, keyless cosign signatures, SBOM and build-provenance attestations for releases. `cargo-vet` is not used ([06-repo-layout.md](06-repo-layout.md) says why).
- **Reviews so far** (internal, by the maintainer with AI assistants; none is an independent audit): ASVS 5.0 L2 of the admin surface (v0.5, [security/asvs-5.0-l2-admin.md](security/asvs-5.0-l2-admin.md), changes in ADR-0025); the v0.8 security review (2026-11-12, ADR-0030 notes); the v0.9 reviews (ADR-0031 and ADR-0032 "As implemented (review fixes)"); the two 1.0 pre-audit reviews of 2026-11-14, one of the HTTP data plane and one of the admin surface, TLS/ACME and the providers (four High and eleven Medium findings, fixed; ADR-0033 "As implemented (review 10 fixes)", which lists what was not done).

## 9. Out of scope

- Volumetric denial of service (network-level floods); rdock offers application-layer limits only.
- A malicious operator or admin, a compromised host or kernel, physical access.
- Vulnerabilities in dependencies that are already public (we ship updates; `cargo deny` tracks them).
- Missing hardening that is a documented, configurable default.
- Experimental features (`http3`, `wasm`) and build features never in a release (`fault-injection`, `alloc-count`, `jemalloc`), unless the maintainer adds them to an audit's scope.
- The website, the documentation playground and the benchmark harnesses.

## 10. Before commissioning an audit (maintainer checklist)

Only a maintainer can do these (research Part C 3.5); the project prepares the rest.

1. **Scope proposal.** Start from §1: HTTP parsing (our side of Pingora), TLS listener setup and resumption, ACME and storage, the admin surface. Decide whether HTTP/3 and WASM are in, and whether one firm (protocol and web) or two.
2. **Artefacts to hand over.** This document; architecture §15; the ASVS review; ADR-0025, -0030, -0031, -0032, -0033; the commit to audit and its release build flags (§2); how to build (`cargo build --release --locked -p rdock`; a C compiler and CMake) and run the suites (`just ci`, `cargo test -p rdock --test e2e_security`, the fuzz workspace); `docs/research/v1.0-stable.md` Part C 3.4 (the internal checklist per surface); the fuzz corpora from the Actions cache; test accounts on a throwaway instance (bootstrap token, one user per role, a tenant).
3. **A second contact** who can receive reports and decide on fixes when the maintainer is unavailable, named in `SECURITY.md` before the audit starts.
4. **Embargo and CVE process.** Findings go through GitHub's private vulnerability reporting (a private fork per advisory); `SECURITY.md`'s 90-day disclosure and CVSS v4 apply; CVEs are requested through GitHub's CNA; a fix release follows [docs/10-stability.md](10-stability.md)'s security exception. Rehearse it once with a dummy advisory.
5. **Funding route.** The research found these routes (facts as read 2026-11-13, not commitments): the NLnet Restack fund, next deadline 2027-01-03 12:00 CET, grants of €5,000–50,000 with a free audit by Radically Open Security for grantees (https://nlnet.nl/propose/, https://nlnet.nl/NGI0/services/); Sovereign Tech Resilience, which provides audits as a service and was accepting applications (https://www.sovereign.tech/programs/bug-resilience); OSTIF, which scopes and manages audits, typically $30k–200k (https://ostif.org/get-an-audit/). Applications must be made by the maintainer.
6. **Publication.** Agree before the audit that the report is published after fixes, and where it will live (`docs/security/`).
