# ADR-0014: HTTP semantics of v0.1, and settings that are not implemented yet

- Status: accepted · Date: 2026-10-26

## Context
The model is a superset of Traefik's ([ADR-0003](0003-config-model-superset-of-traefik.md)), so users migrating from Traefik v3 expect the same behaviour from the same words. The v0.1 research compared Traefik v3.7.16 (the latest v3 release, 2026-10-20) with our model and found differences; it also found settings the model accepts that v0.1 cannot honour yet. Sources: Traefik v3.7.16 code and documentation, RFC 9110/9112, and the smuggling research of the v0.1 notes.

## Decision
**Routing**
- Priority is one number: `priority` when set, else the byte length of the rule as written. Ties go to the route name. Explicit and computed priorities compete, so `priority: 1` makes a catch-all.
- Matcher names are case-insensitive. `Host` ignores case, the port and a trailing dot; IPv6 hosts may be written with or without brackets. `PathPrefix` is a plain string prefix (`/api` matches `/apiv2`). `HostRegexp` and `PathRegexp` are unanchored. `Header` and `Query` match when any value matches; one-argument `Query(k)` matches only an empty value. `Method` compares in upper case.
- Paths are normalised before routing (unreserved escapes decoded, other escapes upper-cased, dot segments and `//` removed) and the **normalised path is forwarded**. Matching uses a decoded form in which reserved characters and `%25` stay encoded, so `%2F` is never a separator. Encoded slashes are allowed, as in Traefik 3.7.
- `ClientIP`, `ip_allow`, `ip_deny`, `rate_limit` and `maintenance.allow` use the **resolved client IP** (trusted proxies, B-NET-08). Traefik uses the TCP peer unless an `ipStrategy` is set; the Traefik label translation (v0.2) maps `ipStrategy` onto `trusted_proxies`.

**Forwarding and limits**
- From untrusted peers, `X-Forwarded-*`, `X-Real-IP`, `Forwarded` and `CF-Connecting-IP` are removed, including `_` spellings, then rewritten; from trusted proxies they are kept and the peer is appended to `X-Forwarded-For`. `X-Forwarded-Proto` is `ws`/`wss` on WebSocket handshakes, as in Traefik.
- HTTP/1.1 requests without `Host`, `Expect` values other than `100-continue` (417) and bare-LF line endings in request headers are refused; Pingora accepts them.
- Defaults: 64 KiB of request headers, 100 headers, 8 KiB request target, no body limit unless set (Traefik and Caddy have none), 10 s to receive request headers, 60 s per-read timeouts, 60 s keep-alive. Upstream read and write timeouts are per read/write (NGINX semantics), not totals.

**Middlewares**
- `redirect.permanent` defaults to **false**; the codes are 301/308 or 302/307, the second for methods other than GET. A redirect to the current URL does nothing. The automatic HTTP→HTTPS redirect uses 301/308 and covers hosts that have an HTTPS route.
- `basic_auth` accepts argon2id and bcrypt, and the weaker Apache MD5 (`$apr1$`, `$1$`) and SHA-1 (`{SHA}`) hashes that Traefik and `htpasswd` produce, with a warning; plain-text passwords are refused.
- `forward_auth`: headers in `copy_headers` are always removed from the client request before the auth service's values are copied. If the service cannot be reached the request fails closed with 502, or 504 on timeout (Traefik answers 500).
- `cors` answers preflights itself with 204; `*` together with credentials stays a validation error (Traefik echoes the origin).
- `compress` uses an allow-list of text types and never touches server-sent events, gRPC, partial responses or HEAD; it honours q-values.
- `errors` keeps the original status and also covers the proxy's own 502/503/504.
- `maintenance` answers with its status (503), `Retry-After`, `Cache-Control: no-store` and the page, except for the `allow` networks.

**Not implemented yet**
- Settings the model accepts but this version cannot honour are reported instead of ignored: `rdock validate` lists them as warnings ("planned for vX.Y"), `rdock run` and reloads refuse the configuration. In v0.1 these are: ACME and DNS-01, TCP/UDP listeners and routes, the PROXY protocol, traffic splits, load-balancing policies other than `round_robin`/`random`, health checks, retries, sticky sessions, client certificates to backends, brotli/zstd, extra configuration files, the Docker/Swarm/Kubernetes providers, `cloudflare` trusted proxies and `cf-connecting-ip`, and tracing.
- Until ACME exists (v0.3), a route asking for automatic HTTPS needs a manual certificate for each of its hosts, or `defaults.certificate`.

## Consequences
- Rules and labels written for Traefik route the same way; the differences above are documented and deliberate.
- The full example configuration stays the target-state document: it validates with warnings and `rdock run` explains what is missing.
