# ADR-0012: rdock owns listeners and the runtime; Pingora's HTTP stack is used as a library

- Status: accepted · Date: 2026-10-26
- Supersedes: [ADR-0008](0008-listener-changes-via-self-upgrade.md)

## Context
Research for v0.1 (Pingora 0.9.0 sources and probes, October 2026) found that Pingora's `Server` and `Service` listeners do not fit a proxy that reloads itself:

- A listener that cannot bind panics its service thread silently; `EADDRINUSE` is retried for 30 s first. Readiness is signalled before binding.
- Graceful shutdown sleeps the full `grace_period_seconds` (default 300 s) even when nothing is in flight, then drops open requests. `run_forever()` always exits 0.
- `TlsSettings` always enables TLS 1.2 and 1.3, takes cipher suites from the process-wide provider, never issues session tickets and offers one ALPN set, so named per-listener policies (B-TLS-01) and TLS-ALPN-01 next to h2 (v0.3) are impossible on Pingora listeners.
- With h2c enabled, Pingora waits for 24 bytes of preface with no timeout; a short HTTP/1.0 request hangs.
- Listeners cannot be added or removed while the server runs, which is why ADR-0008 required a restart for listener changes.

`pingora_proxy::http_proxy()` returns an `HttpProxy` meant for custom accept loops, and `ServerApp::process_new(stream, shutdown)` runs the complete HTTP/1, HTTP/2 and h2c pipeline on any stream.

## Decision
- `rdock run` builds its own Tokio runtime, binds every listener itself and runs one accept loop per listener. Each accepted connection is handed to that listener's `HttpProxy` (our `ProxyHttp` implementation) with `process_new`. Pingora's `Server` is not used.
- TLS handshakes use Pingora's `Acceptor` with our own rustls `ServerConfig` per listener (policy, ALPN `h2`/`http/1.1`, rotating session tickets) and an SNI resolver that is swapped on reload; the handshake-complete callback records the SNI for the access log.
- The accept loop reads the first bytes of cleartext connections itself, so h2c detection never waits, and wraps every connection to enforce a deadline for HTTP/1 request headers (slowloris) and to refuse bare-LF line endings.
- On reload, new sockets are bound and TLS settings built first; only if every bind succeeds is the new configuration published. Listeners whose address is unchanged keep their socket and receive new settings in place; removed listeners stop accepting and drain. **Listener changes no longer need a restart.**
- Shutdown stops accepting, tells open connections to finish (`Connection: close`, HTTP/2 GOAWAY), closes idle keep-alive connections and waits until no connection is left or `lifecycle.drain_timeout` passes.
- The admin endpoints of v0.1 are served by Pingora's HTTP stack (`ServeHttp`) on their own socket; the full API of v0.5 moves to axum as [ADR-0007](0007-admin-api-separate-listener.md) plans.

## Consequences
- Bind errors are reported before anything changes, readiness means "listening", the process exits as soon as it is drained, and `rdock_restart_required` and exit code 3 from ADR-0008 are not needed.
- We maintain the accept loop: TCP_NODELAY, accept back-off, handshake timeout, connection draining. Pingora's SIGQUIT fd-transfer upgrade and TLS handshake offload are not used; zero-downtime *binary* upgrades remain the v0.9 track (H-PERF-04).
- Each listener has its own upstream connection pool (one `HttpProxy` per listener).
- `pingora-core` still links `serde_yaml`/`unsafe-libyaml` for its own configuration format; rdock never calls it (the `deny.toml` ignore records why). Our configuration is parsed by serde-saphyr as in [ADR-0011](0011-yaml-parser-and-msrv.md).
