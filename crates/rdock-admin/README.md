# rdock-admin

The admin listener (`admin.listener`, default `127.0.0.1:2080`): health, readiness, metrics and the admin API.

**v0.1–v0.4:** `GET /healthz`, `GET /readyz` and `GET /metrics` (Prometheus) without authentication; `GET /api/v1/status` and `POST /api/v1/config/reload` with `Authorization: Bearer <token>` (the token is `RDOCK_ADMIN_TOKEN` or `$RDOCK_DATA_DIR/admin/token`, created on first start).

**v0.5** ([ADR-0024](../../docs/decisions/0024-management-api-and-dashboard.md)): axum on a tokio runtime of its own (`admin.threads`), never through proxy listeners. Engine calls are sent to the proxy's runtime, so anything they start lives with the data plane. Every request passes the `Host` allow-list (421, DNS rebinding) and, for unsafe methods, the cross-site check (403); every response gets the security headers. TLS (`admin.tls`, TLS 1.3) is required off loopback. The CLI uses the Unix socket (`admin.socket`, mode 0600), which needs no token. Users, sessions, scoped tokens, the audit log, the configuration API, live streams and the embedded dashboard follow in the v0.5 milestone.
