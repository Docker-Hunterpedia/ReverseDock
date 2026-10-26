# rdock-admin

The admin listener (`admin.listener`, default `127.0.0.1:2080`): health, readiness, metrics and the admin API.

**v0.1:** `GET /healthz`, `GET /readyz` and `GET /metrics` (Prometheus) without authentication; `GET /api/v1/status` and `POST /api/v1/config/reload` with `Authorization: Bearer <token>` (the token is `RDOCK_ADMIN_TOKEN` or `$RDOCK_DATA_DIR/admin/token`, created on first start). `rdock status`, `rdock reload` and `rdock healthcheck` use these endpoints. It is served by Pingora's HTTP stack on its own socket, never through proxy listeners.

**v0.5:** the full REST API with OpenAPI, users, scoped tokens, audit log and the embedded dashboard, on axum ([ADR-0007](../../docs/decisions/0007-admin-api-separate-listener.md), [ADR-0004](../../docs/decisions/0004-embedded-spa-dashboard.md)). Design: [architecture §13](../../docs/05-architecture.md).
