# ADR-0007: Admin API is an axum server on its own localhost listener

- Status: accepted · Date: 2026-10-26

## Context
The admin surface needs rich routing, auth, OpenAPI, SSE and static files; it must never share fate or exposure with proxy listeners.

## Decision
`rdock-admin` runs `axum` on `admin.listener` (default `127.0.0.1:2080`) as a Pingora background service (shared lifecycle). Exposure through the proxy is only possible by an explicit route with middlewares. Auth: bootstrap token, users with argon2id, scoped API tokens, RBAC, audit log, CSRF for sessions.

## Consequences
- Clear security boundary; the data plane keeps serving if the admin task dies.
- Two HTTP stacks in one binary (Pingora + hyper via axum); acceptable, both are Tokio-native.
