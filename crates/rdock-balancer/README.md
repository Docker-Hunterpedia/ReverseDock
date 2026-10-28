# rdock-balancer

Backend selection policies, and later active and passive health checks, retries with budgets and circuit breakers.

Policies: smooth weighted round-robin (the NGINX algorithm), weighted random, least requests, power of two choices and consistent hashing (a ketama-style ring of our own). Per-backend state (`Registry`, `Pool`, `BackendState`) is shared across configuration generations; `StickyKeys` signs sticky-session cookies. Health checks and retries follow in v0.4. Design: [architecture §9](../../docs/05-architecture.md), [ADR-0022](../../docs/decisions/0022-production-reliability.md).
