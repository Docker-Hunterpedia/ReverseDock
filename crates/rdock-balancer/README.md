# rdock-balancer

Backend selection policies, and later active and passive health checks, retries with budgets and circuit breakers.

Policies: smooth weighted round-robin (the NGINX algorithm), weighted random, least requests, power of two choices, consistent hashing (a ketama-style ring of our own) and Peak-EWMA. Also the maths of outlier detection, slow start and priority-tier loads (ADR-0031). Per-backend state (`Registry`, `Pool`, `BackendState`) is shared across configuration generations; `StickyKeys` signs sticky-session cookies. Also active and passive health (`health`), outlier detection (`outlier`), priority tiers (`tiers`) and the Peak-EWMA estimate (`ewma`), which v0.9 added to the v0.4 health checks and retry policy. Design: [architecture §9](../../docs/05-architecture.md), [ADR-0022](../../docs/decisions/0022-production-reliability.md).
