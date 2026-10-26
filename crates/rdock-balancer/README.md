# rdock-balancer

Backend selection policies, and later active and passive health checks, retries with budgets and circuit breakers.

**v0.1:** smooth weighted round-robin (the NGINX algorithm) and weighted random selection. Other policies, health checks and retries arrive in v0.4. Design: [architecture §9](../../docs/05-architecture.md), [ADR-0015](../../docs/decisions/0015-status-code-retries.md).
