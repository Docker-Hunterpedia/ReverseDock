# ADR-0023: Upstream keep-alive pool sized for busy listeners

- Status: accepted
- Date: 2026-10-30

## Context
The first benchmarks ([report](../../benchmarks/results/0.4.0-alpha.1/report.md)) showed ReverseDock collapsing under overload: at a 40,000 req/s target it completed fewer than 2,000 req/s and 52 % of requests failed, while NGINX and HAProxy kept about 17,000 req/s ([#86](https://github.com/Docker-Hunterpedia/ReverseDock/issues/86)). During the run the backend had about 1,000 established connections from ReverseDock and 473 more half-open ones (`SYN_RECV`). Each listener's Pingora proxy keeps at most `upstream_keepalive_pool_size` idle connections to backends, 128 by default (`pingora-core` 0.9.0, `server/configuration`). With more requests in flight than that, every finished request beyond the pool closed its backend connection and the next one opened a new one, so load turned into connection churn that the backend could not accept fast enough. M-LB-08 (connection-pool sizing) was still open.

## Decision
- `security.limits.upstream_idle_connections` sets the idle pool of each listener, **4096** by default. That keeps enough connections for thousands of requests in flight, and an idle connection costs a socket and a few kilobytes. Idle connections still close after the service's `timeouts.idle` (90 s by default).
- The value is read when a listener starts; it is not one of the settings a reload changes in place (ADR-0012).
- `0` is refused.

## Consequences
- With the new default, the same benchmark at a 40,000 req/s target sustains 14,900 req/s with 0.37 % failures (NGINX: 17,100 req/s, 1.29 %), see [the comparison](../../benchmarks/results/2026-10-30-upstream-pool/report.md). The remaining gap in peak throughput is ordinary performance work, not a collapse.
- Busy listeners hold more idle sockets to backends. Backends that limit connections per client should be sized for it, or the value lowered.
