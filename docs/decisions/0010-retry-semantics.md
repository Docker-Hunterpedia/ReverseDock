# ADR-0010: Retry semantics follow Pingora's hook model

- Status: superseded by [ADR-0015](0015-status-code-retries.md) · Date: 2026-10-26

## Context
`pingora-proxy` 0.9 exposes three failure hooks: `fail_to_connect` (connect errors; may mark the error retryable), `error_while_proxy` (errors while proxying, i.e. before or during the upstream response; retryable only before response headers were sent downstream) and `fail_to_proxy` (terminal: write the error response). There is no hook to retry after an upstream *status code* (502/503/504) has been received; Zentinel adds one in a fork (`should_retry_response`). ADR-0001 commits us to a thin adapter and no fork.

## Decision
- v0.4 retries cover connect failures, resets and timeouts **before upstream response headers**, for idempotent methods (or `retry_non_idempotent`) with a replayable body, bounded by attempts and a per-route retry budget, always on a different backend when one exists.
- Status-code retries are **not** promised before an upstream Pingora hook exists. We open/track an upstream PR; if accepted, `retries.on` gains `502/503/504` in a later minor. A maintained patch is not an option for the core binary.
- Passive health and circuit breaking use the same hooks plus observed 5xx responses, which needs no retry capability.

## Consequences
- No fork; one Pingora upgrade PR per release stays realistic.
- Users coming from Traefik's `retry` middleware get the same semantics for transport failures; the docs state that 5xx retries are not supported yet.
