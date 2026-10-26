# ADR-0015: Status-code retries are possible without a Pingora fork

- Status: accepted · Date: 2026-10-26
- Supersedes: [ADR-0010](0010-retry-semantics.md)

## Context
ADR-0010 assumed that Pingora 0.9 has no hook to retry after an upstream status code. A probe against the 0.9.0 sources showed otherwise: returning an error marked retryable from `upstream_response_filter` (nothing has been written to the client yet) goes through `error_while_proxy` into the retry loop, which calls `upstream_peer` again (`proxy_h1.rs`, `proxy_h2.rs`, `lib.rs` of `pingora-proxy` 0.9.0). The probe answered 503 then 200, the client received 200, and a POST was not retried. The research also found two traps: Pingora does not stop retries once response headers were sent, and errors on reused connections carry a "reused only" retry state that panics if read before it is decided.

## Decision
- Retries (v0.4) keep the rules of ADR-0010: idempotent methods (or `retry_non_idempotent`), a replayable body, an attempt limit and a retry budget, and a different backend when one exists.
- `retries.on` gains `502`, `503` and `504`, implemented in `upstream_response_filter` without a fork. On the last attempt the real backend response is passed through.
- `error_while_proxy` always resolves the reuse state and refuses a retry once the client has seen a response (implemented in v0.1, where only Pingora's built-in retry of a closed pooled connection is active).

## Consequences
- Traefik's `retry` middleware with status codes maps onto `services.<name>.retries` without a fork.
- Passive health and circuit breaking can use the same hooks.
