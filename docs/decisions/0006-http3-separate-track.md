# ADR-0006: HTTP/3 is a separate, feature-gated track

- Status: accepted · Date: 2026-10-26

## Context
Pingora has no HTTP/3: PR #514 (quiche h3 server) and #524 (client) were closed unmerged in September 2026; maintainers point to `tokio-quiche`, which requires BoringSSL and "is not a standalone HTTP/3 server". A rustls build cannot host quiche; OpenSSL + BoringSSL cannot be linked together.

## Decision
HTTP/3 lives behind Cargo feature `http3` in a BoringSSL build variant, implemented on `tokio-quiche` as an ingress-only adapter into the same `ProxyHttp` pipeline. It never blocks a milestone and ships as experimental until interop and soak tests pass. Upstream HTTP/3 waits for a Pingora connector.

## Consequences
- Default binary stays rustls-only and small.
- Two release artifacts eventually (`rdock`, `rdock-h3`); the listener abstraction is designed now so adding a QUIC listener is additive.
- Pingora's server `Session` is H1/H2-only: the track either carries a maintained `pingora-core` patch (as PR #514 did) or fronts h3 with an internal h2c hop into the normal pipeline. We start with the hop and measure before considering a patch.
