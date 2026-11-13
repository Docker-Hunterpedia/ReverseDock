# ADR-0032: HTTP/3 ingress on quinn and h3 with our rustls configuration, experimental and feature-gated

- Status: accepted
- Date: 2026-11-13
- Supersedes: [ADR-0006](0006-http3-separate-track.md)

## Context

ADR-0006 put HTTP/3 in a separate BoringSSL build on `tokio-quiche` with an internal h2c hop, because "a rustls build cannot host quiche" and Pingora's server `Session` was H1/H2 only. [Research](../research/v0.9-scale.md) on 2026-11-13 found that two of those facts changed:

- **quinn 0.11.12 with h3 0.0.8 and h3-quinn 0.0.10 builds on rustls 0.23 with ring only**, on Rust 1.89, adding 7 crates whose licences `deny.toml` already allows. A probe served a request through a forced Retry. quinn's server passes the QUIC interop runner's tests it supports against seven clients (run of 2026-11-12).
- **Pingora's `Session` has had a `Custom` variant since 0.7.0**, and `HttpProxy::process_new_http` accepts a session from our own accept loop. The trait is hidden API.
- `tokio-quiche` 0.23.0 is still BoringSSL only: 90 more crates, cmake, a C++ compiler and libclang in the build, a dynamically linked C++ runtime that a static musl build must replace, and a second TLS stack with its own certificate resolver. Pingora has shipped no HTTP/3 and names no date.
- **The weak point is the `h3` crate**: its README calls it experimental, its last release is 18 months old with fixes unreleased on its main branch, its compliance report leaves intermediary validation (RFC 9114 §4.1–4.3) to the user, and issue #379 (header-count panic) is open. `max_field_section_size` is unlimited by default.
- Published attacks on HTTP/3 front ends abuse header decompression and one origin connection per stream held open by trickled data.

## Decision

- **Stack:** `quinn`, `h3` and `h3-quinn` on the `rustls::ServerConfig` and certificate resolver the HTTPS listener already uses, behind the cargo feature `http3`, **off by default and not in release binaries or images** while experimental. One artifact; no BoringSSL. A build without the feature refuses `http3.enabled: true` with a diagnostic, as `type: wasm` is refused.
- **Shape:** an HTTP/3 request stream enters the normal pipeline as a Pingora custom session, so the router, middlewares, cache and access log are the ones HTTP/1 and HTTP/2 use. If the custom-session path does not pass its spike (streaming upload, trailers, client reset mid-body, upstream retry, cache), the fallback is an in-process duplex stream carrying a validated HTTP/1.1 request; a socket hop is not used. `h3` sits behind a thin internal trait.
- **We validate, not h3:** pseudo-headers, field names and values, connection-specific fields, `Content-Length` against the data received, and the `:authority` form are checked before a request reaches the pipeline; a malformed request is reset, never forwarded. `max_header_size` is always set (default 64 KiB, hard ceiling 1 MiB, which also stays below the header-count panic). The mapping has a fuzz target.
- **Configuration** on the `https` listener, which then owns the UDP socket on the same address (a `udp` listener there is refused):
  `http3: { enabled: false, advertise: true, advertise_max_age: 1h, advertise_port, retry: auto | always | never, max_idle: 30s, max_concurrent_streams: 100, max_header_size: 64KiB, max_connections, max_connections_per_client, congestion: cubic | newreno | bbr, gso: true, qlog }`.
  `retry: auto` starts sending Retry at 100 half-open connections (HAProxy's threshold). `Alt-Svc` is added to the listener's HTTP/1 and HTTP/2 responses when `advertise` is on.
- **Refused as planned:** HTTP/3 to backends, 0-RTT, active connection migration, datagrams, WebTransport, CONNECT-UDP, WebSocket over HTTP/3, server push, PROXY protocol on the QUIC socket, Gateway API exposure.
- **Reloads and upgrades:** QUIC connections do not move between processes. On a listener replacement or a binary upgrade (ADR-0031) the old side sends GOAWAY, drains for a bounded time and closes; the stateless-reset and token keys are stored in the data directory so the next process answers old connections with a reset and accepts old tokens.
- **Proof:** an in-tree quinn and h3 client in the testkit for end-to-end tests (Retry, large bodies, trailers, reset, GOAWAY on reload, `Alt-Svc`, fallback when UDP is closed); a non-required CI job `http3` that also runs curl with HTTP/3 from a pinned image and a malformed-request suite built on Cloudflare's h3i outside the workspace.

## Consequences

- H-PERF-05, the roadmap's v0.9 line and the architecture and layout documents name quinn and h3 instead of `tokio-quiche` and BoringSSL. There is no `rdock-h3` artifact.
- The feature rests on an experimental crate and on hidden Pingora API. It leaves "experimental" only after an `h3` release that contains the unreleased fixes, an interop run, and a soak. `deny.toml` keeps refusing git sources; we do not pin `h3` to a commit.
- quinn has had nine advisories in 2024–2026, all denial of service and all fixed; version bumps must be prompt.
- One QUIC endpoint per listener bounds UDP throughput; per-thread sockets with connection-ID routing are later work.
- HTTP/3 upstream still waits for a Pingora connector.
