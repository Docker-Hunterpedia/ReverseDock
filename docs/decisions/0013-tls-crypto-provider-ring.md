# ADR-0013: rustls with the ring provider is the TLS backend

- Status: accepted · Date: 2026-10-26
- Supersedes: [ADR-0002](0002-tls-backend-rustls.md)

## Context
ADR-0002 chose rustls with the `aws-lc-rs` provider. The Pingora 0.9.0 sources show that its `rustls` feature is built on **ring**: `pingora-rustls` enables rustls with `ring, logging, std, tls12` only and installs ring as the process-wide provider (`install_default_crypto_provider`); certificate hashing calls ring directly. Using aws-lc-rs would compile and link both libraries, and upstream pull requests that make the provider selectable (cloudflare/pingora#630, #887) are still open (October 2026). Pingora's crate has no default TLS backend (`default = []`), not OpenSSL.

## Decision
- The default and only supported build uses rustls 0.23 with the ring provider. ReverseDock builds its `ServerConfig` with `builder_with_provider(ring::default_provider())` and declares rustls with `default-features = false` so aws-lc-rs is not compiled in.
- `openssl` and `boringssl` stay possible Cargo features for later (BoringSSL is required by the HTTP/3 track, [ADR-0006](0006-http3-separate-track.md)).

## Consequences
- Static musl binaries without OpenSSL or Perl. ring is C and assembly, so a C compiler is needed; Pingora additionally needs CMake (zlib-ng). Builders: `apk add musl-dev cmake make` (Dockerfile), musl-tools on the CI runners, `brew install cmake` on macOS.
- No FIPS build and no post-quantum key exchange for now (ring offers X25519, P-256 and P-384). Revisit when Pingora lets the provider be chosen.
