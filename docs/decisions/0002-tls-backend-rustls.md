# ADR-0002: rustls is the default TLS backend

- Status: accepted · Date: 2026-10-26

## Context
Pingora supports OpenSSL (default), BoringSSL (FIPS, required by quiche/HTTP/3), rustls (marked experimental) and s2n-tls. We need per-SNI dynamic certificates, mTLS, policy control and simple static builds. Pingora 0.9 added `Acceptor::from_server_config` (runtime-built rustls `ServerConfig`, in-memory keys), which is exactly the hook a cert manager needs. Pingap and Zentinel ship rustls builds.

## Decision
Default build: rustls with the `aws-lc-rs` provider (FIPS-capable). `openssl` and `boringssl` remain Cargo features (BoringSSL needed only by the HTTP/3 track, ADR-0006). Our own TLS test matrix (versions, ciphers, ALPN, SNI edge cases, mTLS, resumption) runs in CI.

## Consequences
- Static musl binaries without OpenSSL or Perl. `aws-lc-rs` compiles C/asm (needs a C compiler and CMake; Go for the FIPS build); the `ring` provider gives a pure-Rust build when FIPS is not needed.
- We accept "experimental" status in Pingora and cover it with tests; if a blocker appears, the OpenSSL feature is the fallback without model changes.
