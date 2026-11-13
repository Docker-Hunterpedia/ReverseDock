//! HTTP/3 ingress on quinn and h3 (experimental, H-PERF-05, ADR-0032).
//!
//! An `https` listener with `http3.enabled` also owns the UDP socket of its address and runs one
//! QUIC endpoint on it. Each request stream is decoded and validated here ([`request`]), never by
//! h3 alone, and then enters the same Pingora pipeline as HTTP/1 and HTTP/2 as a custom session,
//! so routing, middlewares, the cache and the access log are shared.
//!
//! The request mapping ([`request`]) and the frame limits ([`frames`]) are built in every
//! configuration so their tests and fuzz target run without the `http3` feature; the QUIC
//! endpoint is built only with it.

#[cfg(feature = "http3")]
pub mod endpoint;
pub mod frames;
#[cfg(feature = "http3")]
pub mod quic;
pub mod request;
#[cfg(feature = "http3")]
pub mod session;
#[cfg(feature = "http3")]
pub mod stream;

/// Whether this build serves HTTP/3 (the `http3` cargo feature).
pub const ENABLED: bool = cfg!(feature = "http3");

/// What a configuration with `http3.enabled: true` is told by a build without the feature.
pub const DISABLED_MESSAGE: &str =
    "this build does not include HTTP/3; build with --features http3";
