#![doc = include_str!("../README.md")]
// A test harness: failing loudly on broken fixtures is the point.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    missing_docs
)]

pub mod backend;
pub mod certs;
pub mod client;
pub mod rdock;

/// A free TCP port on the loopback interface.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
