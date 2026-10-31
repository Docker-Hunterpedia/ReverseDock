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
pub mod pebble;
pub mod rdock;
pub mod toxiproxy;

/// A free TCP port on the loopback interface.
pub fn free_port() -> u16 {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock, PoisonError};
    // The kernel may give the same ephemeral port to two binds in a row once the first
    // socket is closed; a test that asks twice (listener and admin) must get two ports.
    static GIVEN: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let given = GIVEN.get_or_init(|| Mutex::new(HashSet::new()));
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if given
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(port)
        {
            return port;
        }
    }
}
