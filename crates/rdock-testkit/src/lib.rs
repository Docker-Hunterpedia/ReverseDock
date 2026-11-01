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

/// A free TCP port on the loopback interface, taken by nobody else in this test run.
///
/// Test processes run side by side and the port stays unused until the caller binds it, so a
/// port from the kernel's ephemeral range can go to another test's `bind(0)` or to an outgoing
/// connection in between. These come from below that range (it starts at 32768 on Linux and
/// 49152 on macOS), in a block of their own per process.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    const FIRST_PORT: u32 = 10_000;
    const BLOCKS: u32 = 1_000;
    const BLOCK_SIZE: u32 = 20;
    static GIVEN: AtomicU32 = AtomicU32::new(0);
    let block_start = (std::process::id() % BLOCKS) * BLOCK_SIZE;
    loop {
        let offset = (block_start + GIVEN.fetch_add(1, Ordering::Relaxed)) % (BLOCKS * BLOCK_SIZE);
        let port = u16::try_from(FIRST_PORT + offset).unwrap();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::free_port;

    #[test]
    fn ports_are_distinct_bindable_and_below_the_ephemeral_range() {
        let ports: Vec<u16> = (0..50).map(|_| free_port()).collect();
        let mut unique = ports.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ports.len());
        for port in ports {
            assert!((10_000..30_000).contains(&port), "{port}");
            std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        }
    }
}
