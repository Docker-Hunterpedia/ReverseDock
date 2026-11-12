#![doc = include_str!("../README.md")]
// A test harness: failing loudly on broken fixtures is the point.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    missing_docs
)]

pub mod agent;
pub mod backend;
pub mod certs;
pub mod client;
pub mod cloudflare_access;
pub mod dns_contract;
pub mod fake_api;
pub mod haproxy;
pub mod origin;
pub mod pebble;
pub mod postgres;
pub mod proxy_protocol;
pub mod rdock;
pub mod receiver;
pub mod tcp;
pub mod toxiproxy;
pub mod udp;

/// A free TCP port on the loopback interface, taken by nobody else in this test run.
///
/// Test processes run side by side and the port stays unused until the caller binds it, so a
/// port from the kernel's ephemeral range can go to another test's `bind(0)` or to an outgoing
/// connection in between. These come from below that range (it starts at 32768 on Linux and
/// 49152 on macOS).
///
/// A port is claimed across processes with a file created exclusively in the workspace's
/// `target/test-ports` directory, named after the port and holding the claimant's process id. Blocks per process
/// id alone are not enough: with more than a thousand test processes in a run two live ones
/// share a block, both find the same port free, and both hand it out (two proxies on one
/// port, or a container whose published port "is already allocated"). A claim whose process
/// is gone, or that is older than an hour, is taken over.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    const FIRST_PORT: u32 = 10_000;
    const PORTS: u32 = 20_000;
    static GIVEN: AtomicU32 = AtomicU32::new(0);
    // In the workspace's own build directory, not the shared temporary directory: a fixed
    // name there could be planted by another user.
    let claims = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-ports");
    let _ = std::fs::create_dir_all(&claims);
    // Spread processes over the range so they rarely contend for the same claim.
    let start = std::process::id().wrapping_mul(2_654_435_761) % PORTS;
    loop {
        let offset = (start + GIVEN.fetch_add(1, Ordering::Relaxed)) % PORTS;
        let port = u16::try_from(FIRST_PORT + offset).unwrap();
        if claim(&claims.join(port.to_string()))
            && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
    }
}

/// Creates the claim file, taking over one whose owner is gone. False when another live
/// process holds it.
fn claim(path: &std::path::Path) -> bool {
    use std::io::Write;
    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                let _ = write!(file, "{}", std::process::id());
                return true;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if !abandoned(path) || std::fs::remove_file(path).is_err() {
                    return false;
                }
            }
            // The directory cannot be written: fall back to the bind check alone.
            Err(_) => return true,
        }
    }
    false
}

/// Whether the process that made a claim is gone, or the claim is older than an hour.
fn abandoned(path: &std::path::Path) -> bool {
    let old = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age > std::time::Duration::from_secs(3600));
    if old {
        return true;
    }
    let Ok(owner) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = owner.trim().parse::<u32>() else {
        // Being written right now by its owner.
        return false;
    };
    if pid == std::process::id() {
        return false;
    }
    let proc = std::path::Path::new("/proc");
    proc.join("self").exists() && !proc.join(pid.to_string()).exists()
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

    #[test]
    fn a_port_claimed_by_a_live_process_is_not_handed_out_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("12345");
        assert!(super::claim(&path), "the first claim succeeds");
        assert!(!super::claim(&path), "our own live claim is kept");
        // A claim left by a process that no longer exists is taken over (where /proc exists).
        std::fs::write(&path, "4294967294").unwrap();
        if std::path::Path::new("/proc/self").exists() {
            assert!(super::claim(&path));
        }
    }
}
