//! HAProxy (<https://www.haproxy.org/>) in Docker, as an independent PROXY protocol peer:
//! `server … send-proxy` / `send-proxy-v2` in front of the `rdock` under test.

use std::io::{Read, Write};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const IMAGE: &str = "haproxy:3.2.26-alpine";

/// A running HAProxy. The configuration reaches the Docker host as `rdock-host`.
pub struct Haproxy {
    name: String,
    _dir: TempDir,
}

impl Drop for Haproxy {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

impl Haproxy {
    /// Starts HAProxy with `config` (which needs a `defaults` section with timeouts) and waits
    /// until it serves. Each of `ports` is published on 127.0.0.1 under the same number and must
    /// be bound by the configuration.
    pub fn start(config: &str, ports: &[u16]) -> Self {
        static STARTED: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "rdock-haproxy-{}-{}",
            std::process::id(),
            STARTED.fetch_add(1, Ordering::SeqCst)
        );
        let dir = tempfile::tempdir().unwrap();
        // Docker accepts connections on a published port before the container listens, so
        // readiness is an answer from HAProxy itself.
        let ready = crate::free_port();
        let config = format!(
            "{config}\nfrontend rdock_testkit_ready\n  mode http\n  bind :{ready}\n  monitor-uri /ready\n"
        );
        std::fs::write(dir.path().join("haproxy.cfg"), config).unwrap();
        let mut args = vec![
            "run".to_owned(),
            "-d".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--add-host".to_owned(),
            "rdock-host:host-gateway".to_owned(),
            "-v".to_owned(),
            format!("{}:/usr/local/etc/haproxy:ro", dir.path().display()),
        ];
        for port in ports.iter().chain([&ready]) {
            args.push("-p".to_owned());
            args.push(format!("127.0.0.1:{port}:{port}"));
        }
        args.push(IMAGE.to_owned());
        let out = Command::new("docker").args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "docker run: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let haproxy = Self { name, _dir: dir };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !answers(ready) {
            assert!(Instant::now() < deadline, "HAProxy did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        haproxy
    }
}

/// Whether HAProxy's monitor URI on `port` answers 200.
fn answers(port: u16) -> bool {
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut answer = Vec::new();
    stream.write_all(b"GET /ready HTTP/1.0\r\n\r\n").is_ok()
        && stream.read_to_end(&mut answer).is_ok()
        && answer.starts_with(b"HTTP/1.1 200")
}
