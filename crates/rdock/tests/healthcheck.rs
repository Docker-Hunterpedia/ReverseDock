//! `rdock healthcheck` tells the truth with the admin side off, on, and on with TLS.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rdock_testkit::certs::TestCa;
use rdock_testkit::free_port;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn healthy(dir: &Path) -> bool {
    Command::new(RDOCK)
        .args(["healthcheck", "--config"])
        .arg(dir.join("rdock.yaml"))
        .arg("--data-dir")
        .arg(dir)
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// Stops rdock when dropped, also when an assertion fails.
struct Running(Child);

impl Running {
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

fn start(dir: &Path, config: &str) -> Running {
    std::fs::write(dir.join("rdock.yaml"), config).unwrap();
    Running(
        Command::new(RDOCK)
            .args(["run", "--config"])
            .arg(dir.join("rdock.yaml"))
            .arg("--data-dir")
            .arg(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn wait_healthy(dir: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !healthy(dir) {
        assert!(Instant::now() < deadline, "never became healthy");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn check(config: &str, dir: &Path) {
    let mut rdock = start(dir, config);
    wait_healthy(dir);
    rdock.stop();
    assert!(!healthy(dir), "a stopped proxy is not healthy");
}

fn listener(port: u16) -> String {
    format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\n"
    )
}

#[test]
fn with_the_admin_side_off_it_checks_the_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let config = format!("{}admin: {{ enabled: false }}\n", listener(free_port()));
    check(&config, dir.path());
}

#[test]
fn with_the_admin_side_on_it_asks_readyz() {
    let dir = tempfile::tempdir().unwrap();
    let config = format!(
        "{}admin: {{ listener: \"127.0.0.1:{}\" }}\n",
        listener(free_port()),
        free_port()
    );
    check(&config, dir.path());
}

#[test]
fn an_admin_listener_with_tls_does_not_look_unhealthy() {
    let dir = tempfile::tempdir().unwrap();
    let issued = TestCa::new().issue(dir.path(), "admin", &["localhost"]);
    let config = format!(
        "{}admin:\n  listener: \"127.0.0.1:{}\"\n  tls: {{ cert_file: {}, key_file: {} }}\n",
        listener(free_port()),
        free_port(),
        issued.cert.display(),
        issued.key.display()
    );
    let _rdock = start(dir.path(), &config);
    wait_healthy(dir.path());
}
