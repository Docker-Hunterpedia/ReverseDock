//! End-to-end with a real Docker daemon (v0.2 acceptance): a labelled container is routed,
//! stopping it removes the route within about a second, and losing the Docker socket does
//! not drop traffic.
//!
//! Needs a Linux Docker daemon at `/var/run/docker.sock` whose container addresses the host can
//! reach (not Docker Desktop) and `RDOCK_DOCKER_TESTS=1`; CI sets both. Skipped otherwise.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const IMAGE: &str = "traefik/whoami:v1.11.0";

fn enabled() -> bool {
    let on = std::env::var("RDOCK_DOCKER_TESTS").is_ok_and(|v| v == "1");
    if !on {
        eprintln!("skipped: set RDOCK_DOCKER_TESTS=1 to run against a real Docker daemon");
    }
    on
}

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A Unix socket that forwards to the Docker socket and can be cut, to simulate losing Docker.
struct SocketForwarder {
    path: PathBuf,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: Option<JoinHandle<()>>,
}

impl SocketForwarder {
    fn start(path: &Path) -> Self {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let connections = tasks.clone();
        let accept = tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let task = tokio::spawn(async move {
                    if let Ok(mut daemon) = UnixStream::connect(DOCKER_SOCKET).await {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut daemon).await;
                    }
                });
                connections.lock().unwrap().push(task);
            }
        });
        Self {
            path: path.to_owned(),
            tasks,
            accept: Some(accept),
        }
    }

    fn cut(&mut self) {
        if let Some(accept) = self.accept.take() {
            accept.abort();
        }
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Removes the test container even when an assertion fails.
struct ContainerGuard(String);

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

async fn status_of(addr: SocketAddr, host: &str) -> u16 {
    client::http1(addr, get(host, "/")).await.status
}

async fn wait_for(addr: SocketAddr, host: &str, status: u16, limit: Duration) -> Duration {
    let start = Instant::now();
    while start.elapsed() < limit {
        if status_of(addr, host).await == status {
            return start.elapsed();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{host} did not answer {status} within {limit:?}");
}

#[tokio::test]
async fn docker_containers_are_routed_and_socket_loss_keeps_traffic() {
    if !enabled() {
        return;
    }
    docker(&["pull", "-q", IMAGE]);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("docker.sock");
    let mut forwarder = SocketForwarder::start(&socket);
    let port = free_port();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nproviders:\n  docker: {{ endpoint: \"unix://{}\" }}\n",
        socket.display()
    );
    let mut rdock = Rdock::start(RDOCK, &config);

    let name = format!("rdock-e2e-{}", std::process::id());
    let host = format!("{name}.test");
    let _guard = ContainerGuard(name.clone());
    docker(&[
        "run",
        "-d",
        "--name",
        &name,
        "--label",
        "rdock.enable=true",
        "--label",
        &format!("rdock.host={host}"),
        "--label",
        "rdock.tls=off",
        IMAGE,
    ]);
    let routed = wait_for(addr, &host, 200, Duration::from_secs(10)).await;
    eprintln!("routed {routed:?} after the container started");
    let reply = client::http1(addr, get(&host, "/")).await;
    assert!(reply.text().contains("Hostname:"), "{}", reply.text());

    // Docker goes away: the route keeps working and the provider reports it.
    forwarder.cut();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(status_of(addr, &host).await, 200);
    assert!(
        rdock.log().contains("Docker is unreachable"),
        "{}",
        rdock.log()
    );

    // Docker is back: stopping the container removes the route.
    let mut forwarder = SocketForwarder::start(&socket);
    tokio::time::sleep(Duration::from_secs(3)).await;
    docker(&["stop", "-t", "1", &name]);
    let removed = wait_for(addr, &host, 404, Duration::from_secs(5)).await;
    eprintln!("route removed {removed:?} after the container stopped");
    assert!(removed < Duration::from_secs(2), "took {removed:?}");

    forwarder.cut();
    rdock.stop(Duration::from_secs(10));
}
