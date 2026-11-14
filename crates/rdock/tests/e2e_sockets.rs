//! End-to-end: listener socket options, the TLS handshake bound and the runtime threads
//! (H-PERF-01, ADR-0031).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::certs::TestCa;
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// One HTTP/1.1 GET on a kept-alive stream; the status.
async fn get_on<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, host: &str) -> u16 {
    stream
        .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed");
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf);
        if let Some(end) = text.find("\r\n\r\n") {
            let length: usize = text[..end]
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().ok())?
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + length {
                return text[9..12].parse().unwrap();
            }
        }
    }
}

fn metric(rdock: &Rdock, line_start: &str) -> Option<f64> {
    let (_, text) = rdock.get_admin("/metrics")?;
    text.lines()
        .find(|l| l.starts_with(line_start))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
}

fn tls_config(
    port: u16,
    backend: SocketAddr,
    cert: &rdock_testkit::certs::Issued,
    extra: &str,
) -> String {
    format!(
        r#"
listeners:
  websecure:
    address: "127.0.0.1:{port}"
    tls: {{ {extra} }}
    timeouts: {{ request_header: 30s }}
defaults: {{ listeners: [websecure], tls: off }}
certificates:
  app: {{ cert_file: "{}", key_file: "{}" }}
routes:
  app: {{ match: "Host(`app.test`)", service: app, tls: {{ certificate: app }} }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        cert.cert.display(),
        cert.key.display()
    )
}

/// While stalled clients (TCP open, no `ClientHello`) hold every handshake slot, new
/// connections wait in the backlog without being reset, an established keep-alive connection
/// is still answered at once, and the waiting connections complete once the slots free up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handshake_bound_keeps_established_connections_served() {
    let backend = Backend::start("app").await;
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "app", &["app.test"]);
    let port = free_port();
    let rdock = Rdock::start(
        RDOCK,
        &tls_config(port, backend.addr, &cert, "max_handshakes: 4"),
    );
    let client = ca.client_config(&[b"http/1.1"]);
    let mut established =
        rdock_testkit::client::tls_connect(addr(port), "app.test", client.clone())
            .await
            .unwrap();
    assert_eq!(get_on(&mut established, "app.test").await, 200);

    // Twenty clients that connect and never send a ClientHello: four take the slots, the
    // others stay in the backlog.
    let mut stalled = Vec::new();
    for _ in 0..20 {
        stalled.push(TcpStream::connect(addr(port)).await.unwrap());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while metric(
        &rdock,
        "rdock_tls_handshakes_in_flight{listener=\"websecure\"}",
    ) != Some(4.0)
    {
        assert!(Instant::now() < deadline, "four handshakes in flight");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        metric(
            &rdock,
            "rdock_tls_handshake_waits_total{listener=\"websecure\"}"
        )
        .is_some_and(|n| n >= 1.0),
        "the accept loop waited for a slot"
    );

    // The established connection is not held up by the handshakes.
    for _ in 0..20 {
        let started = Instant::now();
        assert_eq!(get_on(&mut established, "app.test").await, 200);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "answered in {:?}",
            started.elapsed()
        );
    }

    // A new client connects (the kernel accepts into the backlog) but its handshake waits.
    let waiting = tokio::spawn({
        let client = client.clone();
        async move {
            let started = Instant::now();
            let mut tls = rdock_testkit::client::tls_connect(addr(port), "app.test", client)
                .await
                .expect("the waiting connection is served, not reset");
            assert_eq!(get_on(&mut tls, "app.test").await, 200);
            started.elapsed()
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!waiting.is_finished(), "no slot is free yet");
    // The stalled clients go away; the slots free up and the waiting client is served.
    drop(stalled);
    let waited = tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("served after the slots freed")
        .unwrap();
    assert!(
        waited >= Duration::from_millis(400),
        "it waited ({waited:?})"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while metric(
        &rdock,
        "rdock_tls_handshakes_in_flight{listener=\"websecure\"}",
    ) != Some(0.0)
    {
        assert!(Instant::now() < deadline, "no handshake left in flight");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// How many of `count` connection attempts complete within `wait`: with nothing accepting,
/// the kernel completes at most `backlog + 1` (Linux) and leaves the rest unanswered.
async fn completed_connects(port: u16, count: usize, wait: Duration) -> (usize, Vec<TcpStream>) {
    let mut done = Vec::new();
    for _ in 0..count {
        if let Ok(Ok(stream)) = tokio::time::timeout(wait, TcpStream::connect(addr(port))).await {
            done.push(stream);
        }
    }
    (done.len(), done)
}

/// `socket.backlog` sets the listen queue, and a reload changes it on the running socket (no
/// rebind: the queued connections survive).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_backlog_is_set_and_changes_in_place_on_reload() {
    let backend = Backend::start("app").await;
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "app", &["app.test"]);
    let port = free_port();
    // One handshake slot, held by a stalled client, stops the accept loop: everything after it
    // waits in the kernel's queue, whose length is the backlog.
    let config = |backlog: u32| {
        tls_config(port, backend.addr, &cert, "max_handshakes: 1").replace(
            "    timeouts: { request_header: 30s }",
            &format!(
                "    timeouts: {{ request_header: 30s }}\n    socket: {{ backlog: {backlog} }}"
            ),
        )
    };
    let rdock = Rdock::start(RDOCK, &config(2));
    let holder = TcpStream::connect(addr(port)).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while metric(
        &rdock,
        "rdock_tls_handshakes_in_flight{listener=\"websecure\"}",
    ) != Some(1.0)
    {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (first, kept) = completed_connects(port, 8, Duration::from_millis(300)).await;
    assert_eq!(first, 3, "backlog 2 queues 3 connections on Linux");

    rdock.write_config(&config(6));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let (more, _more) = completed_connects(port, 8, Duration::from_millis(300)).await;
    assert_eq!(more, 4, "backlog 6 queues 7: four more than before");
    // The socket was not replaced: the queued connections are still open and are served once
    // the slot frees.
    drop(holder);
    let client = ca.client_config(&[b"http/1.1"]);
    let mut tls =
        rdock_testkit::client::tls_on(kept.into_iter().next().unwrap(), "app.test", client)
            .await
            .expect("a connection queued before the reload is served");
    assert_eq!(get_on(&mut tls, "app.test").await, 200);
}

/// `runtime` sets the proxy's threads at start; the status and a metric show them, and a reload
/// that changes them says that a restart is needed. A changed `reuse_port` keeps the running
/// socket's value and says so too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_threads_and_restart_only_changes_are_reported() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let config = |workers: u16, reuse: bool| {
        format!(
            r#"
runtime: {{ worker_threads: {workers}, max_blocking_threads: 64 }}
listeners:
  web: {{ address: "127.0.0.1:{port}", socket: {{ reuse_port: {reuse}, backlog: 512, keepalive: {{ idle: 60s, interval: 10s, count: 3 }}, user_timeout: 30s, dscp: 10 }} }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
            backend.addr
        )
    };
    let rdock = Rdock::start(RDOCK, &config(2, false));
    let reply =
        rdock_testkit::client::http1(addr(port), rdock_testkit::client::get("a", "/")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        metric(&rdock, "rdock_runtime_threads{kind=\"worker\"}"),
        Some(2.0)
    );
    assert_eq!(
        metric(&rdock, "rdock_runtime_threads{kind=\"max_blocking\"}"),
        Some(64.0)
    );
    let (_, status) = rdock.get_admin("/api/v1/status").unwrap();
    let status: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status["runtime"]["worker_threads"], 2);
    assert_eq!(status["runtime"]["max_blocking_threads"], 64);

    rdock.write_config(&config(3, true));
    let (code, report) = rdock.reload();
    assert_eq!(code, 200, "{report}");
    let paths: Vec<&str> = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["severity"] == "warning")
        .filter_map(|d| d["path"].as_str())
        .collect();
    assert!(paths.contains(&"runtime"), "{report}");
    assert!(
        paths.contains(&"listeners.web.socket.reuse_port"),
        "{report}"
    );
    // Still the threads it started with, and still serving on the same socket.
    assert_eq!(
        metric(&rdock, "rdock_runtime_threads{kind=\"worker\"}"),
        Some(2.0)
    );
    let reply =
        rdock_testkit::client::http1(addr(port), rdock_testkit::client::get("a", "/")).await;
    assert_eq!(reply.status, 200);
}

/// Options that do not fit the listener are refused at validation.
#[test]
fn misplaced_socket_options_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rdock.yaml");
    std::fs::write(
        &path,
        r#"
runtime: { worker_threads: 0 }
listeners:
  dns: { address: ":5353", protocol: udp, socket: { reuse_port: true, backlog: 10 } }
  raw: { address: ":5432", protocol: tcp, tls: { max_handshakes: 0 } }
  v4: { address: "127.0.0.1:8080", socket: { ipv6_only: true, dscp: 64 } }
"#,
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .arg("validate")
        .arg(&path)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    for path in [
        "runtime.worker_threads",
        "listeners.dns.socket.reuse_port",
        "listeners.dns.socket.backlog",
        "listeners.raw.tls.max_handshakes",
        "listeners.v4.socket.ipv6_only",
        "listeners.v4.socket.dscp",
    ] {
        assert!(text.contains(path), "{path} missing from:\n{text}");
    }
}
