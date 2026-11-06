//! End-to-end: inbound PROXY protocol v1/v2 through the real binary (M-L4-03, ADR-0026).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::haproxy::Haproxy;
use rdock_testkit::proxy_protocol as pp;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
/// The client a PROXY header names.
const CLIENT: &str = "203.0.113.7:51234";
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n";

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn client() -> SocketAddr {
    CLIENT.parse().unwrap()
}

/// One plain listener `web` with `proxy_protocol` set to `settings`, routed to `backend`.
fn config(port: u16, backend: SocketAddr, settings: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}", proxy_protocol: {settings} }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    backends: [{{ address: "{backend}" }}]
"#
    )
}

fn wait_for_access_log(rdock: &Rdock, n: usize) -> Vec<serde_json::Value> {
    let started = Instant::now();
    loop {
        let lines = rdock.access_log();
        if lines.len() >= n || started.elapsed() > Duration::from_secs(5) {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn rejected(rdock: &Rdock, reason: &str) -> String {
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    let prefix =
        format!("rdock_proxy_protocol_rejected_total{{listener=\"web\",reason=\"{reason}\"}} ");
    metrics
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .unwrap_or("0")
        .to_owned()
}

/// Sends `bytes` and returns what came back before the server closed the connection.
async fn exchange(port: u16, bytes: &[u8]) -> Vec<u8> {
    client::raw(addr(port), bytes, Duration::from_secs(3)).await
}

#[tokio::test]
async fn trusted_v1_and_v2_headers_name_the_client() {
    let backend = Backend::start("one").await;
    let port = free_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, "{ trusted: [127.0.0.0/8] }"),
    );
    for header in [pp::v1(client(), addr(port)), pp::v2(client(), addr(port))] {
        let reply = client::http1_after(addr(port), &header, get("app.test", "/")).await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        let headers = &reply.json()["headers"];
        assert_eq!(headers["x-forwarded-for"][0], "203.0.113.7");
        assert_eq!(headers["x-real-ip"][0], "203.0.113.7");
    }
    // LOCAL (a health check) keeps the real endpoints.
    let reply = client::http1_after(addr(port), &pp::v2_local(), get("app.test", "/")).await;
    assert_eq!(reply.json()["headers"]["x-forwarded-for"][0], "127.0.0.1");

    let log = wait_for_access_log(&rdock, 3);
    assert_eq!(log.len(), 3, "{log:?}");
    for line in &log[..2] {
        assert_eq!(line["client_ip"], "203.0.113.7");
        let peer = line["proxy_peer"].as_str().unwrap();
        assert!(peer.starts_with("127.0.0.1:"), "{peer}");
    }
    assert_eq!(log[2]["client_ip"], "127.0.0.1");
    assert!(log[2].get("proxy_peer").is_none(), "no header used");
}

#[tokio::test]
async fn untrusted_sender_of_a_header_is_closed_and_counted() {
    let backend = Backend::start("one").await;
    let port = free_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, "{ trusted: [10.0.0.0/8] }"),
    );
    let sent = [pp::v2(client(), addr(port)).as_slice(), REQUEST].concat();
    assert_eq!(exchange(port, &sent).await, b"", "closed without an answer");
    assert_eq!(rejected(&rdock, "untrusted"), "1");
    assert_eq!(backend.requests(), 0);
    // The same source without a header is a plain client.
    let reply = client::http1(addr(port), get("app.test", "/")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["headers"]["x-forwarded-for"][0], "127.0.0.1");
}

#[tokio::test]
async fn trusted_source_without_a_header() {
    let backend = Backend::start("one").await;
    let port = free_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, "{ trusted: [127.0.0.1] }"),
    );
    assert_eq!(exchange(port, REQUEST).await, b"", "a header is required");
    assert_eq!(rejected(&rdock, "missing"), "1");
    let malformed = [b"PROXY TCP4 nonsense\r\n".as_slice(), REQUEST].concat();
    assert_eq!(exchange(port, &malformed).await, b"");
    assert_eq!(rejected(&rdock, "malformed"), "1");
    assert_eq!(backend.requests(), 0);

    let port = free_port();
    let settings = "{ trusted: [127.0.0.1], optional: true }";
    let _rdock = Rdock::start(RDOCK, &config(port, backend.addr, settings));
    let reply = client::http1(addr(port), get("app.test", "/")).await;
    assert_eq!(reply.status, 200, "optional: served without a header");
    let reply = client::http1_after(
        addr(port),
        &pp::v1(client(), addr(port)),
        get("app.test", "/"),
    )
    .await;
    assert_eq!(reply.json()["headers"]["x-forwarded-for"][0], "203.0.113.7");
}

#[tokio::test]
async fn listener_without_proxy_protocol_never_looks_for_a_header() {
    let backend = Backend::start("one").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    backends: [{{ address: "{}" }}]
"#,
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let reply = client::http1(addr(port), get("app.test", "/")).await;
    assert_eq!(reply.status, 200);
    // The header is not taken for one: it is a malformed HTTP request.
    let sent = [pp::v1(client(), addr(port)).as_slice(), REQUEST].concat();
    let answer = exchange(port, &sent).await;
    assert_eq!(
        client::statuses(&answer),
        vec![400],
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(backend.requests(), 1);
}

#[tokio::test]
async fn https_listener_reads_the_header_before_the_client_hello() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "app", &["app.test"]);
    let backend = Backend::start("one").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  websecure: {{ address: "127.0.0.1:{port}", tls: {{}}, proxy_protocol: {{ trusted: [127.0.0.0/8] }} }}
certificates:
  app: {{ cert_file: "{}", key_file: "{}" }}
routes:
  app: {{ match: "Host(`app.test`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        cert.cert.display(),
        cert.key.display(),
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    for alpn in [b"h2".as_slice(), b"http/1.1"] {
        let reply = client::tls_after(
            addr(port),
            &pp::v2_with_tlvs(client(), addr(port)),
            "app.test",
            ca.client_config(&[alpn]),
            get("app.test", "/"),
        )
        .await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        let headers = &reply.json()["headers"];
        assert_eq!(headers["x-forwarded-for"][0], "203.0.113.7");
        assert_eq!(headers["x-forwarded-proto"][0], "https");
    }
    let log = wait_for_access_log(&rdock, 2);
    assert!(
        log.iter().all(|l| l["client_ip"] == "203.0.113.7"),
        "{log:?}"
    );
}

/// HAProxy as an independent sender: `send-proxy` (v1) and `send-proxy-v2`. Needs Docker and
/// `RDOCK_DOCKER_TESTS=1`, as in CI.
#[tokio::test]
async fn haproxy_send_proxy_interop() {
    if !std::env::var("RDOCK_DOCKER_TESTS").is_ok_and(|v| v == "1") {
        eprintln!("skipped: set RDOCK_DOCKER_TESTS=1 (needs Docker)");
        return;
    }
    let backend = Backend::start("one").await;
    let port = free_port();
    // HAProxy connects from a container address; which one depends on the Docker setup.
    let config = config(port, backend.addr, "{ trusted: [0.0.0.0/0, \"::/0\"] }")
        .replace(&format!("127.0.0.1:{port}"), &format!(":{port}"));
    let rdock = Rdock::start(RDOCK, &config);
    let (v1, v2) = (free_port(), free_port());
    let haproxy = format!(
        "defaults\n  mode tcp\n  timeout connect 5s\n  timeout client 30s\n  timeout server 30s\n\
         frontend in_v1\n  bind :{v1}\n  default_backend out_v1\n\
         backend out_v1\n  server rdock rdock-host:{port} send-proxy\n\
         frontend in_v2\n  bind :{v2}\n  default_backend out_v2\n\
         backend out_v2\n  server rdock rdock-host:{port} send-proxy-v2\n"
    );
    let _haproxy = Haproxy::start(&haproxy, &[v1, v2]);
    for front in [v1, v2] {
        let reply = client::http1(addr(front), get("app.test", "/")).await;
        assert_eq!(reply.status, 200, "{}", reply.text());
    }
    let log = wait_for_access_log(&rdock, 2);
    assert_eq!(log.len(), 2, "{log:?}");
    for line in &log {
        // The client HAProxy saw, not HAProxy's own address, is the client.
        let peer: SocketAddr = line["proxy_peer"].as_str().unwrap().parse().unwrap();
        let client = line["client_ip"].as_str().unwrap();
        assert_ne!(client, peer.ip().to_string(), "{line}");
    }
}
