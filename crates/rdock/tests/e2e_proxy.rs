//! End-to-end: protocols through the real binary (v0.1 acceptance: h1, h2, h2c, WebSocket,
//! SSE, gRPC, forwarded headers).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::items_after_statements
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rdock_testkit::backend::Backend;
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use tokio_tungstenite::tungstenite::Message;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Plain HTTP on one port, routed to `backend`.
fn plain(port: u16, backend: SocketAddr, extra: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    backends: [{{ address: "{backend}" }}]
{extra}
"#
    )
}

#[tokio::test]
async fn http1_proxies_and_sets_forwarding_headers() {
    let backend = Backend::start("one").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &plain(port, backend.addr, ""));
    let mut req = get("app.test:8080", "/a/./b/../c?x=1");
    req.headers_mut()
        .insert("x-forwarded-for", "6.6.6.6".parse().unwrap());
    req.headers_mut()
        .insert("x-real-ip", "6.6.6.6".parse().unwrap());
    let reply = client::http1(addr(port), req).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(reply.version, http::Version::HTTP_11);
    let echo = reply.json();
    assert_eq!(echo["target"], "/a/c?x=1", "normalised path is forwarded");
    let headers = &echo["headers"];
    assert_eq!(
        headers["x-forwarded-for"][0], "127.0.0.1",
        "untrusted XFF replaced"
    );
    assert_eq!(headers["x-real-ip"][0], "127.0.0.1");
    assert_eq!(headers["x-forwarded-proto"][0], "http");
    assert_eq!(headers["x-forwarded-host"][0], "app.test:8080");
    assert_eq!(headers["x-forwarded-port"][0], "8080");
    assert_eq!(
        headers["host"][0], "app.test:8080",
        "Host is passed through"
    );
    let request_id = headers["x-request-id"][0].as_str().unwrap().to_owned();
    assert_eq!(reply.header("x-request-id"), Some(request_id.as_str()));

    let log = wait_for_access_log(&rdock, 1);
    let line = &log[0];
    assert_eq!(line["status"], 200);
    assert_eq!(line["route"], "app");
    assert_eq!(line["request_id"], request_id.as_str());
    assert_eq!(line["query_len"], 3);
    assert!(line.get("query").is_none(), "query strings are not logged");
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

#[tokio::test]
async fn trusted_proxies_keep_the_chain() {
    let backend = Backend::start("one").await;
    let port = free_port();
    let config = plain(
        port,
        backend.addr,
        "security: { trusted_proxies: [127.0.0.0/8] }",
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let mut req = get("app.test", "/");
    req.headers_mut()
        .insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
    req.headers_mut()
        .insert("x-forwarded-proto", "https".parse().unwrap());
    let echo = client::http1(addr(port), req).await.json();
    assert_eq!(
        echo["headers"]["x-forwarded-for"][0],
        "198.51.100.7, 127.0.0.1"
    );
    assert_eq!(echo["headers"]["x-real-ip"][0], "198.51.100.7");
    assert_eq!(echo["headers"]["x-forwarded-proto"][0], "https");
}

#[tokio::test]
async fn h2c_downstream_and_upstream() {
    let backend = Backend::start("h2c").await;
    let port = free_port();
    let config =
        plain(port, backend.addr, "").replace("backends: [", "scheme: h2c\n    backends: [");
    let _rdock = Rdock::start(RDOCK, &config);
    let reply = client::h2c(addr(port), get("app.test", "/h2c")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.version, http::Version::HTTP_2);
    assert_eq!(reply.json()["version"], "HTTP/2.0", "h2c to the backend");
    let reply = client::http1(addr(port), get("app.test", "/h1")).await;
    assert_eq!(
        reply.status, 200,
        "HTTP/1.1 clients still work on the h2c listener"
    );
    // A short HTTP/1.0 request must not hang waiting for an h2 preface.
    let raw = client::raw(
        addr(port),
        b"GET / HTTP/1.0\r\n\r\n",
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(
        client::statuses(&raw).first(),
        Some(&200),
        "{}",
        String::from_utf8_lossy(&raw)
    );
}

#[tokio::test]
async fn tls_listener_serves_h2_and_h1_with_sni() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let app = ca.issue(dir.path(), "app", &["app.test"]);
    let other = ca.issue(dir.path(), "other", &["*.other.test"]);
    let backend = Backend::start("tls").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  websecure: {{ address: "127.0.0.1:{port}", tls: {{ policy: modern }} }}
certificates:
  app: {{ cert_file: "{}", key_file: "{}" }}
  other: {{ cert_file: "{}", key_file: "{}" }}
routes:
  app: {{ match: "Host(`app.test`) || HostRegexp(`other`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        app.cert.display(),
        app.key.display(),
        other.cert.display(),
        other.key.display(),
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let h2 = client::tls(
        addr(port),
        "app.test",
        ca.client_config(&[b"h2", b"http/1.1"]),
        get("app.test", "/"),
    )
    .await;
    assert_eq!(h2.status, 200);
    assert_eq!(h2.version, http::Version::HTTP_2);
    assert_eq!(h2.json()["headers"]["x-forwarded-proto"][0], "https");
    let h1 = client::tls(
        addr(port),
        "x.other.test",
        ca.client_config(&[b"http/1.1"]),
        get("x.other.test", "/"),
    )
    .await;
    assert_eq!(h1.status, 200);
    assert_eq!(h1.version, http::Version::HTTP_11);
    // An unknown name has no certificate and no default: the handshake fails.
    assert!(
        client::tls_connect(addr(port), "nope.test", ca.client_config(&[b"h2"]))
            .await
            .is_err()
    );
    // `modern` refuses TLS 1.2.
    let mut tls12 = (*ca.client_config(&[b"http/1.1"])).clone();
    tls12 = rustls_tls12(tls12, &ca);
    assert!(
        client::tls_connect(addr(port), "app.test", std::sync::Arc::new(tls12))
            .await
            .is_err()
    );
}

/// A client configuration limited to TLS 1.2.
fn rustls_tls12(_base: rustls::ClientConfig, ca: &TestCa) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der()).unwrap();
    rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth()
}

#[tokio::test]
async fn http_redirects_to_https_for_tls_hosts() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "app", &["app.test"]);
    let backend = Backend::start("b").await;
    let (plain_port, tls_port) = (free_port(), free_port());
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{plain_port}" }}
  websecure: {{ address: "127.0.0.1:{tls_port}", tls: {{}} }}
certificates:
  app: {{ cert_file: "{}", key_file: "{}" }}
routes:
  secure: {{ match: "Host(`app.test`)", service: app }}
  plain: {{ match: "Host(`plain.test`)", service: app, listeners: [web], tls: off }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        cert.cert.display(),
        cert.key.display(),
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let redirect = client::http1(addr(plain_port), get("app.test", "/x?y=1")).await;
    assert_eq!(redirect.status, 301);
    assert_eq!(
        redirect.header("location"),
        Some(format!("https://app.test:{tls_port}/x?y=1").as_str())
    );
    let post = client::http1(
        addr(plain_port),
        request("POST", "app.test", "/form", "a=1"),
    )
    .await;
    assert_eq!(post.status, 308);
    let plain = client::http1(addr(plain_port), get("plain.test", "/")).await;
    assert_eq!(plain.status, 200, "plain routes are served");
    let unknown = client::http1(addr(plain_port), get("unknown.test", "/")).await;
    assert_eq!(unknown.status, 404);
    assert!(unknown.text().contains("Request ID"), "{}", unknown.text());
}

#[tokio::test]
async fn websocket_upgrade_round_trips() {
    let backend = Backend::start("ws").await;
    let port = free_port();
    let _rdock = Rdock::start(RDOCK, &plain(port, backend.addr, ""));
    let stream = tokio::net::TcpStream::connect(addr(port)).await.unwrap();
    let (mut ws, response) =
        tokio_tungstenite::client_async(format!("ws://127.0.0.1:{port}/ws"), stream)
            .await
            .unwrap();
    assert_eq!(response.status(), 101);
    ws.send(Message::text("hello")).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed, Message::text("hello"));
    ws.send(Message::binary(vec![1, 2, 3])).await.unwrap();
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(echoed, Message::binary(vec![1, 2, 3]));
}

#[tokio::test]
async fn sse_events_stream_without_buffering() {
    let backend = Backend::start("sse").await;
    let port = free_port();
    // `compress` is on the route: event streams must never be buffered by it.
    let config = plain(
        port,
        backend.addr,
        "middlewares:\n  gz: { type: compress }\n",
    )
    .replace("service: app }", "service: app, middlewares: [gz] }");
    let _rdock = Rdock::start(RDOCK, &config);
    let mut stream = tokio::net::TcpStream::connect(addr(port)).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(b"GET /sse?n=3&ms=400 HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n")
        .await
        .unwrap();
    let started = Instant::now();
    let mut seen = String::new();
    let mut first_event_at = None;
    let mut buf = [0u8; 4096];
    while !seen.contains("event 2") && started.elapsed() < Duration::from_secs(5) {
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        if first_event_at.is_none() && seen.contains("event 0") {
            first_event_at = Some(started.elapsed());
        }
    }
    assert!(
        !seen.to_ascii_lowercase().contains("content-encoding"),
        "{seen}"
    );
    let first = first_event_at.expect("first event");
    assert!(
        first < Duration::from_millis(300),
        "first event after {first:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "events were spread out"
    );
}

#[tokio::test]
async fn grpc_over_h2c_keeps_trailers() {
    let backend = Backend::start("grpc").await;
    let port = free_port();
    let config =
        plain(port, backend.addr, "").replace("backends: [", "scheme: h2c\n    backends: [");
    let _rdock = Rdock::start(RDOCK, &config);
    let message = b"\x00\x00\x00\x00\x05hello".to_vec();
    let mut req = request("POST", "app.test", "/grpc", message.clone());
    req.headers_mut()
        .insert("content-type", "application/grpc".parse().unwrap());
    req.headers_mut().insert("te", "trailers".parse().unwrap());
    let reply = client::h2c(addr(port), req).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body.as_ref(), message.as_slice());
    let trailers = reply.trailers.expect("gRPC trailers");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
}

#[tokio::test]
async fn upstream_tls_is_verified() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "backend", &["localhost"]);
    let backend = Backend::start_tls("secure-backend", &cert.cert_pem, &cert.key_pem).await;
    let ca_file = ca.write(dir.path());
    let port = free_port();
    let backend_url = format!("localhost:{}", backend.addr.port());
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  trusted: {{ match: "PathPrefix(`/trusted`)", service: trusted }}
  untrusted: {{ match: "PathPrefix(`/untrusted`)", service: untrusted }}
  insecure: {{ match: "PathPrefix(`/insecure`)", service: insecure }}
services:
  trusted:
    scheme: https
    tls: {{ ca_file: "{}" }}
    backends: [{{ address: "{backend_url}" }}]
  untrusted:
    scheme: https
    backends: [{{ address: "{backend_url}" }}]
  insecure:
    scheme: https
    tls: {{ verify: false }}
    backends: [{{ address: "{backend_url}" }}]
"#,
        ca_file.display()
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let ok = client::http1(addr(port), get("a", "/trusted")).await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(
        ok.json()["version"],
        "HTTP/2.0",
        "h2 by ALPN to the backend"
    );
    let refused = client::http1(addr(port), get("a", "/untrusted")).await;
    assert_eq!(
        refused.status, 502,
        "an unknown CA is refused, even with a pooled connection"
    );
    let insecure = client::http1(addr(port), get("a", "/insecure")).await;
    assert_eq!(insecure.status, 200);
}

#[tokio::test]
async fn backends_by_dns_name() {
    let backend = Backend::start("dns").await;
    let port = free_port();
    let config = plain(port, backend.addr, "").replace(
        &backend.addr.to_string(),
        &format!("localhost:{}", backend.addr.port()),
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let reply = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["backend"], "dns");
}

#[tokio::test]
async fn routing_follows_priority_and_matchers() {
    let one = Backend::start("one").await;
    let two = Backend::start("two").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  catch-all: {{ match: "PathPrefix(`/`)", service: one, priority: 1 }}
  api: {{ match: "Host(`app.test`) && PathPrefix(`/api`)", service: two }}
  admin-ip: {{ match: "Path(`/only-local`) && !ClientIP(`127.0.0.0/8`)", service: two }}
  by-header: {{ match: "Header(`X-Env`, `canary`)", service: two }}
  by-query: {{ match: "Query(`debug`)", service: two }}
services:
  one: {{ backends: [{{ address: "{}" }}] }}
  two: {{ backends: [{{ address: "{}" }}] }}
"#,
        one.addr, two.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let backend_of = |reply: client::Reply| reply.json()["backend"].as_str().unwrap().to_owned();
    assert_eq!(
        backend_of(client::http1(addr(port), get("app.test", "/api/x")).await),
        "two"
    );
    assert_eq!(
        backend_of(client::http1(addr(port), get("APP.test", "/apiv2")).await),
        "two"
    );
    assert_eq!(
        backend_of(client::http1(addr(port), get("other.test", "/api")).await),
        "one"
    );
    assert_eq!(
        backend_of(client::http1(addr(port), get("a", "/only-local")).await),
        "one"
    );
    let mut canary = get("a", "/");
    canary
        .headers_mut()
        .insert("x-env", "canary".parse().unwrap());
    assert_eq!(backend_of(client::http1(addr(port), canary).await), "two");
    assert_eq!(
        backend_of(client::http1(addr(port), get("a", "/?debug")).await),
        "two"
    );
    assert_eq!(
        backend_of(client::http1(addr(port), get("a", "/?debug=1")).await),
        "one"
    );
}

#[tokio::test]
async fn load_is_balanced_by_weight() {
    let one = Backend::start("one").await;
    let two = Backend::start("two").await;
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
    backends: [{{ address: "{}", weight: 3 }}, {{ address: "{}", weight: 1 }}]
"#,
        one.addr, two.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    for _ in 0..8 {
        assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
    }
    assert_eq!((one.requests(), two.requests()), (6, 2));
}
