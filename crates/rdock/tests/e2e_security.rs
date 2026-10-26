//! End-to-end: request smuggling vectors, size limits and slow clients (v0.1 acceptance:
//! "smuggling test vectors rejected"). Vector numbers refer to the catalogue in
//! docs/research/v0.1-security.md.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, statuses};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const WAIT: Duration = Duration::from_millis(1500);

struct Setup {
    _rdock: Rdock,
    backend: Backend,
    addr: SocketAddr,
}

async fn setup(extra: &str) -> Setup {
    let backend = Backend::start("app").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}", timeouts: {{ request_header: 1s }} }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
{extra}
"#,
        backend.addr
    );
    Setup {
        _rdock: Rdock::start(RDOCK, &config),
        backend,
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
    }
}

/// Sends `raw` and returns the response statuses; `/smuggled` must never reach the backend.
async fn send(setup: &Setup, raw: &[u8]) -> Vec<u16> {
    let received = client::raw(setup.addr, raw, WAIT).await;
    let found = statuses(&received);
    assert!(
        !setup
            .backend
            .targets()
            .iter()
            .any(|t| t.contains("smuggled")),
        "a smuggled request reached the backend: {:?}",
        setup.backend.targets()
    );
    found
}

fn rejected(found: &[u16]) -> bool {
    found.iter().all(|s| *s >= 400) || found.is_empty()
}

#[tokio::test]
async fn content_length_and_transfer_encoding_vectors() {
    let s = setup("").await;
    let vectors: &[(&str, &[u8])] = &[
        ("1 duplicate CL", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\n12345"),
        ("3 CL list", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 6\r\n\r\n12345"),
        ("4 CL plus", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\n12345"),
        ("5 CL hex", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x5\r\n\r\n12345"),
        ("7 TE chunked, identity", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n"),
        ("9 TE xchunked", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n"),
        ("12 HTTP/1.0 TE", b"POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        ("13 bare LF chunk size", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\n12345\r\n0\r\n\r\n"),
        ("16 chunk size overflow", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFF\r\n"),
        ("17 bad chunk terminator", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345XX0\r\n\r\n"),
    ];
    for (name, raw) in vectors {
        let found = send(&s, raw).await;
        assert!(rejected(&found), "{name}: {found:?}");
    }
}

#[tokio::test]
async fn cl_te_conflict_cannot_smuggle() {
    let s = setup("").await;
    // Vector 6: the chunked body is empty, so a CL-honouring parser would see `/smuggled` as
    // part of the body while a TE-honouring one would see it as the next request.
    let raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 46\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";
    let found = send(&s, raw).await;
    assert!(found.len() <= 1, "only one response: {found:?}");
    // A smuggling attempt hidden in an upgrade (vector 30).
    let raw = b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";
    send(&s, raw).await;
}

#[tokio::test]
async fn target_authority_and_header_syntax_vectors() {
    let s = setup("").await;
    let vectors: &[(&str, &[u8])] = &[
        ("19 duplicate Host", b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
        ("20 no Host", b"GET / HTTP/1.1\r\n\r\n"),
        ("21 userinfo", b"GET http://u@evil/ HTTP/1.1\r\nHost: evil\r\n\r\n"),
        ("22 absolute-form mismatch", b"GET http://a/ HTTP/1.1\r\nHost: b\r\n\r\n"),
        ("24 space before colon", b"GET / HTTP/1.1\r\nHost: x\r\nFoo : bar\r\n\r\n"),
        ("25 leading space", b"GET / HTTP/1.1\r\n Host: x\r\n\r\n"),
        ("26 obs-fold", b"GET / HTTP/1.1\r\nHost: x\r\nFoo: a\r\n b\r\n\r\n"),
        ("27 CR in value", b"GET / HTTP/1.1\r\nHost: x\r\nFoo: a\rb\r\n\r\n"),
        ("28 bare LF headers", b"GET / HTTP/1.1\nHost: x\n\n"),
        ("29 obfuscated Expect", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nExpect: y 100-continue\r\n\r\nABCDEF"),
        ("31 Connection nominates XFF", b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, X-Forwarded-For\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n"),
    ];
    for (name, raw) in vectors {
        let found = send(&s, raw).await;
        assert!(rejected(&found), "{name}: {found:?}");
    }
    assert_eq!(s.backend.requests(), 0, "{:?}", s.backend.targets());
    // A valid request on the same listener still works.
    let ok = send(
        &s,
        b"GET /fine HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(ok, vec![200]);
}

#[tokio::test]
async fn size_limits_are_enforced() {
    let s = setup("security: { limits: { max_header_bytes: 4KiB, max_headers: 20, max_uri_bytes: 1KiB, max_body_bytes: 1KiB } }").await;
    let big_header = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nX-Big: {}\r\n\r\n",
        "a".repeat(5000)
    );
    assert_eq!(send(&s, big_header.as_bytes()).await, vec![431]);
    let mut many = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
    for i in 0..25 {
        use std::fmt::Write;
        write!(many, "X-{i}: v\r\n").unwrap();
    }
    many.push_str("\r\n");
    assert_eq!(send(&s, many.as_bytes()).await, vec![431]);
    let long_uri = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(2000));
    assert_eq!(send(&s, long_uri.as_bytes()).await, vec![414]);
    let declared = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2000\r\n\r\n{}",
        "a".repeat(2000)
    );
    assert_eq!(send(&s, declared.as_bytes()).await, vec![413]);
    let chunk = "a".repeat(800);
    let chunked = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n320\r\n{chunk}\r\n320\r\n{chunk}\r\n0\r\n\r\n"
    );
    let found = send(&s, chunked.as_bytes()).await;
    assert!(
        found.contains(&413) || found.iter().all(|s| *s != 200),
        "{found:?}"
    );
}

#[tokio::test]
async fn slow_headers_are_cut_off() {
    let s = setup("").await;
    let mut stream = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    let started = Instant::now();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    // Keep dribbling bytes, each well inside the per-read timeout.
    let mut closed = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if stream.write_all(b"X-A: b\r\n").await.is_err() {
            closed = true;
            break;
        }
        let mut buf = [0u8; 64];
        if let Ok(Ok(0)) =
            tokio::time::timeout(Duration::from_millis(10), stream.read(&mut buf)).await
        {
            closed = true;
            break;
        }
    }
    assert!(
        closed,
        "the connection stayed open while headers trickled in"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(s.backend.requests(), 0);
}

#[tokio::test]
async fn idle_connections_without_bytes_are_closed() {
    let s = setup("").await;
    let mut stream = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
    assert!(started.elapsed() < Duration::from_secs(3));
}
