//! End-to-end: the experimental HTTP/3 ingress (H-PERF-05, ADR-0032), with the in-tree quinn and
//! h3 client of the testkit. Built and run only with `--features http3`.

#![cfg(feature = "http3")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::manual_assert,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rdock_proxy::http3::request::{decode, encode};
use rdock_testkit::backend::Backend;
use rdock_testkit::certs::{Issued, TestCa};
use rdock_testkit::client;
use rdock_testkit::free_port;
use rdock_testkit::h3::{self, H3Client, RawOutcome, h3_crate, quinn};
use rdock_testkit::origin::{Origin, Script};
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

/// HTTP/3 error codes (RFC 9114 §8.1, RFC 9204 §6).
const H3_EXCESSIVE_LOAD: u64 = 0x107;
const H3_MESSAGE_ERROR: u64 = 0x10e;
const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;

struct Setup {
    ca: TestCa,
    _dir: tempfile::TempDir,
    cert: Issued,
    port: u16,
}

impl Setup {
    fn new() -> Self {
        let ca = TestCa::new();
        let dir = tempfile::tempdir().unwrap();
        let cert = ca.issue(dir.path(), "app", &["app.test"]);
        Self {
            ca,
            _dir: dir,
            cert,
            port: free_port(),
        }
    }

    fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// A configuration with listener `websecure` (HTTP/3 settings `h3`), route `app` for
    /// `app.test` to `services.app` (`service`), and `extra` appended.
    fn config(&self, h3: &str, service: &str, extra: &str) -> String {
        format!(
            r#"
acme: false
certificates:
  app: {{ cert_file: "{cert}", key_file: "{key}" }}
listeners:
  websecure: {{ address: "127.0.0.1:{port}", tls: {{}}, http3: {{ {h3} }} }}
defaults: {{ tls: off }}
routes:
  app: {{ match: "Host(`app.test`)", service: app, listeners: [websecure], tls: {{ certificate: app }} }}
services:
  app: {service}
{extra}"#,
            cert = self.cert.cert.display(),
            key = self.cert.key.display(),
            port = self.port,
        )
    }

    async fn client(&self) -> H3Client {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match H3Client::connect(self.addr(), "app.test", &[self.ca.der()]).await {
                Ok(client) => return client,
                Err(err) if Instant::now() > deadline => panic!("no HTTP/3 connection: {err}"),
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    async fn https(&self, alpn: &[u8]) -> client::Reply {
        client::tls(
            self.addr(),
            "app.test",
            self.ca.client_config(&[alpn]),
            client::get("app.test", "/"),
        )
        .await
    }
}

fn backend_service(addr: SocketAddr) -> String {
    format!("{{ backends: [{{ address: \"{addr}\" }}] }}")
}

/// Waits until `check` holds on the metrics text, or panics with them and the log.
async fn wait_metrics(rdock: &Rdock, check: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (_, text) = rdock.get_admin("/metrics").unwrap();
        if check(&text) {
            return text;
        }
        if Instant::now() > deadline {
            panic!(
                "metrics never matched:\n{text}\n--- log ---\n{}",
                rdock.log()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Waits until an access-log line satisfies `check`.
async fn wait_log(rdock: &Rdock, check: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(line) = rdock.access_log().into_iter().find(|l| check(l)) {
            return line;
        }
        if Instant::now() > deadline {
            panic!(
                "no matching access-log line:\n{:?}\n--- log ---\n{}",
                rdock.access_log(),
                rdock.log()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn request_fields(extra: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut fields: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"app.test"),
        (b":path", b"/"),
    ];
    fields.extend_from_slice(extra);
    h3::frame(1, &encode::section(&fields))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_and_streaming_post_reach_the_backend_and_are_logged_as_http3() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let rdock = Rdock::start(
        RDOCK,
        &setup.config("enabled: true", &backend_service(backend.addr), ""),
    );
    let mut h3c = setup.client().await;

    let reply = h3c.get("/hello?x=1").await.unwrap();
    assert_eq!(reply.status(), 200, "{}", reply.text());
    let echo: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(echo["target"], "/hello?x=1");
    assert_eq!(echo["headers"]["host"][0], "app.test");
    assert_eq!(echo["version"], "HTTP/1.1", "the backend gets HTTP/1.1");
    assert!(
        reply.header("alt-svc").is_none(),
        "no Alt-Svc on HTTP/3 answers"
    );

    // 8 MiB in 64 KiB DATA frames, without a content-length: chunked to the backend.
    let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
    let body: Vec<Bytes> = std::iter::repeat_n(chunk.clone(), 128).collect();
    let req = h3c.request("POST", "/echo-body").body(()).unwrap();
    let reply = h3c.send(req, body).await.unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.header("x-body-len"), Some("8388608"));
    assert_eq!(reply.header("x-request-transfer-encoding"), Some("chunked"));
    assert_eq!(reply.body.len(), 8 << 20);
    // With a content-length it is passed on.
    let req = h3c
        .request("POST", "/echo-body")
        .header("content-length", "131072")
        .body(())
        .unwrap();
    let reply = h3c.send(req, vec![chunk.clone(), chunk]).await.unwrap();
    assert_eq!(reply.header("x-request-content-length"), Some("131072"));
    assert_eq!(reply.header("x-body-len"), Some("131072"));

    let line = wait_log(&rdock, |l| l["path"] == "/hello").await;
    assert_eq!(line["proto"], "HTTP/3", "{line}");
    assert_eq!(line["sni"], "app.test", "{line}");
    assert_eq!(line["tls_version"], "TLSv1.3", "{line}");
    wait_metrics(&rdock, |m| {
        m.contains("rdock_http3_connections_total{listener=\"websecure\"} 1")
            && m.contains(
                "rdock_http3_requests_total{listener=\"websecure\",status_class=\"2xx\"} 3",
            )
            && m.contains("rdock_http3_connections{listener=\"websecure\"} 1")
    })
    .await;
    assert!(
        rdock.log().contains("HTTP/3 is experimental"),
        "{}",
        rdock.log()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trailers_from_an_h2c_backend_reach_the_client() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let service = format!(
        "{{ scheme: h2c, backends: [{{ address: \"{}\" }}] }}",
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &setup.config("enabled: true", &service, ""));
    let mut h3c = setup.client().await;
    let req = h3c
        .request("POST", "/grpc")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let reply = h3c
        .send(req, vec![Bytes::from_static(b"\0\0\0\0\x02hi")])
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(&reply.body[..], b"\0\0\0\0\x02hi");
    let trailers = reply.trailers.expect("trailers");
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(trailers["grpc-message"], "ok");
}

/// A backend that answers GET requests at once and reads any other request until the
/// connection ends, then reports how much it read.
async fn draining_backend() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<usize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut total = 0;
                let mut buf = [0u8; 16 * 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if total == 0 && buf.starts_with(b"GET ") {
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                            .await;
                        return;
                    }
                    total += n;
                }
                let _ = tx.send(total);
            });
        }
    });
    (addr, rx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_reset_mid_body_ends_the_upstream_request() {
    let (backend, mut ended) = draining_backend().await;
    let setup = Setup::new();
    let rdock = Rdock::start(
        RDOCK,
        &setup.config("enabled: true", &backend_service(backend), ""),
    );
    let mut h3c = setup.client().await;
    let req = h3c.request("POST", "/upload").body(()).unwrap();
    let mut stream = h3c
        .start(req, vec![Bytes::from(vec![b'y'; 256 * 1024])])
        .await
        .unwrap();
    // The upstream request is open (the backend reads the body) before the reset.
    tokio::time::sleep(Duration::from_millis(500)).await;
    stream.stop_stream(h3_crate::error::Code::H3_REQUEST_CANCELLED);
    stream.stop_sending(h3_crate::error::Code::H3_REQUEST_CANCELLED);
    let read = tokio::time::timeout(Duration::from_secs(15), ended.recv())
        .await
        .unwrap_or_else(|_| panic!("the upstream connection stayed open\n{}", rdock.log()))
        .unwrap();
    assert!(read > 0, "the backend got the request");
    // The connection still serves new requests.
    drop(stream);
    let reply = h3c.get("/again").await.unwrap();
    assert_eq!(reply.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_backend_is_retried_on_the_next_one() {
    let backend = Backend::start("live").await;
    let dead = free_port();
    let setup = Setup::new();
    let service = format!(
        "{{ backends: [{{ address: \"127.0.0.1:{dead}\" }}, {{ address: \"{}\" }}], load_balancer: {{ policy: round_robin }} }}",
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &setup.config("enabled: true", &service, ""));
    let mut h3c = setup.client().await;
    for i in 0..4 {
        let req = h3c
            .request("POST", &format!("/echo-body?i={i}"))
            .header("content-length", "5")
            .body(())
            .unwrap();
        let reply = h3c
            .send(req, vec![Bytes::from_static(b"hello")])
            .await
            .unwrap();
        assert_eq!(reply.status(), 200, "{}", reply.text());
        assert_eq!(&reply.body[..], b"hello");
    }
    let line = wait_log(&rdock, |l| {
        l["tried"].as_array().is_some_and(|t| !t.is_empty())
    })
    .await;
    assert_eq!(line["proto"], "HTTP/3");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_502_is_retried_with_the_request_body_replayed() {
    let failing = Backend::start("failing").await;
    failing.fail_pattern(1, 1);
    let live = Backend::start("live").await;
    let setup = Setup::new();
    let service = format!(
        "{{ backends: [{{ address: \"{}\" }}, {{ address: \"{}\" }}], load_balancer: {{ policy: round_robin }}, retries: {{ attempts: 2, on: [connect, \"502\"] }}, health: {{ passive: {{ failures: 1000 }} }} }}",
        failing.addr, live.addr
    );
    let rdock = Rdock::start(RDOCK, &setup.config("enabled: true", &service, ""));
    let mut h3c = setup.client().await;
    let body = Bytes::from(vec![b'z'; 10 * 1024]);
    for _ in 0..4 {
        let req = h3c
            .request("PUT", "/echo-body")
            .header("content-length", "10240")
            .body(())
            .unwrap();
        let reply = h3c.send(req, vec![body.clone()]).await.unwrap();
        assert_eq!(reply.status(), 200, "{}\n{}", reply.text(), rdock.log());
        assert_eq!(reply.body, body, "the replayed body is the one sent");
    }
    assert!(failing.traffic() > 0, "the failing backend was tried");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cache_and_a_rate_limit_apply_to_http3_requests() {
    let origin = Origin::start().await;
    origin.set("/a", Script::ok("alpha").cache_control("max-age=60"));
    let setup = Setup::new();
    let config = setup
        .config("enabled: true", &backend_service(origin.addr), "caches:\n  mem: { type: memory }\nmiddlewares:\n  cache: { type: cache, store: mem }\n  limit: { type: rate_limit, average: 3, burst: 3, period: 1m }\n")
        .replace("service: app, listeners", "service: app, middlewares: [limit, cache], listeners");
    let rdock = Rdock::start(RDOCK, &config);
    let mut h3c = setup.client().await;
    let first = h3c.get("/a").await.unwrap();
    assert_eq!((first.status(), first.text().as_str()), (200, "alpha"));
    let second = h3c.get("/a").await.unwrap();
    assert_eq!(second.text(), "alpha");
    assert_eq!(
        origin.count("/a"),
        1,
        "the second answer came from the cache"
    );
    let line = wait_log(&rdock, |l| l["cache_status"] == "hit").await;
    assert_eq!(line["proto"], "HTTP/3");
    // The third request is the last the burst allows; the fourth is limited.
    assert_eq!(h3c.get("/a").await.unwrap().status(), 200);
    assert_eq!(h3c.get("/a").await.unwrap().status(), 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_always_makes_every_client_prove_its_address() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let rdock = Rdock::start(
        RDOCK,
        &setup.config(
            "enabled: true, retry: always",
            &backend_service(backend.addr),
            "",
        ),
    );
    let mut h3c = setup.client().await;
    assert_eq!(h3c.get("/").await.unwrap().status(), 200);
    wait_metrics(&rdock, |m| {
        m.lines().any(|l| {
            l.starts_with("rdock_http3_retries_total{listener=\"websecure\"}") && !l.ends_with(" 0")
        })
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alt_svc_is_on_http1_and_http2_answers_while_http3_serves() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let service = backend_service(backend.addr);
    let rdock = Rdock::start(RDOCK, &setup.config("enabled: true", &service, ""));
    let _ = setup.client().await;
    let expected = format!("h3=\":{}\"; ma=3600", setup.port);
    for alpn in [&b"http/1.1"[..], b"h2"] {
        let reply = setup.https(alpn).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("alt-svc"), Some(expected.as_str()), "{alpn:?}");
    }
    // An answer of rdock's own (no route) carries it too.
    let reply = client::tls(
        setup.addr(),
        "app.test",
        setup.ca.client_config(&[b"http/1.1"]),
        client::get("other.test", "/"),
    )
    .await;
    assert_eq!(reply.status, 404);
    assert_eq!(reply.header("alt-svc"), Some(expected.as_str()));

    rdock.write_config(&setup.config(
        "enabled: true, advertise_port: 8443, advertise_max_age: 60s",
        &service,
        "",
    ));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let reply = setup.https(b"h2").await;
    assert_eq!(reply.header("alt-svc"), Some("h3=\":8443\"; ma=60"));

    rdock.write_config(&setup.config("enabled: true, advertise: false", &service, ""));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    assert!(setup.https(b"http/1.1").await.header("alt-svc").is_none());
    // Still serving HTTP/3, only not advertised.
    let mut h3c = setup.client().await;
    assert_eq!(h3c.get("/").await.unwrap().status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_requests_are_refused_and_never_forwarded() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let rdock = Rdock::start(
        RDOCK,
        &setup.config("enabled: true", &backend_service(backend.addr), ""),
    );
    let h3c = setup.client().await;
    let wait = Duration::from_secs(10);
    let pseudo_after = h3::frame(
        1,
        &encode::section(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b"x", b"y"),
            (b":authority", b"app.test"),
            (b":path", b"/"),
        ]),
    );
    let twice = h3::frame(
        1,
        &encode::section(&[
            (b":method", b"GET"),
            (b":method", b"DELETE"),
            (b":scheme", b"https"),
            (b":authority", b"app.test"),
            (b":path", b"/"),
        ]),
    );
    let no_authority = h3::frame(
        1,
        &encode::section(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":path", b"/"),
        ]),
    );
    let connect = h3::frame(
        1,
        &encode::section(&[(b":method", b"CONNECT"), (b":authority", b"app.test:443")]),
    );
    let mut too_long = request_fields(&[(b"content-length", b"3")]);
    too_long.extend(h3::frame(0, b"hello"));
    let mut too_short = request_fields(&[(b"content-length", b"9")]);
    too_short.extend(h3::frame(0, b"hello"));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("uppercase name", request_fields(&[(b"X-Upper", b"1")])),
        (
            "connection field",
            request_fields(&[(b"connection", b"close")]),
        ),
        (
            "transfer-encoding",
            request_fields(&[(b"transfer-encoding", b"chunked")]),
        ),
        ("CR LF in a value", request_fields(&[(b"x", b"a\r\nb: c")])),
        ("pseudo after regular", pseudo_after),
        ("repeated pseudo", twice),
        (
            ":status in a request",
            h3::frame(
                1,
                &encode::section(&[
                    (b":status", b"200"),
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"app.test"),
                    (b":path", b"/"),
                ]),
            ),
        ),
        ("no authority", no_authority),
        ("CONNECT", connect),
        (
            "userinfo",
            h3::frame(
                1,
                &encode::section(&[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"u@app.test"),
                    (b":path", b"/"),
                ]),
            ),
        ),
    ];
    for (name, bytes) in &cases {
        let outcome = h3c.raw(bytes, true, wait).await;
        assert_eq!(outcome, RawOutcome::Reset(H3_MESSAGE_ERROR), "{name}");
    }

    // Over max_header_size (64 KiB): 431.
    let big = vec![b'a'; 70 * 1024];
    let outcome = h3c
        .raw(&request_fields(&[(b"x-big", &big)]), true, wait)
        .await;
    let RawOutcome::Answered(headers) = outcome else {
        panic!("{outcome:?}");
    };
    let fields = decode(&headers, 1 << 20).unwrap();
    assert!(
        fields
            .iter()
            .any(|f| &f.name[..] == b":status" && &f.value[..] == b"431"),
        "{fields:?}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(backend.requests(), 0, "nothing malformed was forwarded");
    // A body longer or shorter than its content-length is found only as the DATA arrives,
    // after the (valid) head went upstream: the stream is reset with H3_MESSAGE_ERROR and the
    // upstream request is abandoned, so the backend never gets a complete request.
    assert_eq!(
        h3c.raw(&too_long, true, wait).await,
        RawOutcome::Reset(H3_MESSAGE_ERROR)
    );
    assert_eq!(
        h3c.raw(&too_short, true, wait).await,
        RawOutcome::Reset(H3_MESSAGE_ERROR)
    );
    let metrics = wait_metrics(&rdock, |m| {
        m.contains(
            "rdock_http3_malformed_requests_total{listener=\"websecure\",reason=\"too_large\"} 1",
        )
    })
    .await;
    assert!(metrics.contains("reason=\"field_name\""), "{metrics}");
    assert!(
        metrics.contains("reason=\"connection_specific\""),
        "{metrics}"
    );
    assert!(metrics.contains("reason=\"pseudo_header\""), "{metrics}");
    assert!(metrics.contains("reason=\"connect\""), "{metrics}");

    // A dynamic-table reference (rdock announces no dynamic table) closes the connection.
    let outcome = h3c.raw(&h3::frame(1, &[0, 0, 0x80]), true, wait).await;
    assert_eq!(
        outcome,
        RawOutcome::ConnectionClosed(QPACK_DECOMPRESSION_FAILED)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_flood_closes_the_connection() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let rdock = Rdock::start(
        RDOCK,
        &setup.config("enabled: true", &backend_service(backend.addr), ""),
    );
    let h3c = setup.client().await;
    // HEADERS cut short, then RESET_STREAM, 150 times (the limit is 100 within 10 s).
    let partial = &request_fields(&[])[..6];
    for _ in 0..150 {
        if h3c.raw_reset(partial, 0x10c).await.is_err() {
            break;
        }
    }
    let reason = tokio::time::timeout(Duration::from_secs(15), h3c.conn.closed())
        .await
        .unwrap_or_else(|_| panic!("the connection stayed open\n{}", rdock.log()));
    match reason {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code.into_inner(), H3_EXCESSIVE_LOAD);
        }
        other => panic!("{other:?}"),
    }
    wait_metrics(&rdock, |m| {
        m.contains(
            "rdock_http3_connections_closed_total{listener=\"websecure\",reason=\"reset_flood\"} 1",
        )
    })
    .await;
    assert_eq!(backend.requests(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn goaway_on_reload_lets_the_request_in_flight_finish() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let service = backend_service(backend.addr);
    let rdock = Rdock::start(RDOCK, &setup.config("enabled: true", &service, ""));
    let mut h3c = setup.client().await;
    assert_eq!(h3c.get("/warm").await.unwrap().status(), 200);
    let req = h3c.request("GET", "/slow/2000").body(()).unwrap();
    let mut slow = h3c.start(req, Vec::new()).await.unwrap();
    slow.finish().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Turning HTTP/3 off stops the side: GOAWAY, the request in flight finishes.
    rdock.write_config(&setup.config("enabled: false", &service, ""));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let reply = tokio::time::timeout(Duration::from_secs(15), h3::read_reply(&mut slow))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.text(), "slow from app\n");
    let closed = tokio::time::timeout(Duration::from_secs(15), &mut h3c.closed)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(closed, "");
    // A new request on the connection is not served, and HTTPS no longer advertises.
    assert!(h3c.get("/after").await.is_err());
    assert!(setup.https(b"h2").await.header("alt-svc").is_none());
    let metrics = wait_metrics(&rdock, |m| m.contains("reason=\"drained\"")).await;
    assert!(
        metrics.contains("rdock_http3_connections{listener=\"websecure\"} 0"),
        "{metrics}"
    );
    // Back on: served again.
    rdock.write_config(&setup.config("enabled: true", &service, ""));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let mut again = setup.client().await;
    assert_eq!(again.get("/").await.unwrap().status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_serves_while_the_udp_port_is_taken() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let taken = std::net::UdpSocket::bind(setup.addr()).unwrap();
    let rdock = Rdock::start(
        RDOCK,
        &setup.config("enabled: true", &backend_service(backend.addr), ""),
    );
    let reply = setup.https(b"http/1.1").await;
    assert_eq!(reply.status, 200);
    assert!(
        reply.header("alt-svc").is_none(),
        "nothing advertised without the QUIC endpoint"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !rdock
        .log()
        .contains("cannot bind the UDP socket for HTTP/3")
    {
        assert!(Instant::now() < deadline, "{}", rdock.log());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Once the port is free, HTTP/3 starts without a reload.
    drop(taken);
    let mut h3c = setup.client().await;
    assert_eq!(h3c.get("/").await.unwrap().status(), 200);
    assert!(setup.https(b"http/1.1").await.header("alt-svc").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_rtt_is_never_accepted() {
    let backend = Backend::start("app").await;
    let setup = Setup::new();
    let _rdock = Rdock::start(
        RDOCK,
        &setup.config("enabled: true", &backend_service(backend.addr), ""),
    );
    let _ = setup.client().await;
    // A client that would send early data, keeping its TLS session between connections.
    let config = h3::quic_client(h3::client_tls(&[setup.ca.der()], true));
    let endpoint = h3::endpoint();
    let first = endpoint
        .connect_with(config.clone(), setup.addr(), "app.test")
        .unwrap()
        .await
        .unwrap();
    // Let the server's session ticket arrive, then reconnect.
    let (mut send, mut recv) = first.open_bi().await.unwrap();
    send.write_all(&request_fields(&[])).await.unwrap();
    send.finish().unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1 << 20)).await;
    first.close(0u32.into(), b"");
    let second = endpoint
        .connect_with(config, setup.addr(), "app.test")
        .unwrap();
    match second.into_0rtt() {
        Ok((conn, accepted)) => {
            // The client may try; the server must refuse the early data.
            assert!(!accepted.await, "the server accepted 0-RTT");
            drop(conn);
        }
        Err(connecting) => {
            // Not even offered: the ticket did not allow early data.
            assert!(connecting.await.is_ok());
        }
    }
}
