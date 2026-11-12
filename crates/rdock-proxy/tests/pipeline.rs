//! The phased pipeline and held request bodies (ADR-0030, "Pipeline and body phase"), end to
//! end through an in-process data plane: the configuration is compiled as `rdock run` does, then
//! test-only middlewares are appended to a route's chain (they are not part of the public
//! model). Backends are `rdock-testkit` backends or raw sockets that record what they saw.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::manual_assert_eq,
    reason = "large bodies are compared without printing them"
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_middleware::{
    Body, BodyHold, BodyVerdict, Capabilities, Context, Flow, HeldBody, LogSummary, Middleware,
    Phases, Reply, Upstream,
};
use rdock_proxy::forwarded::CloudflareRanges;
use rdock_proxy::upstream::Dns;
use rdock_proxy::{CompileEnv, DataPlane, Mode, Runtime, compile};
use rdock_testkit::backend::Backend;
use rdock_testkit::{client, free_port};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// -- test doubles ---------------------------------------------------------------------------

/// `upstream_request`: tells the backend which backend and attempt it is.
#[derive(Debug)]
struct TagUpstream;

#[async_trait]
impl Middleware for TagUpstream {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::UPSTREAM_REQUEST)
    }

    async fn upstream_request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let upstream = cx.upstream.clone().expect("set before upstream_request");
        req.insert_header("x-upstream-backend", upstream.backend)
            .unwrap();
        req.insert_header("x-upstream-service", &*upstream.service)
            .unwrap();
        req.insert_header("x-attempt", upstream.attempt.to_string())
            .unwrap();
        Flow::Next
    }
}

/// `request_body`: refuses bodies that contain `evil` with a 2 KiB `403`.
#[derive(Debug)]
struct RefuseEvil;

#[async_trait]
impl Middleware for RefuseEvil {
    fn capabilities(&self) -> Capabilities {
        Capabilities::DEFAULT.with_body(BodyHold::new(1 << 20))
    }

    async fn request_body(&self, body: &HeldBody, _cx: &mut Context) -> BodyVerdict {
        let bytes = body.bytes().await.unwrap();
        if bytes.windows(4).any(|w| w == b"evil") {
            BodyVerdict::Reply(Reply {
                status: 403,
                headers: vec![(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain"),
                )],
                body: Some(Body::Bytes(Bytes::from("refused ".repeat(256)))),
            })
        } else {
            BodyVerdict::Continue
        }
    }
}

/// `upstream_request`: answers `451` instead of sending the request.
#[derive(Debug)]
struct RefuseUpstream;

#[async_trait]
impl Middleware for RefuseUpstream {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::UPSTREAM_REQUEST)
    }

    async fn upstream_request(&self, _req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        Flow::Reply(Reply::status(451))
    }
}

/// `request_body`: replaces the body with its upper-case version.
#[derive(Debug)]
struct Shout;

#[async_trait]
impl Middleware for Shout {
    fn capabilities(&self) -> Capabilities {
        Capabilities::DEFAULT.with_body(BodyHold::new(1 << 20).replacing())
    }

    async fn request_body(&self, body: &HeldBody, _cx: &mut Context) -> BodyVerdict {
        let bytes = body.bytes().await.unwrap();
        BodyVerdict::Replace(Bytes::from(bytes.to_ascii_uppercase()))
    }
}

/// `request_body`: counts its calls and lets everything pass.
#[derive(Debug, Default)]
struct CountBodies(Arc<AtomicUsize>);

#[async_trait]
impl Middleware for CountBodies {
    fn capabilities(&self) -> Capabilities {
        Capabilities::DEFAULT.with_body(BodyHold::new(1 << 20))
    }

    async fn request_body(&self, _body: &HeldBody, _cx: &mut Context) -> BodyVerdict {
        self.0.fetch_add(1, Ordering::SeqCst);
        BodyVerdict::Continue
    }
}

type Seen = Arc<Mutex<Vec<(LogSummary, Option<Upstream>, Option<u32>)>>>;

/// `log` with a state slot: remembers what it saw; the state carries a value from `request`.
#[derive(Debug, Default)]
struct RecordLog(Seen);

#[async_trait]
impl Middleware for RecordLog {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::REQUEST | Phases::LOG).with_state()
    }

    async fn request(&self, _req: &mut RequestHeader, cx: &mut Context) -> Flow {
        cx.set_state(42u32);
        Flow::Next
    }

    fn log(&self, summary: &LogSummary, cx: &Context) {
        self.0.lock().unwrap().push((
            summary.clone(),
            cx.upstream.clone(),
            cx.state::<u32>().copied(),
        ));
    }
}

/// `response_body`: upper-cases the response.
#[derive(Debug)]
struct ShoutBack;

#[async_trait]
impl Middleware for ShoutBack {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::RESPONSE | Phases::RESPONSE_BODY)
    }

    async fn response(&self, resp: &mut ResponseHeader, _cx: &mut Context) {
        resp.insert_header("x-shouted", "1").unwrap();
    }

    fn response_body(&self, body: &mut Option<Bytes>, _end: bool, _cx: &mut Context) {
        if let Some(chunk) = body.as_mut() {
            *chunk = Bytes::from(chunk.to_ascii_uppercase());
        }
    }
}

// -- harness ------------------------------------------------------------------------------

struct Harness {
    plane: DataPlane,
    addr: SocketAddr,
    dir: tempfile::TempDir,
}

impl Harness {
    /// Serves `body` (routes, services, middlewares; `{port}` is not needed) on a fresh port,
    /// with `extra` middlewares appended to the named routes' chains.
    async fn start(body: &str, extra: Vec<(&str, Vec<Arc<dyn Middleware>>)>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool");
        Self::start_in(dir, &spool, body, extra).await
    }

    async fn start_in(
        dir: tempfile::TempDir,
        spool: &std::path::Path,
        body: &str,
        extra: Vec<(&str, Vec<Arc<dyn Middleware>>)>,
    ) -> Self {
        let port = free_port();
        let yaml = format!(
            "acme: false\nlisteners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\n{body}"
        );
        let loaded = rdock_config::load_str(&yaml, rdock_config::Format::Yaml).unwrap();
        assert!(!loaded.has_errors(), "{:?}", loaded.diagnostics);
        let compiled = compile(
            &loaded.config,
            &CompileEnv {
                mode: Mode::Run,
                generation: 1,
                dns: &Dns::default(),
                client: Arc::new(rdock_middleware::HttpClient::default()),
                previous: None,
                cloudflare: &CloudflareRanges::default(),
                backends: &rdock_balancer::Registry::default(),
                sticky_key: b"test",
                live: &rdock_observability::live::Live::default(),
                caches: None,
            },
        );
        let errors: Vec<_> = compiled
            .diagnostics
            .iter()
            .filter(|d| d.is_error())
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        let mut runtime = compiled.runtime.unwrap();
        let listener = runtime.listeners.get_mut("web").unwrap();
        for (route_name, doubles) in extra {
            let route = listener
                .routes
                .iter_mut()
                .find(|r| &*r.name == route_name)
                .unwrap();
            let route = Arc::get_mut(route).expect("a fresh route has one owner");
            let mut chain: Vec<(Arc<str>, Arc<dyn Middleware>)> = route
                .middlewares
                .names()
                .map(Arc::from)
                .zip(route.middlewares.middlewares().cloned())
                .collect();
            for (i, double) in doubles.into_iter().enumerate() {
                chain.push((Arc::from(format!("double-{i}")), double));
            }
            route.middlewares = rdock_middleware::Chain::new(chain);
        }
        let metrics = rdock_observability::Metrics::new("test", "test").unwrap();
        let plane = DataPlane::new(metrics, Runtime::empty());
        plane.open_spool(spool).unwrap();
        plane
            .apply(runtime, Duration::from_millis(10))
            .await
            .unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        wait_listening(addr).await;
        Self { plane, addr, dir }
    }

    fn holders(&self) -> u64 {
        self.plane.spool().unwrap().holders_started()
    }

    fn spool_files(&self) -> usize {
        std::fs::read_dir(self.dir.path().join("spool"))
            .unwrap()
            .count()
    }
}

async fn wait_listening(addr: SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{addr} is not listening");
}

fn service(backend: SocketAddr) -> String {
    format!("services:\n  app: {{ backends: [{{ address: \"{backend}\" }}] }}\n")
}

/// One route `app` with `middlewares` before the doubles.
fn route(middlewares: &str) -> String {
    format!(
        "routes:\n  app: {{ match: \"PathPrefix(`/`)\", service: app, middlewares: [{middlewares}] }}\n"
    )
}

const HOLD_10: &str = "middlewares:\n  hold: { type: hold_body, max: 10 }\n";

fn post(target: &str, body: impl Into<Bytes>) -> http::Request<http_body_util::Full<Bytes>> {
    client::request("POST", "app.test", target, body)
}

/// Sends raw bytes and reads until the peer closes or `wait` passes.
async fn raw_exchange(addr: SocketAddr, parts: &[(&[u8], Duration)], wait: Duration) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    for (bytes, pause) in parts {
        stream.write_all(bytes).await.unwrap();
        tokio::time::sleep(*pause).await;
    }
    let mut out = Vec::new();
    let _ = tokio::time::timeout(wait, stream.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// A backend that records the bytes of one connection until the peer closes it.
async fn recording_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<(Vec<u8>, bool)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        let closed = loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(0) | Err(_)) => break true,
                Ok(Ok(n)) => seen.extend_from_slice(&buf[..n]),
                Err(_) => break false,
            }
        };
        let _ = tx.send((seen, closed));
    });
    (addr, rx)
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| b"0123456789abcdefghijklmnopqrstuvwxyz"[i * 7 % 36])
        .collect()
}

// -- tests --------------------------------------------------------------------------------

#[tokio::test]
async fn a_header_set_in_upstream_request_reaches_the_backend() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!("{}{}", route(""), service(backend.addr)),
        vec![("app", vec![Arc::new(TagUpstream)])],
    )
    .await;
    let reply = client::http1(h.addr, client::get("app.test", "/x")).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let headers = &reply.json()["headers"];
    assert_eq!(headers["x-upstream-backend"][0], backend.addr.to_string());
    assert_eq!(headers["x-upstream-service"][0], "app");
    assert_eq!(headers["x-attempt"][0], "0");
}

#[tokio::test]
async fn an_answer_in_upstream_request_is_sent_and_nothing_reaches_the_backend() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!(
            "{}services:\n  app:\n    backends: [{{ address: \"{}\" }}]\n    retries: {{ attempts: 2, on: [connect, reset] }}\n",
            route(""),
            backend.addr
        ),
        vec![("app", vec![Arc::new(RefuseUpstream)])],
    )
    .await;
    let reply = client::http1(h.addr, client::get("app.test", "/")).await;
    assert_eq!(reply.status, 451);
    assert_eq!(
        backend.requests(),
        0,
        "the head is never sent, and nothing is retried"
    );
}

#[tokio::test]
async fn held_bodies_up_to_the_limit_pass_and_longer_ones_get_413() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!("{}{}{HOLD_10}", route("hold"), service(backend.addr)),
        vec![],
    )
    .await;
    let small = client::http1(h.addr, post("/echo-body", "abc")).await;
    assert_eq!(small.status, 200);
    assert_eq!(&small.body[..], b"abc");
    let exact = client::http1(h.addr, post("/echo-body", "0123456789")).await;
    assert_eq!(exact.status, 200, "exactly at the limit");
    assert_eq!(&exact.body[..], b"0123456789");
    assert_eq!(exact.header("x-request-content-length"), Some("10"));
    let before = backend.requests();
    let over = client::http1(h.addr, post("/echo-body", "0123456789x")).await;
    assert_eq!(over.status, 413);
    assert_eq!(
        backend.requests(),
        before,
        "a declared length over the limit never reaches the backend"
    );
    // A chunked body has no declared length: it is counted while held.
    let chunked = raw_exchange(
        h.addr,
        &[(
            b"POST /echo-body HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n012345\r\n6\r\n6789ab\r\n0\r\n\r\n",
            Duration::ZERO,
        )],
        Duration::from_secs(3),
    )
    .await;
    assert!(chunked.starts_with("HTTP/1.1 413"), "{chunked}");
    assert_eq!(
        h.holders(),
        3,
        "the 413 by declared length started no holder"
    );
}

#[tokio::test]
async fn spooled_bodies_arrive_byte_for_byte_and_leave_no_file() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!(
            "{}{}middlewares:\n  hold: {{ type: hold_body, max: 1MiB }}\n",
            route("hold"),
            service(backend.addr)
        ),
        vec![],
    )
    .await;
    let data = pattern(300_000);
    let reply = client::http1(h.addr, post("/echo-body", data.clone())).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body.len(), data.len());
    assert!(
        reply.body[..] == data[..],
        "the spooled body arrives unchanged"
    );
    assert_eq!(h.spool_files(), 0, "spool files have no name");
    // HTTP/2 upload of the same body.
    let h2 = client::h2c(h.addr, post("/echo-body", data.clone())).await;
    assert_eq!(h2.status, 200);
    assert!(h2.body[..] == data[..]);
    assert_eq!(h.spool_files(), 0);
}

#[tokio::test]
async fn chunked_uploads_are_held_and_forwarded_whole() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!(
            "{}{}middlewares:\n  hold: {{ type: hold_body, max: 1MiB }}\n",
            route("hold"),
            service(backend.addr)
        ),
        vec![],
    )
    .await;
    let out = raw_exchange(
        h.addr,
        &[
            (
                b"POST /echo-body HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n",
                Duration::from_millis(100),
            ),
            (b"6\r\n world\r\n0\r\n\r\n", Duration::ZERO),
        ],
        Duration::from_secs(3),
    )
    .await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.ends_with("hello world"), "{out}");
    assert!(
        out.to_ascii_lowercase()
            .contains("x-request-transfer-encoding: chunked"),
        "chunked stays chunked: the head left before the body: {out}"
    );
}

#[tokio::test]
async fn a_replaced_body_is_sent_without_the_old_length() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!("{}{}", route(""), service(backend.addr)),
        vec![("app", vec![Arc::new(Shout)])],
    )
    .await;
    let reply = client::http1(h.addr, post("/echo-body", "quiet please")).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(&reply.body[..], b"QUIET PLEASE");
    assert_eq!(reply.header("x-request-content-length"), Some("-"));
    assert_eq!(reply.header("x-request-transfer-encoding"), Some("chunked"));
    // HTTP/2 to the proxy, HTTP/1.1 to the backend.
    let h2 = client::h2c(h.addr, post("/echo-body", "and h2")).await;
    assert_eq!(&h2.body[..], b"AND H2");
}

#[tokio::test]
async fn a_refused_body_never_reaches_the_backend_and_the_reply_is_compressed() {
    let (backend, seen) = recording_backend().await;
    let h = Harness::start(
        &format!(
            "{}{}middlewares:\n  gzip: {{ type: compress }}\n",
            route("gzip"),
            service(backend)
        ),
        vec![("app", vec![Arc::new(RefuseEvil)])],
    )
    .await;
    let mut req = post("/upload", "an evil payload");
    req.headers_mut()
        .insert("accept-encoding", "gzip".parse().unwrap());
    let reply = client::http1(h.addr, req).await;
    assert_eq!(reply.status, 403);
    assert_eq!(
        reply.header("content-encoding"),
        Some("gzip"),
        "the middleware's reply passes `compress` like any other"
    );
    let (bytes, closed) = seen.await.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    // What the backend observes: the request head (the connection exists and the head was
    // sent before the body arrived), not one byte of the body, then the connection closes.
    assert!(text.starts_with("POST /upload HTTP/1.1\r\n"), "{text}");
    assert!(
        text.to_ascii_lowercase().contains("content-length: 15"),
        "{text}"
    );
    assert!(text.ends_with("\r\n\r\n"), "only the head: {text:?}");
    assert!(!text.contains("evil"), "{text}");
    assert!(closed, "the upstream connection is closed, not reused");
}

#[tokio::test]
async fn expect_100_continue_gets_the_backend_s_100_and_then_the_answer() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!(
            "{}{}middlewares:\n  hold: {{ type: hold_body, max: 1MiB }}\n",
            route("hold"),
            service(backend.addr)
        ),
        vec![],
    )
    .await;
    let mut stream = TcpStream::connect(h.addr).await.unwrap();
    stream
        .write_all(b"POST /echo-body HTTP/1.1\r\nHost: app.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("a 100 arrives before the body is sent")
        .unwrap();
    let first = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(first.starts_with("HTTP/1.1 100"), "{first}");
    stream.write_all(b"hello").await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    let rest = String::from_utf8_lossy(&rest);
    assert!(rest.contains("HTTP/1.1 200"), "{rest}");
    assert!(rest.ends_with("hello"), "{rest}");
}

#[tokio::test]
async fn a_slow_body_is_refused_when_the_hold_times_out() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!(
            "{}{}middlewares:\n  hold: {{ type: hold_body, max: 1MiB, timeout: 300ms }}\n",
            route("hold"),
            service(backend.addr)
        ),
        vec![],
    )
    .await;
    let started = Instant::now();
    let mut stream = TcpStream::connect(h.addr).await.unwrap();
    stream
        .write_all(b"POST /echo-body HTTP/1.1\r\nHost: app.test\r\nContent-Length: 100\r\n\r\nx")
        .await
        .unwrap();
    // Dribble one byte every 100 ms, well within the listener's 60 s read timeout.
    let writer = tokio::spawn(async move {
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if stream.write_all(b"x").await.is_err() {
                break;
            }
        }
        stream
    });
    let mut stream = writer.await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut out)).await;
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 408"), "{out}");
    assert!(started.elapsed() < Duration::from_secs(4));
    // The same with a client that stops sending: the next read gives up at the deadline.
    let out = raw_exchange(
        h.addr,
        &[(
            b"POST /echo-body HTTP/1.1\r\nHost: app.test\r\nContent-Length: 100\r\n\r\nx",
            Duration::ZERO,
        )],
        Duration::from_secs(3),
    )
    .await;
    assert!(out.starts_with("HTTP/1.1 408"), "{out}");
}

#[tokio::test]
async fn requests_without_a_body_skip_the_holder() {
    let backend = Backend::start("one").await;
    let calls = Arc::new(AtomicUsize::new(0));
    let h = Harness::start(
        &format!("{}{}", route(""), service(backend.addr)),
        vec![("app", vec![Arc::new(CountBodies(calls.clone()))])],
    )
    .await;
    let reply = client::http1(h.addr, client::get("app.test", "/")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(h.holders(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let reply = client::http1(h.addr, post("/", "x")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(h.holders(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_chain_without_new_phases_takes_the_old_path() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!(
            "{}{}middlewares:\n  tag: {{ type: headers, request: {{ set: {{ X-Tag: \"1\" }} }} }}\n  gzip: {{ type: compress }}\n",
            route("tag, gzip"),
            service(backend.addr)
        ),
        vec![],
    )
    .await;
    let runtime = h.plane.runtime();
    let route = &runtime.listeners["web"].routes[0];
    assert!(!route.middlewares.flags().any(), "no phase flag is set");
    for _ in 0..3 {
        let reply = client::http1(h.addr, post("/", "some body")).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.json()["headers"]["x-tag"][0], "1");
    }
    assert_eq!(h.holders(), 0, "no holder is ever constructed");
    // explain prints each middleware's phases.
    let explained = rdock_proxy::explain::explain(
        &runtime,
        "web",
        &rdock_proxy::explain::Request {
            host: "app.test".into(),
            path: "/".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        explained["outcome"]["phases"][0],
        serde_json::json!({ "middleware": "tag", "phases": ["request", "response"] })
    );
}

#[tokio::test]
async fn the_log_phase_sees_status_bytes_duration_and_the_backend() {
    let backend = Backend::start("one").await;
    let seen = Seen::default();
    let h = Harness::start(
        &format!("{}{}", route(""), service(backend.addr)),
        vec![("app", vec![Arc::new(RecordLog(seen.clone()))])],
    )
    .await;
    let reply = client::http1(h.addr, post("/echo-body", "twelve bytes")).await;
    assert_eq!(reply.status, 200);
    // `logging` runs after the response is sent.
    for _ in 0..50 {
        if !seen.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let seen = seen.lock().unwrap();
    let (summary, upstream, state) = &seen[0];
    assert_eq!(summary.status, 200);
    assert_eq!(summary.bytes_in, 12);
    assert_eq!(summary.bytes_out, 12);
    assert!(summary.duration > Duration::ZERO);
    assert!(summary.upstream_duration.is_some());
    assert_eq!(summary.error, None);
    let upstream = upstream.as_ref().unwrap();
    assert_eq!(upstream.backend, backend.addr.to_string());
    assert_eq!(upstream.addr, Some(backend.addr));
    assert_eq!(
        *state,
        Some(42),
        "the state slot carries a value from `request` to `log`"
    );
}

#[tokio::test]
async fn response_body_middlewares_transform_before_compression() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &format!(
            "{}{}middlewares:\n  gzip: {{ type: compress }}\n",
            route("gzip"),
            service(backend.addr)
        ),
        vec![("app", vec![Arc::new(ShoutBack)])],
    )
    .await;
    let reply = client::http1(h.addr, post("/echo-body", "make me loud")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("x-shouted"), Some("1"));
    assert_eq!(&reply.body[..], b"MAKE ME LOUD");
}

#[tokio::test]
async fn a_held_body_over_64_kib_is_not_retried() {
    let first = Backend::start("first").await;
    let second = Backend::start("second").await;
    let h = Harness::start(
        &format!(
            "{}services:\n  app:\n    backends: [{{ address: \"{}\" }}, {{ address: \"{}\" }}]\n    retries: {{ attempts: 1, on: [\"503\"] }}\n{}",
            route("hold"),
            first.addr,
            second.addr,
            "middlewares:\n  hold: { type: hold_body, max: 1MiB }\n"
        ),
        vec![],
    )
    .await;
    let traffic = || first.traffic() + second.traffic();
    // A small held body is replayed from Pingora's buffer: the 503 is retried.
    let reply = client::http1(
        h.addr,
        client::request("PUT", "app.test", "/status/503", pattern(1_000)),
    )
    .await;
    assert_eq!(reply.status, 503);
    assert_eq!(traffic(), 2, "retried once");
    // Over 64 KiB the buffer cannot replay it: no second attempt.
    let reply = client::http1(
        h.addr,
        client::request("PUT", "app.test", "/status/503", pattern(100_000)),
    )
    .await;
    assert_eq!(reply.status, 503);
    assert_eq!(traffic(), 3, "not retried");
}

#[tokio::test]
async fn the_spool_is_emptied_at_start() {
    let backend = Backend::start("one").await;
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("spool");
    std::fs::create_dir_all(&spool).unwrap();
    std::fs::write(spool.join("body-1-7"), b"left by a crashed run").unwrap();
    let h = Harness::start_in(
        dir,
        &spool,
        &format!("{}{}", route(""), service(backend.addr)),
        vec![],
    )
    .await;
    assert_eq!(h.spool_files(), 0);
}
