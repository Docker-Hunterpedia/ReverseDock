//! Native plugins and out-of-process agents (F-EXT-02, F-EXT-04, ADR-0030), end to end through
//! an in-process data plane compiled as `rdock run` compiles it: a plugin registry, the
//! process's metrics, real client connections, `rdock-testkit` backends and a stub agent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rdock_observability::Metrics;
use rdock_plugin_api as api;
use rdock_proxy::forwarded::CloudflareRanges;
use rdock_proxy::upstream::Dns;
use rdock_proxy::{CompileEnv, DataPlane, Mode, Runtime, compile};
use rdock_testkit::agent::{Answer, StubAgent};
use rdock_testkit::backend::Backend;
use rdock_testkit::{client, free_port};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// -- harness --------------------------------------------------------------------------------

struct Harness {
    plane: DataPlane,
    metrics: Metrics,
    addr: SocketAddr,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start(body: &str, plugins: api::Registry) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let yaml = format!(
            "acme: false\nlisteners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\n{body}"
        );
        let loaded = rdock_config::load_str(&yaml, rdock_config::Format::Yaml).unwrap();
        assert!(!loaded.has_errors(), "{:?}", loaded.diagnostics);
        let metrics = Metrics::new("test", "test").unwrap();
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
                plugins: &plugins,
                metrics: Some(&metrics),
                quotas: None,
                abuse: None,
                shared_limits: None,
            },
        );
        let errors: Vec<_> = compiled
            .diagnostics
            .iter()
            .filter(|d| d.is_error())
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        let plane = DataPlane::new(metrics.clone(), Runtime::empty());
        plane.open_spool(&dir.path().join("spool")).unwrap();
        plane
            .apply(compiled.runtime.unwrap(), Duration::from_millis(10))
            .await
            .unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        for _ in 0..100 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Self {
            plane,
            metrics,
            addr,
            _dir: dir,
        }
    }

    fn agent_requests(&self, agent: &str, result: &str) -> u64 {
        self.metrics
            .agent_requests
            .with_label_values(&[agent, result])
            .get()
    }
}

/// One route `app` through `middlewares` to `backend`.
fn site(middlewares: &str, backend: SocketAddr, definitions: &str) -> String {
    format!(
        "routes:\n  app: {{ match: \"PathPrefix(`/`)\", service: app, middlewares: [{middlewares}] }}\nservices:\n  app: {{ backends: [{{ address: \"{backend}\" }}] }}\nmiddlewares:\n{definitions}"
    )
}

fn agent_mw(name: &str, agent: SocketAddr, extra: &str) -> String {
    format!("  {name}: {{ type: agent, address: \"http://{agent}/check\"{extra} }}\n")
}

fn post(target: &str, body: impl Into<Bytes>) -> http::Request<http_body_util::Full<Bytes>> {
    client::request("POST", "app.test", target, body)
}

/// A backend that records the bytes of one connection until the peer closes it.
async fn recording_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(0) | Err(_)) | Err(_) => break,
                Ok(Ok(n)) => seen.extend_from_slice(&buf[..n]),
            }
        }
        let _ = tx.send(seen);
    });
    (addr, rx)
}

// -- plugins --------------------------------------------------------------------------------

/// Panics on `/panic`, tags everything else.
struct Boom;

#[api::async_trait]
impl api::Plugin for Boom {
    fn capabilities(&self) -> api::Capabilities {
        api::Capabilities::new(api::Phases::REQUEST)
    }

    async fn request(&self, req: &mut api::RequestHead, _cx: &mut api::Ctx<'_>) -> api::Decision {
        assert!(req.path() != "/panic", "the plugin panics on /panic");
        req.set_header("x-boom", "ok").unwrap();
        api::Decision::Continue
    }
}

fn boom_registry() -> api::Registry {
    api::Registry::new().plugin(
        "boom",
        |_: &serde_json::Value| -> Result<Arc<dyn api::Plugin>, api::ConfigError> {
            Ok(Arc::new(Boom))
        },
    )
}

#[tokio::test]
async fn a_panicking_plugin_answers_500_for_that_request_only() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &site(
            "boom",
            backend.addr,
            "  boom: { type: plugin, name: boom }\n",
        ),
        boom_registry(),
    )
    .await;
    // Two requests on one HTTP/1.1 connection: the first panics, the connection survives and
    // the second is served.
    let mut stream = TcpStream::connect(h.addr).await.unwrap();
    stream
        .write_all(b"GET /panic HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await
        .unwrap();
    let mut first = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&first).contains("Internal Server Error\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(
            n > 0,
            "the connection was closed: {}",
            String::from_utf8_lossy(&first)
        );
        first.extend_from_slice(&buf[..n]);
    }
    let first = String::from_utf8_lossy(&first);
    assert!(first.starts_with("HTTP/1.1 500"), "{first}");
    stream
        .write_all(b"GET /fine HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "the same connection serves the next request: {text}"
    );
    assert!(text.contains("\"x-boom\":[\"ok\"]"), "{text}");
    // HTTP/2: the panicking stream gets a 500; the connection is not torn down.
    let reply = client::h2c(h.addr, client::get("app.test", "/panic")).await;
    assert_eq!(reply.status, 500);
    assert_eq!(
        h.metrics.plugin_panics.with_label_values(&["boom"]).get(),
        2
    );
    assert_eq!(
        backend.requests(),
        1,
        "only the healthy request reached the backend"
    );
}

#[tokio::test]
async fn explain_prints_a_plugin_s_phases() {
    let backend = Backend::start("one").await;
    let h = Harness::start(
        &site(
            "boom",
            backend.addr,
            "  boom: { type: plugin, name: boom }\n",
        ),
        boom_registry(),
    )
    .await;
    let explained = rdock_proxy::explain::explain(
        &h.plane.runtime(),
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
        serde_json::json!({ "middleware": "boom", "phases": ["request"] })
    );
}

// -- agents: protocol rdock -----------------------------------------------------------------

#[tokio::test]
async fn an_allowing_agent_sees_the_request_and_the_backend_answers() {
    let backend = Backend::start("one").await;
    let agent = StubAgent::start(|_| Answer::allow()).await;
    let h = Harness::start(
        &site("waf", backend.addr, &agent_mw("waf", agent.addr, "")),
        api::Registry::new(),
    )
    .await;
    let mut req = client::get("app.test", "/a/b?q=1");
    req.headers_mut()
        .insert("authorization", "Bearer secret".parse().unwrap());
    req.headers_mut()
        .insert("user-agent", "test-agent/1".parse().unwrap());
    let reply = client::http1(h.addr, req).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let seen = agent.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].target, "/check");
    let doc = seen[0].json();
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["request"]["method"], "GET");
    assert_eq!(doc["request"]["path"], "/a/b");
    assert_eq!(doc["request"]["query"], "q=1");
    assert_eq!(doc["request"]["host"], "app.test");
    assert_eq!(doc["client"]["ip"], "127.0.0.1");
    assert_eq!(doc["route"], "app");
    assert_eq!(doc["body"], serde_json::Value::Null, "a GET has no body");
    let headers = doc["request"]["headers"].to_string();
    assert!(headers.contains("test-agent/1"), "{headers}");
    assert!(
        !headers.contains("secret"),
        "credentials go only when listed: {headers}"
    );
    assert_eq!(h.agent_requests("waf", "allow"), 1);
    // The document and the verdict match the published schema (schema/agent.v1.json).
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schema/agent.v1.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&doc), "{doc}");
    assert!(validator.is_valid(
        &serde_json::json!({ "action": "deny", "status": 451, "headers": { "a": ["1", "2"] } })
    ));
    assert!(!validator.is_valid(&serde_json::json!({ "action": "maybe" })));
}

#[tokio::test]
async fn a_denying_agent_s_response_is_sent_and_the_backend_sees_nothing() {
    let backend = Backend::start("one").await;
    let agent = StubAgent::start(|_| {
        Answer::json(&serde_json::json!({
            "action": "deny", "status": 451,
            "headers": { "x-why": "policy", "content-length": "999" },
            "body": "unavailable for legal reasons\n"
        }))
    })
    .await;
    let h = Harness::start(
        &site("waf", backend.addr, &agent_mw("waf", agent.addr, "")),
        api::Registry::new(),
    )
    .await;
    let reply = client::http1(h.addr, client::get("app.test", "/")).await;
    assert_eq!(reply.status, 451);
    assert_eq!(reply.header("x-why"), Some("policy"));
    assert_eq!(reply.text(), "unavailable for legal reasons\n");
    assert_eq!(backend.requests(), 0);
    assert_eq!(h.agent_requests("waf", "deny"), 1);
}

#[tokio::test]
async fn only_allow_listed_headers_from_the_agent_reach_the_backend() {
    let backend = Backend::start("one").await;
    let agent = StubAgent::start(|_| {
        Answer::json(&serde_json::json!({
            "action": "allow",
            "set_request_headers": { "x-user": "alice", "x-admin": "true" }
        }))
    })
    .await;
    let h = Harness::start(
        &site(
            "auth",
            backend.addr,
            &agent_mw(
                "auth",
                agent.addr,
                ", max_body: 0, response_headers: [X-User], request_headers: [authorization]",
            ),
        ),
        api::Registry::new(),
    )
    .await;
    let mut req = client::get("app.test", "/");
    req.headers_mut()
        .insert("x-user", "mallory".parse().unwrap());
    req.headers_mut()
        .insert("authorization", "Bearer t".parse().unwrap());
    let reply = client::http1(h.addr, req).await;
    assert_eq!(reply.status, 200);
    let seen = &reply.json()["headers"];
    assert_eq!(
        seen["x-user"],
        serde_json::json!(["alice"]),
        "the client's copy is gone"
    );
    assert!(seen.get("x-admin").is_none(), "not on the allow-list");
    assert!(
        agent.seen()[0].json()["request"]["headers"]
            .to_string()
            .contains("Bearer t")
    );
    assert_eq!(
        h.metrics
            .agent_ignored_headers
            .with_label_values(&["auth", "not_allowed"])
            .get(),
        1
    );
    // A request with a body is decided after its head left: the client's copy is still
    // removed, the agent's value cannot be applied (counted as too late).
    let h2 = Harness::start(
        &site(
            "auth",
            backend.addr,
            &agent_mw("auth", agent.addr, ", response_headers: [X-User]"),
        ),
        api::Registry::new(),
    )
    .await;
    let mut req = post("/echo-body", "payload");
    req.headers_mut()
        .insert("x-user", "mallory".parse().unwrap());
    let reply = client::http1(h2.addr, req).await;
    assert_eq!(reply.status, 200);
    assert_eq!(&reply.body[..], b"payload");
    assert_eq!(
        h2.metrics
            .agent_ignored_headers
            .with_label_values(&["auth", "too_late"])
            .get(),
        1
    );
}

#[tokio::test]
async fn a_slow_agent_fails_closed_or_open_as_configured() {
    let backend = Backend::start("one").await;
    let agent = StubAgent::start(|_| Answer::allow().delay(Duration::from_millis(600))).await;
    let definitions = format!(
        "{}{}",
        agent_mw("closed", agent.addr, ", timeout: 100ms"),
        agent_mw("open", agent.addr, ", timeout: 100ms, on_error: allow"),
    );
    let h = Harness::start(
        &format!(
            "routes:\n  closed: {{ match: \"PathPrefix(`/closed`)\", service: app, middlewares: [closed] }}\n  open: {{ match: \"PathPrefix(`/open`)\", service: app, middlewares: [open] }}\nservices:\n  app: {{ backends: [{{ address: \"{}\" }}] }}\nmiddlewares:\n{definitions}",
            backend.addr
        ),
        api::Registry::new(),
    )
    .await;
    let started = Instant::now();
    let reply = client::http1(h.addr, client::get("app.test", "/closed")).await;
    assert_eq!(reply.status, 504);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the timeout is honoured"
    );
    let reply = client::http1(h.addr, client::get("app.test", "/open")).await;
    assert_eq!(reply.status, 200, "on_error: allow lets it through");
    assert_eq!(h.agent_requests("closed", "timeout"), 1);
    assert_eq!(h.agent_requests("open", "timeout"), 1);
}

#[tokio::test]
async fn the_breaker_opens_after_failures_and_closes_after_a_good_trial() {
    let backend = Backend::start("one").await;
    let agent = StubAgent::start(|_| Answer::status(500)).await;
    let h = Harness::start(
        &site(
            "waf",
            backend.addr,
            &agent_mw(
                "waf",
                agent.addr,
                ", breaker: { failures: 2, window: 10s, open_for: 300ms }",
            ),
        ),
        api::Registry::new(),
    )
    .await;
    let gauge = || {
        h.metrics
            .agent_breaker_open
            .with_label_values(&["waf"])
            .get()
    };
    for _ in 0..2 {
        let reply = client::http1(h.addr, client::get("app.test", "/")).await;
        assert_eq!(
            reply.status, 502,
            "an answer that is not a verdict is an error"
        );
    }
    assert_eq!(gauge(), 1);
    let reply = client::http1(h.addr, client::get("app.test", "/")).await;
    assert_eq!(reply.status, 503, "open: refused without calling");
    assert_eq!(agent.count(), 2);
    assert_eq!(h.agent_requests("waf", "breaker_open"), 1);
    agent.set(|_| Answer::allow());
    tokio::time::sleep(Duration::from_millis(400)).await;
    let reply = client::http1(h.addr, client::get("app.test", "/")).await;
    assert_eq!(reply.status, 200, "the trial call succeeds");
    assert_eq!(gauge(), 0);
    assert_eq!(agent.count(), 3);
}

#[tokio::test]
async fn an_unreachable_agent_refuses_requests() {
    let backend = Backend::start("one").await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let h = Harness::start(
        &site("waf", backend.addr, &agent_mw("waf", dead, "")),
        api::Registry::new(),
    )
    .await;
    let reply = client::http1(h.addr, client::get("app.test", "/")).await;
    assert_eq!(reply.status, 502);
    assert_eq!(
        backend.traffic(),
        0,
        "a request without a body is refused before routing"
    );
    let reply = client::http1(h.addr, post("/echo-body", "x")).await;
    assert_eq!(reply.status, 502, "with a body too");
    // A request with a body is decided after its head went to the backend (the body never
    // does; see the test with the recording backend).
    assert_eq!(h.agent_requests("waf", "error"), 2);
}

// -- agents: bodies --------------------------------------------------------------------------

#[tokio::test]
async fn the_body_goes_to_the_agent_and_is_withheld_from_the_backend_until_the_verdict() {
    // Deny after a pause: the backend gets the request head and not one byte of the body.
    let (backend, seen) = recording_backend().await;
    let agent = StubAgent::start(|s| {
        let doc = s.json();
        let refused = doc["body"]["base64"]
            .as_str()
            .is_some_and(|b| b == "ZXZpbCBwYXlsb2Fk");
        let answer = if refused {
            Answer::json(&serde_json::json!({ "action": "deny" }))
        } else {
            Answer::allow()
        };
        answer.delay(Duration::from_millis(200))
    })
    .await;
    let h = Harness::start(
        &site("waf", backend, &agent_mw("waf", agent.addr, "")),
        api::Registry::new(),
    )
    .await;
    let reply = client::http1(h.addr, post("/upload", "evil payload")).await;
    assert_eq!(reply.status, 403);
    let bytes = seen.await.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.starts_with("POST /upload HTTP/1.1\r\n"), "{text}");
    assert!(text.ends_with("\r\n\r\n"), "only the head: {text:?}");
    assert!(!text.contains("evil"), "{text}");
    let doc = agent.seen()[0].json();
    assert_eq!(doc["body"]["length"], 12);
    assert_eq!(doc["body_skipped"], false);

    // Allowed: the body arrives whole, after the agent answered.
    let echo = Backend::start("one").await;
    let h = Harness::start(
        &site("waf", echo.addr, &agent_mw("waf", agent.addr, "")),
        api::Registry::new(),
    )
    .await;
    let reply = client::http1(h.addr, post("/echo-body", "fine payload")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(&reply.body[..], b"fine payload");
}

/// M3 of the v0.8 review records what a body verdict can and cannot withhold under Pingora
/// 0.9.1: a `validate` that refuses a body answers `400`, and the backend has received the
/// request head (its connection was opened before the body was read) but not one byte of the
/// body, and the connection is closed. A refusal from the request head alone (the query
/// here) reaches no backend at all.
#[tokio::test]
async fn a_refused_body_leaves_the_backend_with_the_head_only() {
    let (backend, seen) = recording_backend().await;
    let check = "  check:\n    type: validate\n    query: { type: object, properties: { limit: { type: integer, maximum: 100 } } }\n    body: { type: object, required: [name] }\n";
    let h = Harness::start(&site("check", backend, check), api::Registry::new()).await;
    let mut req = post("/items?limit=1000", r#"{"name":"x"}"#);
    req.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    assert_eq!(client::http1(h.addr, req).await.status, 400);
    let mut req = post("/items", r#"{"evil":"payload"}"#);
    req.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    assert_eq!(client::http1(h.addr, req).await.status, 400);
    let bytes = seen.await.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    // One connection, made only for the request with a body: the query refusal sent nothing.
    assert_eq!(text.matches("HTTP/1.1\r\n").count(), 1, "{text}");
    assert!(text.starts_with("POST /items HTTP/1.1\r\n"), "{text}");
    assert!(text.ends_with("\r\n\r\n"), "only the head: {text:?}");
    assert!(!text.contains("evil"), "{text}");
}

#[tokio::test]
async fn oversize_bodies_are_rejected_or_sent_without_the_body() {
    let backend = Backend::start("one").await;
    let agent = StubAgent::start(|_| Answer::allow()).await;
    let definitions = format!(
        "{}{}",
        agent_mw("reject", agent.addr, ", max_body: 16"),
        agent_mw("skip", agent.addr, ", max_body: 16, on_oversize: skip"),
    );
    let h = Harness::start(
        &format!(
            "routes:\n  reject: {{ match: \"PathPrefix(`/reject`)\", service: app, middlewares: [reject] }}\n  skip: {{ match: \"PathPrefix(`/skip`)\", service: app, middlewares: [skip] }}\nservices:\n  app: {{ backends: [{{ address: \"{}\" }}] }}\nmiddlewares:\n{definitions}",
            backend.addr
        ),
        api::Registry::new(),
    )
    .await;
    let big = "x".repeat(100);
    let reply = client::http1(h.addr, post("/reject/echo-body", big.clone())).await;
    assert_eq!(reply.status, 413);
    assert_eq!(agent.count(), 0, "refused before asking");
    assert_eq!(h.agent_requests("reject", "oversize"), 1);
    let small = client::http1(h.addr, post("/reject/echo-body", "small")).await;
    assert_eq!(small.status, 200);
    assert_eq!(agent.seen()[0].json()["body"]["length"], 5);

    let reply = client::http1(h.addr, post("/skip/echo-body", big.clone())).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(
        reply.json()["body_len"],
        100,
        "the backend got the whole body"
    );
    let doc = agent.seen()[1].json();
    assert_eq!(doc["body"], serde_json::Value::Null);
    assert_eq!(doc["body_skipped"], true);
}

// -- agents: protocol forward ----------------------------------------------------------------

#[tokio::test]
async fn forward_replays_the_request_and_passes_refusals_on() {
    let backend = Backend::start("one").await;
    let agent = StubAgent::start(|s| {
        if s.target.contains("etc/passwd") || s.body.windows(5).any(|w| w == b"DROP ") {
            Answer::status(403)
                .header("content-type", "text/html")
                .header("set-cookie", "waf=1")
                .body("<h1>Forbidden by the WAF</h1>")
        } else {
            Answer::status(204)
        }
    })
    .await;
    let h = Harness::start(
        &site(
            "waf",
            backend.addr,
            &format!(
                "  waf: {{ type: agent, protocol: forward, address: \"http://{}\" }}\n",
                agent.addr
            ),
        ),
        api::Registry::new(),
    )
    .await;
    let reply = client::http1(h.addr, client::get("app.test", "/page?id=1")).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let reply = client::http1(h.addr, client::get("app.test", "/file?f=../../etc/passwd")).await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.text(), "<h1>Forbidden by the WAF</h1>");
    assert_eq!(reply.header("content-type"), Some("text/html"));
    assert_eq!(
        reply.header("set-cookie"),
        None,
        "only a safe subset of headers"
    );
    let reply = client::http1(h.addr, post("/form", "q=1; DROP TABLE users")).await;
    assert_eq!(reply.status, 403, "the body is inspected");
    let seen = agent.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].target.as_str()),
        ("GET", "/page?id=1")
    );
    assert_eq!(
        seen[0].header("host"),
        Some("app.test"),
        "the original host"
    );
    assert_eq!(seen[0].header("x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(seen[2].method, "POST");
    assert_eq!(&seen[2].body[..], b"q=1; DROP TABLE users");
    // The refused GET never reached the backend; the refused POST's head did (its verdict
    // comes with the body), its body did not.
    let targets = backend.targets();
    assert!(targets.contains(&"/page?id=1".to_owned()), "{targets:?}");
    assert!(!targets.iter().any(|t| t.contains("passwd")), "{targets:?}");
}

#[tokio::test]
async fn agents_over_tls_verify_against_the_configured_ca() {
    let backend = Backend::start("one").await;
    let dir = tempfile::tempdir().unwrap();
    let ca = rdock_testkit::certs::TestCa::new();
    let ca_file = ca.write(dir.path());
    let cert = ca.issue(dir.path(), "agent", &["agent.test", "127.0.0.1"]);
    let agent = StubAgent::start_tls(|_| Answer::allow(), &cert.cert_pem, &cert.key_pem).await;
    let definitions = format!(
        "  trusted: {{ type: agent, address: \"https://{}/check\", tls: {{ ca_file: \"{}\", server_name: agent.test }} }}\n  untrusted: {{ type: agent, address: \"https://{}/check\" }}\n",
        agent.addr,
        ca_file.display(),
        agent.addr
    );
    let h = Harness::start(
        &format!(
            "routes:\n  trusted: {{ match: \"PathPrefix(`/trusted`)\", service: app, middlewares: [trusted] }}\n  untrusted: {{ match: \"PathPrefix(`/untrusted`)\", service: app, middlewares: [untrusted] }}\nservices:\n  app: {{ backends: [{{ address: \"{}\" }}] }}\nmiddlewares:\n{definitions}",
            backend.addr
        ),
        api::Registry::new(),
    )
    .await;
    let reply = client::http1(h.addr, client::get("app.test", "/trusted")).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let reply = client::http1(h.addr, client::get("app.test", "/untrusted")).await;
    assert_eq!(
        reply.status, 502,
        "the system roots do not know the test CA"
    );
    assert_eq!(agent.count(), 1);
}
