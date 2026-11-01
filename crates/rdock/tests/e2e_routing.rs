//! End-to-end: weighted splits, mirroring, gRPC-Web and shadowed routes (ADR-0022).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn splits_follow_their_weights_and_nest() {
    let blue = Backend::start("blue").await;
    let green = Backend::start("green").await;
    let canary = Backend::start("canary").await;
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
    split: [{{ service: stable, weight: 3 }}, {{ service: canary, weight: 1 }}]
  stable:
    split: [{{ service: blue, weight: 1 }}, {{ service: green, weight: 1 }}]
  blue: {{ backends: [{{ address: "{}" }}] }}
  green: {{ backends: [{{ address: "{}" }}] }}
  canary: {{ backends: [{{ address: "{}" }}] }}
"#,
        blue.addr, green.addr, canary.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    for _ in 0..8 {
        assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
    }
    assert_eq!(
        (blue.traffic(), green.traffic(), canary.traffic()),
        (3, 3, 2),
        "3:1 between stable and canary, 1:1 inside stable"
    );
    let log = rdock.access_log();
    assert!(
        log.iter().any(|r| r["service"] == "canary"),
        "the access log names the service that answered"
    );
}

#[tokio::test]
async fn mirrors_get_a_copy_and_never_affect_the_answer() {
    let main = Backend::start("main").await;
    let shadow = Backend::start("shadow").await;
    shadow.set_healthy(false);
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app:
    match: "PathPrefix(`/`)"
    service: main
    mirror: {{ service: shadow }}
services:
  main: {{ backends: [{{ address: "{}" }}] }}
  shadow: {{ backends: [{{ address: "{}" }}] }}
"#,
        main.addr, shadow.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    // The shadow answers 503 on /flaky; the client still gets main's 200.
    let reply = client::http1(addr(port), get("a", "/flaky")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("x-backend"), Some("main"));
    let order = request("POST", "a", "/orders", "{\"id\":1}");
    assert_eq!(client::http1(addr(port), order).await.status, 200);
    let deadline = Instant::now() + Duration::from_secs(5);
    while shadow.traffic() < 2 {
        assert!(
            Instant::now() < deadline,
            "the shadow got {:?}",
            shadow.targets()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Copies are sent in the background, so they may arrive in either order.
    let mut targets = shadow.targets();
    targets.sort();
    assert_eq!(targets, vec!["/flaky", "/orders"]);
}

#[tokio::test]
async fn requests_refused_by_middlewares_are_not_mirrored() {
    let main = Backend::start("main").await;
    let shadow = Backend::start("shadow").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  private:
    match: "PathPrefix(`/private`)"
    service: main
    middlewares: [office-only]
    mirror: {{ service: shadow }}
  public:
    match: "PathPrefix(`/`)"
    service: main
    mirror: {{ service: shadow }}
middlewares:
  office-only: {{ type: ip_allow, cidrs: [10.0.0.0/8] }}
services:
  main: {{ backends: [{{ address: "{}" }}] }}
  shadow: {{ backends: [{{ address: "{}" }}] }}
"#,
        main.addr, shadow.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let refused = client::http1(addr(port), get("a", "/private/data")).await;
    assert_eq!(refused.status, 403);
    // A request that is let through is mirrored; once it arrives, the refused one would have too.
    assert_eq!(
        client::http1(addr(port), get("a", "/public")).await.status,
        200
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while shadow.traffic() < 1 {
        assert!(
            Instant::now() < deadline,
            "the allowed request was not mirrored"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        shadow.targets(),
        vec!["/public"],
        "only the allowed request"
    );
    assert_eq!(main.targets(), vec!["/public"]);
}

#[tokio::test]
async fn grpc_web_reaches_a_grpc_backend() {
    let backend = Backend::start("grpc").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: grpc, middlewares: [web-to-grpc] }}
middlewares:
  web-to-grpc: {{ type: grpc_web }}
services:
  grpc: {{ scheme: h2c, backends: [{{ address: "{}" }}] }}
"#,
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    // One length-prefixed message, as a browser's gRPC-Web client sends it over HTTP/1.1.
    let frame: &[u8] = &[0, 0, 0, 0, 3, b'a', b'b', b'c'];
    let mut req = request("POST", "a", "/grpc", frame.to_vec());
    req.headers_mut().insert(
        "content-type",
        "application/grpc-web+proto".parse().unwrap(),
    );
    let reply = client::http1(addr(port), req).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.header("content-type"),
        Some("application/grpc-web"),
        "the backend's application/grpc, translated back"
    );
    let body = reply.body.to_vec();
    assert!(body.starts_with(frame), "the echoed message comes first");
    let trailers = &body[frame.len()..];
    assert_eq!(trailers.first(), Some(&0x80), "then the trailers frame");
    assert!(
        String::from_utf8_lossy(trailers).contains("grpc-status:0"),
        "{trailers:?}"
    );
}

#[test]
fn validate_reports_routes_that_never_match() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    std::fs::write(
        &file,
        r#"
listeners:
  web: { address: ":8080" }
defaults: { listeners: [web], tls: off }
routes:
  everything: { match: "PathPrefix(`/`)", service: app, priority: 100 }
  api: { match: "PathPrefix(`/api`)", service: app }
  twin-a: { match: "Host(`a.test`)", service: app, priority: 200 }
  twin-b: { match: "Host(`a.test`)", service: app, priority: 200 }
services:
  app: { backends: [{ address: "127.0.0.1:3000" }] }
"#,
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .args(["validate", "--format", "json"])
        .arg(&file)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "warnings only: {text}");
    assert!(text.contains("routes.api.match"), "{text}");
    assert!(text.contains("routes.twin-b.match"), "{text}");
    assert!(!text.contains("routes.twin-a.match"), "{text}");
}
