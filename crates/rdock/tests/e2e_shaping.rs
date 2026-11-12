//! End-to-end: `validate` (F-GW-03) and `transform` (F-GW-04) through the proxy: errors in the
//! problem-details envelope, held bodies refused or patched and forwarded with a new framing,
//! JSON responses patched in the synchronous body phase.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use serde_json::{Value, json};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn post(
    target: &str,
    content_type: &str,
    body: &str,
) -> http::Request<http_body_util::Full<bytes::Bytes>> {
    let mut req = request("POST", "app.test", target, body.to_owned());
    req.headers_mut()
        .insert("content-type", content_type.parse().unwrap());
    req.headers_mut()
        .insert("accept", "application/json".parse().unwrap());
    req
}

fn config(port: u16, backend: SocketAddr) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off, errors: {{ format: problem }} }}
routes:
  api: {{ match: "PathPrefix(`/api`)", service: app, middlewares: [check] }}
  patched: {{ match: "PathPrefix(`/echo-body`)", service: app, middlewares: [shape-request] }}
  plain: {{ match: "PathPrefix(`/`)", service: app, middlewares: [shape-response] }}
middlewares:
  check:
    type: validate
    max_body: 1KiB
    query:
      type: object
      properties: {{ limit: {{ type: integer, maximum: 100 }} }}
    body:
      type: object
      required: [name]
      properties: {{ name: {{ type: string, maxLength: 8 }} }}
  shape-request:
    type: transform
    request:
      headers: {{ set: {{ x-shaped: "yes" }} }}
      body:
        patch:
          - {{ op: remove, path: /debug }}
          - {{ op: add, path: /source, value: gateway }}
  shape-response:
    type: transform
    response:
      headers: {{ set: {{ x-shaped: "yes" }} }}
      body:
        patch:
          - {{ op: remove, path: /headers }}
          - {{ op: add, path: /patched, value: true }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#
    )
}

#[tokio::test]
async fn requests_are_validated_and_transformed() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr));
    validation(port, &backend).await;
    transformation(port, &rdock).await;
}

async fn validation(port: u16, backend: &Backend) {
    let mut req = get("app.test", "/api/items?limit=500");
    req.headers_mut()
        .insert("accept", "application/json".parse().unwrap());
    let refused = client::http1(addr(port), req).await;
    assert_eq!(refused.status, 400);
    assert_eq!(
        refused.header("content-type"),
        Some("application/problem+json")
    );
    let problem = refused.json();
    assert!(
        problem["type"]
            .as_str()
            .unwrap()
            .ends_with("#validation-failed"),
        "{problem}"
    );
    assert_eq!(
        problem["errors"],
        json!([{ "pointer": "/query/limit", "message": "must be at most 100" }])
    );

    let ok = client::http1(
        addr(port),
        post("/api/items", "application/json", r#"{"name": "kit"}"#),
    )
    .await;
    assert_eq!(ok.status, 200);
    let bad = client::http1(
        addr(port),
        post(
            "/api/items",
            "application/json",
            r#"{"name": "a-secret-name"}"#,
        ),
    )
    .await;
    assert_eq!(bad.status, 400);
    assert!(!bad.text().contains("a-secret-name"), "{}", bad.text());
    assert_eq!(bad.json()["errors"][0]["pointer"], "/body/name");
    let broken = client::http1(addr(port), post("/api/items", "application/json", "{nope")).await;
    assert_eq!(broken.status, 400);
    let wrong = client::http1(addr(port), post("/api/items", "text/plain", "name=kit")).await;
    assert_eq!(wrong.status, 415);
    let big = format!(r#"{{"name": "{}"}}"#, "x".repeat(2048));
    let large = client::http1(addr(port), post("/api/items", "application/json", &big)).await;
    assert_eq!(large.status, 413);
    // Requests refused in the request phase never reach the backend; a body refused in the
    // body phase aborts a request whose head already left (ADR-0030, held bodies).
    assert!(backend.traffic() <= 3, "{}", backend.traffic());
}

async fn transformation(port: u16, rdock: &Rdock) {
    let shaped = client::http1(
        addr(port),
        post(
            "/echo-body",
            "application/json",
            r#"{"a": 1, "debug": true}"#,
        ),
    )
    .await;
    assert_eq!(shaped.status, 200);
    let forwarded: Value = serde_json::from_slice(&shaped.body).unwrap();
    assert_eq!(forwarded, json!({ "a": 1, "source": "gateway" }));
    assert_eq!(
        shaped.header("x-request-content-length"),
        Some("-"),
        "the client's length is dropped for a replaced body"
    );
    let text = client::http1(addr(port), post("/echo-body", "text/plain", "debug=1")).await;
    assert_eq!(text.text(), "debug=1", "non-JSON bodies pass untouched");

    let answer = client::http1(addr(port), get("app.test", "/hello")).await;
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("x-shaped"), Some("yes"));
    let body = answer.json();
    assert_eq!(body["patched"], true);
    assert!(body.get("headers").is_none(), "{body}");
    assert_eq!(body["backend"], "app");
    let untouched = client::http1(addr(port), get("app.test", "/status/404")).await;
    assert_eq!(untouched.text(), "status 404 from app\n");
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(
        metrics
            .lines()
            .any(|l| l.starts_with("rdock_transform_skipped_total{")
                && l.contains("middleware=\"shape-response\"")
                && l.contains("reason=\"status\"")),
        "{metrics}"
    );
    assert!(
        metrics
            .lines()
            .any(|l| l.starts_with("rdock_validation_requests_total{")
                && l.contains("result=\"invalid\"")),
        "{metrics}"
    );
}
