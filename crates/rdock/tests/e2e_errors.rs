//! End-to-end: the error envelope (F-GW-04). Every answer rdock makes itself goes through one
//! renderer: `defaults.errors.format` and a route's `errors.format` choose between today's
//! HTML (the default, unchanged) and RFC 9457 problem details; `errors` middleware pages and a
//! `maintenance` file keep precedence.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;

use http_body_util::Full;
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use serde_json::Value;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const BASE: &str = "https://reversedock.oday-bakkour.com/docs/reference/problems/#";

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn accept(
    mut req: http::Request<Full<bytes::Bytes>>,
    value: &str,
) -> http::Request<Full<bytes::Bytes>> {
    req.headers_mut().insert("accept", value.parse().unwrap());
    req
}

fn problem(reply: &client::Reply, status: u16, slug: &str) -> Value {
    assert_eq!(reply.status, status, "{}", reply.text());
    assert_eq!(
        reply.header("content-type"),
        Some("application/problem+json"),
        "{}",
        reply.text()
    );
    assert_eq!(reply.header("content-language"), Some("en"));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    let json = reply.json();
    assert_eq!(json["type"], format!("{BASE}{slug}"), "{json}");
    assert_eq!(json["status"], status);
    let id = reply.header("x-request-id").unwrap();
    assert_eq!(json["request_id"], id);
    assert_eq!(json["instance"], format!("urn:uuid:{id}"));
    json
}

#[tokio::test]
async fn rdock_answers_render_as_problem_details_where_configured() {
    let backend = Backend::start("app").await;
    let dir = tempfile::tempdir().unwrap();
    let page = dir.path().join("down.html");
    std::fs::write(&page, "<h1>back soon</h1>").unwrap();
    let custom = dir.path().join("custom.html");
    std::fs::write(&custom, "<h1>custom 401</h1>").unwrap();
    let port = free_port();
    let dead = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off, errors: {{ format: problem }} }}
routes:
  api: {{ match: "Host(`api.test`)", service: app, middlewares: [auth], max_body: 1KiB }}
  limited: {{ match: "Host(`limited.test`)", service: app, middlewares: [slow] }}
  down: {{ match: "Host(`down.test`)", service: dead }}
  html: {{ match: "Host(`html.test`)", service: app, middlewares: [auth], errors: {{ format: html }} }}
  auto: {{ match: "Host(`auto.test`)", service: app, middlewares: [auth], errors: {{ format: auto }} }}
  pages: {{ match: "Host(`pages.test`)", service: app, middlewares: [page401, auth] }}
  maint: {{ match: "Host(`maint.test`)", middlewares: [maint] }}
  maintpage: {{ match: "Host(`maintpage.test`)", middlewares: [maintpage] }}
middlewares:
  auth: {{ type: basic_auth, users: ["u:$2y$05$Ba2L27xH4nV/uMHG7kprmeoQS4NGMKB5hcdRvBYcBkK6rWsMnNEPO"] }}
  slow: {{ type: rate_limit, average: 1, period: 1m }}
  page401: {{ type: errors, status: ["401"], file: "{custom}" }}
  maint: {{ type: maintenance, retry_after: 2m }}
  maintpage: {{ type: maintenance, file: "{page}" }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
  dead: {{ backends: [{{ address: "127.0.0.1:{dead}" }}] }}
"#,
        custom = custom.display(),
        page = page.display(),
        backend = backend.addr,
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let call = |req| client::http1(addr(port), req);

    // No route: `defaults.errors.format` applies; a client without `Accept` accepts JSON.
    let reply = call(get("nowhere.test", "/")).await;
    let json = problem(&reply, 404, "not-found");
    assert_eq!(json["title"], "Not found");
    // A browser still gets the HTML page.
    let reply = call(accept(get("nowhere.test", "/"), "text/html,*/*;q=0.8")).await;
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(reply.text().contains("<h1>404</h1>"));

    // A middleware refusal keeps its own headers.
    let reply = call(accept(get("api.test", "/"), "*/*")).await;
    problem(&reply, 401, "unauthenticated");
    assert!(
        reply
            .header("www-authenticate")
            .unwrap()
            .starts_with("Basic")
    );

    // 413 from the proxy's body limit.
    let mut big = request("POST", "api.test", "/", "x".repeat(4096));
    big.headers_mut()
        .insert("authorization", "Basic dTpw".parse().unwrap());
    problem(&call(big).await, 413, "payload-too-large");

    // 429 carries `Retry-After` and `retry_after`.
    assert_eq!(call(get("limited.test", "/")).await.status, 200);
    let reply = call(get("limited.test", "/")).await;
    let json = problem(&reply, 429, "rate-limited");
    let retry: u64 = reply.header("retry-after").unwrap().parse().unwrap();
    assert_eq!(json["retry_after"], retry);

    // 502 from a backend that refuses connections: no address in the detail.
    let reply = call(get("down.test", "/")).await;
    let json = problem(&reply, 502, "bad-gateway");
    assert!(!reply.text().contains("127.0.0.1"), "{json}");

    // A route can keep the format before v0.8: `basic_auth`'s own text.
    let reply = call(accept(get("html.test", "/"), "application/json")).await;
    assert_eq!(
        reply.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(reply.text(), "401 Unauthorized\n");
    // `auto`: problem details only for clients that prefer JSON.
    let reply = call(accept(get("auto.test", "/"), "*/*")).await;
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    problem(
        &call(accept(get("auto.test", "/"), "application/json")).await,
        401,
        "unauthenticated",
    );

    // Precedence: an `errors` page for the status wins over the envelope.
    let reply = call(accept(get("pages.test", "/"), "application/json")).await;
    assert_eq!(reply.status, 401);
    assert_eq!(reply.text(), "<h1>custom 401</h1>");
    // Maintenance without a file uses the envelope with its own type; with a file, the file.
    let reply = call(get("maint.test", "/")).await;
    let json = problem(&reply, 503, "maintenance");
    assert_eq!(json["retry_after"], 120);
    let reply = call(get("maintpage.test", "/")).await;
    assert_eq!(reply.status, 503);
    assert_eq!(reply.text(), "<h1>back soon</h1>");
}

#[tokio::test]
async fn the_default_format_is_unchanged() {
    let port = free_port();
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes: {{}}\n"
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let reply = client::http1(addr(port), get("x.test", "/")).await;
    assert_eq!(reply.status, 404);
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(reply.header("content-language"), None);
    let reply = client::http1(addr(port), accept(get("x.test", "/"), "application/json")).await;
    assert_eq!(reply.header("content-type"), Some("application/json"));
    let json = reply.json();
    assert_eq!(json["status"], 404);
    assert_eq!(json["error"], "Not Found");
}
