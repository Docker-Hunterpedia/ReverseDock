//! End-to-end: the built-in middlewares through the real binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::io::Read;
use std::net::SocketAddr;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::{Rdock, write};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// One plain listener; `routes` and `middlewares` are YAML blocks; `app` is the backend.
fn config(port: u16, backend: SocketAddr, routes: &str, middlewares: &str) -> String {
    format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes:\n{routes}\nservices:\n  app: {{ backends: [{{ address: \"{backend}\" }}] }}\nmiddlewares:\n{middlewares}\n"
    )
}

#[tokio::test]
async fn headers_redirects_and_paths() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let routes = r#"
  headers: { match: "PathPrefix(`/h`)", service: app, middlewares: [hdr] }
  old: { match: "PathPrefix(`/old`)", service: app, middlewares: [to-new] }
  api: { match: "PathPrefix(`/api`)", service: app, middlewares: [strip-api, add-v1] }
  fixed: { match: "PathPrefix(`/fixed`)", service: app, middlewares: [replace] }
  regex: { match: "PathPrefix(`/r/`)", service: app, middlewares: [rewrite] }
"#;
    let middlewares = r#"
  hdr:
    type: headers
    request: { set: { X-Env: prod }, remove: [X-Debug] }
    response: { set: { X-Frame-Options: DENY }, remove: [X-Backend] }
    hsts: { max_age: 1d }
  to-new: { type: redirect, regex: "^http://([^/]+)/old/(.*)$", replacement: "http://${1}/new/${2}", permanent: true }
  strip-api: { type: strip_prefix, prefixes: [/api] }
  add-v1: { type: add_prefix, prefix: /v1 }
  replace: { type: replace_path, path: /replaced }
  rewrite: { type: rewrite, regex: "^/r/(.*)$", replacement: "/rewritten/$1" }
"#;
    let _rdock = Rdock::start(RDOCK, &config(port, backend.addr, routes, middlewares));
    let mut req = get("a.test", "/h");
    req.headers_mut().insert("x-debug", "1".parse().unwrap());
    let reply = client::http1(addr(port), req).await;
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
    assert_eq!(reply.header("x-backend"), None);
    assert_eq!(
        reply.header("strict-transport-security"),
        None,
        "HSTS only over HTTPS"
    );
    let echo = reply.json();
    assert_eq!(echo["headers"]["x-env"][0], "prod");
    assert!(echo["headers"].get("x-debug").is_none());

    let reply = client::http1(addr(port), get("a.test", "/old/page?q=1")).await;
    assert_eq!(reply.status, 301);
    assert_eq!(reply.header("location"), Some("http://a.test/new/page?q=1"));

    let echo = client::http1(addr(port), get("a.test", "/api/users?page=2"))
        .await
        .json();
    assert_eq!(echo["target"], "/v1/users?page=2");
    assert_eq!(echo["headers"]["x-forwarded-prefix"][0], "/api");

    let echo = client::http1(addr(port), get("a.test", "/fixed/anything"))
        .await
        .json();
    assert_eq!(echo["target"], "/replaced");
    assert_eq!(echo["headers"]["x-replaced-path"][0], "/fixed/anything");

    let echo = client::http1(addr(port), get("a.test", "/r/a/b"))
        .await
        .json();
    assert_eq!(echo["target"], "/rewritten/a/b");
}

#[tokio::test]
async fn basic_auth_challenges_and_admits() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let routes = "  app: { match: \"PathPrefix(`/`)\", service: app, middlewares: [auth] }";
    // `openssl passwd -apr1 -salt saltsalt password`
    let middlewares = "  auth: { type: basic_auth, users: [\"alice:$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/\"], realm: Office, remove_header: true }";
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr, routes, middlewares));
    let denied = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(denied.status, 401);
    assert_eq!(
        denied.header("www-authenticate"),
        Some("Basic realm=\"Office\", charset=\"UTF-8\"")
    );
    let mut ok = get("a", "/");
    ok.headers_mut().insert(
        "authorization",
        "Basic YWxpY2U6cGFzc3dvcmQ=".parse().unwrap(),
    );
    let reply = client::http1(addr(port), ok).await;
    assert_eq!(reply.status, 200);
    assert!(
        reply.json()["headers"].get("authorization").is_none(),
        "removed before forwarding"
    );
    assert_eq!(
        backend.requests(),
        1,
        "the unauthorised request never reached the backend"
    );
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(rdock.access_log().iter().any(|l| l["user"] == "alice"));
    assert!(
        rdock.log().contains("weak hash"),
        "weak hashes are reported"
    );
}

#[tokio::test]
async fn ip_filters_rate_limits_and_maintenance() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let page = write(dir.path(), "down.html", "<h1>Back soon</h1>");
    let routes = r#"
  denied: { match: "PathPrefix(`/denied`)", service: app, middlewares: [no-local] }
  allowed: { match: "PathPrefix(`/allowed`)", service: app, middlewares: [only-local] }
  limited: { match: "PathPrefix(`/limited`)", service: app, middlewares: [limit] }
  down: { match: "PathPrefix(`/down`)", service: app, middlewares: [maintenance] }
"#;
    let middlewares = format!(
        r#"
  no-local: {{ type: ip_deny, cidrs: [127.0.0.0/8] }}
  only-local: {{ type: ip_allow, cidrs: [127.0.0.1] }}
  limit: {{ type: rate_limit, average: 1, burst: 2, period: 1m }}
  maintenance: {{ type: maintenance, file: "{}", retry_after: 2m }}
"#,
        page.display()
    );
    let _rdock = Rdock::start(RDOCK, &config(port, backend.addr, routes, &middlewares));
    assert_eq!(
        client::http1(addr(port), get("a", "/denied")).await.status,
        403
    );
    assert_eq!(
        client::http1(addr(port), get("a", "/allowed")).await.status,
        200
    );
    let statuses: Vec<u16> = futures_util::future::join_all(
        (0..4).map(|_| client::http1(addr(port), get("a", "/limited"))),
    )
    .await
    .iter()
    .map(|r| r.status)
    .collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == 200).count(),
        2,
        "{statuses:?}"
    );
    let limited = client::http1(addr(port), get("a", "/limited")).await;
    assert_eq!(limited.status, 429);
    assert!(limited.header("retry-after").is_some());
    let down = client::http1(addr(port), get("a", "/down")).await;
    assert_eq!(down.status, 503);
    assert_eq!(down.header("retry-after"), Some("120"));
    assert_eq!(down.text(), "<h1>Back soon</h1>");
}

#[tokio::test]
async fn cors_compress_and_error_pages() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let page = write(dir.path(), "error.html", "<h1>custom error</h1>");
    let routes = r#"
  api: { match: "PathPrefix(`/api`) || PathPrefix(`/status`)", service: app, middlewares: [cors, pages] }
  big: { match: "PathPrefix(`/bytes`)", service: app, middlewares: [gzip] }
  broken: { match: "PathPrefix(`/broken`)", service: dead, middlewares: [pages] }
"#;
    let middlewares = format!(
        r#"
  cors: {{ type: cors, allowed_origins: ["https://app.example.com"], allowed_methods: [GET, PUT], allowed_headers: [X-Token], allow_credentials: true }}
  gzip: {{ type: compress }}
  pages: {{ type: errors, status: ["500-599", "404"], file: "{}" }}
"#,
        page.display()
    );
    let mut text = config(port, backend.addr, routes, &middlewares);
    let dead = free_port();
    text = text.replace(
        "services:\n",
        &format!("services:\n  dead: {{ backends: [{{ address: \"127.0.0.1:{dead}\" }}] }}\n"),
    );
    let _rdock = Rdock::start(RDOCK, &text);

    let mut preflight = request("OPTIONS", "a", "/api/x", "");
    preflight
        .headers_mut()
        .insert("origin", "https://app.example.com".parse().unwrap());
    preflight
        .headers_mut()
        .insert("access-control-request-method", "PUT".parse().unwrap());
    let reply = client::http1(addr(port), preflight).await;
    assert_eq!(reply.status, 204);
    assert_eq!(
        reply.header("access-control-allow-origin"),
        Some("https://app.example.com")
    );
    assert_eq!(
        reply.header("access-control-allow-credentials"),
        Some("true")
    );
    assert_eq!(backend.requests(), 0, "preflights never reach the backend");

    let mut simple = get("a", "/api/x");
    simple
        .headers_mut()
        .insert("origin", "https://app.example.com".parse().unwrap());
    let reply = client::http1(addr(port), simple).await;
    assert_eq!(
        reply.header("access-control-allow-origin"),
        Some("https://app.example.com")
    );
    assert_eq!(reply.header("vary"), Some("Origin"));

    let mut gz = get("a", "/bytes/4096");
    gz.headers_mut()
        .insert("accept-encoding", "gzip".parse().unwrap());
    let reply = client::http1(addr(port), gz).await;
    assert_eq!(reply.header("content-encoding"), Some("gzip"));
    let mut text = String::new();
    flate2::read::GzDecoder::new(&reply.body[..])
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "a".repeat(4096));
    assert_eq!(reply.header("etag"), Some("W/\"bytes\""));

    let reply = client::http1(addr(port), get("a", "/status/503")).await;
    assert_eq!(reply.status, 503, "the status is kept");
    assert_eq!(reply.text(), "<h1>custom error</h1>");
    let reply = client::http1(addr(port), get("a", "/broken")).await;
    assert_eq!(reply.status, 502, "proxy errors use the page too");
    assert_eq!(reply.text(), "<h1>custom error</h1>");
    let reply = client::http1(addr(port), get("a", "/status/200")).await;
    assert_eq!(reply.status, 200);
}

#[tokio::test]
async fn forward_auth_allows_refuses_and_fails_closed() {
    let backend = Backend::start("app").await;
    let auth = Backend::start("auth").await;
    let port = free_port();
    let dead = free_port();
    let routes = r#"
  allowed: { match: "PathPrefix(`/in`)", service: app, middlewares: [auth-ok] }
  refused: { match: "PathPrefix(`/out`)", service: app, middlewares: [auth-no] }
  outage: { match: "PathPrefix(`/outage`)", service: app, middlewares: [auth-dead] }
"#;
    let middlewares = format!(
        r#"
  auth-ok: {{ type: forward_auth, address: "http://{a}/verify", copy_headers: [X-Backend] }}
  auth-no: {{ type: forward_auth, address: "http://{a}/status/401" }}
  auth-dead: {{ type: forward_auth, address: "http://127.0.0.1:{dead}/verify", timeout: 1s }}
"#,
        a = auth.addr
    );
    let _rdock = Rdock::start(RDOCK, &config(port, backend.addr, routes, &middlewares));
    let mut req = get("a.test", "/in/page?x=1");
    req.headers_mut()
        .insert("x-backend", "forged".parse().unwrap());
    let reply = client::http1(addr(port), req).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json()["headers"]["x-backend"][0],
        "auth",
        "copied from the auth answer, never from the client"
    );
    let refused = client::http1(addr(port), get("a.test", "/out")).await;
    assert_eq!(refused.status, 401);
    assert!(refused.text().contains("status 401 from auth"));
    let outage = client::http1(addr(port), get("a.test", "/outage")).await;
    assert_eq!(outage.status, 502, "fails closed");
    assert_eq!(auth.requests(), 2);
}
