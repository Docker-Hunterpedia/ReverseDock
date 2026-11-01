//! The admin server on its own runtime: DNS-rebinding and cross-site checks, security headers,
//! the token on TCP, the Unix socket and TLS (ADR-0024).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use rdock_admin::{Control, Running, Settings, TlsFiles};
use rdock_model::settings::AdminPasswords;
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, request};
use rdock_testkit::free_port;
use tokio::sync::watch;

struct Fake;

#[async_trait]
impl Control for Fake {
    fn ready(&self) -> bool {
        true
    }
    fn metrics(&self) -> Option<String> {
        Some("rdock_up 1\n".into())
    }
    async fn status(&self) -> serde_json::Value {
        serde_json::json!({ "ready": true, "generation": 7 })
    }
    async fn reload(&self) -> (bool, serde_json::Value) {
        (
            true,
            serde_json::json!({ "result": "applied", "generation": 8 }),
        )
    }
}

const TOKEN: &str = "rdk_test_token";

struct Admin {
    address: SocketAddr,
    dir: tempfile::TempDir,
    stop: watch::Sender<bool>,
    running: Option<Running>,
}

impl Admin {
    fn start(tls: Option<TlsFiles>, allowed_hosts: Vec<String>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self::start_in(dir, tls, allowed_hosts)
    }

    fn start_in(dir: tempfile::TempDir, tls: Option<TlsFiles>, allowed_hosts: Vec<String>) -> Self {
        let address: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let (stop, stop_rx) = watch::channel(false);
        let settings = Settings {
            address,
            tls,
            socket: Some(dir.path().join("admin.sock")),
            allowed_hosts,
            threads: 1,
            token: TOKEN.into(),
            state_dir: dir.path().join("admin"),
            passwords: AdminPasswords::default(),
        };
        let running = rdock_admin::start(settings, Arc::new(Fake), stop_rx).unwrap();
        Self {
            address,
            dir,
            stop,
            running: Some(running),
        }
    }

    fn socket(&self) -> std::path::PathBuf {
        self.dir.path().join("admin.sock")
    }

    /// Stops the server and hands back its directory, for a restart on the same state.
    async fn stop(mut self) -> tempfile::TempDir {
        self.stop.send(true).unwrap();
        self.running.take().unwrap().stopped().await;
        self.dir
    }
}

fn with(
    mut req: http::Request<http_body_util::Full<bytes::Bytes>>,
    headers: &[(&str, &str)],
) -> http::Request<http_body_util::Full<bytes::Bytes>> {
    for (name, value) in headers {
        req.headers_mut().insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    req
}

#[tokio::test(flavor = "multi_thread")]
async fn health_answers_with_security_headers_and_foreign_hosts_are_refused() {
    let admin = Admin::start(None, Vec::new());
    for host in ["127.0.0.1", "localhost:2080", "[::1]:2080"] {
        let reply = client::http1(admin.address, request("GET", host, "/healthz", "")).await;
        assert_eq!(reply.status, 200, "{host}");
    }
    let reply = client::http1(admin.address, request("GET", "127.0.0.1", "/healthz", "")).await;
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert!(
        reply
            .header("content-security-policy")
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert!(
        reply.header("strict-transport-security").is_none(),
        "no HSTS on plain HTTP"
    );

    // A page on another site that resolves its name to 127.0.0.1 (DNS rebinding).
    let reply = client::http1(
        admin.address,
        request("GET", "attacker.example", "/healthz", ""),
    )
    .await;
    assert_eq!(reply.status, 421);
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_api_needs_the_token_and_refuses_cross_site_writes() {
    let admin = Admin::start(None, Vec::new());
    let bearer = format!("Bearer {TOKEN}");
    let reply = client::http1(
        admin.address,
        request("GET", "127.0.0.1", "/api/v1/status", ""),
    )
    .await;
    assert_eq!(reply.status, 401);
    assert_eq!(reply.header("www-authenticate"), Some("Bearer"));

    let reply = client::http1(
        admin.address,
        with(
            request("GET", "127.0.0.1", "/api/v1/status", ""),
            &[("authorization", &bearer)],
        ),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["generation"], 7);

    for headers in [
        [
            ("authorization", bearer.as_str()),
            ("origin", "https://attacker.example"),
        ],
        [
            ("authorization", bearer.as_str()),
            ("sec-fetch-site", "cross-site"),
        ],
        [("authorization", bearer.as_str()), ("origin", "null")],
    ] {
        let reply = client::http1(
            admin.address,
            with(
                request("POST", "127.0.0.1", "/api/v1/config/reload", ""),
                &headers,
            ),
        )
        .await;
        assert_eq!(reply.status, 403, "{headers:?}");
    }
    let same_site = [
        ("authorization", bearer.as_str()),
        ("origin", "http://127.0.0.1:2080"),
        ("sec-fetch-site", "same-origin"),
    ];
    let reply = client::http1(
        admin.address,
        with(
            request("POST", "127.0.0.1", "/api/v1/config/reload", ""),
            &same_site,
        ),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["generation"], 8);

    let reply = client::http1(
        admin.address,
        request("DELETE", "127.0.0.1", "/healthz", ""),
    )
    .await;
    assert_eq!(reply.status, 405);
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_socket_is_owner_only_needs_no_token_and_is_removed_on_stop() {
    use std::os::unix::fs::PermissionsExt;
    let admin = Admin::start(None, Vec::new());
    let socket = admin.socket();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let path = socket.clone();
    let response = tokio::task::spawn_blocking(move || {
        let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
        stream
            .write_all(
                b"GET /api/v1/status HTTP/1.1\r\nHost: anything\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut text = String::new();
        stream.read_to_string(&mut text).unwrap();
        text
    })
    .await
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("\"generation\":7"), "{response}");
    admin.stop().await;
    assert!(!socket.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_serves_https_with_hsts_and_the_configured_host_names() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();
    let issued = ca.issue(dir.path(), "admin", &["admin.example.test"]);
    let tls = TlsFiles {
        cert_file: issued.cert.clone(),
        key_file: issued.key.clone(),
    };
    let admin = Admin::start_in(dir, Some(tls), vec!["admin.example.test".into()]);
    let config = ca.client_config(&[b"http/1.1"]);
    let reply = client::tls(
        admin.address,
        "admin.example.test",
        config.clone(),
        request("GET", "admin.example.test", "/healthz", ""),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.header("strict-transport-security"),
        Some("max-age=31536000")
    );
    let reply = client::tls(
        admin.address,
        "admin.example.test",
        config,
        request("GET", "127.0.0.1", "/healthz", ""),
    )
    .await;
    assert_eq!(reply.status, 421, "only the configured names");
    admin.stop().await;
}

#[test]
fn a_busy_port_fails_the_start() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime.enter();
    let (_stop, stop_rx) = watch::channel(false);
    let settings = Settings {
        address: taken.local_addr().unwrap(),
        tls: None,
        socket: None,
        allowed_hosts: Vec::new(),
        threads: 1,
        token: TOKEN.into(),
        state_dir: std::env::temp_dir().join("rdock-admin-unused"),
        passwords: AdminPasswords::default(),
    };
    let err = rdock_admin::start(settings, Arc::new(Fake), stop_rx)
        .err()
        .unwrap();
    assert!(
        err.to_string()
            .contains("cannot listen on the admin address"),
        "{err}"
    );
}

fn json_post(
    path: &str,
    body: &serde_json::Value,
    extra: &[(&str, &str)],
) -> http::Request<http_body_util::Full<bytes::Bytes>> {
    let mut headers = vec![("content-type", "application/json")];
    headers.extend_from_slice(extra);
    with(
        request("POST", "127.0.0.1", path, body.to_string()),
        &headers,
    )
}

fn json_body(reply: &client::Reply) -> serde_json::Value {
    serde_json::from_slice(&reply.body).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bootstrap_token_creates_one_admin_who_can_log_in() {
    let admin = Admin::start(None, Vec::new());
    let token_file = admin.dir.path().join("admin/bootstrap-token");
    let token = std::fs::read_to_string(&token_file).unwrap();
    let bearer = format!("Bearer {}", token.trim());
    let first = serde_json::json!({ "name": "Root", "password": "correct horse battery staple" });

    let reply = client::http1(admin.address, json_post("/api/v1/setup", &first, &[])).await;
    assert_eq!(reply.status, 401, "no bootstrap token");
    let reply = client::http1(
        admin.address,
        json_post(
            "/api/v1/setup",
            &first,
            &[("authorization", &format!("Bearer {TOKEN}"))],
        ),
    )
    .await;
    assert_eq!(
        reply.status, 401,
        "the API token is not the bootstrap token"
    );

    let weak = serde_json::json!({ "name": "root", "password": "password1234" });
    let reply = client::http1(
        admin.address,
        json_post("/api/v1/setup", &weak, &[("authorization", &bearer)]),
    )
    .await;
    assert_eq!(reply.status, 422);
    assert!(
        token_file.exists(),
        "a refused password does not use the token up"
    );

    let unknown = serde_json::json!({ "name": "root", "password": "x", "role": "admin" });
    let reply = client::http1(
        admin.address,
        json_post("/api/v1/setup", &unknown, &[("authorization", &bearer)]),
    )
    .await;
    assert_eq!(reply.status, 422, "unknown fields are refused");

    let reply = client::http1(
        admin.address,
        json_post("/api/v1/setup", &first, &[("authorization", &bearer)]),
    )
    .await;
    assert_eq!(reply.status, 201);
    assert_eq!(
        json_body(&reply),
        serde_json::json!({ "name": "root", "role": "admin" })
    );
    assert!(!token_file.exists(), "the token is single use");

    let reply = client::http1(
        admin.address,
        json_post("/api/v1/setup", &first, &[("authorization", &bearer)]),
    )
    .await;
    assert_eq!(reply.status, 409);

    let reply = client::http1(admin.address, json_post("/api/v1/auth/login", &first, &[])).await;
    assert_eq!(reply.status, 200);
    assert_eq!(json_body(&reply)["role"], "admin");
    let dir = admin.stop().await;

    // After a restart the admin exists, so no new bootstrap token is written.
    let again = Admin::start_in(dir, None, Vec::new());
    assert!(!token_file.exists());
    again.stop().await;
}

/// Sends a JSON `POST` over the CLI socket and returns the raw response.
fn socket_post(socket: &std::path::Path, path: &str, body: &serde_json::Value) -> String {
    let body = body.to_string();
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn logins_hide_which_users_exist_and_are_rate_limited() {
    let admin = Admin::start(None, Vec::new());
    let first = serde_json::json!({ "name": "ops", "password": "correct horse battery staple" });
    // The CLI socket needs no bootstrap token: its file permissions are the proof.
    let response = socket_post(&admin.socket(), "/api/v1/setup", &first);
    assert!(response.starts_with("HTTP/1.1 201"), "{response}");

    let reply = client::http1(admin.address, json_post("/api/v1/auth/login", &first, &[])).await;
    assert_eq!(reply.status, 200);

    let wrong = serde_json::json!({ "name": "ops", "password": "wrong horse battery staple" });
    let nobody = serde_json::json!({ "name": "nobody", "password": "wrong horse battery staple" });
    let reply_wrong =
        client::http1(admin.address, json_post("/api/v1/auth/login", &wrong, &[])).await;
    let reply_nobody =
        client::http1(admin.address, json_post("/api/v1/auth/login", &nobody, &[])).await;
    assert_eq!(reply_wrong.status, 401);
    assert_eq!(
        reply_wrong.body, reply_nobody.body,
        "unknown users look like wrong passwords"
    );

    // Two more attempts make five per minute from this address.
    for _ in 0..2 {
        client::http1(admin.address, json_post("/api/v1/auth/login", &wrong, &[])).await;
    }
    let reply = client::http1(admin.address, json_post("/api/v1/auth/login", &first, &[])).await;
    assert_eq!(reply.status, 429);
    let wait: u64 = reply.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    admin.stop().await;
}
