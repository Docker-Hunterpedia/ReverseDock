//! The admin server on its own runtime: DNS-rebinding and cross-site checks, security headers,
//! the token on TCP, the Unix socket and TLS (ADR-0024).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use rdock_admin::{ApiWrite, Control, Running, Settings, TlsFiles};
use rdock_model::settings::{AdminAudit, AdminPasswords, AdminSessions, AdminTokens, MfaPolicy};
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, request};
use rdock_testkit::free_port;
use tokio::sync::watch;

#[derive(Default)]
struct Fake {
    /// The API objects and the generation.
    api: std::sync::Mutex<(serde_json::Value, u64)>,
}

impl Fake {
    fn etag(generation: u64) -> String {
        format!("\"g{generation}-0011223344556677\"")
    }
}

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
    async fn effective_config(&self) -> serde_json::Value {
        serde_json::json!({
            "routes": { "web": {}, "app@docker": {} },
            "services": { "web": { "sticky": { "cookie": { "secret": "plain" } } } }
        })
    }
    async fn api_config(&self) -> (serde_json::Value, String) {
        let api = self.api.lock().unwrap();
        (api.0.clone(), Self::etag(api.1))
    }
    async fn dry_run(
        &self,
        candidate: serde_json::Value,
    ) -> Result<(bool, serde_json::Value), String> {
        if candidate.get("bad").is_some() {
            return Err("bad: unknown field".into());
        }
        let rejected = candidate["routes"].get("reject").is_some();
        Ok((!rejected, serde_json::json!([])))
    }
    async fn write_api(&self, candidate: serde_json::Value, if_match: String) -> ApiWrite {
        let mut api = self.api.lock().unwrap();
        if if_match != Self::etag(api.1) {
            return ApiWrite::Stale {
                etag: Self::etag(api.1),
            };
        }
        if candidate.get("bad").is_some() {
            return ApiWrite::Invalid("bad: unknown field".into());
        }
        if candidate["routes"].get("reject").is_some() {
            return ApiWrite::Rejected {
                report: serde_json::json!({ "result": "rejected" }),
            };
        }
        api.0 = candidate;
        api.1 += 1;
        ApiWrite::Applied {
            report: serde_json::json!({ "result": "applied", "generation": api.1 }),
            etag: Self::etag(api.1),
        }
    }
    async fn history(&self) -> serde_json::Value {
        serde_json::json!([{ "id": 1_793_000_000_000_u64, "generation": 1, "summary": "start", "api": true }])
    }
    async fn history_api(&self, id: u64) -> Option<serde_json::Value> {
        (id == 1_793_000_000_000).then(|| serde_json::json!({ "routes": {} }))
    }
    async fn backends(&self) -> serde_json::Value {
        serde_json::json!([{ "service": "web", "backends": [{ "address": "10.0.0.1:80", "drained": false }] }])
    }
    async fn set_drained(&self, service: String, backend: String, _drained: bool) -> bool {
        service == "web" && backend == "10.0.0.1:80"
    }
    async fn renew_certificate(&self, name: String) -> bool {
        name == "example.com"
    }
    async fn metrics_summary(&self, window_seconds: u64) -> serde_json::Value {
        serde_json::json!({ "total": { "window_seconds": window_seconds }, "routes": {}, "services": {} })
    }
}

/// A string shaped like a token but issued by no one.
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
        Self::start_with(dir, tls, allowed_hosts, |_| {})
    }

    fn start_with(
        dir: tempfile::TempDir,
        tls: Option<TlsFiles>,
        allowed_hosts: Vec<String>,
        change: impl FnOnce(&mut Settings),
    ) -> Self {
        let address: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let (stop, stop_rx) = watch::channel(false);
        let mut settings = Settings {
            address,
            tls,
            socket: Some(dir.path().join("admin.sock")),
            allowed_hosts,
            threads: 1,
            state_dir: dir.path().join("admin"),
            passwords: AdminPasswords::default(),
            sessions: AdminSessions::default(),
            mfa: MfaPolicy::default(),
            dashboard: true,
            tokens: AdminTokens::default(),
            metrics_unauthenticated_on_loopback: false,
            audit_dir: dir.path().join("audit"),
            audit: AdminAudit::default(),
            api_writes: true,
            feeds: None,
        };
        change(&mut settings);
        let running = rdock_admin::start(settings, Arc::new(Fake::default()), stop_rx).unwrap();
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
    let bearer = format!("Bearer {}", api_token(&admin, "operator"));
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
        state_dir: std::env::temp_dir().join("rdock-admin-unused"),
        passwords: AdminPasswords::default(),
        sessions: AdminSessions::default(),
        mfa: MfaPolicy::default(),
        dashboard: true,
        tokens: AdminTokens::default(),
        metrics_unauthenticated_on_loopback: false,
        audit_dir: std::env::temp_dir().join("rdock-admin-unused-audit"),
        audit: AdminAudit::default(),
        api_writes: true,
        feeds: None,
    };
    let err = rdock_admin::start(settings, Arc::new(Fake::default()), stop_rx)
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

/// The current TOTP code for a base32 secret (RFC 6238, SHA-1, 6 digits, 30 s).
fn totp_now(secret: &str) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut key, mut buffer, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in secret.bytes() {
        let value = alphabet.iter().position(|&b| b == c).unwrap();
        buffer = (buffer << 5) | u32::try_from(value).unwrap();
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            key.push(u8::try_from((buffer >> bits) & 0xff).unwrap());
        }
    }
    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key),
        &step.to_be_bytes(),
    );
    let mac = tag.as_ref();
    let offset = (mac[19] & 0x0f) as usize;
    let word = u32::from_be_bytes(mac[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    format!("{:06}", word % 1_000_000)
}

/// `name=value` of the session cookie a response sets.
fn session_cookie(reply: &client::Reply) -> String {
    let set = reply.header("set-cookie").unwrap();
    assert!(
        set.contains("; Path=/; Secure; HttpOnly; SameSite=Strict"),
        "{set}"
    );
    set.split(';').next().unwrap().to_owned()
}

/// A JSON `POST` with a session cookie and its CSRF token.
async fn session_post(
    admin: &Admin,
    path: &str,
    body: &serde_json::Value,
    cookie: &str,
    csrf: &str,
) -> client::Reply {
    client::http1(
        admin.address,
        json_post(path, body, &[("cookie", cookie), ("x-csrf-token", csrf)]),
    )
    .await
}

async fn session_get(admin: &Admin, path: &str, cookie: &str) -> client::Reply {
    let req = with(request("GET", "127.0.0.1", path, ""), &[("cookie", cookie)]);
    client::http1(admin.address, req).await
}

fn csrf_of(reply: &client::Reply) -> String {
    json_body(reply)["csrf_token"].as_str().unwrap().to_owned()
}

/// Creates `root`, logs in and enrols TOTP; returns the full session's cookie, its CSRF
/// token and the recovery codes.
async fn enrolled_admin(admin: &Admin, first: &serde_json::Value) -> (String, String, Vec<String>) {
    assert!(socket_post(&admin.socket(), "/api/v1/setup", first).starts_with("HTTP/1.1 201"));
    // Admins must enrol before anything else (admin.mfa: required_for_admins).
    let reply = client::http1(admin.address, json_post("/api/v1/auth/login", first, &[])).await;
    assert_eq!(reply.status, 200);
    let enrolling = session_cookie(&reply);
    assert!(enrolling.starts_with("__Host-rdock_session="));
    assert_eq!(json_body(&reply)["stage"], "enrol");
    let csrf = csrf_of(&reply);
    let reply = session_get(admin, "/api/v1/status", &enrolling).await;
    assert_eq!(reply.status, 401, "an unfinished login reaches no API");

    let empty = serde_json::json!({});
    let reply = session_post(admin, "/api/v1/auth/totp", &empty, &enrolling, "wrong").await;
    assert_eq!(reply.status, 403, "no CSRF token");
    let reply = session_post(admin, "/api/v1/auth/totp", &empty, &enrolling, &csrf).await;
    assert_eq!(reply.status, 200);
    let secret = json_body(&reply)["secret"].as_str().unwrap().to_owned();
    let uri = json_body(&reply)["uri"].as_str().unwrap().to_owned();
    assert!(uri.starts_with("otpauth://totp/ReverseDock:root?"), "{uri}");

    let code = serde_json::json!({ "code": totp_now(&secret) });
    let reply = session_post(admin, "/api/v1/auth/totp/confirm", &code, &enrolling, &csrf).await;
    assert_eq!(reply.status, 200);
    let full = session_cookie(&reply);
    let full_csrf = csrf_of(&reply);
    assert_eq!(json_body(&reply)["stage"], "full");
    let recovery: Vec<String> =
        serde_json::from_value(json_body(&reply)["recovery_codes"].clone()).unwrap();
    assert_eq!(recovery.len(), 10);
    let reply = session_get(admin, "/api/v1/auth/session", &enrolling).await;
    assert_eq!(
        reply.status, 401,
        "the pre-enrolment session ID was replaced"
    );
    (full, full_csrf, recovery)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_enrols_totp_then_logs_in_with_a_second_factor() {
    let admin = Admin::start(None, Vec::new());
    let first = serde_json::json!({ "name": "root", "password": "correct horse battery staple" });
    let (full, csrf, recovery) = enrolled_admin(&admin, &first).await;
    let empty = serde_json::json!({});

    assert_eq!(
        session_get(&admin, "/api/v1/status", &full).await.status,
        200
    );
    let reply = session_post(&admin, "/api/v1/config/reload", &empty, &full, "").await;
    assert_eq!(reply.status, 403, "writes need the CSRF token");
    let reply = session_post(&admin, "/api/v1/config/reload", &empty, &full, &csrf).await;
    assert_eq!(reply.status, 200);
    let reply = session_get(&admin, "/api/v1/auth/sessions", &full).await;
    assert_eq!(json_body(&reply).as_array().unwrap().len(), 1);

    let reply = session_post(&admin, "/api/v1/auth/logout", &empty, &full, &csrf).await;
    assert_eq!(reply.status, 204);
    assert!(reply.header("clear-site-data").unwrap().contains("cookies"));
    assert!(reply.header("set-cookie").unwrap().contains("Max-Age=0"));
    assert_eq!(
        session_get(&admin, "/api/v1/status", &full).await.status,
        401
    );

    // Next login: the password alone is not enough; a recovery code works once.
    let reply = client::http1(admin.address, json_post("/api/v1/auth/login", &first, &[])).await;
    let pending = session_cookie(&reply);
    let csrf = csrf_of(&reply);
    assert_eq!(json_body(&reply)["stage"], "mfa");
    assert_eq!(
        session_get(&admin, "/api/v1/status", &pending).await.status,
        401
    );
    let wrong = serde_json::json!({ "code": "000000" });
    let reply = session_post(&admin, "/api/v1/auth/mfa", &wrong, &pending, &csrf).await;
    assert_eq!(reply.status, 401);
    let recovery_code = serde_json::json!({ "code": recovery[0] });
    let reply = session_post(&admin, "/api/v1/auth/mfa", &recovery_code, &pending, &csrf).await;
    assert_eq!(reply.status, 200);
    assert_eq!(json_body(&reply)["stage"], "full");

    let users = std::fs::read_to_string(admin.dir.path().join("admin/users.json")).unwrap();
    assert!(
        !users.contains(&recovery[0]),
        "recovery codes are stored hashed"
    );
    let saved: serde_json::Value = serde_json::from_str(&users).unwrap();
    assert_eq!(
        saved["users"][0]["mfa"]["recovery"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_get_the_dashboard_and_the_api_stays_json() {
    let admin = Admin::start(None, Vec::new());
    let reply = client::http1(
        admin.address,
        request("GET", "127.0.0.1", "/api/v1/setup", ""),
    )
    .await;
    assert_eq!(json_body(&reply), serde_json::json!({ "needed": true }));

    // With or without a built dashboard in this binary, a page path answers HTML.
    for path in ["/", "/security"] {
        let reply = client::http1(admin.address, request("GET", "127.0.0.1", path, "")).await;
        assert!(
            reply
                .header("content-type")
                .unwrap()
                .starts_with("text/html"),
            "{path}"
        );
        assert!(reply.header("content-security-policy").is_some());
    }
    let reply = client::http1(
        admin.address,
        request("GET", "127.0.0.1", "/api/v1/nope", ""),
    )
    .await;
    assert_eq!(
        reply.status, 401,
        "unknown API paths reveal nothing before login"
    );
    assert_eq!(reply.header("content-type"), Some("application/json"));
    let viewer = api_token(&admin, "viewer");
    let reply = client::http1(admin.address, bearer_get("/api/v1/nope", &viewer)).await;
    assert_eq!(reply.status, 404);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    admin.stop().await;

    let off = Admin::start_with(tempfile::tempdir().unwrap(), None, Vec::new(), |s| {
        s.dashboard = false;
    });
    let reply = client::http1(off.address, request("GET", "127.0.0.1", "/", "")).await;
    assert_eq!(reply.status, 404);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    off.stop().await;
}

/// Creates an API token over the CLI socket and returns its value.
fn api_token(admin: &Admin, role: &str) -> String {
    let body = serde_json::json!({ "name": format!("test {role}"), "role": role });
    let response = socket_post(&admin.socket(), "/api/v1/tokens", &body);
    assert!(response.starts_with("HTTP/1.1 201"), "{response}");
    let json: serde_json::Value =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    json["token"].as_str().unwrap().to_owned()
}

fn bearer_get(path: &str, token: &str) -> http::Request<http_body_util::Full<bytes::Bytes>> {
    with(
        request("GET", "127.0.0.1", path, ""),
        &[("authorization", &format!("Bearer {token}"))],
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn roles_limit_tokens_and_metrics_needs_one() {
    let admin = Admin::start(None, Vec::new());
    let reply = client::http1(admin.address, request("GET", "127.0.0.1", "/metrics", "")).await;
    assert_eq!(reply.status, 401, "/metrics needs a token since v0.5");

    let metrics = api_token(&admin, "metrics");
    let viewer = api_token(&admin, "viewer");
    let reply = client::http1(admin.address, bearer_get("/metrics", &metrics)).await;
    assert_eq!(reply.status, 200);
    assert!(
        reply.body.starts_with(b"rdock_up 1\n"),
        "the engine's metrics come first"
    );
    let reply = client::http1(admin.address, bearer_get("/api/v1/status", &metrics)).await;
    assert_eq!(reply.status, 403, "a metrics token reads metrics only");
    let reply = client::http1(admin.address, bearer_get("/api/v1/status", &viewer)).await;
    assert_eq!(reply.status, 200);
    let reload = with(
        request("POST", "127.0.0.1", "/api/v1/config/reload", ""),
        &[("authorization", &format!("Bearer {viewer}"))],
    );
    assert_eq!(
        client::http1(admin.address, reload).await.status,
        403,
        "viewers do not reload"
    );

    // A viewer cannot mint a stronger token, and sees only their own.
    let escalate = json_post(
        "/api/v1/tokens",
        &serde_json::json!({ "name": "x", "role": "admin" }),
        &[("authorization", &format!("Bearer {viewer}"))],
    );
    assert_eq!(client::http1(admin.address, escalate).await.status, 403);
    let reply = client::http1(admin.address, bearer_get("/api/v1/tokens", &viewer)).await;
    assert_eq!(
        json_body(&reply).as_array().unwrap().len(),
        2,
        "both were created by cli"
    );
    let listed = json_body(&reply);
    assert!(
        listed.to_string().find("secret").is_none(),
        "no hashes in the list"
    );

    // A one-character typo fails the checksum; revocation is immediate.
    let mut typo = viewer.clone();
    typo.replace_range(20..21, if &viewer[20..21] == "a" { "b" } else { "a" });
    assert_eq!(
        client::http1(admin.address, bearer_get("/api/v1/status", &typo))
            .await
            .status,
        401
    );
    let id = viewer.split('_').nth(2).unwrap();
    let mut stream = std::os::unix::net::UnixStream::connect(admin.socket()).unwrap();
    write!(
        stream,
        "DELETE /api/v1/tokens/{id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 204"), "{response}");
    assert_eq!(
        client::http1(admin.address, bearer_get("/api/v1/status", &viewer))
            .await
            .status,
        401
    );
    admin.stop().await;

    let open = Admin::start_with(tempfile::tempdir().unwrap(), None, Vec::new(), |s| {
        s.metrics_unauthenticated_on_loopback = true;
    });
    let reply = client::http1(open.address, request("GET", "127.0.0.1", "/metrics", "")).await;
    assert_eq!(
        reply.status, 200,
        "the loopback opt-out keeps old scrapers working"
    );
    open.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn admins_manage_users_but_never_remove_the_last_admin() {
    let admin = Admin::start(None, Vec::new());
    let root = serde_json::json!({ "name": "root", "password": "correct horse battery staple" });
    assert!(socket_post(&admin.socket(), "/api/v1/setup", &root).starts_with("HTTP/1.1 201"));
    let ops = serde_json::json!({ "name": "ops", "role": "operator", "password": "another long passphrase" });
    assert!(socket_post(&admin.socket(), "/api/v1/users", &ops).starts_with("HTTP/1.1 201"));
    let weak = serde_json::json!({ "name": "weak", "role": "viewer", "password": "password1234" });
    assert!(socket_post(&admin.socket(), "/api/v1/users", &weak).starts_with("HTTP/1.1 422"));

    let raw = |method: &str, path: &str, body: &str| {
        let mut stream = std::os::unix::net::UnixStream::connect(admin.socket()).unwrap();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    };
    assert!(raw("PATCH", "/api/v1/users/root", r#"{"role":"viewer"}"#).starts_with("HTTP/1.1 409"));
    assert!(raw("DELETE", "/api/v1/users/root", "").starts_with("HTTP/1.1 409"));

    // The operator logs in (no MFA required for operators by default) and gets a token.
    let login = serde_json::json!({ "name": "ops", "password": "another long passphrase" });
    let reply = client::http1(admin.address, json_post("/api/v1/auth/login", &login, &[])).await;
    assert_eq!(json_body(&reply)["stage"], "full");
    let cookie = session_cookie(&reply);
    let csrf = csrf_of(&reply);
    let users = session_get(&admin, "/api/v1/users", &cookie).await;
    assert_eq!(users.status, 403, "only admins see users");
    let body = serde_json::json!({ "name": "deploy", "role": "operator" });
    let reply = session_post(&admin, "/api/v1/tokens", &body, &cookie, &csrf).await;
    assert_eq!(reply.status, 201);
    let token = json_body(&reply)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        client::http1(admin.address, bearer_get("/api/v1/status", &token))
            .await
            .status,
        200
    );

    // Disabling the user ends their sessions, and their tokens stop working with them.
    assert!(raw("PATCH", "/api/v1/users/ops", r#"{"disabled":true}"#).starts_with("HTTP/1.1 200"));
    assert_eq!(
        session_get(&admin, "/api/v1/status", &cookie).await.status,
        401
    );
    assert_eq!(
        client::http1(admin.address, bearer_get("/api/v1/status", &token))
            .await
            .status,
        401
    );
    assert!(raw("DELETE", "/api/v1/users/ops", "").starts_with("HTTP/1.1 204"));
    let listed = raw("GET", "/api/v1/tokens", "");
    assert!(
        !listed.contains("deploy"),
        "deleting a user revokes their tokens"
    );
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_socket_path_too_long_turns_the_socket_off_not_the_admin_api() {
    let dir = tempfile::tempdir().unwrap();
    let long = dir.path().join("x".repeat(120)).join("admin.sock");
    let admin = Admin::start_with(tempfile::tempdir().unwrap(), None, Vec::new(), |s| {
        s.socket = Some(long.clone());
    });
    let reply = client::http1(admin.address, request("GET", "127.0.0.1", "/healthz", "")).await;
    assert_eq!(reply.status, 200);
    assert!(!long.exists());
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn logins_writes_and_refusals_land_in_an_intact_audit_chain() {
    let admin = Admin::start(None, Vec::new());
    let root = serde_json::json!({ "name": "root", "password": "correct horse battery staple" });
    assert!(socket_post(&admin.socket(), "/api/v1/setup", &root).starts_with("HTTP/1.1 201"));
    let wrong = serde_json::json!({ "name": "root", "password": "wrong horse battery staple" });
    client::http1(admin.address, json_post("/api/v1/auth/login", &wrong, &[])).await;
    client::http1(admin.address, json_post("/api/v1/auth/login", &root, &[])).await;
    let viewer = api_token(&admin, "viewer");
    let reload = with(
        request("POST", "127.0.0.1", "/api/v1/config/reload", ""),
        &[("authorization", &format!("Bearer {viewer}"))],
    );
    assert_eq!(client::http1(admin.address, reload).await.status, 403);
    let forged = bearer_get(
        "/api/v1/status",
        "rdk_pat_0000000000_00000000000000000000000000000000000000",
    );
    assert_eq!(client::http1(admin.address, forged).await.status, 401);

    let reply = client::http1(admin.address, bearer_get("/api/v1/audit", &viewer)).await;
    assert_eq!(reply.status, 403, "only admins read the audit log");
    let mut stream = std::os::unix::net::UnixStream::connect(admin.socket()).unwrap();
    write!(
        stream,
        "GET /api/v1/audit?limit=50 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let records: serde_json::Value =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    let seen: Vec<(String, String)> = records
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["action"].as_str().unwrap().to_owned(),
                r["result"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    for expected in [
        ("user.create_first_admin", "ok"),
        ("login", "denied"),
        ("login", "ok"),
        ("token.create", "ok"),
        ("access", "denied"),
        ("auth", "denied"),
    ] {
        assert!(
            seen.contains(&(expected.0.to_owned(), expected.1.to_owned())),
            "{expected:?} missing from {seen:?}"
        );
    }
    assert!(
        !response.contains("correct horse"),
        "no passwords in the audit log"
    );
    let dir = admin.stop().await;
    assert!(matches!(
        rdock_admin::audit::verify(&dir.path().join("audit")).unwrap(),
        rdock_admin::audit::Verdict::Intact { .. }
    ));
}

/// A JSON request with a bearer token and extra headers.
fn bearer_json(
    method: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
    extra: &[(&str, &str)],
) -> http::Request<http_body_util::Full<bytes::Bytes>> {
    let auth = format!("Bearer {token}");
    let mut headers = vec![
        ("authorization", auth.as_str()),
        ("content-type", "application/json"),
    ];
    headers.extend_from_slice(extra);
    with(
        request(method, "127.0.0.1", path, body.to_string()),
        &headers,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn configuration_writes_are_conditional_dry_run_and_audited() {
    let admin = Admin::start(None, Vec::new());
    let operator = api_token(&admin, "operator");
    let viewer = api_token(&admin, "viewer");

    let reply = client::http1(admin.address, bearer_get("/api/v1/config", &viewer)).await;
    let body = json_body(&reply);
    assert_eq!(body["owners"]["routes"]["app@docker"], "docker");
    assert_eq!(body["owners"]["routes"]["web"], "file");
    assert_eq!(
        body["config"]["services"]["web"]["sticky"]["cookie"]["secret"],
        "***"
    );

    let reply = client::http1(admin.address, bearer_get("/api/v1/config/api", &viewer)).await;
    let etag = reply.header("etag").unwrap().to_owned();
    let candidate =
        serde_json::json!({ "routes": { "a": { "match": "Host(`a.example`)", "service": "a" } } });

    let put = |token: &str, extra: &[(&str, &str)]| {
        bearer_json("PUT", "/api/v1/config/api", token, &candidate, extra)
    };
    assert_eq!(
        client::http1(admin.address, put(&viewer, &[("if-match", &etag)]))
            .await
            .status,
        403
    );
    assert_eq!(
        client::http1(admin.address, put(&operator, &[]))
            .await
            .status,
        428
    );
    let stale = client::http1(admin.address, put(&operator, &[("if-match", "\"g0-old\"")])).await;
    assert_eq!(stale.status, 412);
    assert_eq!(stale.header("etag"), Some(etag.as_str()));
    let applied = client::http1(admin.address, put(&operator, &[("if-match", &etag)])).await;
    assert_eq!(applied.status, 200);
    let next = applied.header("etag").unwrap().to_owned();
    assert_ne!(next, etag);
    let again = client::http1(admin.address, put(&operator, &[("if-match", &etag)])).await;
    assert_eq!(again.status, 412, "the old version cannot be written twice");

    // Merge patch on top, then a rejected one leaves the version as it was.
    let patch = with(
        request(
            "PATCH",
            "127.0.0.1",
            "/api/v1/config/api",
            r#"{"routes":{"a":null,"b":{"match":"Host(`b`)","service":"b"}}}"#,
        ),
        &[
            ("authorization", &format!("Bearer {operator}")),
            ("content-type", "application/merge-patch+json"),
            ("if-match", &next),
        ],
    );
    let patched = client::http1(admin.address, patch).await;
    assert_eq!(patched.status, 200);
    let after_patch = patched.header("etag").unwrap().to_owned();
    let reply = client::http1(admin.address, bearer_get("/api/v1/config/api", &viewer)).await;
    assert!(json_body(&reply)["routes"].get("a").is_none());
    assert!(json_body(&reply)["routes"].get("b").is_some());
    let wrong_type = with(
        request("PATCH", "127.0.0.1", "/api/v1/config/api", "{}"),
        &[
            ("authorization", &format!("Bearer {operator}")),
            ("content-type", "text/plain"),
            ("if-match", &after_patch),
        ],
    );
    assert_eq!(client::http1(admin.address, wrong_type).await.status, 415);
    let reject = serde_json::json!({ "routes": { "reject": {} } });
    let reply = client::http1(
        admin.address,
        bearer_json(
            "PUT",
            "/api/v1/config/api",
            &operator,
            &reject,
            &[("if-match", &after_patch)],
        ),
    )
    .await;
    assert_eq!(reply.status, 422);

    // Dry run with a diff; nothing changes.
    let reply = client::http1(
        admin.address,
        bearer_json("POST", "/api/v1/config/validate", &operator, &reject, &[]),
    )
    .await;
    let body = json_body(&reply);
    assert_eq!(body["valid"], false);
    assert!(
        body["diff"].as_str().unwrap().contains("+    \"reject\""),
        "{body}"
    );
    let bad = serde_json::json!({ "bad": 1 });
    let reply = client::http1(
        admin.address,
        bearer_json("POST", "/api/v1/config/validate", &operator, &bad, &[]),
    )
    .await;
    assert_eq!(reply.status, 422);

    let reply = client::http1(admin.address, bearer_get("/api/v1/config/history", &viewer)).await;
    assert_eq!(json_body(&reply)[0]["generation"], 1);
    let rollback = serde_json::json!({ "id": 1_793_000_000_000_u64 });
    let reply = client::http1(
        admin.address,
        bearer_json(
            "POST",
            "/api/v1/config/rollback",
            &operator,
            &rollback,
            &[("if-match", &after_patch)],
        ),
    )
    .await;
    assert_eq!(reply.status, 200);
    let export = client::http1(
        admin.address,
        bearer_get("/api/v1/config/export", &operator),
    )
    .await;
    assert_eq!(export.status, 403, "exports are for admins");

    let mut stream = std::os::unix::net::UnixStream::connect(admin.socket()).unwrap();
    write!(
        stream,
        "GET /api/v1/audit HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.contains("\"config.apply\""));
    assert!(response.contains("\"config.rollback\""));
    assert!(response.contains("config_after"));
    admin.stop().await;

    let gitops = Admin::start_with(tempfile::tempdir().unwrap(), None, Vec::new(), |s| {
        s.api_writes = false;
    });
    let operator = api_token(&gitops, "operator");
    let reply = client::http1(
        gitops.address,
        bearer_json(
            "PUT",
            "/api/v1/config/api",
            &operator,
            &candidate,
            &[("if-match", &Fake::etag(0))],
        ),
    )
    .await;
    assert_eq!(reply.status, 403, "GitOps mode refuses writes");
    gitops.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resources_show_owners_and_only_api_objects_change() {
    let admin = Admin::start(None, Vec::new());
    let operator = api_token(&admin, "operator");
    let reply = client::http1(admin.address, bearer_get("/api/v1/routes", &operator)).await;
    let routes = json_body(&reply);
    assert!(
        routes
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "app@docker" && r["owner"] == "docker")
    );

    let etag = Fake::etag(0);
    let route = serde_json::json!({ "match": "Host(`one.example`)", "service": "one" });
    let put =
        |path: &str, tag: &str| bearer_json("PUT", path, &operator, &route, &[("if-match", tag)]);
    let reply = client::http1(admin.address, put("/api/v1/routes/app@docker", &etag)).await;
    assert_eq!(reply.status, 403, "Docker owns it");
    let reply = client::http1(admin.address, put("/api/v1/routes/web", &etag)).await;
    assert_eq!(reply.status, 403, "the file owns it");
    let reply = client::http1(admin.address, put("/api/v1/routes/one", &etag)).await;
    assert_eq!(reply.status, 200);
    let next = reply.header("etag").unwrap().to_owned();
    let reply = client::http1(admin.address, bearer_get("/api/v1/config/api", &operator)).await;
    assert_eq!(json_body(&reply)["routes"]["one"]["service"], "one");
    let delete = with(
        request("DELETE", "127.0.0.1", "/api/v1/routes/one@api", ""),
        &[
            ("authorization", &format!("Bearer {operator}")),
            ("if-match", &next),
        ],
    );
    assert_eq!(client::http1(admin.address, delete).await.status, 200);

    let drain = |backend: &str| {
        bearer_json(
            "POST",
            "/api/v1/backends/drain",
            &operator,
            &serde_json::json!({ "service": "web", "backend": backend }),
            &[],
        )
    };
    assert_eq!(
        client::http1(admin.address, drain("10.0.0.1:80"))
            .await
            .status,
        200
    );
    assert_eq!(
        client::http1(admin.address, drain("10.9.9.9:80"))
            .await
            .status,
        404
    );
    let renew = bearer_json(
        "POST",
        "/api/v1/certificates/example.com/renew",
        &operator,
        &serde_json::json!({}),
        &[],
    );
    assert_eq!(client::http1(admin.address, renew).await.status, 202);
    let renew = bearer_json(
        "POST",
        "/api/v1/certificates/nope.example/renew",
        &operator,
        &serde_json::json!({}),
        &[],
    );
    assert_eq!(client::http1(admin.address, renew).await.status, 404);
    admin.stop().await;
}

/// Opens a stream over TCP with a bearer token and returns the socket and the status line.
fn tcp_stream(address: SocketAddr, path: &str, token: &str) -> (std::net::TcpStream, String) {
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
    .unwrap();
    let mut buffer = [0u8; 512];
    let n = stream.read(&mut buffer).unwrap();
    let head = String::from_utf8_lossy(&buffer[..n])
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    (stream, head)
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_are_limited_per_identity_and_end_for_revoked_tokens() {
    let admin = Admin::start(None, Vec::new());
    let viewer = api_token(&admin, "viewer");
    let address = admin.address;
    let token = viewer.clone();
    let (heads, sockets) = tokio::task::spawn_blocking(move || {
        let mut heads = Vec::new();
        let mut sockets = Vec::new();
        for _ in 0..5 {
            let (socket, head) = tcp_stream(address, "/api/v1/events/stream", &token);
            heads.push(head);
            sockets.push(socket);
        }
        (heads, sockets)
    })
    .await
    .unwrap();
    assert!(heads[..4].iter().all(|h| h.contains("200")), "{heads:?}");
    assert!(
        heads[4].contains("429"),
        "the fifth stream is refused: {heads:?}"
    );

    let reply = client::http1(admin.address, request("GET", "127.0.0.1", "/metrics", "")).await;
    assert_eq!(reply.status, 401);
    let metrics = api_token(&admin, "metrics");
    let reply = client::http1(admin.address, bearer_get("/metrics", &metrics)).await;
    let text = String::from_utf8_lossy(&reply.body).into_owned();
    assert!(
        text.contains("rdock_admin_sse_subscribers{stream=\"events\"} 4"),
        "{text}"
    );
    assert!(
        text.contains(
            "rdock_admin_requests_total{endpoint=\"/api/v1/tokens\",status_class=\"2xx\"}"
        ),
        "{text}"
    );
    drop(sockets);

    let id = viewer.split('_').nth(2).unwrap().to_owned();
    let mut stream = std::os::unix::net::UnixStream::connect(admin.socket()).unwrap();
    write!(
        stream,
        "DELETE /api/v1/tokens/{id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let token = viewer.clone();
    let head =
        tokio::task::spawn_blocking(move || tcp_stream(address, "/api/v1/events/stream", &token).1)
            .await
            .unwrap();
    assert!(
        head.contains("204"),
        "a revoked token's EventSource stops reconnecting: {head}"
    );
    admin.stop().await;
}
