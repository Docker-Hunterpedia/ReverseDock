//! Tenant-scoped callers (H-SEC-07, ADR-0031): the authorization matrix role × tenant ×
//! operation fails closed, every refusal is audited, and the scoped operations show and
//! change only the tenant's own objects.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rdock_admin::{ApiWrite, Control, Running, Settings};
use rdock_model::settings::{AdminAudit, AdminPasswords, AdminSessions, AdminTokens, MfaPolicy};
use rdock_model::tenant::{Tenant, Tenants};
use rdock_testkit::client::{self, request};
use rdock_testkit::free_port;
use serde_json::{Value, json};
use tokio::sync::watch;

struct Fake {
    api: Mutex<(Value, u64)>,
    written: Mutex<Option<Value>>,
    /// Tenants taken out of the configuration.
    removed: Mutex<Vec<String>>,
}

impl Fake {
    fn new() -> Self {
        Self {
            api: Mutex::new((
                json!({
                    "routes": {
                        "acme-web": { "match": "Host(`acme.example.com`)", "service": "acme-svc" },
                        "globex-web": { "match": "Host(`globex.example.com`)", "service": "globex-svc" }
                    },
                    "services": {
                        "acme-svc": { "backends": [{ "address": "10.0.0.1:80" }] },
                        "globex-svc": { "backends": [{ "address": "10.0.0.2:80" }] }
                    },
                    "middlewares": {},
                    "consumers": { "ann": { "groups": ["gold"] } }
                }),
                1,
            )),
            written: Mutex::new(None),
            removed: Mutex::new(Vec::new()),
        }
    }

    fn etag(generation: u64) -> String {
        format!("\"g{generation}-0011223344556677\"")
    }
}

fn merged(api: &Value) -> Value {
    let mut out = json!({ "listeners": { "web": {} }, "certificates": { "main": {} } });
    for section in ["routes", "services", "middlewares"] {
        let mut map = serde_json::Map::new();
        for (name, object) in api[section].as_object().unwrap() {
            map.insert(format!("{name}@api"), object.clone());
        }
        map.insert("file-object".into(), json!({}));
        out[section] = Value::Object(map);
    }
    out
}

#[async_trait]
impl Control for Fake {
    fn ready(&self) -> bool {
        true
    }
    fn metrics(&self) -> Option<String> {
        Some("rdock_up 1\n".into())
    }
    async fn status(&self) -> Value {
        json!({ "ready": true })
    }
    async fn reload(&self) -> (bool, Value) {
        (true, json!({ "result": "applied" }))
    }
    async fn effective_config(&self) -> Value {
        merged(&self.api.lock().unwrap().0)
    }
    async fn api_config(&self) -> (Value, String) {
        let api = self.api.lock().unwrap();
        (api.0.clone(), Self::etag(api.1))
    }
    async fn dry_run(&self, candidate: Value) -> Result<(bool, Value), String> {
        let rejected = candidate["routes"].get("acme-reject").is_some();
        Ok((
            !rejected,
            json!([
                { "path": "routes[\"acme-reject@api\"].match", "severity": "error", "message": "not inside" },
                { "path": "routes[\"globex-web@api\"].service", "severity": "warning", "message": "globex detail" }
            ]),
        ))
    }
    async fn write_api(&self, candidate: Value, if_match: String) -> ApiWrite {
        let mut api = self.api.lock().unwrap();
        if if_match != Self::etag(api.1) {
            return ApiWrite::Stale {
                etag: Self::etag(api.1),
            };
        }
        if candidate["routes"].get("acme-reject").is_some() {
            return ApiWrite::Rejected {
                report: json!({
                    "result": "rejected", "generation": api.1, "origin": { "path": "/etc/rdock/rdock.yaml" },
                    "error": "the API configuration has errors",
                    "diagnostics": [
                        { "path": "routes[\"acme-reject@api\"].match", "severity": "error", "message": "not inside the host claims of tenant `acme`" },
                        { "path": "routes[\"globex-web@api\"].service", "severity": "warning", "message": "globex detail" }
                    ]
                }),
            };
        }
        *self.written.lock().unwrap() = Some(candidate.clone());
        api.0 = candidate;
        api.1 += 1;
        ApiWrite::Applied {
            report: json!({ "result": "applied", "generation": api.1, "diagnostics": [] }),
            etag: Self::etag(api.1),
        }
    }
    async fn history(&self) -> Value {
        json!([])
    }
    async fn history_api(&self, _id: u64) -> Option<Value> {
        None
    }
    async fn backends(&self) -> Value {
        json!([
            { "service": "acme-svc@api", "backends": [{ "address": "10.0.0.1:80" }] },
            { "service": "globex-svc@api", "backends": [{ "address": "10.0.0.2:80" }] }
        ])
    }
    async fn set_drained(&self, _service: String, _backend: String, _drained: bool) -> bool {
        true
    }
    async fn renew_certificate(&self, _name: String) -> bool {
        true
    }
    async fn caches(&self) -> Value {
        json!([])
    }
    async fn purge_cache(
        &self,
        _store: String,
        _selector: rdock_admin::CachePurge,
    ) -> rdock_admin::PurgeOutcome {
        rdock_admin::PurgeOutcome::NoStore
    }
    async fn explain(&self, _request: Value) -> Result<Value, String> {
        Ok(json!({}))
    }
    async fn metrics_summary(&self, _window_seconds: u64) -> Value {
        json!({ "total": { "requests": 9 }, "routes": { "acme-web@api": {}, "globex-web@api": {} }, "services": { "globex-svc@api": {} } })
    }
    async fn quotas(&self, _consumer: Option<String>) -> Value {
        json!({ "quotas": [
            { "middleware": "acme-q@api", "keys": [] },
            { "middleware": "globex-q@api", "keys": [] }
        ] })
    }
    async fn bans(&self) -> Value {
        json!({ "bans": [
            { "middleware": "acme-ab@api", "key": "ip:192.0.2.1" },
            { "middleware": "globex-ab@api", "key": "ip:192.0.2.2" }
        ] })
    }
    async fn unban(&self, _key: String, _middleware: Option<String>) -> usize {
        1
    }
    async fn tenants(&self) -> Tenants {
        let mut tenants = Tenants::new();
        tenants.insert(
            "acme".into(),
            Tenant {
                hosts: vec!["acme.example.com".into()],
                ..Tenant::default()
            },
        );
        tenants.insert(
            "globex".into(),
            Tenant {
                hosts: vec!["globex.example.com".into()],
                ..Tenant::default()
            },
        );
        for gone in self.removed.lock().unwrap().iter() {
            tenants.remove(gone);
        }
        tenants
    }
}

struct Admin {
    address: SocketAddr,
    dir: tempfile::TempDir,
    stop: watch::Sender<bool>,
    running: Option<Running>,
    fake: Arc<Fake>,
}

impl Admin {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let address: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let (stop, stop_rx) = watch::channel(false);
        let settings = Settings {
            address,
            tls: None,
            socket: Some(dir.path().join("admin.sock")),
            allowed_hosts: Vec::new(),
            threads: 1,
            state_dir: dir.path().join("admin"),
            passwords: AdminPasswords::default(),
            sessions: AdminSessions::default(),
            mfa: MfaPolicy::default(),
            dashboard: false,
            tokens: AdminTokens::default(),
            metrics_unauthenticated_on_loopback: false,
            trust_forwarded_on_loopback: false,
            audit_dir: dir.path().join("audit"),
            audit: AdminAudit::default(),
            api_writes: true,
            feeds: None,
        };
        let fake = Arc::new(Fake::new());
        let running = rdock_admin::start(settings, fake.clone(), stop_rx).unwrap();
        Self {
            address,
            dir,
            stop,
            running: Some(running),
            fake,
        }
    }

    fn socket(&self, method: &str, path: &str, body: &Value) -> (u16, Value) {
        let body = body.to_string();
        let mut stream =
            std::os::unix::net::UnixStream::connect(self.dir.path().join("admin.sock")).unwrap();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap_or(Value::Null))
    }

    fn token(&self, role: &str, tenant: Option<&str>) -> String {
        let mut body = json!({ "name": format!("{role} {tenant:?}"), "role": role });
        if let Some(t) = tenant {
            body["tenant"] = json!(t);
        }
        let (status, json) = self.socket("POST", "/api/v1/tokens", &body);
        assert_eq!(status, 201, "{json}");
        json["token"].as_str().unwrap().to_owned()
    }

    async fn call(
        &self,
        token: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> client::Reply {
        let mut req = request(method, "127.0.0.1", path, body.to_owned());
        let bearer = format!("Bearer {token}");
        req.headers_mut()
            .insert("authorization", bearer.parse().unwrap());
        req.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        for (name, value) in headers {
            req.headers_mut().insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        client::http1(self.address, req).await
    }

    async fn stop(mut self) {
        self.stop.send(true).unwrap();
        self.running.take().unwrap().stopped().await;
    }
}

/// The operations a scoped caller may reach (its handler limits them to the tenant), plus
/// those that identify no caller or act on the caller's own session. Every other documented
/// operation must be refused: adding an operation to the server without classifying it, or
/// classifying it as allowed without listing it here, fails this test.
const REACHABLE: &[(&str, &str)] = &[
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("GET", "/api/openapi.json"),
    ("GET", "/api/v1/setup"),
    ("POST", "/api/v1/setup"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/logout"),
    ("GET", "/api/v1/auth/session"),
    ("GET", "/api/v1/auth/mfa"),
    ("POST", "/api/v1/auth/mfa"),
    ("POST", "/api/v1/auth/password"),
    ("POST", "/api/v1/auth/reauth"),
    ("POST", "/api/v1/auth/recovery-codes"),
    ("GET", "/api/v1/auth/sessions"),
    ("DELETE", "/api/v1/auth/sessions/{id}"),
    ("POST", "/api/v1/auth/totp"),
    ("DELETE", "/api/v1/auth/totp"),
    ("POST", "/api/v1/auth/totp/confirm"),
    ("GET", "/api/v1/tokens"),
    ("POST", "/api/v1/tokens"),
    ("DELETE", "/api/v1/tokens/{id}"),
    ("GET", "/api/v1/audit"),
    ("GET", "/api/v1/config"),
    ("GET", "/api/v1/config/api"),
    ("PUT", "/api/v1/config/api"),
    ("PATCH", "/api/v1/config/api"),
    ("POST", "/api/v1/config/validate"),
    ("GET", "/api/v1/backends"),
    ("POST", "/api/v1/backends/drain"),
    ("POST", "/api/v1/backends/undrain"),
    ("GET", "/api/v1/metrics/summary"),
    ("GET", "/api/v1/quota"),
    ("GET", "/api/v1/quota/{consumer}"),
    ("DELETE", "/api/v1/quota/{consumer}"),
    ("GET", "/api/v1/abuse/bans"),
    ("DELETE", "/api/v1/abuse/bans/{key}"),
    ("GET", "/api/v1/{kind}"),
    ("GET", "/api/v1/{kind}/{name}"),
    ("PUT", "/api/v1/{kind}/{name}"),
    ("DELETE", "/api/v1/{kind}/{name}"),
];

fn concrete(template: &str) -> String {
    template
        .replace("{kind}", "routes")
        .replace("{name}", "globex-web")
        .replace("{id}", "x")
        .replace("{key}", "ip:192.0.2.2")
        .replace("{consumer}", "ann")
        .replace("{store}", "mem")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_matrix_of_role_tenant_and_operation_fails_closed() {
    let admin = Admin::start();
    let document: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schema/openapi.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let mut operations = Vec::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            operations.push((method.to_ascii_uppercase(), path.clone()));
        }
    }
    let mut refused = 0;
    for role in ["viewer", "operator", "admin"] {
        let scoped = admin.token(role, Some("acme"));
        let unscoped = admin.token(role, None);
        for (method, template) in &operations {
            let path = concrete(template);
            let reachable = REACHABLE.iter().any(|(m, t)| m == method && t == template);
            let reply = admin.call(&scoped, method, &path, &[], "{}").await;
            if reachable {
                assert!(
                    !reply
                        .text()
                        .contains("tenant-scoped callers cannot do this")
                        || template.contains("{name}")
                        || template.contains("{consumer}")
                        || template.contains("{key}")
                        || template.contains("/backends/"),
                    "{role}: {method} {template} is reachable but was refused: {}",
                    reply.text()
                );
            } else {
                assert_eq!(
                    reply.status,
                    403,
                    "{role}: {method} {template} must be refused for a scoped caller: {}",
                    reply.text()
                );
                refused += 1;
            }
            // Unscoped callers are never refused for a tenant reason (streams stay open for
            // them, so they are left out here).
            if template.ends_with("/stream") {
                continue;
            }
            let reply = admin.call(&unscoped, method, &path, &[], "{}").await;
            assert!(
                !reply.text().contains("tenant-scoped callers cannot"),
                "{role}: {method} {template} unscoped: {}",
                reply.text()
            );
        }
    }
    assert!(refused > 40, "{refused}");
    // Every refusal was audited with the tenant.
    let (status, records) = admin.socket("GET", "/api/v1/audit?limit=1000", &Value::Null);
    assert_eq!(status, 200);
    let denied = records
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["result"] == "denied"
                && r["tenant"] == "acme"
                && r["reason"]
                    .as_str()
                    .is_some_and(|t| t.starts_with("outside the caller's tenant"))
        })
        .count();
    assert!(denied >= refused, "{denied} audited of {refused}");
    admin.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_reads_and_writes_only_its_own_objects() {
    let admin = Admin::start();
    let acme = admin.token("admin", Some("acme"));

    // Reads: the tenant's objects, nothing of globex, no consumers, no listeners.
    let reply = admin
        .call(&acme, "GET", "/api/v1/config/api", &[], "")
        .await;
    assert_eq!(reply.status, 200);
    let tag = reply.header("etag").unwrap().to_owned();
    assert!(tag.starts_with("\"t-"), "{tag}");
    let text = reply.text();
    assert!(
        text.contains("acme-web") && !text.contains("globex") && !text.contains("consumers"),
        "{text}"
    );
    for path in [
        "/api/v1/config",
        "/api/v1/routes",
        "/api/v1/services",
        "/api/v1/backends",
        "/api/v1/metrics/summary",
        "/api/v1/quota",
        "/api/v1/abuse/bans",
    ] {
        let reply = admin.call(&acme, "GET", path, &[], "").await;
        assert_eq!(reply.status, 200, "{path}");
        let text = reply.text();
        assert!(
            !text.contains("globex")
                && !text.contains("file-object")
                && !text.contains("listeners"),
            "{path}: {text}"
        );
    }
    let summary = admin
        .call(&acme, "GET", "/api/v1/metrics/summary", &[], "")
        .await
        .json();
    assert!(summary["total"].is_null());
    let reply = admin
        .call(&acme, "GET", "/api/v1/routes/acme-web", &[], "")
        .await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    for path in [
        "/api/v1/routes/globex-web@api",
        "/api/v1/routes/file-object",
        "/api/v1/routes/globex-missing",
    ] {
        let reply = admin.call(&acme, "GET", path, &[], "").await;
        assert_eq!(
            reply.status, 403,
            "{path}: refused whether or not it exists"
        );
    }

    // Writes: a foreign name or a consumer is refused (403); the tenant's objects are written
    // and globex's are kept.
    let if_match = [("if-match", tag.as_str())];
    for body in [
        json!({ "routes": { "globex-web": { "match": "Host(`acme.example.com`)", "service": "acme-svc" } } }),
        json!({ "consumers": { "eve": { "groups": [] } } }),
    ] {
        let reply = admin
            .call(
                &acme,
                "PUT",
                "/api/v1/config/api",
                &if_match,
                &body.to_string(),
            )
            .await;
        assert_eq!(reply.status, 403, "{}", reply.text());
    }
    let mine = json!({
        "routes": { "acme-shop": { "match": "Host(`acme.example.com`)", "service": "acme-svc" } },
        "services": { "acme-svc": { "backends": [{ "address": "10.0.0.1:80" }] } }
    });
    let reply = admin
        .call(
            &acme,
            "PUT",
            "/api/v1/config/api",
            &[("if-match", "\"g1-0011223344556677\"")],
            &mine.to_string(),
        )
        .await;
    assert_eq!(reply.status, 412, "the global tag is not the tenant's");
    let reply = admin
        .call(
            &acme,
            "PUT",
            "/api/v1/config/api",
            &if_match,
            &mine.to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let written = admin.fake.written.lock().unwrap().clone().unwrap();
    assert!(
        written["routes"].get("globex-web").is_some(),
        "globex kept: {written}"
    );
    assert!(
        written["routes"].get("acme-web").is_none(),
        "acme's part replaced"
    );
    assert!(written["consumers"].get("ann").is_some(), "consumers kept");
    let tag = reply.header("etag").unwrap().to_owned();

    // A write the validation refuses: 422, audited, and only acme's diagnostics shown.
    let rejected = json!({ "routes": { "acme-reject": { "match": "PathPrefix(`/`)", "service": "acme-svc" } } });
    let reply = admin
        .call(
            &acme,
            "PUT",
            "/api/v1/config/api",
            &[("if-match", tag.as_str())],
            &rejected.to_string(),
        )
        .await;
    assert_eq!(reply.status, 422);
    let text = reply.text();
    assert!(
        text.contains("not inside") && !text.contains("globex") && !text.contains("rdock.yaml"),
        "{text}"
    );
    let reply = admin
        .call(
            &acme,
            "POST",
            "/api/v1/config/validate",
            &[],
            &rejected.to_string(),
        )
        .await;
    let text = reply.text();
    assert_eq!(reply.status, 200, "{text}");
    assert!(
        !text.contains("globex"),
        "the dry run and its diff stay inside: {text}"
    );

    // Object endpoints, drains, quota resets and unbans outside the tenant are refused.
    let reply = admin
        .call(
            &acme,
            "PUT",
            "/api/v1/routes/globex-web",
            &[("if-match", tag.as_str())],
            "{}",
        )
        .await;
    assert_eq!(reply.status, 403);
    let reply = admin
        .call(
            &acme,
            "POST",
            "/api/v1/backends/drain",
            &[],
            &json!({ "service": "globex-svc@api", "backend": "10.0.0.2:80" }).to_string(),
        )
        .await;
    assert_eq!(reply.status, 403);
    let reply = admin
        .call(
            &acme,
            "POST",
            "/api/v1/backends/drain",
            &[],
            &json!({ "service": "acme-svc@api", "backend": "10.0.0.1:80" }).to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let reply = admin
        .call(&acme, "DELETE", "/api/v1/quota/ann", &[], "")
        .await;
    assert_eq!(reply.status, 403, "a reset across every quota is refused");
    let reply = admin
        .call(
            &acme,
            "DELETE",
            "/api/v1/quota/ann?middleware=acme-q@api",
            &[],
            "",
        )
        .await;
    assert_eq!(reply.status, 200);
    let reply = admin
        .call(
            &acme,
            "DELETE",
            "/api/v1/abuse/bans/ip:192.0.2.2?middleware=globex-ab@api",
            &[],
            "",
        )
        .await;
    assert_eq!(reply.status, 403);

    // Tokens: always the creator's tenant; the audit log shows the tenant's records only.
    let body = json!({ "name": "other", "role": "viewer", "tenant": "globex" });
    let reply = admin
        .call(&acme, "POST", "/api/v1/tokens", &[], &body.to_string())
        .await;
    assert_eq!(
        reply.status, 403,
        "people and the socket create tokens; a token cannot"
    );
    let (status, _) = admin.socket(
        "POST",
        "/api/v1/tokens",
        &json!({ "name": "x", "role": "viewer", "tenant": "ghost" }),
    );
    assert_eq!(status, 422, "an unknown tenant");
    let reply = admin.call(&acme, "GET", "/api/v1/audit", &[], "").await;
    assert_eq!(reply.status, 200);
    let records = reply.json();
    assert_ne!(records.as_array().unwrap().len(), 0);
    assert!(
        records
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["tenant"] == "acme"),
        "{records}"
    );
    let reply = admin.call(&acme, "GET", "/api/v1/tokens", &[], "").await;
    assert!(
        reply
            .json()
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["tenant"] == "acme")
    );
    admin.stop().await;
}

/// Logs `name` in with a password; returns the session cookie and its CSRF token.
async fn login(admin: &Admin, name: &str, password: &str) -> Option<(String, String)> {
    let mut req = request(
        "POST",
        "127.0.0.1",
        "/api/v1/auth/login",
        json!({ "name": name, "password": password }).to_string(),
    );
    req.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    let reply = client::http1(admin.address, req).await;
    if reply.status != 200 {
        return None;
    }
    let cookie = reply.header("set-cookie")?.split(';').next()?.to_owned();
    let csrf = reply.json()["csrf_token"].as_str()?.to_owned();
    Some((cookie, csrf))
}

async fn session_call(
    admin: &Admin,
    (cookie, csrf): &(String, String),
    method: &str,
    path: &str,
    body: &Value,
) -> client::Reply {
    let mut req = request(method, "127.0.0.1", path, body.to_string());
    for (name, value) in [
        ("cookie", cookie.as_str()),
        ("x-csrf-token", csrf.as_str()),
        ("content-type", "application/json"),
    ] {
        req.headers_mut().insert(name, value.parse().unwrap());
    }
    client::http1(admin.address, req).await
}

/// L5 of the tenants review: a scoped *session* (not a token, which cannot mint tokens at
/// all) asking for a token of another tenant is refused and audited. L3: removing a tenant
/// retires its users and tokens for good; adding the name back does not revive them.
#[tokio::test(flavor = "multi_thread")]
async fn scoped_sessions_mint_only_their_tenants_tokens_and_removed_tenants_retire_principals() {
    const PASSWORD: &str = "correct horse battery staple";
    let admin = Admin::start();
    let (status, body) = admin.socket(
        "POST",
        "/api/v1/users",
        &json!({ "name": "acme-ops", "role": "operator", "password": PASSWORD, "tenant": "acme" }),
    );
    assert_eq!(status, 201, "{body}");
    let session = login(&admin, "acme-ops", PASSWORD).await.expect("logs in");
    let reply = session_call(
        &admin,
        &session,
        "POST",
        "/api/v1/tokens",
        &json!({ "name": "steal", "role": "viewer", "tenant": "globex" }),
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.text());
    let (_, records) = admin.socket("GET", "/api/v1/audit?limit=1000", &Value::Null);
    assert!(
        records
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["result"] == "denied"
                && r["tenant"] == "acme"
                && r["resource"] == "/api/v1/tokens"),
        "{records}"
    );
    let reply = session_call(
        &admin,
        &session,
        "POST",
        "/api/v1/tokens",
        &json!({ "name": "mine", "role": "viewer" }),
    )
    .await;
    assert_eq!(reply.status, 201, "{}", reply.text());
    let created = reply.json();
    assert_eq!(created["tenant"], "acme");
    let token = created["token"].as_str().unwrap().to_owned();
    let reply = admin
        .call(&token, "GET", "/api/v1/config/api", &[], "")
        .await;
    assert_eq!(reply.status, 200);

    // The administrator removes `acme`; the next scoped request notices.
    admin.fake.removed.lock().unwrap().push("acme".into());
    let globex = admin.token("operator", Some("globex"));
    let reply = admin
        .call(&globex, "GET", "/api/v1/config/api", &[], "")
        .await;
    assert_eq!(reply.status, 200);
    // `acme` comes back, perhaps for someone else: the old principals stay retired.
    admin.fake.removed.lock().unwrap().clear();
    let reply = admin
        .call(&token, "GET", "/api/v1/config/api", &[], "")
        .await;
    assert_eq!(reply.status, 401, "the token was revoked: {}", reply.text());
    let reply = session_call(&admin, &session, "GET", "/api/v1/config/api", &Value::Null).await;
    assert_ne!(reply.status, 200, "the session ended");
    assert!(
        login(&admin, "acme-ops", PASSWORD).await.is_none(),
        "the user is disabled"
    );
    let (_, users) = admin.socket("GET", "/api/v1/users", &Value::Null);
    let user = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "acme-ops")
        .unwrap();
    assert_eq!(user["disabled"], true);
    assert_eq!(user["tenant"], "acme");
    admin.stop().await;
}
