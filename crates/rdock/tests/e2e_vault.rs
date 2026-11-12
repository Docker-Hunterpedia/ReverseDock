//! End-to-end: `${vault:…}` references against a fake Vault/`OpenBao` KV v2 server (W-OBS-02,
//! ADR-0030): the value is used (a JWT HMAC key), a rotation is picked up after a refresh, a
//! failed refresh keeps the old value and reports Vault degraded, a failed first read fails
//! the start, and the value appears in no file under the state directory, no admin answer and
//! no log line. The last test runs against a real `OpenBao` (`#[ignore]`; CI job `openbao`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rdock_testkit::vault::FakeVault;
use serde_json::{Value, json};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

/// Two throw-away HMAC keys (at least 32 bytes, RFC 7518 §3.2); they protect nothing.
const KEY_1: &str = "first-hmac-key-0123456789abcdefghijkl";
const KEY_2: &str = "second-hmac-key-9876543210zyxwvutsrqp";

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn token(key: &str) -> String {
    let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header = json!({ "alg": "HS256", "typ": "JWT" });
    let claims =
        json!({ "iss": "https://idp.test", "aud": "api", "sub": "alice", "exp": now + 300 });
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.as_bytes());
    let tag = ring::hmac::sign(&key, input.as_bytes());
    format!("{input}.{}", b64(tag.as_ref()))
}

async fn status_with(port: u16, key: &str) -> u16 {
    let mut req = get("api.test", "/");
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", token(key)).parse().unwrap(),
    );
    client::http1(addr(port), req).await.status
}

fn config(port: u16, backend: SocketAddr, vault: &str, auth: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
secrets:
  vault:
    address: "{vault}"
    auth: {auth}
    refresh: 1s
    timeout: 500ms
routes:
  api: {{ match: "PathPrefix(`/`)", service: api, middlewares: [auth] }}
middlewares:
  auth:
    type: jwt
    hmac_secret: "${{vault:secret/rdock/jwt#key}}"
    algorithms: [HS256]
    issuer: https://idp.test
    audiences: [api]
services:
  api: {{ backends: [{{ address: "{backend}" }}] }}
"#
    )
}

/// Waits up to `limit` for `check`.
async fn eventually(limit: Duration, mut check: impl AsyncFnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn vault_status(rdock: &Rdock) -> Value {
    let (code, body) = rdock.get_admin("/api/v1/status").unwrap();
    assert_eq!(code, 200, "{body}");
    serde_json::from_str::<Value>(&body).unwrap()["secrets"]["vault"].clone()
}

/// Every file below `dir`, recursively (sockets and unreadable files skipped).
fn files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn assert_nowhere(rdock: &Rdock, secrets: &[&str]) {
    let mut all = Vec::new();
    files(rdock.dir.path(), &mut all);
    assert!(all.len() > 1, "{all:?}");
    for file in &all {
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for secret in secrets {
            assert!(
                !text.contains(secret),
                "{} holds a Vault value",
                file.display()
            );
        }
    }
    for path in [
        "/api/v1/config",
        "/api/v1/config/effective",
        "/api/v1/config/history",
        "/api/v1/status",
        "/api/v1/middlewares",
        "/metrics",
    ] {
        if let Some((_, body)) = rdock.get_admin(path) {
            for secret in secrets {
                assert!(!body.contains(secret), "{path} shows a Vault value");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn values_are_read_rotated_and_kept_when_vault_fails() {
    let vault = FakeVault::start().await;
    vault.put("secret/rdock/jwt", json!({ "key": KEY_1 }));
    let backend = Backend::start("api").await;
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("vault-token");
    std::fs::write(&token_file, vault.root_token()).unwrap();
    let auth = format!("{{ token: \"${{file:{}}}\" }}", token_file.display());
    let rdock = tokio::task::block_in_place(|| {
        Rdock::start(RDOCK, &config(port, backend.addr, vault.url(), &auth))
    });

    assert_eq!(
        status_with(port, KEY_1).await,
        200,
        "the value from Vault is the key"
    );
    assert_eq!(status_with(port, KEY_2).await, 401);
    let status = vault_status(&rdock);
    assert_eq!(status["state"], "ok", "{status}");
    assert_eq!(status["references"], 1);
    let reads = vault.lines();
    assert!(
        reads.iter().any(|l| l == "GET /v1/secret/data/rdock/jwt"),
        "{reads:?}"
    );
    let sent = vault.requests();
    assert!(
        sent.iter()
            .all(|r| r.header("x-vault-token") == Some(vault.root_token()))
    );

    // Rotation: picked up after a refresh, without touching the file.
    vault.put("secret/rdock/jwt", json!({ "key": KEY_2 }));
    assert!(
        eventually(Duration::from_secs(10), async || status_with(port, KEY_2)
            .await
            == 200)
        .await,
        "the rotated key is used after a refresh"
    );
    assert_eq!(status_with(port, KEY_1).await, 401);

    // A failing Vault: the last value stays in use and Vault is degraded.
    vault.set_failing(true);
    assert!(
        eventually(
            Duration::from_secs(10),
            async || vault_status(&rdock)["state"] == "degraded"
        )
        .await,
        "a failed refresh marks Vault degraded"
    );
    assert_eq!(
        status_with(port, KEY_2).await,
        200,
        "the last value stays in use"
    );
    let error = vault_status(&rdock)["error"].as_str().unwrap().to_owned();
    assert!(
        error.contains("503") && error.contains("secret/rdock/jwt#key"),
        "{error}"
    );
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    let failures = metrics
        .lines()
        .find(|l| l.starts_with("rdock_vault_refresh_failures_total "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    assert!(failures >= 1.0, "{metrics}");
    vault.set_failing(false);
    assert!(
        eventually(
            Duration::from_secs(10),
            async || vault_status(&rdock)["state"] == "ok"
        )
        .await,
        "Vault recovers"
    );

    let log = rdock.log();
    assert!(log.contains("Vault is degraded"), "{log}");
    for secret in [KEY_1, KEY_2, vault.root_token()] {
        assert!(!log.contains(secret), "the log holds a secret");
        assert!(
            !rdock
                .access_log()
                .iter()
                .any(|r| r.to_string().contains(secret))
        );
    }
    assert_nowhere(&rdock, &[KEY_1, KEY_2, vault.root_token()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kubernetes_login_is_renewed_before_the_lease_ends() {
    let vault = FakeVault::start().await;
    vault.put("secret/rdock/jwt", json!({ "key": KEY_1 }));
    vault.kubernetes_role("kubernetes", "rdock", "service-account-jwt");
    vault.set_lease(3);
    let backend = Backend::start("api").await;
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let sa = dir.path().join("token");
    std::fs::write(&sa, "service-account-jwt\n").unwrap();
    let auth = format!(
        "{{ kubernetes: {{ role: rdock, token_file: \"{}\" }} }}",
        sa.display()
    );
    let rdock = tokio::task::block_in_place(|| {
        Rdock::start(RDOCK, &config(port, backend.addr, vault.url(), &auth))
    });
    assert_eq!(status_with(port, KEY_1).await, 200);
    assert_eq!(vault.logins(), 1);
    let login = vault
        .requests()
        .into_iter()
        .find(|r| r.path == "/v1/auth/kubernetes/login")
        .unwrap();
    assert_eq!(
        login.json(),
        json!({ "role": "rdock", "jwt": "service-account-jwt" })
    );
    // Two thirds of a 3 s lease: a new login every 2 s, before the token runs out.
    assert!(
        eventually(Duration::from_secs(10), async || vault.logins() >= 3).await,
        "logins: {}",
        vault.logins()
    );
    // A revoked token (403) leads to one new login, not to a degraded Vault.
    vault.set_lease(0);
    vault.revoke_logins();
    let before = vault.logins();
    assert!(eventually(Duration::from_secs(10), async || vault.logins() > before).await);
    assert!(
        eventually(
            Duration::from_secs(5),
            async || vault_status(&rdock)["state"] == "ok"
        )
        .await
    );
    assert_nowhere(&rdock, &[KEY_1, "service-account-jwt"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_first_read_fails_the_start_and_validation() {
    let vault = FakeVault::start().await;
    vault.put("secret/rdock/other", json!({ "key": KEY_1 }));
    let backend = Backend::start("api").await;
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("vault-token");
    std::fs::write(&token_file, vault.root_token()).unwrap();
    let auth = format!("{{ token: \"${{file:{}}}\" }}", token_file.display());
    let text = config(port, backend.addr, vault.url(), &auth);
    // The secret does not exist: the start fails like a missing `${file:…}`.
    let started = tokio::task::block_in_place(|| Rdock::try_start(RDOCK, &text));
    let Err(log) = started else {
        panic!("rdock started without its Vault value");
    };
    assert!(
        log.contains("${vault:secret/rdock/jwt#key}") && log.contains("404"),
        "{log}"
    );
    assert!(!log.contains(vault.root_token()));

    let file = dir.path().join("rdock.yaml");
    std::fs::write(&file, &text).unwrap();
    let out = tokio::task::block_in_place(|| {
        std::process::Command::new(RDOCK)
            .args(["validate", "--format", "json"])
            .arg(&file)
            .output()
            .unwrap()
    });
    assert!(!out.status.success());
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        report.contains("cannot be read") && report.contains("secret/rdock/jwt"),
        "{report}"
    );
    vault.put("secret/rdock/jwt", json!({ "key": KEY_1 }));
    let out = tokio::task::block_in_place(|| {
        std::process::Command::new(RDOCK)
            .args(["validate"])
            .arg(&file)
            .output()
            .unwrap()
    });
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains(KEY_1));

    // `${vault:…}` outside a secret field is refused: its value would enter the configuration.
    let header = text.replace(
        "services:",
        "  tag: { type: headers, request: { set: { x-key: \"${vault:secret/rdock/jwt#key}\" } } }\nservices:",
    );
    std::fs::write(&file, header).unwrap();
    let out = std::process::Command::new(RDOCK)
        .args(["validate"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("accepted only in secret fields"));
}

/// Against a real `OpenBao` dev server: `RDOCK_OPENBAO_ADDR` and `RDOCK_OPENBAO_TOKEN` (a
/// throw-away root token), KV v2 at `secret/`. Run by the CI job `openbao`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs an OpenBao dev server (CI job `openbao`)"]
async fn openbao_values_are_read_and_rotated() {
    let address = std::env::var("RDOCK_OPENBAO_ADDR").expect("RDOCK_OPENBAO_ADDR");
    let root = std::env::var("RDOCK_OPENBAO_TOKEN").expect("RDOCK_OPENBAO_TOKEN");
    let host: SocketAddr = address
        .trim_start_matches("http://")
        .parse()
        .expect("an http://<ip>:<port> address");
    let write = async |key: &str| {
        let body = json!({ "data": { "key": key } }).to_string();
        let mut req = client::request("POST", &host.to_string(), "/v1/secret/data/rdock/jwt", body);
        req.headers_mut()
            .insert("x-vault-token", root.parse().unwrap());
        req.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        let reply = client::http1(host, req).await;
        assert!(
            reply.status == 200 || reply.status == 204,
            "OpenBao answered {}",
            reply.status
        );
    };
    write(KEY_1).await;
    let backend = Backend::start("api").await;
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("vault-token");
    std::fs::write(&token_file, &root).unwrap();
    let auth = format!("{{ token: \"${{file:{}}}\" }}", token_file.display());
    let rdock = tokio::task::block_in_place(|| {
        Rdock::start(RDOCK, &config(port, backend.addr, &address, &auth))
    });
    assert_eq!(status_with(port, KEY_1).await, 200);
    write(KEY_2).await;
    assert!(
        eventually(Duration::from_secs(15), async || status_with(port, KEY_2)
            .await
            == 200)
        .await
    );
    assert_nowhere(&rdock, &[KEY_1, KEY_2, &root]);
}
