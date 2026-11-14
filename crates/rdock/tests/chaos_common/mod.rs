//! Shared by the chaos suite (`chaos_*.rs`, ADR-0033): waiting for states with deadlines, the
//! process's status, and the pass criteria about the data directory and the audit chain.
//!
//! No helper sleeps for a fixed time to let something happen: each polls for the state with a
//! generous deadline and panics with the process log when it does not come.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use rdock_testkit::rdock::Rdock;

pub const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

pub fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Polls `check` every 50 ms until it holds; panics after `limit` with `what` and the log.
/// Returns how long it took.
pub async fn wait_until(
    rdock: &Rdock,
    limit: Duration,
    what: &str,
    mut check: impl FnMut() -> bool,
) -> Duration {
    let start = Instant::now();
    loop {
        if check() {
            return start.elapsed();
        }
        assert!(
            start.elapsed() < limit,
            "{what}: not within {limit:?}\n--- process log ---\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `GET /api/v1/status` as JSON.
pub fn status(rdock: &Rdock) -> Option<serde_json::Value> {
    let (code, body) = rdock.get_admin("/api/v1/status")?;
    (code == 200)
        .then(|| serde_json::from_str(&body).ok())
        .flatten()
}

/// `rdock audit verify` on the data directory; panics with its output unless the chain holds.
pub fn assert_audit_intact(rdock: &Rdock) {
    let out = rdock.command(&["audit", "verify"]);
    assert!(
        out.status.success(),
        "rdock audit verify failed:\n{}{}\n--- process log ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        rdock.log()
    );
}

/// The audit records in the data directory, oldest first.
pub fn audit_records(data_dir: &Path) -> Vec<serde_json::Value> {
    let mut files: Vec<_> = std::fs::read_dir(data_dir.join("audit"))
        .map(|d| d.filter_map(Result::ok).map(|e| e.path()).collect())
        .unwrap_or_default();
    files.sort();
    files
        .iter()
        .flat_map(|f| {
            std::fs::read_to_string(f)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The data directory is consistent: no temporary file is left behind, every stored JSON file
/// parses (history, last-known-good, snapshots, quota counters, ban lists, certificate
/// metadata), and the configuration history is readable through the API.
pub fn assert_data_dir_consistent(rdock: &Rdock) {
    let dir = rdock.data_dir();
    let mut stack = vec![dir.clone()];
    while let Some(at) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&at) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                // The spool holds unlinked files only; the cache and audit are checked apart.
                if name != "spool" {
                    stack.push(path);
                }
                continue;
            }
            assert!(
                !name.ends_with(".tmp") || name.starts_with(".ballast"),
                "a temporary file is left behind: {}\n--- process log ---\n{}",
                path.display(),
                rdock.log()
            );
            if name.ends_with(".json") {
                let text = std::fs::read(&path).unwrap();
                assert!(
                    serde_json::from_slice::<serde_json::Value>(&text).is_ok(),
                    "{} does not parse ({} bytes)",
                    path.display(),
                    text.len()
                );
            }
        }
    }
    let (code, body) = rdock
        .get_admin("/api/v1/config/history")
        .expect("the admin API answers");
    assert_eq!(code, 200, "history: {body}");
}

/// The `ETag` of a response head.
pub fn etag(head: &str) -> String {
    head.lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("etag")
                .then(|| value.trim().to_owned())
        })
        .unwrap()
}

/// Sends a configuration write again while it is answered `429` (the shared budget of five
/// writes a second), after the `Retry-After` it names, at most 30 times.
fn within_budget(mut send: impl FnMut() -> (u16, String)) -> (u16, String) {
    for _ in 0..30 {
        let answer = send();
        if answer.0 != 429 {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(1100));
    }
    send()
}

/// Writes `document` as the API objects (`PUT /api/v1/config/api` with the current version);
/// returns status and body.
pub fn put_api(rdock: &Rdock, document: &serde_json::Value) -> (u16, String) {
    within_budget(|| put_api_once(rdock, document))
}

fn put_api_once(rdock: &Rdock, document: &serde_json::Value) -> (u16, String) {
    let (_, head, _) = rdock
        .admin_send("GET", "/api/v1/config/api", &[], "")
        .unwrap();
    let tag = etag(&head);
    let (status, _, body) = rdock
        .admin_send(
            "PUT",
            "/api/v1/config/api",
            &[("Content-Type", "application/json"), ("If-Match", &tag)],
            &document.to_string(),
        )
        .unwrap();
    (status, body)
}

/// Rolls the API objects back to history entry `id`; returns status and body.
pub fn rollback(rdock: &Rdock, id: u64) -> (u16, String) {
    within_budget(|| rollback_once(rdock, id))
}

fn rollback_once(rdock: &Rdock, id: u64) -> (u16, String) {
    let (_, head, _) = rdock
        .admin_send("GET", "/api/v1/config/api", &[], "")
        .unwrap();
    let tag = etag(&head);
    let (status, _, body) = rdock
        .admin_send(
            "POST",
            "/api/v1/config/rollback",
            &[("Content-Type", "application/json"), ("If-Match", &tag)],
            &serde_json::json!({ "id": id }).to_string(),
        )
        .unwrap();
    (status, body)
}

/// The history entries' ids, newest first.
pub fn history_ids(rdock: &Rdock) -> Vec<u64> {
    let (_, body) = rdock.get_admin("/api/v1/config/history").unwrap();
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    list.as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["id"].as_u64())
        .collect()
}

/// A metric's value in the Prometheus text over the admin API (the sum over label sets that
/// contain `labels`), or 0.
pub fn metric(rdock: &Rdock, name: &str, labels: &str) -> f64 {
    let Some((200, text)) = rdock.get_admin("/metrics") else {
        return 0.0;
    };
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| {
            l.split([' ', '{']).next() == Some(name) && (labels.is_empty() || l.contains(labels))
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

/// An HTTP and an HTTPS port for ACME scenarios.
pub struct Ports {
    pub http: u16,
    pub https: u16,
}

impl Ports {
    pub fn new() -> Self {
        Self {
            http: rdock_testkit::free_port(),
            https: rdock_testkit::free_port(),
        }
    }

    pub fn http(&self) -> SocketAddr {
        addr(self.http)
    }

    pub fn https(&self) -> SocketAddr {
        addr(self.https)
    }
}

/// A configuration with automatic HTTPS from `directory` (trusting `root`) for `names`, all
/// routed to `backend`.
pub fn acme_config(
    directory: &str,
    root: &Path,
    ports: &Ports,
    names: &[&str],
    backend: SocketAddr,
) -> String {
    use std::fmt::Write as _;
    let routes = names
        .iter()
        .enumerate()
        .fold(String::new(), |mut out, (i, n)| {
            let _ = writeln!(out, "  r{i}: {{ match: \"Host(`{n}`)\", service: app }}");
            out
        });
    format!(
        r#"listeners:
  web: {{ address: "127.0.0.1:{http}" }}
  websecure: {{ address: "127.0.0.1:{https}", tls: {{}} }}
acme:
  ca: "{directory}"
  ca_root: "{root}"
  challenges: [http-01]
routes:
{routes}services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        http = ports.http,
        https = ports.https,
        root = root.display(),
    )
}

/// A TLS client trusting `pem`.
pub fn trust(pem: &str) -> std::sync::Arc<rustls::ClientConfig> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    std::sync::Arc::new(config)
}

/// The leaf served for `host` after a verified handshake, if any.
pub async fn served(
    addr: SocketAddr,
    host: &str,
    config: &std::sync::Arc<rustls::ClientConfig>,
) -> Option<Vec<u8>> {
    let stream = rdock_testkit::client::tls_connect(addr, host, config.clone())
        .await
        .ok()?;
    let leaf = stream.get_ref().1.peer_certificates()?.first()?.clone();
    Some(leaf.as_ref().to_vec())
}

/// Waits until `host` serves a verified certificate other than `before`; returns its leaf.
pub async fn issued(
    rdock: &Rdock,
    https: SocketAddr,
    host: &str,
    trust: &std::sync::Arc<rustls::ClientConfig>,
    before: Option<&[u8]>,
    limit: Duration,
) -> Vec<u8> {
    let start = Instant::now();
    loop {
        if let Some(leaf) = served(https, host, trust).await
            && Some(leaf.as_slice()) != before
        {
            return leaf;
        }
        assert!(
            start.elapsed() < limit,
            "{host} got no new certificate within {limit:?}\nstatus: {:?}\n--- process log ---\n{}",
            status(rdock).map(|s| s["certificates"].clone()),
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The automatic certificate's status entry for `host`.
pub fn cert_status(rdock: &Rdock, host: &str) -> serde_json::Value {
    status(rdock)
        .and_then(|s| {
            s["certificates"]
                .as_array()?
                .iter()
                .find(|c| {
                    c["names"]
                        .as_array()
                        .is_some_and(|n| n.iter().any(|x| x == host))
                })
                .cloned()
        })
        .unwrap_or_default()
}

/// Asks for renewal now through the admin API.
pub fn force_renewal(rdock: &Rdock, host: &str) {
    let (code, body) = rdock
        .admin_request("POST", &format!("/api/v1/certificates/{host}/renew"))
        .unwrap();
    assert!((200..300).contains(&code), "renew {host}: {code} {body}");
}

/// Polls `check` every 50 ms for up to `limit`; whether it held. For conditions whose failure
/// message the caller builds itself.
pub async fn wait_for(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    check()
}
