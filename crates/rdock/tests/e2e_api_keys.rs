//! End-to-end: consumers and API keys (F-GW-01, ADR-0030). Keys from the configuration file,
//! a keys file and the admin API authenticate requests and set the consumer; a key revoked
//! through the API stops working with the configuration that applies the revocation; and no
//! clear-text key is ever written anywhere rdock writes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::path::Path;

use http_body_util::Full;
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use serde_json::{Value, json};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn etag(head: &str) -> String {
    head.lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("etag")
                .then(|| value.trim().to_owned())
        })
        .unwrap()
}

fn with_key(header: &str, value: &str) -> http::Request<Full<bytes::Bytes>> {
    let mut req = get("api.test", "/");
    req.headers_mut().insert(
        http::HeaderName::try_from(header).unwrap(),
        value.parse().unwrap(),
    );
    req
}

/// A key minted by the same code rdock uses, and its `id` and `hash`.
fn mint() -> (String, String, String) {
    let made = rdock_credentials::API_KEY.generate().unwrap();
    (made.value.into_inner(), made.id, made.secret_sha256)
}

/// Every file under `dir`, as text where it is text.
fn all_files(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            all_files(&path, out);
        } else if let Ok(bytes) = std::fs::read(&path) {
            out.push((
                path.display().to_string(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
}

/// Whether `text` contains the secret part of `key` (or the whole key).
fn leaks(text: &str, key: &str) -> bool {
    let (_, secret) = rdock_credentials::API_KEY.parse(key).unwrap();
    text.contains(key) || text.contains(secret)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_authenticate_revoke_within_one_reload_and_never_leak() {
    let backend = Backend::start("api").await;
    let port = free_port();
    let (inline_key, inline_id, inline_hash) = mint();
    let (file_key, file_id, file_hash) = mint();
    let (expired_key, expired_id, expired_hash) = mint();
    let dir = tempfile::tempdir().unwrap();
    let keys_file = dir.path().join("partner.keys");
    std::fs::write(
        &keys_file,
        format!("# partner keys\n{file_id}:{file_hash}\n{expired_id}:{expired_hash}:2020-01-01T00:00:00Z\n"),
    )
    .unwrap();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
consumers:
  acme:
    groups: [gold]
    keys: [{{ id: {inline_id}, hash: "{inline_hash}", note: CI }}]
  partner:
    keys_file: "{keys}"
routes:
  api: {{ match: "Host(`api.test`)", service: api, middlewares: [keys] }}
  gold: {{ match: "Host(`gold.test`)", service: api, middlewares: [gold] }}
middlewares:
  keys: {{ type: api_key }}
  gold: {{ type: api_key, groups: [gold] }}
services:
  api: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        keys = keys_file.display(),
        backend = backend.addr,
    );
    let rdock = Rdock::start(RDOCK, &config);

    // Inline key, by `Authorization: Bearer`; the key does not reach the backend.
    let ok = client::http1(
        addr(port),
        with_key("authorization", &format!("Bearer {inline_key}")),
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    let headers = &ok.json()["headers"];
    assert!(headers["authorization"].is_null(), "{headers}");
    assert_eq!(headers["x-consumer-name"][0], "acme");
    assert_eq!(headers["x-consumer-groups"][0], "gold");
    assert_eq!(headers["x-credential-id"][0], inline_id.as_str());
    // Keys-file key, by `X-API-Key`.
    assert_eq!(
        client::http1(addr(port), with_key("x-api-key", &file_key))
            .await
            .status,
        200
    );
    // Expired, unknown, malformed.
    assert_eq!(
        client::http1(addr(port), with_key("x-api-key", &expired_key))
            .await
            .status,
        401
    );
    let (stranger, _, _) = mint();
    assert_eq!(
        client::http1(addr(port), with_key("x-api-key", &stranger))
            .await
            .status,
        401
    );
    let missing = client::http1(addr(port), get("api.test", "/")).await;
    assert_eq!(missing.status, 401);
    assert!(
        missing
            .header("www-authenticate")
            .unwrap()
            .starts_with("Bearer realm=")
    );
    // Groups.
    assert_eq!(
        client::http1(addr(port), {
            let mut r = with_key("x-api-key", &file_key);
            *r.headers_mut().get_mut("host").unwrap() = "gold.test".parse().unwrap();
            r
        })
        .await
        .status,
        403
    );

    // Mint a key for `partner` through the admin API: shown once, stored hashed.
    let (status, head, body) = rdock
        .admin_send("GET", "/api/v1/consumers", &[], "")
        .unwrap();
    assert_eq!(status, 200, "{body}");
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["consumers"].as_array().unwrap().len(), 2, "{listed}");
    let tag = etag(&head);
    let json_tag = [
        ("Content-Type", "application/json"),
        ("If-Match", tag.as_str()),
    ];
    let (status, head, body) = rdock
        .admin_send(
            "POST",
            "/api/v1/consumers/partner/keys",
            &json_tag,
            r#"{"note":"mobile app","expires_in_days":30}"#,
        )
        .unwrap();
    assert_eq!(status, 201, "{body}\n{}", rdock.log());
    let minted: Value = serde_json::from_str(&body).unwrap();
    let api_key = minted["key"].as_str().unwrap().to_owned();
    let api_id = minted["id"].as_str().unwrap().to_owned();
    assert!(api_key.starts_with("rdk_"));
    assert_eq!(
        client::http1(addr(port), with_key("x-api-key", &api_key))
            .await
            .status,
        200
    );
    let tag = etag(&head);

    // Revoke: refused with the configuration that applies the revocation, no restart.
    let (status, _, body) = rdock
        .admin_send(
            "DELETE",
            &format!("/api/v1/consumers/partner/keys/{api_id}"),
            &[("If-Match", tag.as_str())],
            "",
        )
        .unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        client::http1(addr(port), with_key("x-api-key", &api_key))
            .await
            .status,
        401
    );
    // A file key is not the API's to revoke.
    let (status, head, _) = rdock
        .admin_send("GET", "/api/v1/consumers", &[], "")
        .unwrap();
    assert_eq!(status, 200);
    let (status, _, _) = rdock
        .admin_send(
            "DELETE",
            &format!("/api/v1/consumers/acme/keys/{inline_id}"),
            &[("If-Match", etag(&head).as_str())],
            "",
        )
        .unwrap();
    assert_eq!(status, 403);
    // Removing a line from the keys file revokes that key on the next reload.
    std::fs::write(
        &keys_file,
        format!("{expired_id}:{expired_hash}:2020-01-01T00:00:00Z\n"),
    )
    .unwrap();
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    assert_eq!(
        client::http1(addr(port), with_key("x-api-key", &file_key))
            .await
            .status,
        401
    );

    // The CLI: offline hashing, and minting through the socket.
    let hashed = rdock.command_with_input(&["keys", "hash"], &inline_key);
    let out = String::from_utf8_lossy(&hashed.stdout);
    assert!(out.contains(&format!("{inline_id}:{inline_hash}")), "{out}");
    let created = rdock.command(&["keys", "create", "acme", "--days", "1", "--note", "cli"]);
    let out = String::from_utf8_lossy(&created.stdout).into_owned();
    assert!(
        created.status.success(),
        "{out}{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let cli_key = out.lines().next().unwrap().trim().to_owned();
    assert_eq!(
        client::http1(addr(port), with_key("x-api-key", &cli_key))
            .await
            .status,
        200
    );
    let listed = rdock.command(&["consumers", "list"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("acme"));

    // Access log: consumer and key ID, never the key.
    let log = rdock.access_log();
    assert!(
        log.iter()
            .any(|r| r["consumer"] == "acme" && r["key_id"] == json!(inline_id)),
        "{log:?}"
    );
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(
        metrics.contains(
            "rdock_consumer_requests_total{consumer=\"acme\",route=\"api\",status_class=\"2xx\"} 2"
        ),
        "{metrics}"
    );

    // No clear-text key anywhere: the data directory (API snapshot, history, audit log,
    // access log, token store), the configuration API, the effective configuration, the
    // process log and `rdock validate`.
    let keys = [&inline_key, &file_key, &expired_key, &api_key, &cli_key];
    let mut files = Vec::new();
    all_files(&rdock.data_dir(), &mut files);
    assert!(
        files
            .iter()
            .any(|(p, t)| p.contains("history") || t.contains(&api_id)),
        "the API key's ID is recorded somewhere: {:?}",
        files.iter().map(|f| &f.0).collect::<Vec<_>>()
    );
    let mut texts: Vec<(String, String)> = files;
    for path in [
        "/api/v1/config",
        "/api/v1/config/api",
        "/api/v1/config/history",
        "/api/v1/consumers",
        "/api/v1/audit",
        "/api/v1/status",
    ] {
        let (status, body) = rdock.get_admin(path).unwrap();
        assert_eq!(status, 200, "{path}: {body}");
        texts.push((path.to_owned(), body));
    }
    texts.push(("process log".into(), rdock.log()));
    let validate = rdock.command(&["validate"]);
    texts.push((
        "rdock validate".into(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&validate.stdout),
            String::from_utf8_lossy(&validate.stderr)
        ),
    ));
    for key in keys {
        for (place, text) in &texts {
            assert!(!leaks(text, key), "a clear-text key appears in {place}");
        }
    }
    // The minting answer was the only place: it is not in the audit record of the creation.
    let (_, audit) = rdock.get_admin("/api/v1/audit").unwrap();
    assert!(
        audit.contains("consumer.key.create") && audit.contains(&api_id),
        "{audit}"
    );
}

#[test]
fn a_key_written_into_the_configuration_is_refused_without_echoing_it() {
    let (key, id, _) = mint();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    std::fs::write(
        &file,
        format!("consumers:\n  acme:\n    keys: [{{ id: {id}, hash: \"{key}\" }}]\n"),
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .arg("validate")
        .arg(&file)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success());
    assert!(text.contains("looks like an API key itself"), "{text}");
    assert!(!leaks(&text, &key), "{text}");
}
