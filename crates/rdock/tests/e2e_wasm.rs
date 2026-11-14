//! End-to-end: a signed WASM plugin (F-EXT-03, ADR-0030; experimental, `wasm` feature) on a
//! route of the real binary: the Rust example guest edits the request and the response and
//! answers one path itself; a reload swaps the module; a reload with a module that fails its
//! checks is refused while the loaded one keeps serving; a failing plugin fails closed.

#![cfg(feature = "wasm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::path::Path;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rdock_wasm::artifact::{default_signature_path, sha256_hex};
use rdock_wasm::testing::{self, Guest, TestKey};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Writes `bytes` to `dir/name`, signed by `key`; returns the `sha256` pin.
fn install(dir: &Path, name: &str, bytes: &[u8], key: &TestKey) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::write(default_signature_path(&path), key.sign(bytes, true)).unwrap();
    sha256_hex(bytes)
}

fn config(
    port: u16,
    backend: SocketAddr,
    dir: &Path,
    file: &str,
    sha256: &str,
    key: &str,
    on_error: &str,
) -> String {
    format!(
        r#"
experimental: [wasm]
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "Host(`app.test`)", service: app, middlewares: [plugin] }}
middlewares:
  plugin:
    type: wasm
    path: "{path}"
    sha256: "{sha256}"
    trusted_keys: ["{key}"]
    on_error: {on_error}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        path = dir.join(file).display(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signed_wasm_plugin_serves_reloads_and_fails_closed() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let modules = tempfile::tempdir().unwrap();
    let key = TestKey::new(21);
    let example = std::fs::read(testing::build_example().unwrap()).unwrap();
    let sha = install(modules.path(), "header.wasm", &example, &key);
    let rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            backend.addr,
            modules.path(),
            "header.wasm",
            &sha,
            &key.public(),
            "deny",
        ),
    );

    // The example guest: a request header for the backend, response headers for the client.
    let reply = client::http1(addr(port), get("app.test", "/hello")).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let echo: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(echo["headers"]["x-wasm"], serde_json::json!(["yes"]));
    assert_eq!(reply.header("x-wasm-response"), Some("yes"));
    let request_id = reply.header("x-wasm-request-id").unwrap();
    assert_ne!(request_id, "");
    // A path the plugin answers itself; the backend is not asked.
    let blocked = client::http1(addr(port), get("app.test", "/blocked")).await;
    assert_eq!(blocked.status, 403);
    assert_eq!(blocked.text(), "denied by wasm\n");
    assert_eq!(blocked.header("content-type"), Some("text/plain"));

    // A reload swaps the module: this one makes no edits.
    let plain = Guest::default().wat();
    let sha_plain = install(modules.path(), "plain.wat", plain.as_bytes(), &key);
    rdock.write_config(&config(
        port,
        backend.addr,
        modules.path(),
        "plain.wat",
        &sha_plain,
        &key.public(),
        "deny",
    ));
    let (status, body) = rdock.reload();
    assert_eq!(status, 200, "{body}");
    let reply = client::http1(addr(port), get("app.test", "/hello")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("x-wasm-response"), None);
    let echo: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert!(echo["headers"].get("x-wasm").is_none(), "{echo}");

    // A module signed by an unknown key is refused; the loaded one keeps serving.
    let stranger = TestKey::new(99);
    let sha_header = install(modules.path(), "unknown.wasm", &example, &stranger);
    rdock.write_config(&config(
        port,
        backend.addr,
        modules.path(),
        "unknown.wasm",
        &sha_header,
        &key.public(),
        "deny",
    ));
    let (status, body) = rdock.reload();
    assert_eq!(status, 422, "{body}");
    assert!(
        body.to_string().contains("not among the trusted keys"),
        "{body}"
    );
    let reply = client::http1(addr(port), get("app.test", "/blocked")).await;
    assert_eq!(reply.status, 200, "the previous module still runs");

    // A plugin that traps fails closed: 500, and the failure is counted.
    let trap = Guest {
        on_request: testing::TRAP,
        ..Guest::default()
    }
    .wat();
    let sha_trap = install(modules.path(), "trap.wat", trap.as_bytes(), &key);
    rdock.write_config(&config(
        port,
        backend.addr,
        modules.path(),
        "trap.wat",
        &sha_trap,
        &key.public(),
        "deny",
    ));
    let (status, body) = rdock.reload();
    assert_eq!(status, 200, "{body}");
    let reply = client::http1(addr(port), get("app.test", "/")).await;
    assert_eq!(reply.status, 500);
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(
        metrics.contains(r#"rdock_wasm_failures_total{middleware="plugin",reason="trap"} 1"#),
        "{metrics}"
    );
    // `on_error: allow` lets the request through.
    rdock.write_config(&config(
        port,
        backend.addr,
        modules.path(),
        "trap.wat",
        &sha_trap,
        &key.public(),
        "allow",
    ));
    let (status, body) = rdock.reload();
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        client::http1(addr(port), get("app.test", "/")).await.status,
        200
    );
}
