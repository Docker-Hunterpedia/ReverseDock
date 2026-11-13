//! End-to-end: the custom binary starts, both plugins act on real requests, and `validate`
//! reports plugin configuration errors with their paths.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::process::Command;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const CUSTOM: &str = env!("CARGO_BIN_EXE_custom-rdock");

fn config(port: u16, backend: SocketAddr) -> String {
    format!(
        r#"listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  open: {{ match: "PathPrefix(`/open`)", service: app, middlewares: [tidy] }}
  closed: {{ match: "PathPrefix(`/closed`)", service: app, middlewares: [blocklist, tidy] }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
middlewares:
  tidy:
    type: plugin
    name: header_rewrite
    config:
      request: {{ set: {{ X-Team: core }}, remove: [X-Debug] }}
      response: {{ set: {{ X-Frame-Options: DENY }} }}
  blocklist:
    type: plugin
    name: ip_blocklist
    config: {{ deny: [127.0.0.0/8, "::1"], message: "blocked by ip_blocklist\n" }}
"#
    )
}

#[tokio::test]
async fn both_plugins_act_on_real_requests() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(CUSTOM, &config(port, backend.addr));
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let mut req = get("app.test", "/open/x");
    req.headers_mut().insert("x-debug", "1".parse().unwrap());
    let reply = client::http1(addr, req).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
    let seen = &reply.json()["headers"];
    assert_eq!(seen["x-team"][0], "core", "header_rewrite set it upstream");
    assert!(seen.get("x-debug").is_none(), "header_rewrite removed it");

    let before = backend.requests();
    let refused = client::http1(addr, get("app.test", "/closed/x")).await;
    assert_eq!(refused.status, 403);
    assert_eq!(refused.text(), "blocked by ip_blocklist\n");
    assert_eq!(backend.requests(), before, "the backend never saw it");
    // HTTP/2 the same.
    let refused = client::h2c(addr, get("app.test", "/closed/y")).await;
    assert_eq!(refused.status, 403);
    assert!(
        rdock.log().contains("native plugins compiled in"),
        "{}",
        rdock.log()
    );
}

#[test]
fn validate_and_version_know_the_plugins() {
    let dir = tempfile_dir();
    let good = dir.join("good.yaml");
    std::fs::write(&good, config(8080, "127.0.0.1:9".parse().unwrap())).unwrap();
    let out = Command::new(CUSTOM)
        .arg("validate")
        .arg(&good)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    let bad = dir.join("bad.yaml");
    std::fs::write(
        &bad,
        "middlewares:\n  blocklist: { type: plugin, name: ip_blocklist, config: { deny: [10.0.0.1/8] } }\n  other: { type: plugin, name: geo_block }\n",
    )
    .unwrap();
    let out = Command::new(CUSTOM)
        .arg("validate")
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(
            "error: middlewares.blocklist.config.deny[0]: `10.0.0.1/8` has host bits set"
        ),
        "{text}"
    );
    assert!(
        text.contains("error: middlewares.other.name: no plugin `geo_block` is registered in this build; registered: header_rewrite, ip_blocklist"),
        "{text}"
    );

    let out = Command::new(CUSTOM)
        .args(["version", "--json"])
        .output()
        .unwrap();
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        info["plugins"],
        serde_json::json!(["header_rewrite", "ip_blocklist"])
    );
    assert_eq!(info["plugin_api"], rdock::plugin_api::API_VERSION);
    // The schema is the stock one: `config` is free-form.
    let out = Command::new(CUSTOM).arg("schema").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"plugin\""));
}

fn tempfile_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("custom-rdock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
