//! Chaos suite, scenario 6 "config rollback under load" (ADR-0033, vision §7). Rootless; runs
//! in the required `rust` job.
//!
//! Requests flow (plain HTTP and HTTPS, open model) while the configuration changes and rolls
//! back through every path an operator has: the configuration API's write and rollback, `rdock
//! config rollback`, a rollback racing a file reload, and a file change of a listener and of a
//! certificate that is then reverted (the configuration API holds routes, services and
//! middlewares; listeners and certificates come from the file, so their "rollback" is the file
//! put back and reloaded). Pass: zero failed requests, every write and rollback is one audit
//! record and the chain verifies, the history lists each applied change, and a rolled-back
//! route set is served within 1 s of the `200`.
//!
//! A cluster rollout abandoned under load is not here: `e2e_cluster` proves the NACK and
//! fall-back path without load (see `docs/07-roadmap.md`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod chaos_common;

use std::time::{Duration, Instant};

use chaos_common::*;
use rdock_testkit::backend::Backend;
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::load::{Load, Target};
use rdock_testkit::rdock::Rdock;
use serde_json::json;

/// Write-and-rollback rounds through the API.
const ROUNDS: usize = 10;

fn file_config(
    web: u16,
    tls: u16,
    extra: Option<u16>,
    backend: std::net::SocketAddr,
    cert: &rdock_testkit::certs::Issued,
) -> String {
    let extra = extra.map_or_else(String::new, |port| {
        format!("  extra: {{ address: \"127.0.0.1:{port}\" }}\n")
    });
    format!(
        r#"listeners:
  web: {{ address: "127.0.0.1:{web}" }}
  websecure: {{ address: "127.0.0.1:{tls}", tls: {{}} }}
{extra}defaults: {{ listeners: [web, websecure], tls: off, redirect_http_to_https: false }}
certificates:
  app: {{ cert_file: "{cert}", key_file: "{key}" }}
routes:
  app: {{ match: "Host(`app.test`)", service: app, tls: {{ certificate: app }} }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
lifecycle: {{ drain_timeout: 5s }}
"#,
        cert = cert.cert.display(),
        key = cert.key.display(),
    )
}

fn api_document(backend: std::net::SocketAddr, with_b: bool) -> serde_json::Value {
    let mut routes = json!({ "a": { "match": "Host(`api.test`)", "service": "api" } });
    if with_b {
        routes["b"] = json!({ "match": "Host(`b.test`)", "service": "api" });
    }
    json!({
        "routes": routes,
        "services": { "api": { "backends": [{ "address": backend.to_string() }] } }
    })
}

async fn status_of(port: u16, host: &str) -> u16 {
    tokio::time::timeout(
        Duration::from_secs(2),
        client::http1(addr(port), get(host, "/")),
    )
    .await
    .map_or(0, |r| r.status)
}

/// Waits until `host` answers `status`; returns how long it took.
async fn served_within(port: u16, host: &str, status: u16, limit: Duration) -> Duration {
    let start = Instant::now();
    loop {
        if status_of(port, host).await == status {
            return start.elapsed();
        }
        assert!(
            start.elapsed() < limit,
            "{host} did not answer {status} within {limit:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rollbacks_under_load_drop_nothing() {
    let backend = Backend::start("app").await;
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "one", &["app.test"]);
    let (web, tls) = (free_port(), free_port());
    let mut rdock = Rdock::start(RDOCK, &file_config(web, tls, None, backend.addr, &cert));
    let (code, body) = put_api(&rdock, &api_document(backend.addr, false));
    assert_eq!(code, 200, "{body}");
    // The entry with only route `a`: what every rollback returns to.
    let a = history_ids(&rdock)[0];
    let records_before = audit_records(&rdock.data_dir()).len();

    let load = Load::start(
        vec![
            Target::http(addr(web), "app.test", "/"),
            Target::http(addr(web), "api.test", "/"),
            Target::https(addr(tls), "app.test", "/", ca.client_config(&[b"http/1.1"])),
        ],
        90,
    );
    load.wait_for_ok(90, Duration::from_secs(30)).await;

    // Writes and rollbacks through the API, back to back.
    let mut slowest = Duration::ZERO;
    for round in 0..ROUNDS {
        let (code, body) = put_api(&rdock, &api_document(backend.addr, true));
        assert_eq!(code, 200, "round {round}: {body}");
        served_within(web, "b.test", 200, Duration::from_secs(5)).await;
        let (code, body) = rollback(&rdock, a);
        assert_eq!(code, 200, "round {round}: {body}");
        slowest = slowest.max(served_within(web, "b.test", 404, Duration::from_secs(5)).await);
    }
    assert!(
        slowest < Duration::from_secs(1),
        "a rolled-back route set was served {slowest:?} after the 200"
    );

    // `rdock config rollback`, the CLI.
    let (code, body) = put_api(&rdock, &api_document(backend.addr, true));
    assert_eq!(code, 200, "{body}");
    let out = rdock.command(&["config", "rollback", &a.to_string()]);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    served_within(web, "b.test", 404, Duration::from_secs(1)).await;

    // A rollback racing a reload of the file: both are applied one after the other.
    let (code, body) = put_api(&rdock, &api_document(backend.addr, true));
    assert_eq!(code, 200, "{body}");
    let racing = {
        let socket = rdock.data_dir().join("admin.sock");
        std::thread::spawn(move || {
            let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
            std::io::Write::write_all(
                &mut stream,
                b"POST /api/v1/config/reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            let mut answer = String::new();
            std::io::Read::read_to_string(&mut stream, &mut answer).unwrap();
            answer
        })
    };
    let (code, body) = rollback(&rdock, a);
    assert!(code == 200 || code == 412, "{code}: {body}");
    let reload = racing.join().unwrap();
    assert!(reload.starts_with("HTTP/1.1 200"), "{reload}");
    if code == 412 {
        // The reload changed the version first: the rollback is repeated on the new one.
        let (code, body) = rollback(&rdock, a);
        assert_eq!(code, 200, "{body}");
    }
    served_within(web, "b.test", 404, Duration::from_secs(1)).await;

    // A listener added in the file and taken away again, under load on the others.
    let extra = free_port();
    rdock.write_config(&file_config(web, tls, Some(extra), backend.addr, &cert));
    assert_eq!(rdock.reload().0, 200);
    // It answers (404: no route is on it), so it is bound.
    assert_eq!(status_of(extra, "app.test").await, 404);
    rdock.write_config(&file_config(web, tls, None, backend.addr, &cert));
    assert_eq!(rdock.reload().0, 200);
    wait_until(
        &rdock,
        Duration::from_secs(10),
        "the extra listener closes",
        || std::net::TcpStream::connect(addr(extra)).is_err(),
    )
    .await;

    // A certificate replaced in the file and put back, under HTTPS load (both from the CA
    // the load trusts).
    let two = ca.issue(dir.path(), "two", &["app.test"]);
    rdock.write_config(&file_config(web, tls, None, backend.addr, &two));
    assert_eq!(rdock.reload().0, 200);
    load.wait_for_ok(45, Duration::from_secs(30)).await;
    rdock.write_config(&file_config(web, tls, None, backend.addr, &cert));
    assert_eq!(rdock.reload().0, 200);
    load.wait_for_ok(45, Duration::from_secs(30)).await;

    let report = load.stop().await;
    eprintln!("load: {report:?}");
    report.assert_clean("config rollback under load", &rdock.log());

    // Every write and rollback is one audit record, and the chain holds.
    let records = audit_records(&rdock.data_dir());
    let new = &records[records_before..];
    let count = |action: &str| {
        new.iter()
            .filter(|r| r["action"] == action && r["result"] == "ok")
            .count()
    };
    assert_eq!(count("config.apply"), ROUNDS + 2, "{new:#?}");
    assert_eq!(count("config.rollback"), ROUNDS + 2, "{new:#?}");
    assert_audit_intact(&rdock);
    assert_data_dir_consistent(&rdock);
    let (_, _, api) = rdock
        .admin_send("GET", "/api/v1/config/api", &[], "")
        .unwrap();
    assert!(
        !api.contains("b.test"),
        "the API objects are route `a` only: {api}"
    );
    rdock.stop(Duration::from_secs(15));
}
