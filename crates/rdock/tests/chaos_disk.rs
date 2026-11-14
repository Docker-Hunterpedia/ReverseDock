//! Chaos suite, scenario 4 "disk full" (ADR-0033, vision §7): the disk-full rules under load.
//!
//! The disk is made full one of two ways (`rdock_testkit::disk`): a dedicated tmpfs filled
//! with a ballast file (`ENOSPC`, root or passwordless `sudo`; `RDOCK_CHAOS_DISK=tmpfs`, the
//! `chaos` CI job) or the rdock process's file-size limit set to zero (`EFBIG`, no privileges,
//! the default, run in the required `rust` job). Either way the data directory refuses writes
//! while requests flow, and the pass criteria are:
//!
//! - zero failed client requests for the whole run (plain routes, an API route, and a disk
//!   cache route whose every request is a miss that tries to store);
//! - a configuration write and a rollback are refused with `507`, and the stored API objects
//!   and history are unchanged;
//! - a mutating admin call whose audit record cannot be written is refused with `507`, every
//!   one that succeeded is in the audit log, read-only calls keep working;
//! - when space returns, a configuration write succeeds within 30 s without a restart, the
//!   audit chain verifies (`rdock audit verify`), and the data directory is consistent;
//! - (tmpfs only) a restart while the disk is full starts and serves the stored API routes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod chaos_common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use chaos_common::*;
use rdock_testkit::backend::Backend;
use rdock_testkit::disk::{self, Mechanism, Tmpfs};
use rdock_testkit::free_port;
use rdock_testkit::load::{Load, Target};
use rdock_testkit::origin::{Origin, Script};
use rdock_testkit::rdock::Rdock;
use serde_json::json;

/// How long the system may take to write again once space is back.
const RECOVERY: Duration = Duration::from_secs(30);

/// A full disk, either way.
struct Full {
    mechanism: Mechanism,
    tmpfs: Option<Tmpfs>,
}

impl Full {
    fn new() -> Self {
        let mechanism = disk::mechanism();
        let tmpfs = (mechanism == Mechanism::Tmpfs).then(|| {
            Tmpfs::mount(48 << 20).unwrap_or_else(|e| panic!("RDOCK_CHAOS_DISK=tmpfs: {e}"))
        });
        eprintln!("disk full by {mechanism:?}");
        Self { mechanism, tmpfs }
    }

    fn data_dir(&self) -> Option<PathBuf> {
        self.tmpfs.as_ref().map(|t| t.path().join("data"))
    }

    fn fill(&self, rdock: &Rdock) {
        match &self.tmpfs {
            Some(tmpfs) => tmpfs.fill(),
            None => disk::limit_file_size(rdock.pid(), Some(0)),
        }
    }

    fn free(&self, rdock: &Rdock) {
        match &self.tmpfs {
            Some(tmpfs) => tmpfs.free(),
            None => disk::limit_file_size(rdock.pid(), None),
        }
    }
}

fn config(port: u16, backend: std::net::SocketAddr, origin: std::net::SocketAddr) -> String {
    format!(
        r#"listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
caches:
  dsk: {{ type: disk, max_size: 16MiB }}
middlewares:
  cache: {{ type: cache, store: dsk }}
routes:
  app: {{ match: "Host(`app.test`)", service: app }}
  cached: {{ match: "Host(`cache.test`)", service: origin, middlewares: [cache] }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
  origin: {{ backends: [{{ address: "{origin}" }}] }}
  spare: {{ backends: [{{ address: "127.0.0.1:9" }}] }}
"#
    )
}

/// The API objects: a route for `api.test`, and one for `extra` when given.
fn api_document(backend: std::net::SocketAddr, extra: &str) -> serde_json::Value {
    let mut routes = json!({ "api": { "match": "Host(`api.test`)", "service": "api" } });
    if extra != "api.test" {
        routes["extra"] = json!({ "match": format!("Host(`{extra}`)"), "service": "api" });
    }
    json!({
        "routes": routes,
        "services": { "api": { "backends": [{ "address": backend.to_string() }] } }
    })
}

fn create_token(rdock: &Rdock, name: &str) -> (u16, String) {
    let body = json!({ "name": name, "role": "viewer", "expires_in_days": 30 }).to_string();
    let (status, _, text) = rdock
        .admin_send(
            "POST",
            "/api/v1/tokens",
            &[("Content-Type", "application/json")],
            &body,
        )
        .unwrap();
    (status, text)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_disk_refuses_changes_and_keeps_serving() {
    let full = Full::new();
    let backend = Backend::start("app").await;
    let origin = Origin::start().await;
    origin.set(
        "/c",
        Script::ok("cacheable-".repeat(8 * 1024)).cache_control("max-age=600"),
    );
    let port = free_port();
    let data = full.data_dir();
    let mut rdock = Rdock::try_start_in(
        RDOCK,
        &config(port, backend.addr, origin.addr),
        &[],
        data.as_deref(),
        Duration::from_secs(30),
    )
    .unwrap_or_else(|log| panic!("rdock did not start:\n{log}"));
    let proxy = addr(port);

    // Before the fault: an API route, a token, a clean audit chain.
    let (code, body) = put_api(&rdock, &api_document(backend.addr, "api.test"));
    assert_eq!(code, 200, "{body}");
    assert_eq!(create_token(&rdock, "before").0, 201);
    let history_before = history_ids(&rdock);
    let snapshot = rdock.data_dir().join("state/providers/api.json");
    let snapshot_before = std::fs::read(&snapshot).unwrap();

    let load = Load::start(
        vec![
            Target::http(proxy, "app.test", "/"),
            Target::http(proxy, "api.test", "/"),
            Target::http(proxy, "cache.test", "/c").unique_paths(),
        ],
        60,
    );
    load.wait_for_ok(60, Duration::from_secs(30)).await;

    full.fill(&rdock);

    // A configuration write and a rollback are refused; nothing stored changes.
    let (code, body) = put_api(&rdock, &api_document(backend.addr, "api2.test"));
    assert_eq!(code, 507, "{body}\n{}", rdock.log());
    // Refused by the audit gate (no room for its record) or by the configuration's own store
    // (its history entry or API snapshot), whichever runs out of room first.
    assert!(
        body.contains("cannot store the configuration") || body.contains("audit log"),
        "{body}"
    );
    let oldest = *history_before.last().unwrap();
    let (code, body) = rollback(&rdock, oldest);
    assert_eq!(code, 507, "{body}");
    assert_eq!(history_ids(&rdock), history_before, "history unchanged");
    assert_eq!(
        std::fs::read(&snapshot).unwrap(),
        snapshot_before,
        "stored API objects unchanged"
    );

    // Mutating admin calls: some may still land in the audit log's reserved room; once that
    // is used up they are refused. Every one that succeeded is audited.
    let mut created = Vec::new();
    let mut refused = false;
    for i in 0..200 {
        let name = format!("during-{i}");
        match create_token(&rdock, &name) {
            (201, _) => created.push(name),
            (507, text) => {
                assert!(
                    text.contains("audit log") || text.contains("disk is full"),
                    "{text}"
                );
                refused = true;
                break;
            }
            (code, text) => panic!("token create answered {code}: {text}\n{}", rdock.log()),
        }
    }
    assert!(
        refused,
        "a mutating call was refused while the disk was full"
    );
    // A call that stores nothing but its audit record (draining a backend): admitted while
    // the audit log's reserved room lasts, refused by the audit gate after that.
    let mut drains = 0;
    let mut gated = false;
    for i in 0..400 {
        let path = if i % 2 == 0 { "drain" } else { "undrain" };
        let body = json!({ "service": "spare", "backend": "127.0.0.1:9" }).to_string();
        let (code, _, text) = rdock
            .admin_send(
                "POST",
                &format!("/api/v1/backends/{path}"),
                &[("Content-Type", "application/json")],
                &body,
            )
            .unwrap();
        match code {
            200 => drains += 1,
            507 => {
                assert!(text.contains("audit log"), "{text}");
                gated = true;
                break;
            }
            other => panic!("drain answered {other}: {text}"),
        }
    }
    assert!(
        gated,
        "the audit gate refused a call once its room was used up"
    );
    // Read-only calls keep working.
    assert_eq!(rdock.get_admin("/api/v1/tokens").unwrap().0, 200);
    assert!(status(&rdock).is_some_and(|s| s["ready"] == true));
    assert!(metric(&rdock, "rdock_admin_audit_refusals_total", "") >= 1.0);
    if full.mechanism == Mechanism::Tmpfs {
        // On a tmpfs the audit log's reserved room let the write reach its own store.
        assert!(
            metric(
                &rdock,
                "rdock_state_write_failures_total",
                "what=\"config\""
            ) >= 1.0,
            "the configuration store refused the write"
        );
    }
    // Requests keep flowing for a while on the full disk.
    load.wait_for_ok(180, Duration::from_secs(60)).await;

    // Space returns: writes succeed again without a restart.
    full.free(&rdock);
    let freed = Instant::now();
    let mut answer = (0, String::new());
    while freed.elapsed() < RECOVERY {
        answer = put_api(&rdock, &api_document(backend.addr, "api2.test"));
        if answer.0 == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(answer.0, 200, "{}\n{}", answer.1, rdock.log());
    eprintln!(
        "configuration writes resumed {:?} after space returned",
        freed.elapsed()
    );
    assert_eq!(create_token(&rdock, "after").0, 201);
    load.wait_for_ok(30, Duration::from_secs(30)).await;

    let report = load.stop().await;
    eprintln!("load: {report:?}");
    report.assert_clean("disk full", &rdock.log());

    // The pass criteria on disk.
    assert_audit_intact(&rdock);
    assert_data_dir_consistent(&rdock);
    let records = audit_records(&rdock.data_dir());
    for name in &created {
        assert!(
            records
                .iter()
                .any(|r| r["action"] == "token.create" && r["result"] == "ok")
                && records
                    .iter()
                    .filter(|r| r["action"] == "token.create")
                    .count()
                    >= created.len() + 2,
            "the token {name} created during the outage is audited"
        );
    }
    let audited_drains = records
        .iter()
        .filter(|r| {
            r["action"]
                .as_str()
                .is_some_and(|a| a.starts_with("backend."))
                && r["result"] == "ok"
        })
        .count();
    assert_eq!(audited_drains, drains, "every admitted drain is audited");
    let history = history_ids(&rdock);
    assert_eq!(
        history.len(),
        history_before.len() + 1,
        "one new history entry"
    );

    // Restart while the disk is full (tmpfs: the real thing): rdock starts on what it has.
    if full.mechanism == Mechanism::Tmpfs {
        full.fill(&rdock);
        rdock
            .restart()
            .unwrap_or_else(|log| panic!("no restart on a full disk:\n{log}"));
        assert_eq!(
            rdock_testkit::client::http1(proxy, rdock_testkit::client::get("api2.test", "/"))
                .await
                .status,
            200,
            "the stored API route is served after a restart on a full disk"
        );
        full.free(&rdock);
        assert_audit_intact(&rdock);
    }
}

/// The certificate rule: no order is placed while the data directory has no room for its
/// result (`CERT_ROOM`, 1 MiB), the current certificate keeps serving, the failure shows in
/// the status and the metrics, and once space returns exactly one order is placed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_certificate_is_ordered_without_room_to_store_it() {
    use rdock_testkit::fake_acme::{CaMode, FakeAcme};
    const NAME: &str = "a.example.com";
    let full = Full::new();
    let backend = Backend::start("app").await;
    let ports = Ports::new();
    let fake = FakeAcme::start(vec![ports.http()], vec![ports.https()]).await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.pem");
    std::fs::write(&root, fake.root_pem()).unwrap();
    let data = full.data_dir();
    let rdock = Rdock::try_start_in(
        RDOCK,
        &acme_config(&fake.directory(), &root, &ports, &[NAME], backend.addr),
        &[("RDOCK_TEST_ACME_RETRY", "1")],
        data.as_deref(),
        Duration::from_secs(30),
    )
    .unwrap_or_else(|log| panic!("rdock did not start:\n{log}"));
    let trust = trust(fake.issuing_pem());
    let first = issued(
        &rdock,
        ports.https(),
        NAME,
        &trust,
        None,
        Duration::from_secs(60),
    )
    .await;
    let orders = |fake: &FakeAcme| fake.orders_created().get(NAME).copied().unwrap_or(0);
    assert_eq!(orders(&fake), 1);
    let load = Load::start(
        vec![Target::https(ports.https(), NAME, "/", trust.clone())],
        30,
    );
    load.wait_for_ok(30, Duration::from_secs(30)).await;

    // A renewal is asked for while the CA is unreachable, then the disk fills and the CA
    // comes back: the retries find no room and order nothing.
    fake.set_mode(CaMode::Down);
    force_renewal(&rdock, NAME);
    wait_until(
        &rdock,
        Duration::from_secs(30),
        "the renewal fails while the CA is down",
        || cert_status(&rdock, NAME)["failures"].as_u64() >= Some(1),
    )
    .await;
    full.fill(&rdock);
    fake.set_mode(CaMode::Up);
    let mut seen = serde_json::Value::Null;
    let refused = wait_for(Duration::from_secs(60), || {
        seen = cert_status(&rdock, NAME);
        seen["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("not ordering"))
    })
    .await;
    assert!(refused, "no renewal refused for lack of room: {seen}");
    assert_eq!(orders(&fake), 1, "no order while the disk is full");
    assert!(
        metric(
            &rdock,
            "rdock_state_write_failures_total",
            "what=\"certificate\""
        ) >= 1.0
    );
    assert!(metric(&rdock, "rdock_cert_renewal_failures_total", NAME) >= 2.0);
    assert_eq!(
        served(ports.https(), NAME, &trust).await.as_deref(),
        Some(first.as_slice()),
        "the current certificate keeps serving"
    );

    // Space returns: the next retry orders once and the new certificate is served.
    full.free(&rdock);
    let renewed = issued(
        &rdock,
        ports.https(),
        NAME,
        &trust,
        Some(&first),
        Duration::from_secs(90),
    )
    .await;
    assert_ne!(renewed, first);
    assert_eq!(orders(&fake), 2, "exactly one order once space returned");
    let report = load.stop().await;
    report.assert_clean("certificate order on a full disk", &rdock.log());
    assert_data_dir_consistent(&rdock);
    assert_audit_intact(&rdock);
}
