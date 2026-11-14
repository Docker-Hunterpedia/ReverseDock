//! Proof 1 of v0.9 (ADR-0031): "3-instance cluster survives control-plane outage", with real
//! processes on loopback: `rdock control run` and three `rdock run` data planes that enrol with
//! join tokens and pull bundles.
//!
//! The control plane is killed (`SIGKILL`): the three keep serving their configuration with no
//! failed request; one of them is restarted meanwhile and boots from its stored bundle; the
//! control plane comes back on the same data directory and all three take the next revision.
//! A revision every data plane refuses (a listener whose port is taken on each) is refused (NACK) and
//! all three stay on the previous one, while the control plane reports who refused it and why.
//! A revoked instance stops receiving bundles and keeps serving its last one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

/// `rdock control run` with its own directory.
struct Control {
    dir: tempfile::TempDir,
    child: Option<Child>,
    cluster: u16,
}

impl Drop for Control {
    fn drop(&mut self) {
        self.kill();
    }
}

impl Control {
    /// A control plane that rolls revisions out to every instance at once (the behaviour the
    /// outage proof was written for).
    fn start() -> Self {
        Self::start_with("  rollout: { mode: all }\n")
    }

    /// A control plane with extra lines under `control:`.
    fn start_with(extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cluster = free_port();
        let admin = free_port();
        std::fs::write(
            dir.path().join("control.yaml"),
            format!(
                "control:\n  listener: \"127.0.0.1:{cluster}\"\n  identity_lifetime: 1h\n  offline_after: 15s\n{extra}admin: {{ listener: \"127.0.0.1:{admin}\" }}\n"
            ),
        )
        .unwrap();
        let mut control = Self {
            dir,
            child: None,
            cluster,
        };
        control.spawn();
        control
    }

    fn data(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("control.log")).unwrap_or_default()
    }

    fn spawn(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.path().join("control.log"))
            .unwrap();
        let child = Command::new(RDOCK)
            .args(["control", "run", "--log-format", "json", "-c"])
            .arg(self.dir.path().join("control.yaml"))
            .arg("--data-dir")
            .arg(self.data())
            // What the control plane validates `${env:…}` in listener addresses with.
            .env("DP_PORT", "1")
            .env("DP_BUSY_PORT", "2")
            .env("DP_TLS_PORT", "3")
            .env("DP_EXTRA", "control-plane")
            .stdout(Stdio::null())
            .stderr(log)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.admin("GET", "/readyz", None).0 != 200 {
            assert!(
                Instant::now() < deadline,
                "the control plane did not start\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// One request over the admin socket (trusted like the CLI).
    fn admin(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        let Ok(mut stream) = UnixStream::connect(self.data().join("admin.sock")) else {
            return (0, Value::Null);
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let body = body.map(Value::to_string).unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        if stream.write_all(request.as_bytes()).is_err() {
            return (0, Value::Null);
        }
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let Some((head, body)) = raw.split_once("\r\n\r\n") else {
            return (0, Value::Null);
        };
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, serde_json::from_str(body).unwrap_or(Value::Null))
    }

    fn token(&self) -> (String, String) {
        let (status, body) = self.admin("POST", "/api/v1/cluster/tokens", Some(&json!({})));
        assert_eq!(status, 201, "{body}");
        (
            body["token"].as_str().unwrap().to_owned(),
            body["ca_pin"].as_str().unwrap().to_owned(),
        )
    }

    fn publish(&self, document: &Value) -> Value {
        let (status, body) = self.admin(
            "POST",
            "/api/v1/cluster/revisions",
            Some(&json!({ "document": document })),
        );
        assert_eq!(status, 201, "{body}");
        body
    }

    fn instances(&self) -> Value {
        self.admin("GET", "/api/v1/cluster/instances", None).1
    }
}

/// The configuration a revision publishes: one listener per data plane (its port from its own
/// environment), a route answering with the revision in a header.
fn bundle(revision: &str, backend: SocketAddr, busy: bool) -> Value {
    let mut listeners = json!({ "web": { "address": "127.0.0.1:${env:DP_PORT}" } });
    if busy {
        listeners["busy"] = json!({ "address": "127.0.0.1:${env:DP_BUSY_PORT}" });
    }
    json!({
        "acme": false,
        "listeners": listeners,
        "defaults": { "listeners": ["web"], "tls": "off" },
        "routes": { "app": { "match": "PathPrefix(`/`)", "service": "app", "middlewares": ["tag"] } },
        "services": { "app": { "backends": [{ "address": backend.to_string() }] } },
        "middlewares": { "tag": { "type": "headers", "response": { "set": { "X-Revision": revision } } } },
    })
}

/// A data plane with its ports.
struct Member {
    rdock: Rdock,
    port: u16,
    _busy: std::net::TcpListener,
}

impl Member {
    fn addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.port).parse().unwrap()
    }

    fn status(&self) -> Value {
        self.rdock
            .get_admin("/api/v1/status")
            .and_then(|(_, body)| serde_json::from_str(&body).ok())
            .unwrap_or(Value::Null)
    }
}

fn join(control: &Control, index: usize, dir: &Path) -> Member {
    join_with(control, index, dir, free_port(), &[])
}

fn join_with(
    control: &Control,
    index: usize,
    dir: &Path,
    port: u16,
    env: &[(&str, &str)],
) -> Member {
    join_full(control, index, dir, port, env, "")
}

/// A data plane with `extra` lines under `cluster:`.
fn join_full(
    control: &Control,
    index: usize,
    dir: &Path,
    port: u16,
    env: &[(&str, &str)],
    extra: &str,
) -> Member {
    let (token, pin) = control.token();
    let token_file = dir.join(format!("join-{index}"));
    std::fs::write(&token_file, &token).unwrap();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = busy.local_addr().unwrap().port().to_string();
    let config = format!(
        "cluster:\n  instance: edge-{index}\n  control:\n    url: \"https://127.0.0.1:{}\"\n    ca_pin: \"{pin}\"\n    join_token: \"${{file:{}}}\"\n    poll_timeout: 5s\n{extra}",
        control.cluster,
        token_file.display()
    );
    let port_text = port.to_string();
    let mut vars = vec![
        ("DP_PORT", port_text.as_str()),
        ("DP_BUSY_PORT", busy_port.as_str()),
    ];
    vars.extend_from_slice(env);
    let rdock = Rdock::try_start_with_env(RDOCK, &config, &vars)
        .unwrap_or_else(|log| panic!("edge-{index} did not start:\n{log}\n{}", control.log()));
    Member {
        rdock,
        port,
        _busy: busy,
    }
}

/// The revision header a data plane answers with, or `None` when the request fails.
async fn probe(addr: SocketAddr) -> Option<String> {
    let work = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.ok()?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
        if status != 200 {
            return None;
        }
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("x-revision")
                .then(|| v.trim().to_owned())
        })
    };
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .ok()
        .flatten()
}

async fn wait_serving(members: &[&Member], revision: &str, within: Duration, control: &Control) {
    let deadline = Instant::now() + within;
    loop {
        let mut all = true;
        for m in members {
            if probe(m.addr()).await.as_deref() != Some(revision) {
                all = false;
            }
        }
        if all {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "not every data plane serves revision {revision}\n{}\n----\n{}",
            members
                .iter()
                .map(|m| m.rdock.log())
                .collect::<Vec<_>>()
                .join("\n----\n"),
            control.log()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for(what: &str, within: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // one scenario, in order
async fn three_data_planes_survive_a_control_plane_outage() {
    let backend = Backend::start("app").await;
    let mut control = Control::start();
    let dir = tempfile::tempdir().unwrap();
    control.publish(&bundle("1", backend.addr, false));
    let mut members: Vec<Member> = (0..3).map(|i| join(&control, i, dir.path())).collect();
    wait_serving(
        &members.iter().collect::<Vec<_>>(),
        "1",
        Duration::from_secs(60),
        &control,
    )
    .await;

    // Revision 2 reaches all three; the control plane sees them synced.
    let published = control.publish(&bundle("2", backend.addr, false));
    assert_eq!(published["revision"], 2);
    wait_serving(
        &members.iter().collect::<Vec<_>>(),
        "2",
        Duration::from_secs(60),
        &control,
    )
    .await;
    wait_for("three synced instances", Duration::from_secs(30), || {
        let instances = control.instances();
        instances["instances"].as_array().is_some_and(|list| {
            list.len() == 3
                && list
                    .iter()
                    .all(|i| i["state"] == "synced" && i["serving"] == 2)
        })
    })
    .await;
    for (i, m) in members.iter().enumerate() {
        let stored = m.rdock.data_dir().join("state/control/bundle.json");
        let bundle: Value = serde_json::from_slice(&std::fs::read(&stored).unwrap()).unwrap();
        assert_eq!(
            bundle["revision"], 2,
            "edge-{i} stored the bundle it acknowledged"
        );
        // The identity (key, certificate, CA) is one file, written atomically and private.
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(m.rdock.data_dir().join("cluster/identity.json"))
                .unwrap()
                .permissions(),
        );
        assert_eq!(mode & 0o777, 0o600, "edge-{i}'s identity is private");
        assert!(!m.rdock.data_dir().join("cluster/enroll-key.pem").exists());
    }

    // Requests run against all three for the whole outage.
    let failures = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(AtomicUsize::new(0));
    let running = Arc::new(AtomicBool::new(true));
    let mut load = Vec::new();
    for m in &members {
        let (addr, failures, served, running) =
            (m.addr(), failures.clone(), served.clone(), running.clone());
        load.push(tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                match probe(addr).await.as_deref() {
                    Some("2") => {
                        served.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {
                        failures.fetch_add(1, Ordering::SeqCst);
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }));
    }

    // The control plane dies.
    control.kill();
    // Every data plane notices and says so, still serving revision 2.
    wait_for(
        "every data plane to report the control plane unreachable",
        Duration::from_secs(60),
        || {
            members.iter().all(|m| {
                let status = m.status();
                status["cluster"]["connected"] == false
                    && status["cluster"]["serving"] == 2
                    && status["origin"] == "control"
            })
        },
    )
    .await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    running.store(false, Ordering::SeqCst);
    for task in load {
        task.await.unwrap();
    }
    assert_eq!(
        failures.load(Ordering::SeqCst),
        0,
        "no request failed while the control plane was away"
    );
    assert!(
        served.load(Ordering::SeqCst) > 100,
        "requests kept being served"
    );

    // One data plane restarts while the control plane is away: it boots from its stored bundle.
    members[0].rdock.restart().unwrap();
    assert_eq!(
        probe(members[0].addr()).await.as_deref(),
        Some("2"),
        "{}",
        members[0].rdock.log()
    );
    assert!(
        members[0].rdock.log().contains("serving the stored bundle"),
        "{}",
        members[0].rdock.log()
    );

    // The control plane returns on the same data directory; all three reconnect and take the
    // next revision, published with the CLI.
    control.spawn();
    let file = dir.path().join("revision-3.yaml");
    std::fs::write(
        &file,
        serde_json::to_string(&bundle("3", backend.addr, false)).unwrap(),
    )
    .unwrap();
    let output = Command::new(RDOCK)
        .args(["control", "publish"])
        .arg(&file)
        .arg("-c")
        .arg(control.dir.path().join("control.yaml"))
        .arg("--data-dir")
        .arg(control.data())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("published revision 3"));
    wait_serving(
        &members.iter().collect::<Vec<_>>(),
        "3",
        Duration::from_secs(90),
        &control,
    )
    .await;
    wait_for("reconnected data planes", Duration::from_secs(30), || {
        members
            .iter()
            .all(|m| m.status()["cluster"]["connected"] == true)
    })
    .await;

    // A revision every data plane refuses: its extra listener's port is taken on each. All
    // three NACK it and stay on revision 3; the control plane says who refused it and why.
    let refused = control.publish(&bundle("4", backend.addr, true));
    assert_eq!(refused["revision"], 4);
    wait_for("three NACKs of revision 4", Duration::from_secs(60), || {
        let revisions = control.admin("GET", "/api/v1/cluster/revisions", None).1;
        revisions["revisions"]
            .as_array()
            .and_then(|list| list.iter().find(|r| r["revision"] == 4))
            .and_then(|r| r["refused_by"].as_array().cloned())
            .is_some_and(|by| by.len() == 3)
    })
    .await;
    let revisions = control.admin("GET", "/api/v1/cluster/revisions", None).1;
    let four = revisions["revisions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["revision"] == 4)
        .unwrap()
        .clone();
    let why = four["refused_by"][0]["diagnostics"].to_string();
    assert!(
        why.contains("busy") || why.contains("bind") || why.contains("address"),
        "{why}"
    );
    let instances = control.instances();
    assert!(
        instances["instances"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["state"] == "error" && i["serving"] == 3),
        "{instances}"
    );
    for m in &members {
        assert_eq!(probe(m.addr()).await.as_deref(), Some("3"));
        assert_eq!(m.status()["cluster"]["serving"], 3);
    }

    // A fixed revision follows and is taken.
    control.publish(&bundle("5", backend.addr, false));
    wait_serving(
        &members.iter().collect::<Vec<_>>(),
        "5",
        Duration::from_secs(60),
        &control,
    )
    .await;

    // edge-2 is revoked: it receives no further revision and keeps serving its last one.
    let (status, body) = control.admin(
        "POST",
        "/api/v1/cluster/instances/edge-2/revoke",
        Some(&json!({})),
    );
    assert_eq!(status, 200, "{body}");
    control.publish(&bundle("6", backend.addr, false));
    wait_serving(
        &[&members[0], &members[1]],
        "6",
        Duration::from_secs(60),
        &control,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(
        probe(members[2].addr()).await.as_deref(),
        Some("5"),
        "a revoked instance takes no new revision"
    );
    let instances = control.instances();
    let edge2 = instances["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "edge-2")
        .unwrap()
        .clone();
    assert_eq!(edge2["state"], "revoked");
    wait_for(
        "edge-2 to report the refusal",
        Duration::from_secs(60),
        || {
            members[2].status()["cluster"]["error"]
                .as_str()
                .is_some_and(|e| e.contains("refused"))
        },
    )
    .await;

    // A join token works once: a fourth data plane presenting edge-0's is refused and exits.
    let (_, pin) = control.token();
    let config = format!(
        "cluster:\n  instance: edge-9\n  control:\n    url: \"https://127.0.0.1:{}\"\n    ca_pin: \"{pin}\"\n    join_token: \"${{file:{}}}\"\n",
        control.cluster,
        dir.path().join("join-0").display()
    );
    let refused = Rdock::try_start_with_env(RDOCK, &config, &[("DP_PORT", "1")])
        .err()
        .unwrap_or_default();
    assert!(refused.contains("join token is not valid"), "{refused}");
    // A wrong pin is refused before anything is sent.
    let (token, _) = control.token();
    std::fs::write(dir.path().join("join-x"), token).unwrap();
    let config = format!(
        "cluster:\n  instance: edge-8\n  control:\n    url: \"https://127.0.0.1:{}\"\n    ca_pin: \"sha256:{}\"\n    join_token: \"${{file:{}}}\"\n",
        control.cluster,
        "0".repeat(64),
        dir.path().join("join-x").display()
    );
    let log = Rdock::try_start_with_env(RDOCK, &config, &[("DP_PORT", "1")])
        .err()
        .expect("a data plane started against a control plane whose CA does not match its pin");
    assert!(log.contains("pinned digest"), "{log}");
    members.clear();
}

fn rollout(control: &Control) -> Value {
    let (status, body) = control.admin("GET", "/api/v1/cluster/rollout", None);
    assert_eq!(status, 200, "{body}");
    body
}

/// Staged rollout (H-HA-02): a revision reaches the canary (named in `control.rollout.canary`)
/// first and the other instances only after the soak time; abandoning a rollout during the
/// soak sends the canary back; a refusal by the canary halts the rollout with the other
/// instances left on the stable revision, visible and audited; resuming lets them take it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // one scenario, in order
async fn a_revision_reaches_the_canary_first_and_a_refusal_halts_the_rollout() {
    const SOAK: u64 = 8;
    let backend = Backend::start("app").await;
    let control = Control::start_with(&format!(
        "  rollout: {{ canary: edge-1, soak: {SOAK}s, canary_timeout: 60s }}\n"
    ));
    let dir = tempfile::tempdir().unwrap();
    control.publish(&bundle("1", backend.addr, false));
    // Only edge-0 and edge-2 have DP_EXTRA: a revision that needs it is refused by the canary.
    let members: Vec<Member> = (0..3)
        .map(|i| {
            let env: &[(&str, &str)] = if i == 1 { &[] } else { &[("DP_EXTRA", "here")] };
            join_with(&control, i, dir.path(), free_port(), env)
        })
        .collect();
    let all: Vec<&Member> = members.iter().collect();
    let others = [&members[0], &members[2]];
    // The first revision of a cluster goes everywhere at once.
    wait_serving(&all, "1", Duration::from_secs(60), &control).await;
    wait_for("three online instances", Duration::from_secs(30), || {
        control.instances()["instances"]
            .as_array()
            .is_some_and(|l| l.len() == 3 && l.iter().all(|i| i["state"] == "synced"))
    })
    .await;

    // Revision 2: the canary first, the others only after the soak time.
    control.publish(&bundle("2", backend.addr, false));
    wait_serving(&[&members[1]], "2", Duration::from_secs(60), &control).await;
    let canary_took = Instant::now();
    let state = rollout(&control);
    assert_eq!(state["canary"], "edge-1", "{state}");
    assert_eq!(state["stable"], 1, "{state}");
    while canary_took.elapsed() < Duration::from_secs(SOAK - 2) {
        for m in others {
            assert_eq!(
                probe(m.addr()).await.as_deref(),
                Some("1"),
                "an instance took revision 2 before the canary's soak time ended"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let instances = control.instances();
    let edge0 = instances["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "edge-0")
        .unwrap()
        .clone();
    assert_eq!(edge0["state"], "behind", "{instances}");
    assert_eq!(edge0["target"], 1, "{instances}");
    wait_serving(&all, "2", Duration::from_secs(60), &control).await;
    wait_for(
        "the rollout of revision 2 to complete",
        Duration::from_secs(30),
        || {
            let state = rollout(&control);
            state["phase"] == "complete" && state["stable"] == 2
        },
    )
    .await;

    // Revision 3 reaches the canary; abandoning during the soak sends it back: revision 4
    // republishes revision 2's configuration and every instance takes it at once.
    control.publish(&bundle("3", backend.addr, false));
    wait_serving(&[&members[1]], "3", Duration::from_secs(60), &control).await;
    wait_for(
        "the canary's acknowledgement",
        Duration::from_secs(30),
        || rollout(&control)["phase"] == "soaking",
    )
    .await;
    let (status, body) = control.admin("POST", "/api/v1/cluster/rollout/abandon", Some(&json!({})));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revision"], 4, "{body}");
    assert_eq!(body["rollback_of"], 2, "{body}");
    wait_serving(&all, "2", Duration::from_secs(30), &control).await;
    wait_for(
        "every instance on revision 4",
        Duration::from_secs(30),
        || {
            members
                .iter()
                .all(|m| m.status()["cluster"]["serving"] == 4)
        },
    )
    .await;
    let revisions = control.admin("GET", "/api/v1/cluster/revisions", None).1;
    let three = revisions["revisions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["revision"] == 3)
        .unwrap()
        .clone();
    assert_eq!(three["rollout"]["state"], "abandoned", "{revisions}");
    // Nothing left to abandon or resume.
    assert_eq!(
        control
            .admin("POST", "/api/v1/cluster/rollout/abandon", Some(&json!({})))
            .0,
        409
    );

    // Revision 5 needs DP_EXTRA, which the canary lacks: it refuses, the rollout halts, and
    // the others stay on revision 4 well past the soak time.
    let mut five = bundle("5", backend.addr, false);
    five["middlewares"]["tag"]["response"]["set"]["X-Extra"] = json!("${env:DP_EXTRA}");
    control.publish(&five);
    wait_for(
        "the rollout of revision 5 to halt",
        Duration::from_secs(60),
        || rollout(&control)["phase"] == "halted",
    )
    .await;
    let state = rollout(&control);
    assert_eq!(state["halt"]["instance"], "edge-1", "{state}");
    assert!(
        state["halt"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("edge-1 refused revision 5")),
        "{state}"
    );
    tokio::time::sleep(Duration::from_secs(SOAK + 3)).await;
    for m in &members {
        assert_eq!(probe(m.addr()).await.as_deref(), Some("2"));
        assert_eq!(m.status()["cluster"]["serving"], 4);
    }
    let instances = control.instances();
    let edge1 = instances["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "edge-1")
        .unwrap()
        .clone();
    assert_eq!(edge1["state"], "error", "{instances}");
    assert!(
        edge1["last_error"]
            .as_str()
            .is_some_and(|e| e.starts_with("revision 5:")),
        "{instances}"
    );
    let revisions = control.admin("GET", "/api/v1/cluster/revisions", None).1;
    assert_eq!(revisions["revisions"][0]["revision"], 5);
    assert_eq!(revisions["revisions"][0]["rollout"]["state"], "halted");
    let audit = control.admin("GET", "/api/v1/audit?limit=50", None).1;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["action"].as_str())
        .collect();
    assert!(actions.contains(&"cluster.rollout.halt"), "{audit}");
    assert!(actions.contains(&"cluster.rollout.abandon"), "{audit}");

    // Resume: the others take revision 5; the canary, which refused it, stays on 4.
    let (status, body) = control.admin("POST", "/api/v1/cluster/rollout/resume", Some(&json!({})));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["phase"], "complete", "{body}");
    wait_serving(&others, "5", Duration::from_secs(30), &control).await;
    assert_eq!(probe(members[1].addr()).await.as_deref(), Some("2"));
    let audit = control.admin("GET", "/api/v1/audit?limit=50", None).1;
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "cluster.rollout.resume"),
        "{audit}"
    );
}

/// The status of `GET <path>` on `addr`, sent from the loopback address `source` (each phase
/// of the limits test is its own client), or `None` when the request fails.
async fn status_from(addr: SocketAddr, path: &str, source: std::net::Ipv4Addr) -> Option<u16> {
    let work = async {
        let socket = tokio::net::TcpSocket::new_v4().ok()?;
        socket.bind(SocketAddr::from((source, 0))).ok()?;
        let mut stream = socket.connect(addr).await.ok()?;
        stream
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .ok()?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.ok()?;
        String::from_utf8_lossy(&raw)
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    };
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .ok()
        .flatten()
}

/// Requests to `path` from `source`, `rounds` times round-robin over the members: how many
/// each admitted (`200`); every other answer must be `429`.
async fn admitted(
    members: &[Member],
    path: &str,
    source: std::net::Ipv4Addr,
    rounds: usize,
) -> Vec<u64> {
    let mut counts = vec![0u64; members.len()];
    for _ in 0..rounds {
        for (i, m) in members.iter().enumerate() {
            match status_from(m.addr(), path, source).await {
                Some(200) => counts[i] += 1,
                Some(429) => {}
                other => panic!("{path} on edge-{i}: {other:?}\n{}", m.rdock.log()),
            }
        }
        // An instance admits from what it has claimed (and, for a key new to it, up to its
        // share until its first claim returns) and never waits for the store, so the pause
        // between rounds needs no room for a store round trip.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    counts
}

fn metric(member: &Member, name: &str) -> Option<f64> {
    let (_, text) = member.rdock.get_admin("/metrics").unwrap_or_default();
    text.lines()
        .find(|l| l.starts_with(name) && l[name.len()..].starts_with(' '))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

/// Cluster-scoped limits (H-HA-04): three data planes share a `rate_limit` and a `quota` of
/// 30 through the control plane's store and admit at least the limit less one headroom per
/// instance and no more than the documented bound `L + N × max(c, ⌈L / N⌉)` =
/// 30 + 3 × max(⌈30 × 10 / 300⌉, ⌈30 / 3⌉) = 60; with the control plane stopped each falls
/// back to its share ⌈30 / 3⌉ = 10 (counted by a metric and logged); when it returns they
/// share again within the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // one scenario, in order
async fn three_data_planes_share_cluster_scoped_limits() {
    const LIMIT: u64 = 30;
    // L + N × max(c, ⌈L / N⌉) with L = 30, N = 3, c = 1.
    const BOUND: u64 = 60;
    // Fixed windows of an hour from the epoch: do not start within two minutes of the end of
    // one, so the scenario stays inside a single window.
    let into_hour = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        % 3600;
    if into_hour > 3600 - 120 {
        tokio::time::sleep(Duration::from_secs(3600 - into_hour + 2)).await;
    }
    let backend = Backend::start("app").await;
    let mut control = Control::start();
    let dir = tempfile::tempdir().unwrap();
    let document = json!({
        "acme": false,
        "listeners": { "web": { "address": "127.0.0.1:${env:DP_PORT}" } },
        "defaults": { "listeners": ["web"], "tls": "off" },
        "routes": {
            "rl": { "match": "PathPrefix(`/rl`)", "service": "app", "middlewares": ["shared-rate"] },
            "q": { "match": "PathPrefix(`/q`)", "service": "app", "middlewares": ["keys", "shared-quota"] },
            "app": { "match": "PathPrefix(`/`)", "service": "app", "priority": 1, "middlewares": ["tag"] },
        },
        "services": { "app": { "backends": [{ "address": backend.addr.to_string() }] } },
        "middlewares": {
            "tag": { "type": "headers", "response": { "set": { "X-Revision": "1" } } },
            "shared-rate": { "type": "rate_limit", "average": LIMIT, "period": "1h", "burst": 1000, "scope": "cluster" },
            "keys": { "type": "api_key", "anonymous": "allow" },
            "shared-quota": { "type": "quota", "limit": LIMIT, "window": "hour", "scope": "cluster" },
        },
    });
    control.publish(&document);
    let extra = "  limits:\n    sync_interval: 200ms\n    headroom_percent: 10\n";
    let members: Vec<Member> = (0..3)
        .map(|i| join_full(&control, i, dir.path(), free_port(), &[], extra))
        .collect();
    wait_serving(
        &members.iter().collect::<Vec<_>>(),
        "1",
        Duration::from_secs(60),
        &control,
    )
    .await;
    wait_for(
        "three members sharing limits",
        Duration::from_secs(60),
        || {
            members.iter().all(|m| {
                metric(m, "rdock_cluster_limits_members") == Some(3.0)
                    && metric(m, "rdock_cluster_limits_store_up") == Some(1.0)
            })
        },
    )
    .await;

    // Shared: the cluster admits at least the limit and at most the bound.
    let first = std::net::Ipv4Addr::new(127, 0, 0, 11);
    for path in ["/rl", "/q"] {
        let counts = admitted(&members, path, first, 60).await;
        let total: u64 = counts.iter().sum();
        assert!(
            (LIMIT - 3..=BOUND).contains(&total),
            "{path}: the cluster admitted {total} ({counts:?}), bound {BOUND}\n{}",
            members
                .iter()
                .map(|m| m.rdock.log())
                .collect::<Vec<_>>()
                .join("\n----\n")
        );
        assert!(
            counts.iter().all(|c| *c > 0),
            "{path}: every instance took part ({counts:?})"
        );
    }

    // The store goes away: each instance falls back to its share of a fresh client's budget,
    // says so in its log and its metric, and no request fails for it.
    control.kill();
    wait_for(
        "every instance to see the limit store away",
        Duration::from_secs(60),
        || {
            members
                .iter()
                .all(|m| metric(m, "rdock_cluster_limits_store_up") == Some(0.0))
        },
    )
    .await;
    let second = std::net::Ipv4Addr::new(127, 0, 0, 12);
    for path in ["/rl", "/q"] {
        let counts = admitted(&members, path, second, 25).await;
        assert_eq!(
            counts,
            vec![10, 10, 10],
            "{path}: ⌈30 / 3⌉ per instance while the store is away"
        );
    }
    for m in &members {
        assert!(
            m.rdock
                .log()
                .contains("cluster-scoped limits fall back to each instance's share"),
            "{}",
            m.rdock.log()
        );
    }

    // It returns: shared again, within the bound, for a third client.
    control.spawn();
    wait_for(
        "every instance to see the limit store again",
        Duration::from_secs(90),
        || {
            members
                .iter()
                .all(|m| metric(m, "rdock_cluster_limits_store_up") == Some(1.0))
        },
    )
    .await;
    let third = std::net::Ipv4Addr::new(127, 0, 0, 13);
    for path in ["/rl", "/q"] {
        let counts = admitted(&members, path, third, 60).await;
        let total: u64 = counts.iter().sum();
        assert!(
            (LIMIT - 3..=BOUND).contains(&total),
            "{path} after the store returned: {total} ({counts:?}), bound {BOUND}"
        );
    }
    // The second client's fallback admissions were added to the store's count, which leaves
    // nothing for it: at most each instance's headroom of 1 more.
    let counts = admitted(&members, "/q", second, 10).await;
    assert!(counts.iter().sum::<u64>() <= 3, "{counts:?}");
    assert!(
        members.iter().all(
            |m| metric(m, "rdock_cluster_limit_claims_total{outcome=\"forced\"}").unwrap_or(0.0)
                >= 1.0
        ),
        "fallback admissions were reconciled"
    );
}

/// Cluster-scoped limits through a Redis-compatible server (the testkit's in-process RESP
/// server, with a password read from a file reference): three `rdock run` without a control
/// plane share a `rate_limit` within the bound, fall back to their share while the server is
/// stopped, and share again when it returns. The password never reaches the logs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_instances_share_a_limit_through_redis() {
    const PASSWORD: &str = "redis-test-password-0123456789";
    let into_hour = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        % 3600;
    if into_hour > 3600 - 120 {
        tokio::time::sleep(Duration::from_secs(3600 - into_hour + 2)).await;
    }
    let backend = Backend::start("app").await;
    let mut redis = rdock_testkit::redis::FakeRedis::start(Some(PASSWORD)).await;
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("redis-password");
    std::fs::write(&secret, format!("{PASSWORD}\n")).unwrap();
    let members: Vec<Member> = (0..3)
        .map(|i| {
            let port = free_port();
            let config = format!(
                "cluster:\n  instance: edge-{i}\n  limits:\n    store: redis\n    sync_interval: 200ms\n    redis:\n      url: \"redis://127.0.0.1:{}/1\"\n      password: \"${{file:{}}}\"\n      timeout: 300ms\n\
acme: false\nlisteners: {{ web: {{ address: \"127.0.0.1:{port}\" }} }}\n\
defaults: {{ listeners: [web], tls: \"off\" }}\n\
routes:\n  rl: {{ match: \"PathPrefix(`/rl`)\", service: app, middlewares: [shared-rate] }}\n\
services: {{ app: {{ backends: [{{ address: \"{}\" }}] }} }}\n\
middlewares:\n  shared-rate: {{ type: rate_limit, average: 30, period: 1h, burst: 1000, scope: cluster }}\n",
                redis.addr.port(),
                secret.display(),
                backend.addr
            );
            let rdock = Rdock::try_start_with_env(RDOCK, &config, &[])
                .unwrap_or_else(|log| panic!("edge-{i} did not start:\n{log}"));
            let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            Member { rdock, port, _busy: busy }
        })
        .collect();
    wait_for(
        "three members sharing limits through redis",
        Duration::from_secs(60),
        || {
            members.iter().all(|m| {
                metric(m, "rdock_cluster_limits_members") == Some(3.0)
                    && metric(m, "rdock_cluster_limits_store_up") == Some(1.0)
            })
        },
    )
    .await;
    let counts = admitted(&members, "/rl", std::net::Ipv4Addr::new(127, 0, 0, 21), 60).await;
    let total: u64 = counts.iter().sum();
    assert!((27..=60).contains(&total), "{total} ({counts:?})");
    assert!(redis.commands() > 0);
    // Stopped: each instance admits its share ⌈30 / 3⌉ of a fresh client's budget.
    redis.stop();
    wait_for(
        "every instance to see redis away",
        Duration::from_secs(60),
        || {
            members
                .iter()
                .all(|m| metric(m, "rdock_cluster_limits_store_up") == Some(0.0))
        },
    )
    .await;
    let counts = admitted(&members, "/rl", std::net::Ipv4Addr::new(127, 0, 0, 22), 25).await;
    assert_eq!(counts, vec![10, 10, 10]);
    // Back: shared again within the bound.
    redis.resume().await;
    wait_for(
        "every instance to see redis again",
        Duration::from_secs(60),
        || {
            members
                .iter()
                .all(|m| metric(m, "rdock_cluster_limits_store_up") == Some(1.0))
        },
    )
    .await;
    let counts = admitted(&members, "/rl", std::net::Ipv4Addr::new(127, 0, 0, 23), 60).await;
    let total: u64 = counts.iter().sum();
    assert!((27..=60).contains(&total), "{total} ({counts:?})");
    for m in &members {
        let log = m.rdock.log();
        assert!(!log.contains(PASSWORD), "the password is in a log:\n{log}");
        assert!(log.contains("cluster-scoped limits fall back"), "{log}");
    }
}

#[test]
fn a_control_plane_refuses_data_plane_sections_and_rdock_run_refuses_control() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("control.yaml");
    std::fs::write(&file, "control: {}\nroutes: { a: { match: \"PathPrefix(`/`)\", service: s } }\nservices: { s: { backends: [{ address: \"127.0.0.1:1\" }] } }\n").unwrap();
    let output = Command::new(RDOCK)
        .args(["control", "run", "-c"])
        .arg(&file)
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not serve traffic"), "{stderr}");
    let run = dir.path().join("run.yaml");
    std::fs::write(&run, "control: {}\n").unwrap();
    let output = Command::new(RDOCK)
        .args(["run", "-c"])
        .arg(&run)
        .arg("--data-dir")
        .arg(dir.path().join("run-data"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("rdock control run"));
}

/// Forwards each connection on `listen` to the next of `targets` in turn, so consecutive
/// validation requests of a CA reach different instances.
async fn round_robin(listen: SocketAddr, targets: Vec<SocketAddr>) -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
    tokio::spawn(async move {
        let mut next = 0usize;
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                continue;
            };
            let target = targets[next % targets.len()];
            next += 1;
            tokio::spawn(async move {
                if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    })
}

/// A revision ordering certificates for `names` from `directory` (with `root` as the CA's
/// HTTPS root), answering on each data plane's own ports.
fn acme_bundle(
    directory: &str,
    root: &Path,
    names: &[&str],
    challenge: &str,
    backend: SocketAddr,
    bind: &str,
) -> Value {
    let routes: serde_json::Map<String, Value> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            (
                format!("r{i}"),
                json!({ "match": format!("Host(`{n}`)"), "service": "app" }),
            )
        })
        .collect();
    json!({
        "acme": { "ca": directory, "ca_root": root.display().to_string(), "challenges": [challenge] },
        "listeners": {
            "web": { "address": format!("{bind}:${{env:DP_PORT}}") },
            "websecure": { "address": format!("{bind}:${{env:DP_TLS_PORT}}"), "tls": {} },
        },
        "routes": routes,
        "services": { "app": { "backends": [{ "address": backend.to_string() }] } },
    })
}

/// The leaf each data plane serves for `name` over TLS (trusting `issuer`).
async fn leaves(tls_ports: &[u16], name: &str, issuer: &str) -> Vec<Option<Vec<u8>>> {
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pki_types::CertificateDer::pem_slice_iter(issuer.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    let mut out = Vec::new();
    for port in tls_ports {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let leaf = match rdock_testkit::client::tls_connect(addr, name, config.clone()).await {
            Ok(stream) => stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.as_ref().to_vec()),
            Err(_) => None,
        };
        out.push(leaf);
    }
    out
}

async fn wait_same_certificate(
    tls_ports: &[u16],
    names: &[&str],
    issuer: &str,
    within: Duration,
    logs: &dyn Fn() -> String,
) {
    let deadline = Instant::now() + within;
    loop {
        let mut done = true;
        for name in names {
            let served = leaves(tls_ports, name, issuer).await;
            if !(served[0].is_some() && served.iter().all(|l| *l == served[0])) {
                done = false;
            }
        }
        if done {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the data planes did not converge on one certificate per name\n{}",
            logs()
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Proof 2 with the control plane as the store, without Docker: three data planes need the
/// same names at once; the testkit's fake CA (which asks every instance for the HTTP-01
/// answer) counts exactly one order per name, and all three serve the same certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_data_planes_issue_once_through_the_control_plane_store() {
    use rdock_testkit::fake_acme::FakeAcme;
    let backend = Backend::start("app").await;
    let control = Control::start();
    let dir = tempfile::tempdir().unwrap();
    let ports: Vec<(u16, u16)> = (0..3).map(|_| (free_port(), free_port())).collect();
    let http: Vec<SocketAddr> = ports
        .iter()
        .map(|(h, _)| format!("127.0.0.1:{h}").parse().unwrap())
        .collect();
    let fake = FakeAcme::start(http, Vec::new()).await;
    let root = dir.path().join("root.pem");
    std::fs::write(&root, fake.root_pem()).unwrap();
    let names = ["a.example.com", "b.example.com", "c.example.com"];
    control.publish(&acme_bundle(
        &fake.directory(),
        &root,
        &names,
        "http-01",
        backend.addr,
        "127.0.0.1",
    ));
    let members: Vec<Member> = ports
        .iter()
        .enumerate()
        .map(|(i, (h, t))| {
            let t = t.to_string();
            join_with(&control, i, dir.path(), *h, &[("DP_TLS_PORT", t.as_str())])
        })
        .collect();
    let tls_ports: Vec<u16> = ports.iter().map(|(_, t)| *t).collect();
    let logs = || {
        format!(
            "{}\n----\n{}",
            members
                .iter()
                .map(|m| m.rdock.log())
                .collect::<Vec<_>>()
                .join("\n----\n"),
            control.log()
        )
    };
    wait_same_certificate(
        &tls_ports,
        &names,
        fake.issuing_pem(),
        Duration::from_secs(90),
        &logs,
    )
    .await;
    let once: std::collections::BTreeMap<String, usize> =
        names.iter().map(|n| ((*n).to_owned(), 1)).collect();
    assert_eq!(fake.orders_created(), once, "{:?}", fake.failures());
    assert_eq!(fake.issued(), once);
    // The certificates and the account live in the control plane's store, keys private.
    let store = control.data().join("control/store");
    for name in names {
        let key = store.join("certs").join(name).join("key.pem");
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&key).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600, "{}", key.display());
    }
    assert!(
        std::fs::read_dir(store.join("accounts")).unwrap().count() == 1,
        "one shared ACME account"
    );
}

/// Proof 2 against Pebble (Let's Encrypt's test CA, in Docker; CI sets `RDOCK_ACME_TESTS=1`):
/// three data planes behind a round-robin forwarder on the validation ports, the control plane
/// as the store. Asserted at the CA (its log): one issuance per name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_data_planes_issue_once_against_pebble() {
    if !std::env::var("RDOCK_ACME_TESTS").is_ok_and(|v| v == "1") {
        eprintln!("skipped: set RDOCK_ACME_TESTS=1 to run against Pebble in Docker");
        return;
    }
    let backend = Backend::start("app").await;
    let control = Control::start();
    let dir = tempfile::tempdir().unwrap();
    let (http_port, tls_port) = (free_port(), free_port());
    let pebble = rdock_testkit::pebble::Pebble::start(http_port, tls_port);
    let ports: Vec<(u16, u16)> = (0..3).map(|_| (free_port(), free_port())).collect();
    let _http = round_robin(
        format!("0.0.0.0:{http_port}").parse().unwrap(),
        ports
            .iter()
            .map(|(h, _)| format!("127.0.0.1:{h}").parse().unwrap())
            .collect(),
    )
    .await;
    let _tls = round_robin(
        format!("0.0.0.0:{tls_port}").parse().unwrap(),
        ports
            .iter()
            .map(|(_, t)| format!("127.0.0.1:{t}").parse().unwrap())
            .collect(),
    )
    .await;
    let names = [
        "a.example.com",
        "b.example.com",
        "c.example.com",
        "d.example.com",
        "e.example.com",
    ];
    control.publish(&acme_bundle(
        &pebble.directory,
        &pebble.endpoint_root(),
        &names,
        "http-01",
        backend.addr,
        "127.0.0.1",
    ));
    let members: Vec<Member> = ports
        .iter()
        .enumerate()
        .map(|(i, (h, t))| {
            let t = t.to_string();
            join_with(&control, i, dir.path(), *h, &[("DP_TLS_PORT", t.as_str())])
        })
        .collect();
    let tls_ports: Vec<u16> = ports.iter().map(|(_, t)| *t).collect();
    let logs = || {
        members
            .iter()
            .map(|m| m.rdock.log())
            .collect::<Vec<_>>()
            .join("\n----\n")
    };
    wait_same_certificate(
        &tls_ports,
        &names,
        &pebble.issuing_root(),
        Duration::from_secs(120),
        &logs,
    )
    .await;
    assert_eq!(
        pebble.issued_count(),
        names.len(),
        "exactly one issuance per name at the CA\n{}",
        logs()
    );
}
