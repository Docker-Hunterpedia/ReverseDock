//! Data-directory compatibility (ADR-0033, `docs/10-stability.md`: "a release that cannot read
//! the directory of either of the two minors before it" is breaking). Each test writes a data
//! directory the way an earlier release left it, byte for byte in the shapes that release
//! wrote, and starts the current binary on it.
//!
//! Covered here: the last-known-good copy and the history (`state/`), the users file
//! (`admin/users.json`), the audit chain (`audit/`) and the format marker (`rdock.format`,
//! written since 0.9). Certificates of the 0.8 layout (`meta.json` without `chain_sha256`, no
//! `next/`) are covered by `a_pre_0_9_directory_loads_and_renews` in `rdock-acme`, the quota
//! counters by the tests of `rdock-limits`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

/// The `prev` of the first audit record.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn sha256_hex(text: &str) -> String {
    use std::fmt::Write;
    ring::digest::digest(&ring::digest::SHA256, text.as_bytes())
        .as_ref()
        .iter()
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn write(dir: &Path, path: &str, text: &str) {
    let full = dir.join(path);
    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
    std::fs::write(full, text).unwrap();
}

/// A configuration document as `state/lkg.json` and the history store it (as written).
fn document(port: u16) -> String {
    let admin = free_port();
    format!(
        r#"{{
  "admin": {{ "listener": "127.0.0.1:{admin}" }},
  "listeners": {{ "web": {{ "address": "127.0.0.1:{port}" }} }},
  "routes": {{ "app": {{ "match": "PathPrefix(`/`)", "service": "app", "listeners": ["web"] }} }},
  "services": {{ "app": {{ "backends": [{{ "address": "127.0.0.1:9" }}] }} }}
}}
"#
    )
}

/// The files 0.8 wrote. `tenant` marks the fields 0.9 added (absent in 0.8).
fn layout(dir: &Path, port: u16, release: &str) {
    let source = document(port);
    write(dir, "state/lkg.json", &source);
    let entry = format!(
        r#"{{"applied_at_ms":1790000000000,"generation":1,"summary":"written by {release}","source":{source}}}"#
    );
    write(
        dir,
        "state/history/1790000000000-0123456789abcdef.json",
        &entry,
    );
    let password = {
        use argon2::password_hash::PasswordHasher;
        argon2::Argon2::default()
            .hash_password(b"not a real password")
            .unwrap()
            .to_string()
    };
    let tenant = if release == "0.9" {
        r#","tenant":null"#
    } else {
        ""
    };
    write(
        dir,
        "admin/users.json",
        &format!(
            r#"{{"version":1,"users":[{{"name":"alice","role":"admin","password":"{password}","created_at":1790000000,"disabled":false{tenant}}}]}}"#
        ),
    );
    // Two audit records chained by the SHA-256 of the previous line.
    let first = format!(
        r#"{{"action":"login","actor":"alice","client":"127.0.0.1","method":"POST","prev":"{GENESIS}","reason":null,"resource":null,"result":"ok","seq":1,"time":"2026-09-20T10:00:00Z"}}"#
    );
    let second = format!(
        r#"{{"action":"config.reload","actor":"alice","client":"127.0.0.1","method":"POST","prev":"{}","reason":null,"resource":null,"result":"ok","seq":2,"time":"2026-09-20T10:00:05Z"}}"#,
        sha256_hex(&first)
    );
    write(
        dir,
        "audit/audit-000000000001.jsonl",
        &format!("{first}\n{second}\n"),
    );
    if release == "0.9" {
        write(dir, "rdock.format", "1\n");
    }
}

fn audit_verify(data_dir: &Path) -> (bool, String) {
    let output = Command::new(RDOCK)
        .args(["audit", "verify", "--data-dir"])
        .arg(data_dir)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr),
    )
}

fn reads_the_directory_of(release: &str) {
    let port = free_port();
    // A configuration file that cannot be used: the start falls back to the copy in the data
    // directory, so the current binary must read what the earlier release wrote.
    let mut rdock = Rdock::try_start_prepared(RDOCK, "routes: [not valid", |dir| {
        layout(dir, port, release);
        let (ok, out) = audit_verify(dir);
        assert!(ok, "the {release} audit chain does not verify: {out}");
    })
    .unwrap_or_else(|log| panic!("rdock did not start on a {release} data directory:\n{log}"));
    let (status, body) = rdock.get_admin("/api/v1/status").unwrap();
    assert_eq!(status, 200, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["origin"], "last-known-good", "{body}");
    let (status, body) = rdock.get_admin("/api/v1/users").unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"alice\""), "{body}");
    let (status, body) = rdock.get_admin("/api/v1/config/history").unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(&format!("written by {release}")), "{body}");
    rdock.stop(std::time::Duration::from_secs(10));
    let data = rdock.data_dir();
    // The format marker is written (or kept), and the audit chain still verifies after the
    // current binary appended to it.
    assert_eq!(
        std::fs::read_to_string(data.join("rdock.format")).unwrap(),
        "1\n"
    );
    let (ok, out) = audit_verify(&data);
    assert!(ok, "{out}");
}

#[test]
fn reads_a_data_directory_written_by_0_8() {
    reads_the_directory_of("0.8");
}

#[test]
fn reads_a_data_directory_written_by_0_9() {
    reads_the_directory_of("0.9");
}

#[test]
fn refuses_a_newer_format() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "rdock.format", "2\n");
    let output = Command::new(RDOCK)
        .args(["run", "--no-watch", "-c"])
        .arg(dir.path().join("missing.yaml"))
        .arg("--data-dir")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("newer than this binary understands"),
        "{text}"
    );
}
