//! End-to-end tests of the `rdock` binary.

// Test helpers spawn the binary and decode its output; failing loudly is the point.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

fn rdock(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdock"))
        .args(args)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn validates_the_examples() {
    let output = rdock(&[
        "validate",
        "examples/config/rdock.full.yaml",
        "examples/config/rdock.minimal.json",
    ]);
    assert!(output.status.success(), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("examples/config/rdock.full.yaml: valid, "),
        "{text}"
    );
    assert!(
        text.contains("warning: observability.tracing: OpenTelemetry tracing: not supported in this version (planned for v0.4)"),
        "{text}"
    );
    let quickstart = rdock(&[
        "validate",
        "--strict",
        "examples/config/rdock.quickstart.yaml",
    ]);
    assert!(quickstart.status.success(), "{}", stdout(&quickstart));
    assert_eq!(
        stdout(&quickstart),
        "examples/config/rdock.quickstart.yaml: valid\n"
    );
}

#[test]
fn reports_errors_with_paths_and_hints() {
    let dir = std::env::temp_dir().join(format!("rdock-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("broken.yaml");
    std::fs::write(&file, "routes:\n  app:\n    match: \"Host(`a.example.com`)\"\n    service: ap\n    midlewares: []\nservices:\n  app:\n    backends: [{ address: \"app:3000\" }]\n").unwrap();
    let output = rdock(&["validate", file.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(
        text.contains(
            "error: routes.app.midlewares: unknown key `midlewares`\n    did you mean `middlewares`?"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "error: routes.app.service: service `ap` does not exist\n    did you mean `app`?"
        ),
        "{text}"
    );
    assert!(
        text.ends_with("broken.yaml: 2 errors, 0 warnings\n"),
        "{text}"
    );

    let json = rdock(&["validate", "--format", "json", file.to_str().unwrap()]);
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report[0]["errors"], 2);
    assert_eq!(report[0]["diagnostics"][1]["path"], "routes.app.service");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_files_are_errors() {
    let output = rdock(&["validate", "does-not-exist.yaml"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("cannot read does-not-exist.yaml"));
}

#[test]
fn private_names_go_to_the_local_ca_except_single_labels() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("local.yaml");
    std::fs::write(
        &file,
        "listeners:\n  websecure: { address: \":443\", tls: {} }\nroutes:\n  app:\n    match: \"Host(`app.localhost`) || Host(`nas`)\"\n    service: app\nservices:\n  app:\n    backends: [{ address: \"app:3000\" }]\n",
    )
    .unwrap();
    let output = rdock(&["validate", file.to_str().unwrap()]);
    let text = stdout(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("warning: routes.app.tls: no certificate authority, not even the local one, can certify the single-label name nas\n    use `nas.internal` or `nas.home.arpa`"),
        "{text}"
    );
    assert!(!text.contains("app.localhost"), "{text}");
}

#[test]
fn prints_the_committed_schema() {
    let output = rdock(&["schema"]);
    assert!(output.status.success());
    let committed = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schema/rdock.v1.json"),
    )
    .unwrap();
    assert_eq!(stdout(&output), committed);
}

#[test]
fn prints_version_information() {
    let output = rdock(&["version", "--json"]);
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(info["rustc"].as_str().unwrap().starts_with("rustc "));
    let text = stdout(&rdock(&["--version"]));
    assert_eq!(text, format!("rdock {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn hash_prints_a_verifiable_argon2id_entry() {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(env!("CARGO_BIN_EXE_rdock"))
        .args(["hash", "--user", "alice"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"s3cret\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = stdout(&output);
    let hash = text.trim_end().strip_prefix("alice:").unwrap();
    assert!(hash.starts_with("$argon2id$"), "{hash}");
    let parsed = PasswordHash::new(hash).unwrap();
    assert!(
        Argon2::default()
            .verify_password(b"s3cret", &parsed)
            .is_ok()
    );
    assert!(
        Argon2::default()
            .verify_password(b"s3cret\n", &parsed)
            .is_err()
    );

    let empty = Command::new(env!("CARGO_BIN_EXE_rdock"))
        .arg("hash")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(2));
}
