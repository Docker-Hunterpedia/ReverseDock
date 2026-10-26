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
        text.contains("warning: providers.docker: the Docker provider: not supported in this version (planned for v0.2)"),
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
