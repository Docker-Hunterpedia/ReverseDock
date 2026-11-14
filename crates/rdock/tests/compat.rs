//! The compatibility snapshots of ADR-0033 (`schema/compat/`): the committed files match what
//! the binary prints, and every `RDOCK_*` variable the code reads is either in the public list
//! (`schema/compat/env.json`) or internal by the stability page's rules.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Snapshots the binary prints with `rdock schema --compat <surface>`.
const SURFACES: [&str; 6] = [
    "metrics",
    "cli",
    "access-log",
    "problems",
    "env",
    "deprecations",
];

#[test]
fn committed_snapshots_are_current() {
    for surface in SURFACES {
        let output = Command::new(env!("CARGO_BIN_EXE_rdock"))
            .args(["schema", "--compat", surface])
            .output()
            .unwrap();
        assert!(output.status.success(), "{surface}: {output:?}");
        let printed = String::from_utf8(output.stdout).unwrap();
        let path = repo().join(format!("schema/compat/{surface}.json"));
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == printed,
            "schema/compat/{surface}.json is out of date; run `just compat` and commit the result"
        );
    }
}

/// Problem types are a stable surface (ADR-0033): the generic types rdock's own answers use
/// are stable in the snapshot, so the compatibility check fails when one is removed or its
/// status changes; only types a beta feature alone produces are exempt.
#[test]
fn generic_problem_types_are_stable() {
    let text = std::fs::read_to_string(repo().join("schema/compat/problems.json")).unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&text).unwrap();
    let problems = snapshot["problems"].as_object().unwrap();
    for slug in [
        "not-found",
        "bad-gateway",
        "service-unavailable",
        "rate-limited",
        "unauthenticated",
        "maintenance",
    ] {
        let entry = problems
            .iter()
            .find(|(uri, _)| uri.ends_with(&format!("#{slug}")))
            .unwrap_or_else(|| panic!("{slug} missing"))
            .1;
        assert_eq!(entry["maturity"], "stable", "{slug}: {entry}");
        assert_eq!(entry["feature"], "problem-types", "{slug}");
    }
    let validation = problems
        .iter()
        .find(|(uri, _)| uri.ends_with("#validation-failed"))
        .unwrap()
        .1;
    assert_eq!(validation["maturity"], "beta");
}

#[test]
fn snapshots_are_the_same_on_every_machine() {
    for surface in SURFACES {
        let text =
            std::fs::read_to_string(repo().join(format!("schema/compat/{surface}.json"))).unwrap();
        for word in ["/home/", "/Users/", "/tmp/", "target/debug", "\\\\"] {
            assert!(
                !text.contains(word),
                "schema/compat/{surface}.json names a machine path ({word})"
            );
        }
    }
}

/// `RDOCK_*` variables that are not part of the promise (`docs/10-stability.md`, the
/// environment variables row): build, test, fault-injection and benchmark hooks.
fn internal(name: &str) -> bool {
    name.starts_with("RDOCK_BUILD_")
        || name.ends_with("_TESTS")
        || name.starts_with("RDOCK_FAULT")
        || name.starts_with("RDOCK_TEST_")
        || name.starts_with("RDOCK_COMPAT_")
        || [
            "RDOCK_UPGRADE_FAULT",
            "RDOCK_UPDATE_GOLDEN",
            "RDOCK_ALLOC_COUNT_SOCKET",
        ]
        .contains(&name)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            // Integration tests, benchmarks and the test kit only run in tests.
            if !["tests", "benches", "target", "rdock-testkit", "examples"].contains(&name.as_str())
            {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs")
            && name != "tests.rs"
            && name != "testing.rs"
        {
            out.push(path);
        }
    }
}

/// `RDOCK_` followed by upper-case letters, digits and `_`, in quotes, in the part of the file
/// before its unit tests.
fn variables(text: &str) -> BTreeSet<String> {
    let code = text.split("#[cfg(test)]").next().unwrap_or_default();
    let mut out = BTreeSet::new();
    let mut rest = code;
    while let Some(at) = rest.find("\"RDOCK_") {
        let tail = &rest[at + 1..];
        let end = tail
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(tail.len());
        out.insert(tail[..end].to_owned());
        rest = &tail[end..];
    }
    out
}

#[test]
fn every_variable_the_code_reads_is_public_or_internal() {
    let snapshot: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("schema/compat/env.json")).unwrap(),
    )
    .unwrap();
    let public: BTreeSet<String> = snapshot["variables"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let mut files = Vec::new();
    rust_files(&repo().join("crates"), &mut files);
    let mut unknown = Vec::new();
    let mut seen = BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for name in variables(&text) {
            seen.insert(name.clone());
            if !public.contains(&name) && !internal(&name) {
                unknown.push(format!("{name} in {}", file.display()));
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "undocumented RDOCK_* variables (add them to PUBLIC_ENV in crates/rdock/src/compat.rs and to the environment reference, or name them by an internal pattern in docs/10-stability.md): {unknown:?}"
    );
    // The scan finds the ones it must.
    for name in ["RDOCK_ADMIN_TOKEN", "RDOCK_ZONE", "RDOCK_POD_NAME"] {
        assert!(seen.contains(name), "{name} not found by the scan");
    }
    // Every public variable is still read somewhere.
    for name in &public {
        assert!(
            seen.contains(name),
            "{name} is listed as public but nothing reads it"
        );
    }
}
