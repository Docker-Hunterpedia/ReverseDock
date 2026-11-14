//! The Caddy corpus with golden output (ADR-0033): every directory under
//! `tests/conformance/caddy-json/` holds a Caddyfile, the JSON `caddy adapt` makes of it
//! (`caddy.json`, written by hand in the shapes of Caddy v2.11.9's adapter; see the corpus
//! README), the expected `rdock migrate caddy` output (`expected.yaml`) and report
//! (`report.json`). The test also checks that every source item is accounted for, that the
//! output reads as rdock.yaml and validates, and that no credential reaches it.
//! `RDOCK_UPDATE_GOLDEN=1` (or `just migrate-golden`) rewrites the golden files.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use rdock_migrate::caddy::{Options, caddy};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    input: String,
    exercises: Vec<String>,
    /// Where the JSON shapes come from.
    source: String,
    #[serde(default)]
    full: bool,
    #[serde(default)]
    expect_invalid: Vec<String>,
}

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/caddy-json")
}

/// Values in inputs that look like credentials; none may reach an output.
const SECRETS: [&str; 2] = ["not-copied-example-value", "NOT-COPIED-PEM-KEY"];

#[test]
fn caddy_corpus_matches_the_golden_files() {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(corpus())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    assert!(
        dirs.len() >= 15,
        "the corpus needs at least 15 cases, found {}",
        dirs.len()
    );
    let update = std::env::var_os("RDOCK_UPDATE_GOLDEN").is_some_and(|v| v == "1");
    let mut failures = Vec::new();
    for dir in &dirs {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let case: Case =
            serde_json::from_str(&std::fs::read_to_string(dir.join("case.json")).unwrap())
                .unwrap_or_else(|e| panic!("{name}/case.json: {e}"));
        assert!(
            !case.exercises.is_empty(),
            "{name}: say what the case exercises"
        );
        assert!(
            case.source.contains("v2.11.9"),
            "{name}: cite the Caddy version of the shapes"
        );
        let caddyfile = std::fs::read_to_string(dir.join("Caddyfile")).unwrap_or_default();
        assert!(
            caddyfile.contains("Exercises:"),
            "{name}: the Caddyfile's header comment must state what it exercises"
        );
        let text = std::fs::read_to_string(dir.join(&case.input)).unwrap();
        let migration = caddy(
            &text,
            &Options {
                file: case.input.clone(),
                full: case.full,
            },
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut report = serde_json::to_value(&migration.report).unwrap();
        report["rdock_version"] = "<version>".into();
        let report = serde_json::to_string_pretty(&report).unwrap() + "\n";
        let s = &migration.report.summary;
        assert_eq!(
            s.exact + s.approximate + s.manual + s.dropped,
            s.items,
            "{name}"
        );
        for finding in &migration.report.findings {
            let code = rdock_migrate::report::code_info(&finding.code)
                .unwrap_or_else(|| panic!("{name}: {} is not listed", finding.code));
            assert_eq!(code.level, finding.level, "{name}: {}", finding.code);
        }
        let invalid: Vec<&str> = migration
            .report
            .findings
            .iter()
            .filter(|f| f.code == "output.invalid")
            .map(|f| f.message.as_str())
            .collect();
        let unexpected: Vec<&&str> = invalid
            .iter()
            .filter(|m| !case.expect_invalid.iter().any(|e| m.contains(e.as_str())))
            .collect();
        let unmet: Vec<&String> = case
            .expect_invalid
            .iter()
            .filter(|e| !invalid.iter().any(|m| m.contains(e.as_str())))
            .collect();
        if !unexpected.is_empty() || !unmet.is_empty() {
            failures.push(format!("{name}: the output does not validate as expected: unexpected {unexpected:?}, missing {unmet:?}"));
        }
        rdock_config::load_str(&migration.yaml, rdock_config::Format::Yaml)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        for secret in SECRETS {
            if migration.yaml.contains(secret) || report.contains(secret) {
                failures.push(format!("{name}: a credential reached the output"));
            }
        }
        for (file, actual) in [("expected.yaml", &migration.yaml), ("report.json", &report)] {
            let path = dir.join(file);
            if update {
                std::fs::write(&path, actual).unwrap();
            } else if std::fs::read_to_string(&path).unwrap_or_default() != **actual {
                failures.push(format!(
                    "{name}/{file} differs; run `just migrate-golden` and review the diff"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_caddyfile_is_refused_with_how_to_adapt_it() {
    let err = caddy(
        "example.com {\n\treverse_proxy app:8080\n}\n",
        &Options {
            file: "Caddyfile".into(),
            full: false,
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("caddy adapt --config Caddyfile"),
        "{err}"
    );
}
