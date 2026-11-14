//! The Compose corpus with golden output (ADR-0033, layer 2 of "conformance-tested"): every
//! directory under `tests/conformance/traefik-compose/` holds an input (`case.json` names it
//! and the options), the expected `rdock migrate traefik` output (`expected.yaml`) and report
//! (`report.json`). The test also checks that every source item is accounted for, that the
//! output reads as rdock.yaml and validates, and that no credential found in the input reaches
//! the output. `RDOCK_UPDATE_GOLDEN=1` (or `just migrate-golden`) rewrites the golden files.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use rdock_migrate::{Options, StaticFile, compose, report::Level, traefik};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    input: String,
    exercises: Vec<String>,
    diff: bool,
    #[serde(default)]
    args: Args,
    /// Validation errors the output is expected to have (a fragment that refers to something
    /// the rest of rdock.yaml defines, or a manual finding), each as a part of the message.
    #[serde(default)]
    expect_invalid: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(default)]
    full: bool,
    #[serde(default)]
    expose_by_default: bool,
    #[serde(default)]
    env_file: Option<String>,
    #[serde(default, rename = "static")]
    static_file: Option<String>,
}

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/traefik-compose")
}

/// Values in inputs that look like credentials; none may reach an output.
const SECRETS: [&str; 1] = ["not-copied-example-value"];

#[test]
#[allow(clippy::too_many_lines)] // one pass over the corpus, every check in order
fn compose_corpus_matches_the_golden_files() {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(corpus())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    assert!(
        dirs.len() >= 40,
        "the corpus needs at least 40 cases, found {}",
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
        let text = std::fs::read_to_string(dir.join(&case.input)).unwrap();
        assert!(
            text.contains("Exercises:"),
            "{name}: the input's header comment must state what it exercises"
        );
        let vars = match &case.args.env_file {
            Some(file) => compose::env_file(
                &std::fs::read_to_string(dir.join(file)).unwrap(),
                &compose::Vars::new(),
            )
            .unwrap(),
            None => compose::Vars::new(),
        };
        let options = Options {
            file: case.input.clone(),
            expose_by_default: case.args.expose_by_default,
            vars,
            static_file: case.args.static_file.as_ref().map(|f| StaticFile {
                name: f.clone(),
                text: std::fs::read_to_string(dir.join(f)).unwrap(),
            }),
            full: case.args.full,
        };
        // `traefik` fails when an item is not accounted for exactly once.
        let migration = traefik(&text, &options).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut report = serde_json::to_value(&migration.report).unwrap();
        report["rdock_version"] = "<version>".into();
        let report = serde_json::to_string_pretty(&report).unwrap() + "\n";
        let s = &migration.report.summary;
        assert_eq!(
            s.exact + s.approximate + s.manual + s.dropped,
            s.items,
            "{name}"
        );
        // The output reads as rdock.yaml and validates on its own.
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
            failures.push(format!(
                "{name}: the output does not validate as expected: unexpected {unexpected:?}, missing {unmet:?}"
            ));
        }
        // It reads as rdock.yaml; validation is the migration's own check above (a fragment is
        // checked with the static configuration's listeners, which `--full` writes).
        rdock_config::load_str(&migration.yaml, rdock_config::Format::Yaml)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        for secret in SECRETS {
            if migration.yaml.contains(secret) || report.contains(secret) {
                failures.push(format!("{name}: a credential reached the output"));
            }
        }
        if case.diff
            && migration
                .report
                .findings
                .iter()
                .any(|f| f.level == Level::Manual)
        {
            failures.push(format!(
                "{name}: a case for the differential test must have no manual finding"
            ));
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
