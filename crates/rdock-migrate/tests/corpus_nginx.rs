//! The NGINX corpus with golden output (ADR-0033): every directory under
//! `tests/conformance/nginx/` holds a configuration (`case.json` names it), the expected
//! `rdock migrate nginx` output (`expected.yaml`) and report (`report.json`). The test also checks
//! that every directive is accounted for, that the output reads as rdock.yaml and validates, and
//! that no credential or referenced secret file reaches it. `RDOCK_UPDATE_GOLDEN=1` (or
//! `just migrate-golden`) rewrites the golden files.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use rdock_migrate::nginx::{Options, nginx};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    input: String,
    exercises: Vec<String>,
    /// Where the semantics come from.
    source: String,
    #[serde(default)]
    full: bool,
    #[serde(default)]
    include_outside: bool,
    #[serde(default)]
    expect_invalid: Vec<String>,
}

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/nginx")
}

#[test]
fn nginx_corpus_matches_the_golden_files() {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(corpus())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    assert!(
        dirs.len() >= 20,
        "the corpus needs at least 20 cases, found {}",
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
            case.source.contains("nginx.org"),
            "{name}: cite the official reference"
        );
        let path = dir.join(&case.input);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("Exercises:"),
            "{name}: the input's comment must state what it exercises"
        );
        let options = Options {
            file: case.input.clone(),
            path: Some(path),
            include_outside: case.include_outside,
            full: case.full,
        };
        let migration = nginx(&text, &options).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut report = serde_json::to_value(&migration.report).unwrap();
        report["rdock_version"] = "<version>".into();
        // Paths of included files are absolute on disk: keep them relative to the case.
        let prefix = format!("{}/", dir.display());
        let report = (serde_json::to_string_pretty(&report).unwrap() + "\n").replace(&prefix, "");
        let yaml = migration.yaml.replace(&prefix, "");
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
        for (file, actual) in [("expected.yaml", &yaml), ("report.json", &report)] {
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
fn referenced_secret_files_are_never_read() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("htpasswd"),
        "admin:not-copied-example-value\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("key.pem"), "NOT-COPIED-PEM-KEY\n").unwrap();
    let conf = "http { server { listen 443 ssl; server_name s.example.com; ssl_certificate cert.pem; ssl_certificate_key key.pem; auth_basic \"x\"; auth_basic_user_file htpasswd; location / { proxy_pass http://s:80; } } }\n";
    let path = dir.path().join("nginx.conf");
    std::fs::write(&path, conf).unwrap();
    let m = nginx(
        conf,
        &Options {
            file: "nginx.conf".into(),
            path: Some(path),
            include_outside: false,
            full: true,
        },
    )
    .unwrap();
    let report = serde_json::to_string(&m.report).unwrap();
    for secret in ["not-copied-example-value", "NOT-COPIED-PEM-KEY"] {
        assert!(
            !m.yaml.contains(secret) && !report.contains(secret),
            "{secret}"
        );
    }
    assert!(m.yaml.contains("users_file: htpasswd"), "{}", m.yaml);
}

#[test]
fn other_formats_are_refused() {
    let err = nginx(
        "{\"apps\":{}}",
        &Options {
            file: "caddy.json".into(),
            ..Options::default()
        },
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not an NGINX configuration"),
        "{err}"
    );
    let err = nginx(
        "foo bar;\n",
        &Options {
            file: "x.conf".into(),
            ..Options::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("no `http`"), "{err}");
}
