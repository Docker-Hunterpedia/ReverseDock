//! Every example configuration, and the canonical YAML in docs/05-architecture.md §3.1, loads
//! without diagnostics and matches the published JSON Schema.

// Test helpers read fixed repository files; failing loudly is the point.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use rdock_config::{Format, LoadOptions, load_file, load_str};

const STRICT: LoadOptions = LoadOptions { strict: true };

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(repo().join("examples/config"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "yaml" || e == "json"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 3,
        "expected example configs in examples/config"
    );
    files
}

/// The first YAML code block after the "### 3.1" heading.
fn architecture_yaml() -> String {
    let doc = std::fs::read_to_string(repo().join("docs/05-architecture.md")).unwrap();
    let section = &doc[doc.find("### 3.1").expect("§3.1 heading")..];
    let start = section.find("```yaml\n").expect("yaml block in §3.1") + "```yaml\n".len();
    let end = section[start..].find("```").expect("end of yaml block");
    section[start..start + end].to_owned()
}

fn schema_errors(instance: &serde_json::Value) -> Vec<String> {
    let schema = serde_json::to_value(rdock_model::json_schema()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    validator
        .iter_errors(instance)
        .map(|e| format!("{} at `{}`", e, e.instance_path()))
        .collect()
}

#[test]
fn examples_load_without_diagnostics() {
    for file in example_files() {
        let loaded = load_file(&file, STRICT).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        assert!(
            loaded.diagnostics.is_empty(),
            "{}: {:#?}",
            file.display(),
            loaded.diagnostics
        );
    }
}

#[test]
fn architecture_example_is_the_full_example() {
    let example = std::fs::read_to_string(repo().join("examples/config/rdock.full.yaml")).unwrap();
    assert_eq!(
        architecture_yaml(),
        example,
        "docs/05-architecture.md §3.1 and examples/config/rdock.full.yaml differ"
    );
}

#[test]
fn architecture_example_loads_without_diagnostics() {
    let loaded = load_str(&architecture_yaml(), Format::Yaml, STRICT).unwrap();
    assert!(loaded.diagnostics.is_empty(), "{:#?}", loaded.diagnostics);
}

#[test]
fn examples_match_the_json_schema() {
    for file in example_files() {
        let text = std::fs::read_to_string(&file).unwrap();
        let value: serde_json::Value = serde_saphyr::from_str(&text).unwrap();
        assert_eq!(
            schema_errors(&value),
            Vec::<String>::new(),
            "{}",
            file.display()
        );
    }
    let value: serde_json::Value = serde_saphyr::from_str(&architecture_yaml()).unwrap();
    assert_eq!(
        schema_errors(&value),
        Vec::<String>::new(),
        "docs/05-architecture.md §3.1"
    );
}

#[test]
fn schema_rejects_typos_that_runtime_only_warns_about() {
    let value = serde_json::json!({ "servics": {} });
    assert_ne!(schema_errors(&value), Vec::<String>::new());
}
