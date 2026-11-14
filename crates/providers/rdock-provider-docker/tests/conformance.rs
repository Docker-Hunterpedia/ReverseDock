//! Traefik label conformance (W-DKR-03): every `*.yaml` under
//! `tests/conformance/traefik-labels/` lists containers as the Engine API reports them and the
//! routing table and diagnostics the Docker provider must produce. No Docker daemon needed.
//!
//! `expect.routes`, `expect.services`, `expect.middlewares`, `expect.tcp_routes`,
//! `expect.tcp_services`, `expect.udp_routes` and `expect.udp_services` name exactly the objects produced; each object's fields are compared as a subset of the full object (unset fields
//! are not checked; lists are compared whole). `expect.diagnostics` lists one text per
//! diagnostic, in order, each contained in that diagnostic's `path: message`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rdock_model::providers::DockerProvider;
use rdock_provider_docker::labels::{Container, Health, translate};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    #[allow(dead_code)]
    description: String,
    #[serde(default)]
    settings: Option<Value>,
    containers: Vec<FixtureContainer>,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureContainer {
    name: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    networks: BTreeMap<String, Option<IpAddr>>,
    #[serde(default)]
    host_network: bool,
    #[serde(default)]
    ports: BTreeSet<u16>,
    #[serde(default)]
    health: Option<String>,
    #[serde(default)]
    stopping: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    #[serde(default)]
    routes: BTreeMap<String, Value>,
    #[serde(default)]
    services: BTreeMap<String, Value>,
    #[serde(default)]
    middlewares: BTreeMap<String, Value>,
    #[serde(default)]
    tcp_routes: BTreeMap<String, Value>,
    #[serde(default)]
    tcp_services: BTreeMap<String, Value>,
    #[serde(default)]
    udp_routes: BTreeMap<String, Value>,
    #[serde(default)]
    udp_services: BTreeMap<String, Value>,
    #[serde(default)]
    diagnostics: Vec<String>,
}

fn suite_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/conformance/traefik-labels")
}

fn container(c: FixtureContainer) -> Container {
    Container {
        name: c.name,
        labels: c.labels,
        networks: c.networks,
        host_network: c.host_network,
        exposed_ports: c.ports,
        health: match c.health.as_deref() {
            None | Some("none") => Health::None,
            Some("starting") => Health::Starting,
            Some("healthy") => Health::Healthy,
            Some("unhealthy") => Health::Unhealthy,
            Some(other) => panic!("unknown health `{other}`"),
        },
        stopping: c.stopping,
        dns_name: None,
    }
}

/// Whether `expected` is contained in `actual`: objects by key, everything else by equality.
fn subset(expected: &Value, actual: &Value, path: &str, problems: &mut Vec<String>) {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (key, value) in e {
                match a.get(key) {
                    Some(found) => subset(value, found, &format!("{path}.{key}"), problems),
                    None => problems.push(format!("{path}.{key}: missing")),
                }
            }
        }
        _ if expected == actual => {}
        _ => problems.push(format!("{path}: expected {expected}, got {actual}")),
    }
}

fn compare<T: serde::Serialize>(
    kind: &str,
    expected: &BTreeMap<String, Value>,
    actual: &BTreeMap<String, T>,
    problems: &mut Vec<String>,
) {
    let want: Vec<&String> = expected.keys().collect();
    let got: Vec<&String> = actual.keys().collect();
    if want != got {
        problems.push(format!("{kind}: expected {want:?}, got {got:?}"));
        return;
    }
    for (name, value) in expected {
        let actual = serde_json::to_value(&actual[name]).unwrap();
        subset(value, &actual, &format!("{kind}.{name}"), problems);
    }
}

fn run(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap();
    let fixture: Fixture =
        serde_saphyr::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let settings: DockerProvider = match fixture.settings {
        Some(value) => serde_json::from_value(value).unwrap(),
        None => DockerProvider::default(),
    };
    let containers: Vec<Container> = fixture.containers.into_iter().map(container).collect();
    let out = translate(&containers, &settings);
    let mut problems = Vec::new();
    compare(
        "routes",
        &fixture.expect.routes,
        &out.fragment.routes,
        &mut problems,
    );
    compare(
        "services",
        &fixture.expect.services,
        &out.fragment.services,
        &mut problems,
    );
    compare(
        "middlewares",
        &fixture.expect.middlewares,
        &out.fragment.middlewares,
        &mut problems,
    );
    compare(
        "tcp_routes",
        &fixture.expect.tcp_routes,
        &out.fragment.tcp_routes,
        &mut problems,
    );
    compare(
        "tcp_services",
        &fixture.expect.tcp_services,
        &out.fragment.tcp_services,
        &mut problems,
    );
    compare(
        "udp_routes",
        &fixture.expect.udp_routes,
        &out.fragment.udp_routes,
        &mut problems,
    );
    compare(
        "udp_services",
        &fixture.expect.udp_services,
        &out.fragment.udp_services,
        &mut problems,
    );
    let found: Vec<String> = out
        .diagnostics
        .iter()
        .map(|d| format!("{}: {}", d.path, d.message))
        .collect();
    let matches = found.len() == fixture.expect.diagnostics.len()
        && found
            .iter()
            .zip(&fixture.expect.diagnostics)
            .all(|(f, e)| f.contains(e.as_str()));
    if !matches {
        problems.push(format!(
            "diagnostics: expected {:?}, got {found:?}",
            fixture.expect.diagnostics
        ));
    }
    problems
}

#[test]
fn traefik_label_conformance() {
    let mut files: Vec<PathBuf> = std::fs::read_dir(suite_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 40,
        "the suite needs at least 40 fixtures, found {}",
        files.len()
    );
    let failures: Vec<String> = files
        .iter()
        .filter_map(|file| {
            let problems = run(file);
            let name = file.file_name().unwrap().to_string_lossy();
            (!problems.is_empty()).then(|| format!("{name}:\n  {}", problems.join("\n  ")))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} fixtures failed:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );
}

use rdock_provider_docker::labels::coverage::{self, Coverage, TRAEFIK_OPTIONS};

/// Fixture files of the suite, sorted.
fn fixture_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(suite_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    files
}

/// The containers of each fixture with the translation of them, by file name.
fn translated_fixtures() -> Vec<(
    String,
    Vec<Container>,
    rdock_provider_docker::labels::Translation,
)> {
    fixture_files()
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path).unwrap();
            let fixture: Fixture = serde_saphyr::from_str(&text).unwrap();
            let settings: DockerProvider = match fixture.settings {
                Some(value) => serde_json::from_value(value).unwrap(),
                None => DockerProvider::default(),
            };
            let containers: Vec<Container> =
                fixture.containers.into_iter().map(container).collect();
            let out = translate(&containers, &settings);
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, containers, out)
        })
        .collect()
}

/// Whether a diagnostic of `out` is at `label` (keys compare in lower case).
fn warned(out: &rdock_provider_docker::labels::Translation, label: &str) -> Option<String> {
    let lower = label.to_ascii_lowercase();
    out.diagnostics
        .iter()
        .find(|d| {
            d.path
                .to_ascii_lowercase()
                .contains(&format!("\"{lower}\""))
                || d.path.to_ascii_lowercase().ends_with(&format!(".{lower}"))
        })
        .map(|d| d.message.clone())
}

/// The coverage table and the translator agree (ADR-0033): a label is taken exactly when its
/// row says exact or approximate. Each row is tried with its example value on an exposed
/// container that has a router.
#[test]
fn coverage_table_matches_the_translator() {
    let mut keys: Vec<&str> = TRAEFIK_OPTIONS.iter().map(|r| r.key).collect();
    let count = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), count, "a key is listed twice");
    let mut problems = Vec::new();
    for row in TRAEFIK_OPTIONS {
        assert_eq!(
            coverage::normalize(&coverage::instantiate(row.key)),
            row.key,
            "{} is not in normalized form",
            row.key
        );
        if !row.proven_by.is_empty() {
            continue;
        }
        let label = coverage::instantiate(row.key);
        let mut labels = BTreeMap::from([
            ("traefik.enable".to_owned(), "true".to_owned()),
            (
                "traefik.http.routers.r.rule".to_owned(),
                "Host(`r.example.com`)".to_owned(),
            ),
        ]);
        labels.insert(label.clone(), row.example.to_owned());
        let c = Container {
            name: "app".into(),
            labels,
            networks: BTreeMap::from([("web".to_owned(), Some("172.18.0.2".parse().unwrap()))]),
            host_network: false,
            exposed_ports: BTreeSet::from([80]),
            health: Health::None,
            stopping: false,
            dns_name: None,
        };
        let out = translate(&[c], &DockerProvider::default());
        let warning = warned(&out, &label);
        match (row.status.translated(), warning) {
            (true, Some(message)) => problems.push(format!(
                "{}: marked {} but the translator refuses `{}`: {message}",
                row.key,
                row.status.as_str(),
                row.example
            )),
            (false, None) => problems.push(format!(
                "{}: marked {} but the translator takes `{}`",
                row.key,
                row.status.as_str(),
                row.example
            )),
            _ => {}
        }
        if row.status == Coverage::Approximate && row.note.is_empty() {
            problems.push(format!(
                "{}: approximate without a stated difference",
                row.key
            ));
        }
        if !row.status.translated() && row.note.is_empty() {
            problems.push(format!(
                "{}: {} without a note",
                row.key,
                row.status.as_str()
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Every Traefik label a fixture uses is in the coverage table, unless the fixture shows it
/// refused as unknown.
#[test]
fn every_fixture_label_is_in_the_table() {
    let mut problems = Vec::new();
    for (name, containers, out) in translated_fixtures() {
        for c in &containers {
            for key in c.labels.keys() {
                if !key.to_ascii_lowercase().starts_with("traefik.") {
                    continue;
                }
                if coverage::lookup(key).is_none() {
                    let generic = warned(&out, key)
                        .is_some_and(|m| m.contains("not in the supported Traefik label subset"));
                    if !generic {
                        problems.push(format!("{name}: `{key}` is not in the coverage table"));
                    }
                }
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The generated coverage table (`tests/conformance/traefik-labels/coverage.json`) and the
/// label snapshot of the compatibility check (`schema/compat/labels.json`, ADR-0033), both
/// from the coverage table and the fixtures: each row lists the fixtures that use it, and a
/// row without one fails. `RDOCK_UPDATE_GOLDEN=1` (or `just compat`) rewrites both files;
/// otherwise they must be current.
#[test]
#[allow(clippy::too_many_lines)] // two generated files, built in one pass
fn label_snapshot_is_current() {
    let mut used: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, containers, _) in translated_fixtures() {
        for c in &containers {
            for key in c.labels.keys() {
                if key.to_ascii_lowercase().starts_with("traefik.") {
                    used.entry(coverage::normalize(key))
                        .or_default()
                        .insert(name.clone());
                }
            }
        }
    }
    let mut missing = Vec::new();
    let mut rows = Vec::new();
    let mut totals: BTreeMap<&str, usize> = BTreeMap::new();
    for row in TRAEFIK_OPTIONS {
        let fixtures: Vec<String> = used
            .get(row.key)
            .map(|f| f.iter().cloned().collect())
            .unwrap_or_default();
        if fixtures.is_empty() && row.proven_by.is_empty() {
            missing.push(row.key);
        }
        *totals.entry(row.status.as_str()).or_default() += 1;
        let mut value = serde_json::to_value(row).unwrap();
        value["fixtures"] = serde_json::json!(fixtures);
        rows.push(value);
    }
    assert!(
        missing.is_empty(),
        "coverage rows without a fixture:\n{}",
        missing.join("\n")
    );
    let reference = serde_json::json!({
        "version": coverage::TRAEFIK_VERSION,
        "reference": coverage::TRAEFIK_REFERENCE,
        "checked": coverage::CHECKED,
    });
    let table = serde_json::json!({
        "generated_by": "the label_snapshot_is_current test of rdock-provider-docker (just compat), from crates/providers/rdock-provider-docker/src/labels/coverage.rs",
        "traefik": reference,
        "totals": totals,
        "options": rows,
    });
    // Every section of the full form is read.
    for section in rdock_provider_docker::labels::NATIVE_SECTIONS {
        let key = format!("rdock.{section}.x.unknown_field_for_the_check");
        let c = Container {
            name: "app".into(),
            labels: [
                ("rdock.enable".to_owned(), "true".to_owned()),
                (key, "1".into()),
            ]
            .into_iter()
            .collect(),
            networks: BTreeMap::new(),
            host_network: false,
            exposed_ports: BTreeSet::new(),
            health: Health::None,
            stopping: false,
            dns_name: None,
        };
        let out = translate(&[c], &DockerProvider::default());
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| d.message.contains("unknown label")),
            "section {section} is not read: {:?}",
            out.diagnostics
        );
    }
    let mut native: Vec<&str> = rdock_provider_docker::labels::NATIVE_LABELS.to_vec();
    native.sort_unstable();
    let mut sections: Vec<&str> = rdock_provider_docker::labels::NATIVE_SECTIONS.to_vec();
    sections.sort_unstable();
    let traefik: BTreeSet<&str> = TRAEFIK_OPTIONS
        .iter()
        .filter(|r| r.status.translated())
        .map(|r| r.key)
        .collect();
    let approximate: BTreeSet<&str> = TRAEFIK_OPTIONS
        .iter()
        .filter(|r| r.status == Coverage::Approximate)
        .map(|r| r.key)
        .collect();
    let snapshot = serde_json::json!({
        "generated_by": "the label_snapshot_is_current test of rdock-provider-docker (just compat)",
        "native": {
            "full_form": "rdock.<section>.<name>.<field>, where <field> is a dotted path of the configuration schema; checked with schema/rdock.v1.json",
            "labels": native,
            "sections": sections,
        },
        "stability": "docs/10-stability.md; compared with the last release tag by scripts/compat.py",
        "surface": "labels",
        "traefik": {
            "approximate": approximate,
            "checked_against": reference,
            "labels": traefik,
            "source": "the coverage table (tests/conformance/traefik-labels/coverage.json): every Traefik label marked exact or approximate, each proven by a fixture",
        },
    });
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let files = [
        (root.join("schema/compat/labels.json"), snapshot),
        (
            root.join("tests/conformance/traefik-labels/coverage.json"),
            table,
        ),
    ];
    for (path, value) in files {
        let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
        if std::env::var_os("RDOCK_UPDATE_GOLDEN").is_some_and(|v| v == "1") {
            std::fs::write(&path, &text).unwrap();
            continue;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == text,
            "{} is out of date; run `just compat` and commit the result",
            path.display()
        );
    }
}

#[test]
fn traefik_keys_are_normalized() {
    assert_eq!(
        coverage::normalize("traefik.http.routers.App.tls.domains[0].main"),
        "traefik.http.routers.<name>.tls.domains[n].main"
    );
    assert_eq!(coverage::normalize("traefik.enable"), "traefik.enable");
    assert_eq!(
        coverage::normalize(
            "traefik.http.middlewares.h.headers.customRequestHeaders.X-Script-Name"
        ),
        "traefik.http.middlewares.<name>.headers.customrequestheaders.<header>"
    );
    assert_eq!(
        coverage::normalize("traefik.http.middlewares.p.plugin.demo.some.key"),
        "traefik.http.middlewares.<name>.plugin.<plugin>.<option>"
    );
}
