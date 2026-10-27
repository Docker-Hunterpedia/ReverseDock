//! Traefik label conformance (W-DKR-03): every `*.yaml` under
//! `tests/conformance/traefik-labels/` lists containers as the Engine API reports them and the
//! routing table and diagnostics the Docker provider must produce. No Docker daemon needed.
//!
//! `expect.routes`, `expect.services` and `expect.middlewares` name exactly the objects
//! produced; each object's fields are compared as a subset of the full object (unset fields
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
