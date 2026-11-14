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

/// A Traefik label key with object names and list indices replaced, lower-cased as Traefik
/// reads keys: `traefik.http.routers.<name>.tls.domains[n].main`.
fn normalized(key: &str) -> String {
    let lower = key.to_ascii_lowercase();
    let mut parts: Vec<String> = lower.split('.').map(str::to_owned).collect();
    if parts.len() > 3
        && ["http", "tcp", "udp"].contains(&parts[1].as_str())
        && ["routers", "services", "middlewares"].contains(&parts[2].as_str())
    {
        "<name>".clone_into(&mut parts[3]);
    }
    // A header name is the user's, like an object name.
    let n = parts.len();
    let header_map = n >= 2
        && matches!(
            parts[n - 2].as_str(),
            "customrequestheaders" | "customresponseheaders"
        )
        || n >= 3 && parts[n - 2] == "headers" && parts[n - 3] == "healthcheck";
    if header_map {
        "<header>".clone_into(&mut parts[n - 1]);
    }
    let joined = parts.join(".");
    let mut out = String::with_capacity(joined.len());
    let mut chars = joined.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(c);
        if c == '[' {
            while chars.peek().is_some_and(char::is_ascii_digit) {
                chars.next();
            }
            out.push('n');
        }
    }
    out
}

/// The label snapshot of the compatibility check (ADR-0033): the native labels, and every
/// Traefik label the conformance fixtures use that its translation takes without a warning
/// at that label, i.e. the conformance-tested subset. `RDOCK_UPDATE_GOLDEN=1` (or
/// `just compat`) rewrites `schema/compat/labels.json`; otherwise it must be current.
#[test]
fn label_snapshot_is_current() {
    let mut files: Vec<PathBuf> = std::fs::read_dir(suite_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    let mut traefik = BTreeSet::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        let fixture: Fixture = serde_saphyr::from_str(&text).unwrap();
        let settings: DockerProvider = match fixture.settings {
            Some(value) => serde_json::from_value(value).unwrap(),
            None => DockerProvider::default(),
        };
        let containers: Vec<Container> = fixture.containers.into_iter().map(container).collect();
        let out = translate(&containers, &settings);
        for c in &containers {
            for key in c.labels.keys() {
                let warned = out
                    .diagnostics
                    .iter()
                    .any(|d| d.path.contains(key.as_str()));
                if key.to_ascii_lowercase().starts_with("traefik.") && !warned {
                    traefik.insert(normalized(key));
                }
            }
        }
    }
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
            "labels": traefik,
            "source": "labels the fixtures in tests/conformance/traefik-labels use and the translation takes without a warning",
        },
    });
    let text = serde_json::to_string_pretty(&snapshot).unwrap() + "\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../schema/compat/labels.json");
    if std::env::var_os("RDOCK_UPDATE_GOLDEN").is_some_and(|v| v == "1") {
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == text,
        "schema/compat/labels.json is out of date; run `just compat` and commit the result"
    );
}

#[test]
fn traefik_keys_are_normalized() {
    assert_eq!(
        normalized("traefik.http.routers.App.tls.domains[0].main"),
        "traefik.http.routers.<name>.tls.domains[n].main"
    );
    assert_eq!(normalized("traefik.enable"), "traefik.enable");
    assert_eq!(
        normalized("traefik.http.middlewares.h.headers.customRequestHeaders.X-Script-Name"),
        "traefik.http.middlewares.<name>.headers.customrequestheaders.<header>"
    );
}
