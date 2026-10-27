#![doc = include_str!("../README.md")]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use rdock_config::merge::Fragment;
use rdock_model::providers::DockerProvider;
use rdock_model::route::Route;
use rdock_model::service::Service;
use rdock_model::{Config, Diagnostic};
use rdock_provider_docker::labels::{Container, Health, translate};
use serde_json::{Map, Value};

/// What `rdock migrate traefik` read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// A Docker Compose file whose services carry `traefik.*` labels.
    Compose,
    /// A Traefik dynamic configuration file (file provider: `http.routers`, …).
    Dynamic,
}

/// The result: an `rdock.yaml` fragment and what could not be carried over.
#[derive(Debug, Clone, PartialEq)]
pub struct Migration {
    /// What was read.
    pub input: Input,
    /// Routes, services and middlewares as YAML, with the notes as a comment header.
    pub yaml: String,
    /// Labels or settings that were not migrated, and why.
    pub notes: Vec<String>,
}

/// Translates a Compose file or a Traefik dynamic configuration (detected from its top-level
/// keys). With `expose_by_default`, Compose services without `traefik.enable` are migrated too,
/// as Traefik does by default.
pub fn traefik(text: &str, expose_by_default: bool) -> Result<Migration, String> {
    let document: Value =
        serde_saphyr::from_str(text).map_err(|err| format!("invalid YAML: {err}"))?;
    let (input, containers, extra_servers, mut notes) = if document.get("services").is_some() {
        let (containers, notes) = compose(&document)?;
        (Input::Compose, containers, BTreeMap::new(), notes)
    } else if document.get("http").is_some()
        || document.get("tcp").is_some()
        || document.get("tls").is_some()
    {
        let (container, servers, notes) = dynamic(&document);
        (Input::Dynamic, vec![container], servers, notes)
    } else {
        return Err(
            "neither a Compose file (`services:`) nor a Traefik dynamic configuration (`http:`)"
                .to_owned(),
        );
    };
    let settings = DockerProvider {
        expose_by_default,
        traefik_labels: true,
        ..DockerProvider::default()
    };
    let mut translation = translate(&containers, &settings);
    add_servers(&mut translation.fragment, &extra_servers);
    notes.extend(translation.diagnostics.iter().map(note));
    if input == Input::Compose && !expose_by_default {
        for container in &containers {
            let enabled = container.labels.keys().any(|k| {
                k.eq_ignore_ascii_case("traefik.enable") || k.eq_ignore_ascii_case("rdock.enable")
            });
            let routed = container
                .labels
                .keys()
                .any(|k| k.to_ascii_lowercase().starts_with("traefik.http."));
            if routed && !enabled {
                notes.push(format!(
                    "{}: has Traefik router labels but no `traefik.enable`; skipped (Traefik exposes it by default; rerun with --expose-by-default)",
                    container.name
                ));
            }
        }
    }
    notes.extend(check(&translation.fragment));
    let yaml = render(&translation.fragment, &notes)?;
    Ok(Migration { input, yaml, notes })
}

/// A diagnostic as a note: `docker.web.labels["…"]: message` → `web: label "…": message`.
fn note(diagnostic: &Diagnostic) -> String {
    let path = diagnostic
        .path
        .strip_prefix("docker.")
        .unwrap_or(&diagnostic.path);
    let path = path
        .replace(".labels[", ": label [")
        .replace("[\"", "\"")
        .replace("\"]", "\"");
    format!("{path}: {}", diagnostic.message)
}

/// Services of a Compose file as containers reachable by their service name.
fn compose(document: &Value) -> Result<(Vec<Container>, Vec<String>), String> {
    let Some(Value::Object(services)) = document.get("services") else {
        return Err("`services` is not a mapping".to_owned());
    };
    let mut notes = Vec::new();
    let mut containers = Vec::new();
    for (service, spec) in services {
        let mut labels = labels_of(spec.get("labels"));
        let deploy = labels_of(spec.pointer("/deploy/labels"));
        if !deploy.is_empty() {
            notes.push(format!(
                "{service}: `deploy.labels` (Swarm) were read as container labels; the Swarm provider arrives in v0.6"
            ));
            labels.extend(deploy);
        }
        let mut ports = BTreeSet::new();
        for list in ["expose", "ports"] {
            if let Some(Value::Array(items)) = spec.get(list) {
                ports.extend(items.iter().filter_map(container_port));
            }
        }
        let host_network = spec.get("network_mode").and_then(Value::as_str) == Some("host");
        let has_port_label = labels.keys().any(|k| {
            k.to_ascii_lowercase().ends_with("loadbalancer.server.port") || k == "rdock.port"
        });
        if ports.is_empty() && !host_network && !has_port_label {
            // Traefik would read the port the image exposes, which a Compose file does not say.
            ports.insert(80);
            notes.push(format!(
                "{service}: no `expose`, `ports` or port label; assumed port 80 (Traefik uses the image's exposed port): check it"
            ));
        }
        let name = spec
            .get("container_name")
            .and_then(Value::as_str)
            .unwrap_or(service)
            .to_owned();
        containers.push(Container {
            name,
            labels,
            networks: BTreeMap::new(),
            host_network,
            exposed_ports: ports,
            health: Health::None,
            stopping: false,
            dns_name: Some(service.clone()),
        });
    }
    Ok((containers, notes))
}

/// Compose `labels`: a mapping, or a list of `key=value`.
fn labels_of(value: Option<&Value>) -> BTreeMap<String, String> {
    match value {
        Some(Value::Object(map)) => map.iter().map(|(k, v)| (k.clone(), text(v))).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|item| {
                let (k, v) = item.split_once('=').unwrap_or((item, ""));
                (k.to_owned(), v.to_owned())
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// The container side of `80`, `8080:80`, `127.0.0.1:8080:80/tcp` or `{ target: 80 }`.
fn container_port(value: &Value) -> Option<u16> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::Object(map) => map.get("target").and_then(container_port),
        Value::String(s) => {
            let (spec, proto) = s.split_once('/').unwrap_or((s, "tcp"));
            if proto != "tcp" {
                return None;
            }
            spec.rsplit(':').next()?.parse().ok()
        }
        _ => None,
    }
}

/// A Traefik dynamic configuration as the labels of one pseudo-container, plus every server
/// URL of each service (labels hold one).
fn dynamic(document: &Value) -> (Container, BTreeMap<String, Vec<String>>, Vec<String>) {
    let mut labels = BTreeMap::from([("traefik.enable".to_owned(), "true".to_owned())]);
    let mut servers = BTreeMap::new();
    let mut notes = Vec::new();
    if let Some(Value::Object(http)) = document.get("http") {
        for (kind, objects) in http {
            let Value::Object(objects) = objects else {
                continue;
            };
            for (name, object) in objects {
                let mut object = object.clone();
                if kind == "services" {
                    let urls = take_servers(&mut object);
                    if let Some(first) = urls.first() {
                        labels.insert(
                            format!("traefik.http.services.{name}.loadbalancer.server.url"),
                            first.clone(),
                        );
                    }
                    if urls.len() > 1 {
                        servers.insert(name.clone(), urls);
                    }
                }
                flatten(&format!("traefik.http.{kind}.{name}"), &object, &mut labels);
            }
        }
    }
    for section in ["tcp", "udp"] {
        if document.get(section).is_some() {
            notes.push(format!(
                "`{section}`: TCP and UDP routing are not supported in this version (planned for v0.6)"
            ));
        }
    }
    if document.get("tls").is_some() {
        notes.push(
            "`tls`: move certificates to `certificates` in rdock.yaml (cert_file, key_file); TLS options are not migrated"
                .to_owned(),
        );
    }
    let container = Container {
        name: "dynamic".to_owned(),
        labels,
        ..Container::default()
    };
    (container, servers, notes)
}

/// Removes `loadBalancer.servers` and returns their URLs.
fn take_servers(service: &mut Value) -> Vec<String> {
    let Some(Value::Object(lb)) = service.as_object_mut().and_then(|s| {
        s.iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case("loadbalancer"))
            .map(|(_, v)| v)
    }) else {
        return Vec::new();
    };
    let key = lb
        .keys()
        .find(|k| k.eq_ignore_ascii_case("servers"))
        .cloned();
    let Some(Value::Array(items)) = key.and_then(|k| lb.remove(&k)) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.get("url").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// `{a: {b: 1}, c: [x, y], d: [{e: 1}]}` under `p` → `p.a.b=1`, `p.c=x,y`, `p.d[0].e=1`.
fn flatten(prefix: &str, value: &Value, out: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                flatten(&format!("{prefix}.{key}"), item, out);
            }
        }
        Value::Array(items) if items.iter().all(|i| !i.is_object() && !i.is_array()) => {
            let joined: Vec<String> = items.iter().map(text).collect();
            out.insert(prefix.to_owned(), joined.join(","));
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                flatten(&format!("{prefix}[{i}]"), item, out);
            }
        }
        scalar => {
            out.insert(prefix.to_owned(), text(scalar));
        }
    }
}

/// Puts every server URL of a service into its backends.
fn add_servers(fragment: &mut Fragment, servers: &BTreeMap<String, Vec<String>>) {
    for (name, urls) in servers {
        let Some(service) = fragment.services.get_mut(name) else {
            continue;
        };
        let backends: Vec<Value> = urls
            .iter()
            .filter_map(|url| {
                url.split_once("://")
                    .map(|(_, rest)| rest.trim_end_matches('/'))
            })
            .map(|address| serde_json::json!({ "address": address }))
            .collect();
        if let Ok(backends) = serde_json::from_value(Value::Array(backends)) {
            service.backends = backends;
        }
    }
}

/// Validation findings of the result on its own (references to other files are expected).
fn check(fragment: &Fragment) -> Vec<String> {
    let config = Config {
        routes: fragment.routes.clone(),
        services: fragment.services.clone(),
        middlewares: fragment.middlewares.clone(),
        ..Config::default()
    };
    config
        .validate()
        .into_iter()
        .filter(Diagnostic::is_error)
        .map(|d| format!("{}: {}", d.path, d.message))
        .collect()
}

/// The fragment as YAML without settings equal to their defaults, under a header of notes.
fn render(fragment: &Fragment, notes: &[String]) -> Result<String, String> {
    let route_base = baseline::<Route>(&serde_json::json!({ "match": "", "service": "" }));
    let service_base = baseline::<Service>(&serde_json::json!({ "backends": [] }));
    let mut document = Map::new();
    let sections: [(&str, Value, Option<&Value>); 3] = [
        ("routes", to_value(&fragment.routes)?, route_base.as_ref()),
        (
            "services",
            to_value(&fragment.services)?,
            service_base.as_ref(),
        ),
        ("middlewares", to_value(&fragment.middlewares)?, None),
    ];
    for (key, mut objects, base) in sections {
        if let Value::Object(map) = &mut objects {
            for object in map.values_mut() {
                prune(object, base);
                // A backend's weight is 1 unless set.
                if let Some(Value::Array(backends)) = object.get_mut("backends") {
                    for backend in backends.iter_mut().filter_map(Value::as_object_mut) {
                        if backend.get("weight") == Some(&Value::from(1)) {
                            backend.remove("weight");
                        }
                    }
                }
            }
            if !map.is_empty() {
                document.insert(key.to_owned(), objects);
            }
        }
    }
    let body = if document.is_empty() {
        "{}\n".to_owned()
    } else {
        serde_saphyr::to_string(&Value::Object(document)).map_err(|e| e.to_string())?
    };
    let mut header = String::from(
        "# Generated by `rdock migrate traefik`. Review before use; add listeners and defaults as needed.\n",
    );
    if notes.is_empty() {
        header.push_str("# Everything was migrated.\n");
    } else {
        let _ = writeln!(header, "# {} note(s):", notes.len());
        for note in notes {
            let _ = writeln!(header, "#   - {note}");
        }
    }
    Ok(format!("{header}{body}"))
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

/// A type's defaults as JSON, from the smallest valid input.
fn baseline<T: serde::de::DeserializeOwned + serde::Serialize>(minimal: &Value) -> Option<Value> {
    serde_json::from_value::<T>(minimal.clone())
        .ok()
        .and_then(|t| serde_json::to_value(t).ok())
}

/// Removes nulls, empty lists and maps, and fields equal to `base`.
fn prune(value: &mut Value, base: Option<&Value>) {
    let Value::Object(map) = value else { return };
    map.retain(|key, item| {
        let default = base.and_then(|b| b.get(key));
        if let Some(default) = default
            && item.is_object()
        {
            prune(item, Some(default));
        } else if item.is_object() {
            prune(item, None);
        }
        let empty = match item {
            Value::Null => true,
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.is_empty(),
            _ => false,
        };
        !empty && default != Some(item)
    });
}

#[cfg(test)]
mod tests;
