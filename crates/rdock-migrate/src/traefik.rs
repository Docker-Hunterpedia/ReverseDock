//! `rdock migrate traefik` (F-MGMT-03, ADR-0033): a Compose file with Traefik labels, a
//! Traefik dynamic configuration file, or Traefik's static configuration, into rdock.yaml with
//! a report that accounts for every source item.
//!
//! Labels go through the Docker provider's own translator, so the migration says what the
//! provider would do with the same labels; each label's level comes from the coverage table
//! (`rdock_provider_docker::labels::coverage`) and from the translator's diagnostics.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use rdock_config::merge::Fragment;
use rdock_model::providers::DockerProvider;
use rdock_model::route::{Route, RouteTls, TcpRoute, TlsMode, UdpRoute};
use rdock_model::service::{Service, TcpService, UdpService};
use rdock_model::{Config, Diagnostic, path_key};
use rdock_provider_docker::labels::coverage::{self, Coverage};
use rdock_provider_docker::labels::{Container, Health, Settings, Translation, exposed, translate};
use serde_json::{Map, Value, json};

use crate::compose::{self, Problem, Vars};
use crate::report::{
    AccountingError, Builder, Finding, ItemId, ItemKind, Report, Source, SourceInfo,
};

mod dynamic;
mod statics;

/// The command, as reports name it.
const TOOL: &str = "rdock migrate traefik";

/// What `rdock migrate traefik` read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// A Docker Compose file whose services carry `traefik.*` labels.
    Compose,
    /// A Traefik dynamic configuration file (file provider: `http.routers`, …).
    Dynamic,
    /// Traefik's static configuration (`traefik.yml`: `entryPoints`, `providers`, …).
    Static,
    /// A TOML file, which is reported and not read.
    Toml,
}

/// A second file: Traefik's static configuration (`--static`).
#[derive(Debug, Clone)]
pub struct StaticFile {
    /// Its name, for the report.
    pub name: String,
    /// Its text.
    pub text: String,
}

/// How to migrate.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The input's name for the report (`-` for standard input).
    pub file: String,
    /// Expose Compose services without `traefik.enable`, as Traefik's `exposedByDefault`.
    pub expose_by_default: bool,
    /// Values for Compose `${VAR}` references (`--env-file`, `--process-env`).
    pub vars: Vars,
    /// Traefik's static configuration (`--static`).
    pub static_file: Option<StaticFile>,
    /// Write a complete rdock.yaml (listeners, acme, providers) instead of a fragment.
    pub full: bool,
}

/// The result: rdock.yaml (or a fragment of it) with the report.
#[derive(Debug, Clone, PartialEq)]
pub struct Migration {
    /// What was read.
    pub input: Input,
    /// The YAML, under a comment header that summarises the report.
    pub yaml: String,
    /// Every finding.
    pub report: Report,
}

impl Migration {
    /// The findings that are not exact, one line each.
    #[must_use]
    pub fn notes(&self) -> Vec<String> {
        self.report.notable().map(Finding::line).collect()
    }
}

/// Why nothing was migrated.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not one of the kinds this tool reads.
    #[error("{0}")]
    Input(String),
    /// A bug: the report does not account for every source item.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

/// One label (or, for a dynamic file, one key that became a label) and what it belongs to.
#[derive(Debug, Clone)]
pub(crate) struct LabelItem {
    pub(crate) id: ItemId,
    /// The container (Compose service) it is on.
    pub(crate) container: String,
    /// The label key as written.
    pub(crate) key: String,
    /// Its value after interpolation.
    pub(crate) value: String,
    /// The object it declares: (section, name).
    pub(crate) object: Option<(&'static str, String)>,
    /// Compose interpolation problems in its value.
    pub(crate) problems: Vec<Problem>,
}

/// Migrates `text`. Compose files and dynamic configurations are told apart by their top-level
/// keys; a file with `entryPoints` or `providers` is read as static configuration.
pub fn traefik(text: &str, options: &Options) -> Result<Migration, Error> {
    let mut b = Builder::default();
    let mut files = vec![options.file.clone()];
    let mut static_options = Vec::new();
    if let Some(file) = &options.static_file {
        files.push(file.name.clone());
        if looks_like_toml(&file.text) {
            toml(&file.name, &mut b);
        } else {
            let document: Value = serde_saphyr::from_str(&file.text)
                .map_err(|err| Error::Input(format!("{}: invalid YAML: {err}", file.name)))?;
            static_options.extend(statics::from_file(&file.name, &document));
        }
    }
    let mut run = Run {
        options,
        items: Vec::new(),
        containers: Vec::new(),
        service_items: BTreeMap::new(),
        static_options,
        env_names: BTreeSet::new(),
        extra: dynamic::Extra::default(),
    };
    let input = if looks_like_toml(text) {
        toml(&options.file, &mut b);
        Input::Toml
    } else {
        let document: Value = serde_saphyr::from_str(text)
            .map_err(|err| Error::Input(format!("invalid YAML: {err}")))?;
        let input = detect(&document)?;
        match input {
            Input::Compose => run.compose(&document, &mut b)?,
            Input::Dynamic => run.dynamic(&document, &mut b),
            Input::Static => run
                .static_options
                .extend(statics::from_file(&options.file, &document)),
            Input::Toml => {}
        }
        input
    };
    let mut st = statics::Static::default();
    statics::interpret(&run.static_options, &run.env_names, &mut b, &mut st);
    let settings = DockerProvider {
        expose_by_default: options.expose_by_default || st.expose_by_default == Some(true),
        traefik_labels: true,
        ..DockerProvider::default()
    };
    let mut translation = translate(&run.containers, &settings);
    if input == Input::Dynamic {
        run.apply(&mut translation.fragment, &mut b);
    }
    run.classify(&translation, &settings, &mut b);
    run.routers(&mut translation.fragment, &st, &mut b);
    run.incomplete(&mut translation.fragment, &mut b);
    tcp_listeners(&translation.fragment, &mut st);
    let document = output(
        &translation.fragment,
        &run.extra,
        &st,
        options.full,
        input,
        &mut b,
    )?;
    // A fragment is checked with the static configuration's sections, which `--full` writes.
    let mut checked = document.clone();
    if !options.full {
        for (key, value) in st.sections() {
            checked.entry(key.to_owned()).or_insert(value);
        }
    }
    for finding in check(&checked) {
        b.result(finding);
    }
    let report = b.finish(
        TOOL,
        SourceInfo {
            kind: "traefik".to_owned(),
            checked_against: format!("Traefik {}", coverage::TRAEFIK_VERSION),
            files,
        },
    )?;
    let yaml = render(&document, &report, options.full)?;
    Ok(Migration {
        input,
        yaml,
        report,
    })
}

/// A file that is not YAML but TOML (a `[section]` header or `key = value` line first).
fn looks_like_toml(text: &str) -> bool {
    let Some(first) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
    else {
        return false;
    };
    (first.starts_with('[') && first.ends_with(']') && !first.contains(", "))
        || first
            .split_once('=')
            .is_some_and(|(k, _)| !k.contains(':') && !k.trim().contains(' ') && k.ends_with(' '))
}

/// A TOML file is one item, reported as manual.
fn toml(file: &str, b: &mut Builder) {
    let id = b.item(Source {
        file: file.to_owned(),
        line: None,
        scope: None,
        kind: ItemKind::Object,
        item: file.to_owned(),
    });
    b.account(
        id,
        Finding::new(
            "traefik.file.toml",
            "TOML is not read (no TOML parser is built in); nothing from this file was migrated",
        )
        .hint("convert it to YAML with the same keys (for example with `yq -p toml -o yaml`) and run the migration again"),
    );
}

fn detect(document: &Value) -> Result<Input, Error> {
    let has = |key: &str| {
        document
            .as_object()
            .is_some_and(|m| m.keys().any(|k| k.eq_ignore_ascii_case(key)))
    };
    if has("services") {
        Ok(Input::Compose)
    } else if has("http") || has("tcp") || has("udp") || has("tls") {
        Ok(Input::Dynamic)
    } else if has("entryPoints") || has("providers") || has("certificatesResolvers") || has("api") {
        Ok(Input::Static)
    } else {
        Err(Error::Input(
            "neither a Compose file (`services:`), a Traefik dynamic configuration (`http:`, `tcp:`, `udp:`, `tls:`) nor Traefik's static configuration (`entryPoints:`, `providers:`)".to_owned(),
        ))
    }
}

/// Swarm provider labels with no meaning in a migrated configuration.
const SWARM_OPTIONS: [&str; 5] = [
    "traefik.swarm.network",
    "traefik.swarm.lbswarm",
    "traefik.docker.network",
    "traefik.docker.lbswarm",
    "rdock.swarm.lbswarm",
];

/// The state of one migration.
struct Run<'a> {
    options: &'a Options,
    items: Vec<LabelItem>,
    containers: Vec<Container>,
    /// Compose service items by container name.
    service_items: BTreeMap<String, ItemId>,
    static_options: Vec<statics::Option_>,
    /// Variable names set on Traefik's service (values are never kept).
    env_names: BTreeSet<String>,
    extra: dynamic::Extra,
}

/// The object a label declares: `traefik.http.routers.web.rule` → (`routes`, `web`).
fn object_of(key: &str) -> Option<(&'static str, String)> {
    let lower = key.to_ascii_lowercase();
    let parts: Vec<&str> = lower.splitn(5, '.').collect();
    let section = match (parts.first(), parts.get(1), parts.get(2)) {
        (Some(&"traefik"), Some(&"http"), Some(&"routers")) => "routes",
        (Some(&"traefik"), Some(&"http"), Some(&"services")) => "services",
        (Some(&"traefik"), Some(&"http" | &"tcp"), Some(&"middlewares")) => "middlewares",
        (Some(&"traefik"), Some(&"tcp"), Some(&"routers")) => "tcp_routes",
        (Some(&"traefik"), Some(&"tcp"), Some(&"services")) => "tcp_services",
        (Some(&"traefik"), Some(&"udp"), Some(&"routers")) => "udp_routes",
        (Some(&"traefik"), Some(&"udp"), Some(&"services")) => "udp_services",
        (Some(&"rdock"), Some(section), _) => match *section {
            "routes" => "routes",
            "services" => "services",
            "middlewares" => "middlewares",
            "tcp_routes" => "tcp_routes",
            "tcp_services" => "tcp_services",
            "udp_routes" => "udp_routes",
            "udp_services" => "udp_services",
            _ => return None,
        },
        _ => return None,
    };
    let name_index = if parts.first() == Some(&"rdock") {
        2
    } else {
        3
    };
    // The name keeps its case.
    let name = key.split('.').nth(name_index)?.to_owned();
    Some((section, name))
}

/// Compose `labels` (a mapping, or a list of `key=value`) after interpolation, each with its
/// problems. In the mapping form only values are interpolated (Compose does not interpolate
/// keys).
fn compose_labels(value: Option<&Value>, vars: &Vars) -> Vec<(String, String, Vec<Problem>)> {
    match value {
        Some(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| {
                let (value, problems) = compose::interpolate(&text(v), vars);
                (k.clone(), value, problems)
            })
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|item| {
                let (item, problems) = compose::interpolate(item, vars);
                let (k, v) = item.split_once('=').unwrap_or((&item, ""));
                (k.to_owned(), v.to_owned(), problems)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// A Compose value as text after interpolation (problems are added to `problems`).
fn compose_text(value: &Value, vars: &Vars, problems: &mut Vec<Problem>) -> String {
    let (out, found) = compose::interpolate(&text(value), vars);
    problems.extend(found);
    out
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// The container side of `80`, `8080:80`, `127.0.0.1:8080:80/tcp` or `{ target: 80 }`.
fn container_port(value: &Value, vars: &Vars, problems: &mut Vec<Problem>) -> Option<u16> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::Object(map) => map
            .get("target")
            .and_then(|t| container_port(t, vars, problems)),
        Value::String(s) => {
            let s = compose_text(&Value::String(s.clone()), vars, problems);
            let (spec, proto) = s.split_once('/').unwrap_or((&s, "tcp"));
            if proto != "tcp" {
                return None;
            }
            spec.rsplit(':').next()?.parse().ok()
        }
        _ => None,
    }
}

/// Whether an image is Traefik's (`traefik:v3.7`, `docker.io/library/traefik`, `traefik`).
fn is_traefik_image(image: &str) -> bool {
    let name = image.split('@').next().unwrap_or(image);
    let last = name.rsplit('/').next().unwrap_or(name);
    let repository = last.split(':').next().unwrap_or(last);
    repository.eq_ignore_ascii_case("traefik")
}

impl Run<'_> {
    /// The services of a Compose file as containers reachable by their service name, and
    /// Traefik's own service as static configuration.
    #[allow(clippy::too_many_lines)]
    fn compose(&mut self, document: &Value, b: &mut Builder) -> Result<(), Error> {
        let Some(Value::Object(services)) = document.get("services") else {
            return Err(Error::Input("`services` is not a mapping".to_owned()));
        };
        let vars = &self.options.vars;
        let file = self.options.file.clone();
        for (service, spec) in services {
            let mut problems = Vec::new();
            let image = spec
                .get("image")
                .map(|i| compose_text(i, vars, &mut problems))
                .unwrap_or_default();
            let traefik_service = is_traefik_image(&image);
            let mut labels = compose_labels(spec.get("labels"), vars);
            let mut deploy = compose_labels(spec.pointer("/deploy/labels"), vars);
            let deploy_used = !deploy.is_empty();
            // They choose how the Swarm provider reaches tasks; migrated backends are addressed
            // by service name.
            deploy.retain(|(key, ..)| !SWARM_OPTIONS.contains(&key.to_ascii_lowercase().as_str()));
            labels.extend(deploy);
            let relevant = |key: &str| {
                let lower = key.to_ascii_lowercase();
                lower.starts_with("traefik.") || lower.starts_with("rdock.")
            };
            if !traefik_service && !labels.iter().any(|(k, ..)| relevant(k)) {
                continue;
            }
            let item = b.item(Source {
                file: file.clone(),
                line: None,
                scope: Some(service.clone()),
                kind: ItemKind::Object,
                item: format!("services.{service}"),
            });
            let mut ports = BTreeSet::new();
            for list in ["expose", "ports"] {
                if let Some(Value::Array(entries)) = spec.get(list) {
                    ports.extend(
                        entries
                            .iter()
                            .filter_map(|p| container_port(p, vars, &mut problems)),
                    );
                }
            }
            let host_network = spec
                .get("network_mode")
                .map(|m| compose_text(m, vars, &mut problems))
                .is_some_and(|m| m == "host");
            let has_port_label = labels.iter().any(|(k, ..)| {
                let k = k.to_ascii_lowercase();
                k.ends_with("loadbalancer.server.port") || k == "rdock.port"
            });
            let name = spec
                .get("container_name")
                .map_or_else(|| service.clone(), |n| compose_text(n, vars, &mut problems));
            let base = if traefik_service {
                self.traefik_service(service, spec, &mut problems);
                Finding::new(
                    "compose.service.traefik",
                    format!("the service runs Traefik ({image}): its flags and `TRAEFIK_*` variables are read as static configuration"),
                )
                .hint("replace the image with ReverseDock's and remove Traefik's flags: `rdock run` does not accept them")
            } else if ports.is_empty() && !host_network && !has_port_label {
                // Traefik would read the port the image exposes, which a Compose file does not
                // say.
                ports.insert(80);
                Finding::new(
                    "compose.service.port_assumed",
                    "no `expose`, `ports` or port label: port 80 was assumed (Traefik uses the port the image exposes)",
                )
            } else {
                Finding::new(
                    "compose.service",
                    format!("backends reach it as `{service}` (its Compose service name)"),
                )
            };
            b.account(item, base);
            if deploy_used {
                b.raise(
                    item,
                    Finding::new(
                        "compose.deploy_labels",
                        "`deploy.labels` (Swarm) were read as container labels",
                    )
                    .hint(
                        "to keep them on the stack instead, run ReverseDock with `providers.swarm`",
                    ),
                );
            }
            if let Some(problem) = problems.first() {
                b.raise(item, interpolation_finding(problem));
            }
            self.service_items.insert(name.clone(), item);
            // Routers of Traefik's own API and dashboard.
            let internal: BTreeSet<String> = labels
                .iter()
                .filter_map(|(k, v, _)| {
                    let lower = k.to_ascii_lowercase();
                    let rest = lower.strip_prefix("traefik.http.routers.")?;
                    let (router, field) = rest.split_once('.')?;
                    (field == "service" && v.ends_with("@internal")).then(|| router.to_owned())
                })
                .collect();
            let mut container_labels = BTreeMap::new();
            for (key, value, problems) in labels {
                if !relevant(&key) {
                    continue;
                }
                let id = b.item(Source {
                    file: file.clone(),
                    line: None,
                    scope: Some(service.clone()),
                    kind: ItemKind::Label,
                    item: key.clone(),
                });
                let lower = key.to_ascii_lowercase();
                let router = lower
                    .strip_prefix("traefik.http.routers.")
                    .and_then(|r| r.split_once('.'))
                    .map(|(r, _)| r.to_owned());
                if router.is_some_and(|r| internal.contains(&r)) {
                    b.account(
                        id,
                        Finding::new(
                            "traefik.label.manual",
                            "a router to Traefik's own API or dashboard (`…@internal`): ReverseDock's API and dashboard are on the admin listener (`admin`), not routed",
                        )
                        .hint("set `admin.enabled: true`; remove these labels"),
                    );
                    continue;
                }
                container_labels.insert(key.clone(), value.clone());
                self.items.push(LabelItem {
                    id,
                    container: name.clone(),
                    object: object_of(&key),
                    key,
                    value,
                    problems,
                });
            }
            self.containers.push(Container {
                name,
                labels: container_labels,
                networks: BTreeMap::new(),
                host_network,
                exposed_ports: ports,
                health: Health::None,
                stopping: false,
                dns_name: Some(service.clone()),
            });
        }
        Ok(())
    }

    /// The `command:` flags and `TRAEFIK_*` variables of Traefik's service.
    fn traefik_service(&mut self, service: &str, spec: &Value, problems: &mut Vec<Problem>) {
        let vars = &self.options.vars;
        let file = &self.options.file;
        let flags: Vec<String> = match spec.get("command") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|i| compose_text(i, vars, problems))
                .collect(),
            Some(Value::String(line)) => compose_text(&Value::String(line.clone()), vars, problems)
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        };
        self.static_options
            .extend(statics::from_flags(file, service, &flags));
        let mut env = BTreeMap::new();
        match spec.get("environment") {
            Some(Value::Object(map)) => {
                for (k, v) in map {
                    env.insert(k.clone(), compose_text(v, vars, problems));
                }
            }
            Some(Value::Array(items)) => {
                for item in items.iter().filter_map(Value::as_str) {
                    let item = compose_text(&Value::String(item.to_owned()), vars, problems);
                    let (k, v) = item.split_once('=').unwrap_or((&item, ""));
                    env.insert(k.to_owned(), v.to_owned());
                }
            }
            _ => {}
        }
        // Only the names of other variables are kept: they may hold credentials.
        self.env_names
            .extend(env.keys().filter(|k| !k.starts_with("TRAEFIK_")).cloned());
        self.static_options
            .extend(statics::from_env(file, service, &env));
    }

    /// A dynamic configuration file as the labels of one pseudo-container.
    fn dynamic(&mut self, document: &Value, b: &mut Builder) {
        let mut labels = BTreeMap::from([("traefik.enable".to_owned(), "true".to_owned())]);
        dynamic::read(
            &self.options.file,
            document,
            b,
            &mut labels,
            &mut self.items,
            &mut self.extra,
        );
        // The translator creates a service from its first server; every server is put in
        // afterwards ([`Run::apply`]).
        for (name, backends) in &self.extra.backends {
            if let Some(first) = backends.first()
                && let (Some(scheme), Some(address)) = (
                    first.get("scheme").and_then(Value::as_str),
                    first.get("address").and_then(Value::as_str),
                )
            {
                labels.insert(
                    format!("traefik.http.services.{name}.loadbalancer.server.url"),
                    format!("{scheme}://{address}"),
                );
            }
        }
        self.containers.push(Container {
            name: "dynamic".to_owned(),
            labels,
            ..Container::default()
        });
    }

    /// What a dynamic file says beyond labels, put into the translation.
    fn apply(&mut self, fragment: &mut Fragment, b: &mut Builder) {
        let extra = &self.extra;
        for (name, backends) in &extra.backends {
            let Some(service) = fragment.services.get_mut(name) else {
                continue;
            };
            let list: Vec<Value> = backends
                .iter()
                .filter(|b| b.get("address").is_some())
                .map(|b| {
                    let mut backend = json!({ "address": b["address"] });
                    if let Some(weight) = b.get("weight") {
                        backend["weight"] = weight.clone();
                    }
                    backend
                })
                .collect();
            if let Ok(backends) = serde_json::from_value(Value::Array(list)) {
                service.backends = backends;
            }
        }
        for (service, (transport, _)) in &extra.uses_transport {
            let (Some(target), Some(settings)) = (
                fragment.services.get_mut(service),
                extra.transports.get(transport),
            ) else {
                continue;
            };
            let Ok(mut value) = serde_json::to_value(&*target) else {
                continue;
            };
            for (key, patch) in settings {
                merge(&mut value[key.as_str()], patch);
            }
            if let Ok(service) = serde_json::from_value(value) {
                *target = service;
            }
        }
        for (name, split) in &extra.splits {
            match serde_json::from_value::<Service>(json!({ "split": split })) {
                Ok(service) => {
                    fragment.services.insert(name.clone(), service);
                }
                Err(err) => b.result(
                    Finding::new(
                        "output.invalid",
                        format!("weighted service `{name}` could not be written: {err}"),
                    )
                    .target(format!("services.{name}")),
                ),
            }
        }
        for (name, path) in &extra.users_files {
            let entry = fragment.middlewares.entry(name.clone()).or_insert_with(|| {
                rdock_model::middleware::Middleware::BasicAuth(
                    rdock_model::middleware::BasicAuthConfig::default(),
                )
            });
            if let rdock_model::middleware::Middleware::BasicAuth(auth) = entry {
                auth.users_file = Some(path.into());
            }
        }
        for (name, service) in &extra.tcp_services {
            match serde_json::from_value::<TcpService>(service.clone()) {
                Ok(service) => {
                    fragment.tcp_services.insert(name.clone(), service);
                }
                Err(err) => b.result(
                    Finding::new(
                        "output.invalid",
                        format!("TCP service `{name}` could not be written: {err}"),
                    )
                    .target(format!("tcp_services.{name}")),
                ),
            }
        }
        for (name, service) in &extra.udp_services {
            match serde_json::from_value::<UdpService>(service.clone()) {
                Ok(service) => {
                    fragment.udp_services.insert(name.clone(), service);
                }
                Err(err) => b.result(
                    Finding::new(
                        "output.invalid",
                        format!("UDP service `{name}` could not be written: {err}"),
                    )
                    .target(format!("udp_services.{name}")),
                ),
            }
        }
    }

    /// Accounts for every label from the translator's view of it.
    fn classify(&self, t: &Translation, settings: &DockerProvider, b: &mut Builder) {
        let provider = Settings::docker(settings);
        for item in &self.items {
            let Some(container) = self.containers.iter().find(|c| c.name == item.container) else {
                continue;
            };
            let lower = item.key.to_ascii_lowercase();
            let target = item
                .object
                .as_ref()
                .filter(|_| !lower.contains(".retry.") && !lower.contains(".chain."))
                .map(|(section, name)| format!("{section}.{name}"));
            let diagnostic = label_diagnostic(t, &item.container, &lower);
            let eligible = exposed(&container.labels, &provider);
            let finding = if let Some(problem) = item.problems.first() {
                interpolation_finding(problem)
            } else if !eligible {
                not_exposed(container, &lower, diagnostic)
            } else if lower.starts_with("rdock.") {
                match diagnostic {
                    Some(d) => Finding::new("rdock.label.invalid", d.message.clone()),
                    None => Finding::new("rdock.label", "read as it is"),
                }
            } else {
                traefik_label(&lower, diagnostic)
            };
            let finding = match target.clone() {
                Some(target) => finding.target(target),
                None => finding,
            };
            b.account(item.id, finding);
            if !eligible {
                continue;
            }
            if let Some((section, name)) = &item.object
                && let Some(ignored) = t.ignored.iter().find(|i| {
                    i.section == *section
                        && i.name == *name
                        && i.container.as_ref().is_none_or(|c| *c == item.container)
                })
            {
                b.raise(
                    item.id,
                    Finding::new("traefik.label.object_ignored", ignored.message.clone())
                        .target(format!("{section}.{name}")),
                );
            }
        }
        // Problems with a container as a whole.
        let ignored: BTreeSet<&str> = t.ignored.iter().map(|i| i.message.as_str()).collect();
        for diagnostic in &t.diagnostics {
            let Some(container) = self
                .containers
                .iter()
                .find(|c| diagnostic.path == path_key("docker", &c.name))
            else {
                continue;
            };
            if ignored.contains(diagnostic.message.as_str()) {
                continue;
            }
            let finding = if diagnostic.message.contains("is not exposed") {
                Finding::new("compose.service.not_exposed", diagnostic.message.clone())
                    .hint(diagnostic.hint.clone().unwrap_or_default())
            } else {
                Finding::new("compose.service.problem", diagnostic.message.clone())
                    .hint(diagnostic.hint.clone().unwrap_or_default())
            };
            match self.service_items.get(&container.name) {
                Some(item) => b.raise(*item, finding),
                None => b.result(finding),
            }
        }
    }

    /// Routes that use a middleware or service this input declared and that was not migrated
    /// are written disabled, so a route never goes live without (say) its authentication.
    fn incomplete(&self, fragment: &mut Fragment, b: &mut Builder) {
        let declared = |section: &str, name: &str| {
            self.items.iter().any(|i| {
                i.object
                    .as_ref()
                    .is_some_and(|(s, n)| *s == section && n == name)
            })
        };
        let names: Vec<String> = fragment.routes.keys().cloned().collect();
        for name in names {
            let Some(route) = fragment.routes.get(&name) else {
                continue;
            };
            let mut missing: Vec<String> = route
                .middlewares
                .iter()
                .filter(|m| !m.contains('@'))
                .filter(|m| !fragment.middlewares.contains_key(*m) && declared("middlewares", m))
                .map(|m| format!("middleware `{m}`"))
                .collect();
            if let Some(service) = &route.service
                && !service.contains('@')
                && !fragment.services.contains_key(service)
                && declared("services", service)
            {
                missing.push(format!("service `{service}`"));
            }
            if missing.is_empty() {
                continue;
            }
            if let Some(route) = fragment.routes.get_mut(&name) {
                route.enabled = false;
            }
            let item = self
                .items
                .iter()
                .filter(|i| {
                    i.object
                        .as_ref()
                        .is_some_and(|(s, n)| *s == "routes" && *n == name)
                })
                .find(|i| i.key.to_ascii_lowercase().ends_with(".middlewares"))
                .or_else(|| {
                    self.items.iter().find(|i| {
                        i.object
                            .as_ref()
                            .is_some_and(|(s, n)| *s == "routes" && *n == name)
                    })
                });
            let finding = Finding::new(
                "traefik.route.disabled",
                format!(
                    "route `{name}` is written disabled (`enabled: false`): it uses {}, which {} not migrated (see {})",
                    missing.join(", "),
                    if missing.len() == 1 { "was" } else { "were" },
                    if missing.len() == 1 { "its findings" } else { "their findings" }
                ),
            )
            .target(format!("routes.{name}"))
            .hint("replace what was not migrated, then remove `enabled: false`")
            .security();
            match item {
                Some(item) => b.raise(item.id, finding),
                None => b.result(finding),
            }
        }
    }

    /// Router-level differences: no entry points, and no TLS (plain HTTP in Traefik).
    fn routers(&self, fragment: &mut Fragment, st: &statics::Static, b: &mut Builder) {
        self.wildcards(fragment, st, b);
        let mut routers: BTreeMap<(&str, &str), Vec<&LabelItem>> = BTreeMap::new();
        for item in &self.items {
            if let Some(("routes", name)) = item.object.as_ref().map(|(s, n)| (*s, n.as_str()))
                && item.key.to_ascii_lowercase().starts_with("traefik.")
            {
                routers
                    .entry((item.container.as_str(), name))
                    .or_default()
                    .push(item);
            }
        }
        for ((_, name), items) in routers {
            let Some(route) = fragment.routes.get_mut(name) else {
                continue;
            };
            let field = |item: &LabelItem| {
                let lower = item.key.to_ascii_lowercase();
                lower
                    .split_once(&format!("routers.{}.", name.to_ascii_lowercase()))
                    .map(|(_, f)| f.to_owned())
                    .unwrap_or_default()
            };
            let rule = items
                .iter()
                .find(|i| field(i) == "rule")
                .or_else(|| items.first())
                .map(|i| i.id);
            let Some(rule) = rule else { continue };
            let entrypoints = items.iter().find(|i| field(i) == "entrypoints");
            let has_tls = items.iter().any(|i| field(i).starts_with("tls"));
            let target = format!("routes.{name}");
            let Some(entrypoints) = entrypoints else {
                b.raise(
                    rule,
                    Finding::new(
                        "traefik.router.all_entrypoints",
                        format!("router `{name}` names no entry point: Traefik attaches it to every entry point, ReverseDock to `defaults.listeners` (`websecure` unless set)"),
                    )
                    .target(target),
                );
                continue;
            };
            if has_tls {
                continue;
            }
            let names: Vec<&str> = entrypoints
                .value
                .split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .collect();
            if st.known {
                let tls = names
                    .iter()
                    .filter(|e| st.tls_entrypoints.contains(**e))
                    .count();
                let redirecting = names.iter().any(|e| st.redirecting.contains(*e));
                if tls == names.len() {
                    continue;
                }
                let all_known = names.iter().all(|e| st.listeners.contains_key(*e));
                if tls == 0 && !redirecting && all_known {
                    // Traefik serves it as plain HTTP on those entry points: so does the route.
                    route.tls = Some(RouteTls::Mode(TlsMode::Off));
                    continue;
                }
                let why = if redirecting {
                    "its entry point redirects every request elsewhere"
                } else {
                    "some of its entry points use TLS and some do not"
                };
                b.raise(
                    rule,
                    Finding::new(
                        "traefik.router.plain_http",
                        format!("router `{name}` has no `tls` and {why}; the route gets ReverseDock's defaults (HTTPS with an automatic certificate, HTTP redirected)"),
                    )
                    .target(target),
                );
            } else {
                b.raise(
                    rule,
                    Finding::new(
                        "traefik.router.plain_http",
                        format!("router `{name}` has no `tls`: Traefik serves it as plain HTTP unless its entry point sets `http.tls`; the route gets HTTPS with an automatic certificate and HTTP is redirected"),
                    )
                    .target(target)
                    .hint("migrate the static configuration too (`--static`, or the Traefik service in the same Compose file) to get the entry points' behaviour; or write `tls: off` on the route"),
                );
            }
        }
    }
}

impl Run<'_> {
    /// A wildcard certificate needs DNS-01: the DNS provider of the static configuration when
    /// there is one, else a manual finding.
    fn wildcards(&self, fragment: &mut Fragment, st: &statics::Static, b: &mut Builder) {
        let provider = st.acme.get("dns_provider").and_then(Value::as_str);
        for (name, route) in &mut fragment.routes {
            let Some(RouteTls::Options(tls)) = &mut route.tls else {
                continue;
            };
            if tls.dns_provider.is_some() || !tls.domains.iter().any(|d| d.starts_with("*.")) {
                continue;
            }
            if let Some(provider) = provider {
                tls.dns_provider = Some(provider.to_owned());
                continue;
            }
            let item = self.items.iter().find(|i| {
                i.object
                    .as_ref()
                    .is_some_and(|(s, n)| *s == "routes" && n == name)
                    && i.key.to_ascii_lowercase().contains(".tls.domains[")
            });
            if let Some(item) = item {
                b.raise(
                    item.id,
                    Finding::new(
                        "traefik.label.manual",
                        "a wildcard certificate needs the DNS-01 challenge: set `tls.dns_provider` on the route (or migrate the static configuration, whose DNS resolver then fills it in)",
                    )
                    .target(format!("routes.{name}.tls")),
                );
            }
        }
    }
}

/// Traefik's entry points carry any protocol; a listener here has one. An entry point that
/// only TCP routers use becomes a `tcp` listener (one with `http.tls` stays HTTPS, where TCP
/// routes match by SNI).
fn tcp_listeners(fragment: &Fragment, st: &mut statics::Static) {
    for (name, listener) in &mut st.listeners {
        let Value::Object(listener) = listener else {
            continue;
        };
        if listener.contains_key("protocol") || listener.contains_key("tls") {
            continue;
        }
        let tcp = fragment
            .tcp_routes
            .values()
            .any(|r| r.listeners.iter().flatten().any(|l| l == name));
        let http = fragment.routes.values().any(|r| {
            r.listeners
                .as_ref()
                .is_some_and(|ls| ls.iter().any(|l| l == name))
        });
        if tcp && !http {
            listener.insert("protocol".to_owned(), json!("tcp"));
        }
    }
}

/// Merges `patch` into `value` (objects key by key).
fn merge(value: &mut Value, patch: &Value) {
    match (value, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, item) in patch {
                merge(target.entry(key.clone()).or_insert(Value::Null), item);
            }
        }
        (slot, patch) => *slot = patch.clone(),
    }
}

/// The finding of a Compose interpolation problem.
fn interpolation_finding(problem: &Problem) -> Finding {
    let code = match problem {
        Problem::Unset(_) => "compose.interpolation.unset",
        Problem::Required { .. } => "compose.interpolation.required",
        Problem::Invalid(_) => "compose.interpolation.invalid",
    };
    let finding = Finding::new(code, problem.describe());
    match problem.variable() {
        Some(name) => finding.hint(format!(
            "pass `{name}` with `--env-file FILE` (or `--process-env`)"
        )),
        None => finding.hint("fix the reference; write `$$` for a literal `$`"),
    }
}

/// The translator's diagnostic at a label of a container.
fn label_diagnostic<'t>(
    t: &'t Translation,
    container: &str,
    lower: &str,
) -> Option<&'t Diagnostic> {
    let path = path_key(&format!("{}.labels", path_key("docker", container)), lower);
    t.diagnostics.iter().find(|d| d.path == path)
}

/// A label of a container nothing exposes.
fn not_exposed(container: &Container, lower: &str, diagnostic: Option<&Diagnostic>) -> Finding {
    let enable = ["rdock.enable", "traefik.enable"].iter().find_map(|key| {
        container
            .labels
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
    });
    match enable {
        Some((key, value)) if value == "false" => {
            if key == lower {
                Finding::new("traefik.label.exact", "the container is not routed, as in Traefik")
            } else {
                Finding::new(
                    "traefik.label.inactive",
                    "the container is turned off (`enable=false`); Traefik ignores the label too",
                )
            }
        }
        Some((key, _)) if key == lower => Finding::new(
            "traefik.label.invalid",
            diagnostic.map_or_else(|| "the value is not `true` or `false`".to_owned(), |d| d.message.clone()),
        ),
        _ => Finding::new(
            "traefik.label.not_exposed",
            "not migrated: the container is not exposed (no `traefik.enable`; Traefik's `exposedByDefault` would route it)",
        )
        .hint("add `traefik.enable=true`, rerun with `--expose-by-default`, or migrate the static configuration (`--static`)"),
    }
}

/// A Traefik label of an exposed container, by the coverage table and the translator.
fn traefik_label(lower: &str, diagnostic: Option<&Diagnostic>) -> Finding {
    let row = coverage::lookup(lower);
    match (row, diagnostic) {
        (None, Some(d)) => Finding::new("traefik.label.unknown", d.message.clone()),
        (None, None) => Finding::new(
            "traefik.label.approximate",
            "translated, but not in the coverage table (please report it)",
        ),
        (Some(row), Some(d)) => match row.status {
            Coverage::Exact | Coverage::Approximate => {
                Finding::new("traefik.label.invalid", d.message.clone())
            }
            Coverage::Manual => {
                let finding = Finding::new("traefik.label.manual", d.message.clone());
                if d.message.contains(row.note) {
                    finding
                } else {
                    finding.hint(row.note)
                }
            }
            Coverage::None => Finding::new("traefik.label.unsupported", d.message.clone()),
        },
        (Some(row), None) => match row.status {
            Coverage::Exact => Finding::new("traefik.label.exact", row.rdock),
            Coverage::Approximate => Finding::new(
                "traefik.label.approximate",
                format!("{}; {}", row.rdock, row.note),
            ),
            // The translator always refuses these; a quiet one is a table bug, reported.
            Coverage::Manual | Coverage::None => Finding::new("traefik.label.manual", row.note),
        },
    }
}

/// The output document: a fragment (routes, services, middlewares, TCP and UDP objects,
/// certificates), or with `full` a complete rdock.yaml.
fn output(
    fragment: &Fragment,
    extra: &dynamic::Extra,
    st: &statics::Static,
    full: bool,
    input: Input,
    b: &mut Builder,
) -> Result<Map<String, Value>, Error> {
    let mut document = Map::new();
    if full {
        let mut sections = st.sections();
        if !sections.iter().any(|(k, _)| *k == "listeners") {
            sections.insert(
                0,
                (
                    "listeners",
                    json!({ "web": { "address": ":80" }, "websecure": { "address": ":443", "tls": {} } }),
                ),
            );
        }
        if input == Input::Compose && !sections.iter().any(|(k, _)| *k == "providers") {
            sections.push(("providers", json!({ "docker": {} })));
        }
        for (key, value) in sections {
            document.insert(key.to_owned(), value);
        }
        if let Some(name) = &extra.default_certificate {
            let defaults = document.entry("defaults").or_insert_with(|| json!({}));
            defaults["certificate"] = json!(name);
        }
    }
    let labels_live = full && input == Input::Compose;
    let route_base = baseline::<Route>(&json!({ "match": "", "service": "" }));
    let service_base = baseline::<Service>(&json!({ "backends": [] }));
    let tcp_route_base = baseline::<TcpRoute>(&json!({ "match": "", "service": "" }));
    let tcp_service_base = baseline::<TcpService>(&json!({ "backends": [] }));
    let udp_route_base = baseline::<UdpRoute>(&json!({ "service": "" }));
    let udp_service_base = baseline::<UdpService>(&json!({ "backends": [] }));
    let sections: [(&str, Value, Option<&Value>); 8] = [
        (
            "certificates",
            Value::Object(extra.certificates.clone()),
            None,
        ),
        ("routes", to_value(&fragment.routes)?, route_base.as_ref()),
        (
            "services",
            to_value(&fragment.services)?,
            service_base.as_ref(),
        ),
        ("middlewares", to_value(&fragment.middlewares)?, None),
        (
            "tcp_routes",
            to_value(&fragment.tcp_routes)?,
            tcp_route_base.as_ref(),
        ),
        (
            "tcp_services",
            to_value(&fragment.tcp_services)?,
            tcp_service_base.as_ref(),
        ),
        (
            "udp_routes",
            to_value(&fragment.udp_routes)?,
            udp_route_base.as_ref(),
        ),
        (
            "udp_services",
            to_value(&fragment.udp_services)?,
            udp_service_base.as_ref(),
        ),
    ];
    let mut skipped = false;
    for (key, mut objects, base) in sections {
        let Value::Object(map) = &mut objects else {
            continue;
        };
        if map.is_empty() {
            continue;
        }
        if labels_live && key != "certificates" {
            skipped = true;
            continue;
        }
        for object in map.values_mut() {
            prune(object, base);
            // A backend's weight is 1 unless set.
            if let Some(Value::Array(backends)) = object.get_mut("backends") {
                for backend in backends.iter_mut().filter_map(Value::as_object_mut) {
                    if backend.get("weight") == Some(&Value::from(1)) {
                        backend.remove("weight");
                    }
                    if backend.get("backup") == Some(&Value::Bool(false)) {
                        backend.remove("backup");
                    }
                }
            }
        }
        document.insert(key.to_owned(), objects);
    }
    if skipped {
        b.result(Finding::new(
            "output.labels_live",
            "the routes, services and middlewares from labels are not written: with `--full` the Docker provider reads the same labels at run time (run without `--full` to see them as YAML)",
        ));
    }
    Ok(document)
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, Error> {
    serde_json::to_value(value).map_err(|e| Error::Input(e.to_string()))
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
        // `tls: {}` on a listener means TLS with its defaults.
        let keep_empty =
            key == "tls" && item.as_object().is_some_and(Map::is_empty) && default.is_none();
        (keep_empty || !empty) && default != Some(item)
    });
}

/// Validation errors of the result on its own (references to other files are expected).
fn check(document: &Map<String, Value>) -> Vec<Finding> {
    let config: Config = match serde_json::from_value(Value::Object(document.clone())) {
        Ok(config) => config,
        Err(err) => {
            return vec![Finding::new(
                "output.invalid",
                format!("the result does not read as rdock.yaml: {err}"),
            )];
        }
    };
    config
        .validate()
        .into_iter()
        .filter(Diagnostic::is_error)
        .map(|d| {
            let target = d.path.clone();
            Finding::new("output.invalid", d.message).target(target)
        })
        .collect()
}

/// The YAML under a header: the counts, then every finding that is not exact.
fn render(document: &Map<String, Value>, report: &Report, full: bool) -> Result<String, Error> {
    let body = if document.is_empty() {
        "{}\n".to_owned()
    } else {
        serde_saphyr::to_string(&Value::Object(document.clone()))
            .map_err(|e| Error::Input(e.to_string()))?
    };
    let what = if full {
        "a complete rdock.yaml"
    } else {
        "an rdock.yaml fragment (add listeners and defaults as needed)"
    };
    let mut header = format!(
        "# Generated by `{TOOL}` from {}: {what}. Review before use.\n# {}\n",
        report.source.files.join(", "),
        report.counts()
    );
    let notable: Vec<&Finding> = report.notable().collect();
    if notable.is_empty() {
        header.push_str("# Everything was migrated as it is.\n");
    } else {
        let _ = writeln!(header, "# To review ({}):", notable.len());
        for finding in notable {
            let line = finding.line().replace('\n', " ");
            let _ = writeln!(header, "#   - {line}");
        }
    }
    Ok(format!("{header}{body}"))
}
