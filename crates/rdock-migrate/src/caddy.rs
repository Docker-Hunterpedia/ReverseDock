//! `rdock migrate caddy` (F-MGMT-03, B-CFG-04, ADR-0033): Caddy's native JSON configuration (the
//! output of `caddy adapt`, or `GET /config/` of a running Caddy) into rdock.yaml, with a report
//! that accounts for every handler, matcher and setting.
//!
//! The JSON shapes are Caddy v2.11.9's, read on 2026-11-14 from the JSON reference
//! (<https://caddyserver.com/docs/json/>, served by its documentation API under
//! `https://caddyserver.com/api/docs/config/…`) and from the Caddyfile adapter's tests and source
//! at the `v2.11.9` tag (<https://github.com/caddyserver/caddy/tree/v2.11.9>,
//! `caddytest/integration/caddyfile_adapt/*.caddyfiletest`, `caddyconfig/httpcaddyfile/`,
//! `modules/caddyhttp/`). Each translation cites its source next to it.
//!
//! Caddy runs every matching route of a server in order and chains their handlers until one
//! answers; ReverseDock picks one route per request. Routes are therefore flattened by
//! following every path through the route list (`routes.rs`): each path that ends in a handler
//! that answers becomes one route whose rule is the conjunction of the matchers on the path,
//! whose middlewares are the handlers before it, and whose priority keeps Caddy's order.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::output::{self, Names};
pub(crate) use crate::output::{Notes, Objects};
use crate::report::{
    AccountingError, Builder, Finding, ItemId, ItemKind, Report, Source, SourceInfo,
};

mod handlers;
mod proxy;
mod routes;
mod tls;

/// The command, as reports name it.
const TOOL: &str = "rdock migrate caddy";

/// The Caddy release the shapes were checked against.
pub const CADDY_VERSION: &str = "v2.11.9";

/// How to migrate.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The input's name for the report (`-` for standard input).
    pub file: String,
    /// Write a complete rdock.yaml (listeners, defaults, acme) instead of a fragment.
    pub full: bool,
}

/// The result: rdock.yaml (or a fragment of it) with the report.
#[derive(Debug, Clone, PartialEq)]
pub struct Migration {
    /// The YAML, under a comment header that summarises the report.
    pub yaml: String,
    /// Every finding.
    pub report: Report,
}

/// Why nothing was migrated.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not Caddy's JSON configuration.
    #[error("{0}")]
    Input(String),
    /// A bug: the report does not account for every source item.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

/// The state of one migration.
pub(crate) struct Run<'a> {
    pub(crate) file: &'a str,
    pub(crate) b: Builder,
    pub(crate) services: Objects,
    pub(crate) middlewares: Objects,
    pub(crate) certificates: Map<String, Value>,
    pub(crate) routes: Map<String, Value>,
    pub(crate) route_names: Names,
    pub(crate) listeners: BTreeMap<String, Value>,
    pub(crate) acme: Map<String, Value>,
    pub(crate) defaults: Map<String, Value>,
    pub(crate) security: Map<String, Value>,
    pub(crate) observability: Map<String, Value>,
    /// Defaults of Caddy that the output writes explicitly or that change: code → message.
    pub(crate) defaults_changed: BTreeMap<&'static str, String>,
    /// Routes written disabled, with the item that caused it.
    pub(crate) disabled: Vec<(String, String)>,
    /// TLS settings that select a certificate or a DNS provider per host.
    pub(crate) tls: tls::HostTls,
}

impl Run<'_> {
    /// Registers a source item: a JSON pointer in the input.
    pub(crate) fn item(&mut self, scope: Option<&str>, pointer: &str) -> ItemId {
        self.b.item(Source {
            file: self.file.to_owned(),
            line: None,
            scope: scope.map(str::to_owned),
            kind: ItemKind::Key,
            item: pointer.to_owned(),
        })
    }

    /// Registers and accounts for an item in one go.
    pub(crate) fn account(
        &mut self,
        scope: Option<&str>,
        pointer: &str,
        finding: Finding,
    ) -> ItemId {
        let id = self.item(scope, pointer);
        self.b.account(id, finding);
        id
    }
}

/// Migrates Caddy's JSON configuration.
#[allow(clippy::too_many_lines)] // the top-level keys and the HTTP app's in one pass
pub fn caddy(text: &str, options: &Options) -> Result<Migration, Error> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        return Err(Error::Input(
            "not Caddy's JSON configuration: this reads the JSON that `caddy adapt` writes, not a Caddyfile; run `caddy adapt --config Caddyfile | rdock migrate caddy -` (or pass the JSON from Caddy's admin API, `GET /config/`)".to_owned(),
        ));
    }
    let document: Value = serde_json::from_str(text).map_err(|err| {
        Error::Input(format!(
            "invalid JSON: {err} (a Caddyfile must be adapted first: `caddy adapt --config Caddyfile | rdock migrate caddy -`)"
        ))
    })?;
    let Value::Object(root) = &document else {
        return Err(Error::Input("the JSON is not an object".to_owned()));
    };
    if !root.contains_key("apps") && !root.contains_key("admin") && !root.contains_key("logging") {
        return Err(Error::Input(
            "not Caddy's JSON configuration: no `apps`, `admin` or `logging` key".to_owned(),
        ));
    }
    let mut run = Run {
        file: &options.file,
        b: Builder::default(),
        services: Objects::default(),
        middlewares: Objects::default(),
        certificates: Map::new(),
        routes: Map::new(),
        route_names: Names::default(),
        listeners: BTreeMap::new(),
        acme: Map::new(),
        defaults: Map::new(),
        security: Map::new(),
        observability: Map::new(),
        defaults_changed: BTreeMap::new(),
        disabled: Vec::new(),
        tls: tls::HostTls::default(),
    };
    top_level(&mut run, root);
    let apps = root
        .get("apps")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // The TLS app first: the HTTP servers' routes select its certificates and DNS providers.
    if let Some(app) = apps.get("tls") {
        tls::app(&mut run, app);
    }
    let http = apps.get("http").cloned().unwrap_or(Value::Null);
    let mut plain_port = 80;
    let mut tls_port = 443;
    if let Value::Object(app) = &http {
        for (key, value) in app {
            let pointer = format!("/apps/http/{key}");
            match key.as_str() {
                "servers" => {}
                "http_port" | "https_port" => {
                    let port = value.as_u64().and_then(|p| u16::try_from(p).ok());
                    let mut notes = Notes::default();
                    match port {
                        Some(port) => {
                            if key == "http_port" {
                                plain_port = port;
                            } else {
                                tls_port = port;
                            }
                            notes.exact(format!(
                                "the {} listener uses port {port}",
                                if key == "http_port" {
                                    "plain HTTP (`web`)"
                                } else {
                                    "HTTPS (`websecure`)"
                                }
                            ));
                        }
                        None => notes.manual("not a port number"),
                    }
                    run.account(
                        Some("http"),
                        &pointer,
                        notes.finding("caddy.config", Some("listeners")),
                    );
                }
                "grace_period" | "shutdown_delay" => {
                    let mut notes = Notes::default();
                    match handlers::duration(value) {
                        Some(d) if key == "grace_period" => {
                            run.defaults.insert("__drain".to_owned(), json!(d));
                            notes.approx(format!("written as `lifecycle.drain_timeout: {d}` (with `--full`): ReverseDock drains open connections for this long at shutdown"));
                        }
                        Some(_) => {
                            notes.dropped("ReverseDock has no delay before it starts draining");
                        }
                        None => notes.manual("not a duration"),
                    }
                    run.account(
                        Some("http"),
                        &pointer,
                        notes.finding("caddy.config", Some("lifecycle")),
                    );
                }
                _ => {
                    let mut notes = Notes::default();
                    notes.dropped(format!("`{key}` of the HTTP app has no equivalent"));
                    run.account(Some("http"), &pointer, notes.finding("caddy.config", None));
                }
            }
        }
    }
    let servers = http
        .get("servers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut ports = Ports {
        http: plain_port,
        https: tls_port,
    };
    for (name, server) in &servers {
        routes::server(&mut run, name, server, &mut ports);
    }
    for (name, app) in &apps {
        if name == "http" || name == "tls" {
            continue;
        }
        let mut notes = Notes::default();
        match name.as_str() {
            "pki" => {
                notes.manual("the `pki` app (Caddy's own certificate authorities) is not migrated: ReverseDock's local CA signs private names automatically (`rdock trust` installs its root)");
                notes.hint("check that the names Caddy signed internally end in a private suffix (`.localhost`, `.internal`, `.test`, …) or are private addresses");
            }
            "layer4" => {
                notes.manual("the `layer4` app (a plugin) is not migrated");
                notes.hint("write `tcp_routes` and `tcp_services` (with `HostSNI` and `tls.passthrough`) or `udp_routes` by hand");
            }
            other => {
                notes.manual(format!("app `{other}` is not one ReverseDock migrates (a plugin or a Caddy app without an equivalent)"));
            }
        }
        let _ = app;
        run.account(
            Some(name),
            &format!("/apps/{name}"),
            notes.finding("caddy.config", None),
        );
    }
    finish(run, options, ports)
}

/// The ports of the HTTP app (`http_port`, `https_port`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ports {
    pub(crate) http: u16,
    pub(crate) https: u16,
}

/// `admin`, `logging`, `storage` and the other top-level keys.
fn top_level(run: &mut Run<'_>, root: &Map<String, Value>) {
    for (key, value) in root {
        let pointer = format!("/{key}");
        let mut notes = Notes::default();
        match key.as_str() {
            "apps" => continue,
            "admin" => {
                notes.dropped("Caddy's admin API has no equivalent here: ReverseDock's admin API (`admin`) is a different API, so nothing carries over");
                notes.hint("set `admin.enabled: true` for ReverseDock's API and dashboard");
            }
            "storage" => {
                notes.manual("a storage module: ReverseDock keeps certificates and state in its data directory (`RDOCK_DATA_DIR`, or `acme.storage`), not in a shared storage module");
                notes.hint("for several instances, see the cluster guide (`cluster`)");
            }
            "logging" => {
                logging(run, value, &mut notes);
            }
            other => {
                notes.dropped(format!("top-level key `{other}` has no equivalent"));
            }
        }
        run.account(None, &pointer, notes.finding("caddy.config", None));
    }
}

/// `logging.logs`: the default log's level, access logs are per server.
fn logging(run: &mut Run<'_>, value: &Value, notes: &mut Notes) {
    let level = value.pointer("/logs/default/level").and_then(Value::as_str);
    match level {
        Some(level) => {
            notes.approx(format!(
                "the default log's level `{level}` is not a configuration setting here: run `rdock run --log {}`",
                level.to_ascii_lowercase()
            ));
        }
        None => notes.approx("Caddy's logs and writers have no equivalent here: ReverseDock writes its own log to standard error and access logs as `observability.access_log` says"),
    }
    let _ = run;
    notes.hint("access logs: `observability.access_log` (global, not per site)");
}

/// The output document, the check, the report and the YAML.
fn finish(mut run: Run<'_>, options: &Options, ports: Ports) -> Result<Migration, Error> {
    for (code, message) in std::mem::take(&mut run.defaults_changed) {
        run.b.result(Finding::new(code, message));
    }
    for (route, why) in std::mem::take(&mut run.disabled) {
        run.b.result(
            Finding::new(
                "caddy.route.disabled",
                format!("route `{route}` is written disabled (`enabled: false`): {why}"),
            )
            .target(format!("routes.{route}"))
            .hint("replace what was not migrated, then remove `enabled: false`")
            .security(),
        );
    }
    let mut full = Map::new();
    let mut listeners = Map::new();
    for (name, listener) in std::mem::take(&mut run.listeners) {
        listeners.insert(name, listener);
    }
    if listeners.is_empty() {
        listeners.insert(
            "web".to_owned(),
            json!({ "address": format!(":{}", ports.http) }),
        );
        listeners.insert(
            "websecure".to_owned(),
            json!({ "address": format!(":{}", ports.https), "tls": {} }),
        );
    }
    full.insert("listeners".to_owned(), Value::Object(listeners));
    let drain = run.defaults.remove("__drain");
    if !run.defaults.is_empty() {
        full.insert("defaults".to_owned(), Value::Object(run.defaults.clone()));
    }
    if !run.acme.is_empty() {
        full.insert("acme".to_owned(), Value::Object(run.acme.clone()));
    }
    if !run.security.is_empty() {
        full.insert("security".to_owned(), Value::Object(run.security.clone()));
    }
    if !run.observability.is_empty() {
        full.insert(
            "observability".to_owned(),
            Value::Object(run.observability.clone()),
        );
    }
    if let Some(drain) = drain {
        full.insert("lifecycle".to_owned(), json!({ "drain_timeout": drain }));
    }
    let mut fragment = Map::new();
    if !run.certificates.is_empty() {
        fragment.insert(
            "certificates".to_owned(),
            Value::Object(run.certificates.clone()),
        );
    }
    let route_base =
        output::baseline::<rdock_model::route::Route>(&json!({ "match": "", "service": "" }));
    let service_base =
        output::baseline::<rdock_model::service::Service>(&json!({ "backends": [] }));
    let mut routes = std::mem::take(&mut run.routes);
    for route in routes.values_mut() {
        output::prune(route, route_base.as_ref());
    }
    let mut services = std::mem::take(&mut run.services.map);
    for service in services.values_mut() {
        output::prune(service, service_base.as_ref());
    }
    // Middlewares are written as built: an empty list (`precompressed: []`) is a setting.
    let middlewares = std::mem::take(&mut run.middlewares.map);
    for (key, objects) in [
        ("routes", routes),
        ("services", services),
        ("middlewares", middlewares),
    ] {
        if !objects.is_empty() {
            fragment.insert(key.to_owned(), Value::Object(objects));
        }
    }
    let mut checked = full.clone();
    for (key, value) in &fragment {
        checked.insert(key.clone(), value.clone());
    }
    let document = if options.full {
        checked.clone()
    } else {
        fragment
    };
    for finding in output::check(&checked) {
        run.b.result(finding);
    }
    let report = run.b.finish(
        TOOL,
        SourceInfo {
            kind: "caddy".to_owned(),
            checked_against: format!("Caddy {CADDY_VERSION}"),
            files: vec![options.file.clone()],
        },
    )?;
    let yaml = output::render(TOOL, &document, &report, options.full).map_err(Error::Input)?;
    Ok(Migration { yaml, report })
}
