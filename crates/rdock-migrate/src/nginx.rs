//! `rdock migrate nginx` (F-MGMT-03, B-CFG-04, ADR-0033; beta): an NGINX configuration into
//! rdock.yaml, with a report that accounts for every directive.
//!
//! The faithful subset of research note B §3.3, with each directive's semantics from the official
//! reference for NGINX 1.30 (stable; 1.31 mainline), read on 2026-11-14 at
//! <https://nginx.org/en/docs/>: `ngx_http_core_module` (`server`, `listen`, `server_name`,
//! `location`, `root`, `alias`, `try_files`, `client_max_body_size`), `ngx_http_proxy_module`
//! (`proxy_pass`, `proxy_set_header` and their defaults), `ngx_http_upstream_module`,
//! `ngx_http_rewrite_module`, `ngx_http_headers_module`, `ngx_http_ssl_module`,
//! `ngx_http_gzip_module`, `ngx_http_auth_basic_module`, `ngx_http_access_module`,
//! `ngx_http_index_module`, `ngx_http_autoindex_module` and `ngx_http_map_module`. Each rule
//! below quotes or cites its page.
//!
//! The translation is per construct: what has no faithful equivalent (`if`, `map` beyond the
//! WebSocket idiom, `set`, `rewrite … last`, named locations other than a `try_files` fallback,
//! variables, scripting modules, `stream`, `mail`, caching, `FastCGI`) is refused with its reason,
//! and the routes it affects are written disabled, so nothing goes live with the wrong behaviour.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Map, Value, json};

use crate::output::{self, Names, Notes, Objects};
use crate::report::{
    AccountingError, Builder, Finding, ItemId, ItemKind, Report, Source, SourceInfo,
};

pub mod files;
pub mod parser;
mod translate;

use parser::Directive;

/// The command, as reports name it.
const TOOL: &str = "rdock migrate nginx";

/// The NGINX version the semantics were checked against.
pub const NGINX_VERSION: &str = "1.30";

/// How to migrate.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The input's name for the report (`-` for standard input).
    pub file: String,
    /// The input's path, to resolve `include` against its directory (`None` for standard input).
    pub path: Option<PathBuf>,
    /// Read included files outside the main file's directory tree.
    pub include_outside: bool,
    /// Write a complete rdock.yaml (listeners, defaults) instead of a fragment.
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
    /// The input is not an NGINX configuration this tool reads.
    #[error("{0}")]
    Input(String),
    /// A bug: the report does not account for every source item.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

/// Migrates an NGINX configuration (a file, or a dump of `nginx -T`).
pub fn nginx(text: &str, options: &Options) -> Result<Migration, Error> {
    let (main_name, main_text, main_path, source) = match files::split_dump(text) {
        Some((main, dumped)) => {
            let content = dumped.get(&main).cloned().unwrap_or_default();
            (
                main.display().to_string(),
                content,
                main,
                files::Source::Dump(dumped),
            )
        }
        None => match &options.path {
            Some(path) => {
                let base = path
                    .parent()
                    .map(std::path::Path::to_path_buf)
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| PathBuf::from("."));
                (
                    options.file.clone(),
                    text.to_owned(),
                    path.clone(),
                    files::Source::Disk {
                        base,
                        allow_outside: options.include_outside,
                    },
                )
            }
            None => (
                options.file.clone(),
                text.to_owned(),
                PathBuf::from(&options.file),
                files::Source::None,
            ),
        },
    };
    let trimmed = main_text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with("---") || trimmed.starts_with("apiVersion:")
    {
        return Err(Error::Input(
            "not an NGINX configuration (this looks like JSON or YAML)".to_owned(),
        ));
    }
    let loaded = files::load(&main_name, &main_text, &main_path, &source).map_err(Error::Input)?;
    let has_known = contains(
        &loaded.tree,
        &[
            "http", "server", "location", "upstream", "events", "stream", "mail",
        ],
    );
    if !has_known {
        return Err(Error::Input(
            "not an NGINX configuration: no `http`, `server`, `location`, `upstream`, `events`, `stream` or `mail` block".to_owned(),
        ));
    }
    let mut run = Run::new(&loaded);
    run.register(&loaded.tree);
    translate::top(&mut run, &loaded.tree);
    finish(run, options)
}

fn contains(tree: &[Directive], names: &[&str]) -> bool {
    tree.iter()
        .any(|d| names.contains(&d.name.as_str()) && d.block.is_some())
}

/// The state of one migration.
pub(crate) struct Run<'t> {
    pub(crate) loaded: &'t files::Loaded,
    pub(crate) b: Builder,
    /// The item of each directive, by (file, line, column).
    items: BTreeMap<(usize, u32, u32), ItemId>,
    /// Notes per item, turned into findings at the end.
    notes: BTreeMap<ItemId, Notes>,
    /// Codes other than `nginx.directive.*` for an item.
    codes: BTreeMap<ItemId, &'static str>,
    pub(crate) services: Objects,
    pub(crate) middlewares: Objects,
    pub(crate) certificates: Map<String, Value>,
    pub(crate) routes: Map<String, Value>,
    pub(crate) route_names: Names,
    pub(crate) listeners: BTreeMap<String, Value>,
    pub(crate) defaults: Map<String, Value>,
    pub(crate) security: Map<String, Value>,
    pub(crate) observability: Map<String, Value>,
    /// Defaults of NGINX that the output writes explicitly or that change: code → message.
    pub(crate) defaults_changed: BTreeMap<&'static str, String>,
    /// Routes written disabled, with why.
    pub(crate) disabled: Vec<(String, String)>,
}

impl<'t> Run<'t> {
    fn new(loaded: &'t files::Loaded) -> Self {
        Self {
            loaded,
            b: Builder::default(),
            items: BTreeMap::new(),
            notes: BTreeMap::new(),
            codes: BTreeMap::new(),
            services: Objects::default(),
            middlewares: Objects::default(),
            certificates: Map::new(),
            routes: Map::new(),
            route_names: Names::default(),
            listeners: BTreeMap::new(),
            defaults: Map::new(),
            security: Map::new(),
            observability: Map::new(),
            defaults_changed: BTreeMap::new(),
            disabled: Vec::new(),
        }
    }

    /// Registers every directive as an item, in reading order.
    fn register(&mut self, tree: &[Directive]) {
        let mut order: Vec<&Directive> = Vec::new();
        walk(tree, &mut order, 0);
        for d in order {
            let file = self.loaded.files.get(d.file).cloned().unwrap_or_default();
            let id = self.b.item(Source {
                file,
                line: Some(d.line),
                scope: None,
                kind: ItemKind::Directive,
                item: d.label(),
            });
            self.items.insert((d.file, d.line, d.column), id);
        }
    }

    fn id(&self, d: &Directive) -> Option<ItemId> {
        self.items.get(&(d.file, d.line, d.column)).copied()
    }

    /// Adds a note to a directive's item.
    pub(crate) fn note(&mut self, d: &Directive, f: impl FnOnce(&mut Notes)) {
        if let Some(id) = self.id(d) {
            f(self.notes.entry(id).or_default());
        }
    }

    pub(crate) fn exact(&mut self, d: &Directive, message: impl Into<String>) {
        let message = message.into();
        self.note(d, |n| n.exact(message));
    }
    pub(crate) fn approx(&mut self, d: &Directive, message: impl Into<String>) {
        let message = message.into();
        self.note(d, |n| n.approx(message));
    }
    pub(crate) fn manual(&mut self, d: &Directive, message: impl Into<String>, hint: &str) {
        let message = message.into();
        self.note(d, |n| {
            n.manual(message);
            if !hint.is_empty() {
                n.hint(hint);
            }
        });
    }
    pub(crate) fn dropped(&mut self, d: &Directive, message: impl Into<String>) {
        let message = message.into();
        self.note(d, |n| n.dropped(message));
    }
    /// Uses another code for the directive's finding.
    pub(crate) fn code(&mut self, d: &Directive, code: &'static str) {
        if let Some(id) = self.id(d) {
            self.codes.insert(id, code);
        }
    }
    /// Whether the directive has a note already.
    pub(crate) fn noted(&self, d: &Directive) -> bool {
        self.id(d).is_some_and(|id| self.notes.contains_key(&id))
    }
}

/// Every directive, depth-first in reading order.
fn walk<'a>(list: &'a [Directive], out: &mut Vec<&'a Directive>, depth: usize) {
    for d in list {
        out.push(d);
        if let Some(block) = &d.block
            && depth < parser::MAX_DEPTH + 1
        {
            walk(block, out, depth + 1);
        }
    }
}

/// Findings, the output document, the check and the YAML.
#[allow(clippy::too_many_lines)] // one pass, in reading order
fn finish(mut run: Run<'_>, options: &Options) -> Result<Migration, Error> {
    let ids: Vec<ItemId> = run.items.values().copied().collect();
    for id in ids {
        let notes = run.notes.remove(&id).unwrap_or_else(|| {
            let mut n = Notes::default();
            n.dropped("not read: inside a block that was not migrated");
            n
        });
        let finding = match run.codes.get(&id) {
            Some(code) => notes.finding_as(code, None),
            None => notes.finding("nginx.directive", None),
        };
        run.b.account(id, finding);
    }
    for (code, message) in std::mem::take(&mut run.defaults_changed) {
        let mut finding = Finding::new(code, message);
        if code == "nginx.default.upstream_tls" {
            finding = finding.security().hint("name the backend's CA (`tls.ca_file`), or set `tls.verify: false` on the service for a self-signed backend you accept");
        }
        run.b.result(finding);
    }
    for (route, why) in std::mem::take(&mut run.disabled) {
        run.b.result(
            Finding::new(
                "nginx.route.disabled",
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
    if !listeners.is_empty() {
        full.insert("listeners".to_owned(), Value::Object(listeners));
    }
    if !run.defaults.is_empty() {
        full.insert("defaults".to_owned(), Value::Object(run.defaults.clone()));
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
    let files = run.loaded.files.clone();
    let report = run.b.finish(
        TOOL,
        SourceInfo {
            kind: "nginx".to_owned(),
            checked_against: format!("NGINX {NGINX_VERSION}"),
            files,
        },
    )?;
    let yaml = output::render(TOOL, &document, &report, options.full).map_err(Error::Input)?;
    Ok(Migration { yaml, report })
}
