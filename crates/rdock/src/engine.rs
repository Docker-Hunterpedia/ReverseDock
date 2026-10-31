//! The configuration engine of `rdock run`: load → validate → compile → apply, with the
//! last-known-good fallback and the on-disk history (architecture §5).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rdock_config::includes::{Included, expand, load_file_with_includes};
use rdock_config::merge::{ObjectKey, Snapshot, assemble, is_provider_owned, owner, skipped};
use rdock_config::state::{HISTORY_LIMIT, HistoryEntry, StateDir};
use rdock_config::{Format, Loaded, System, load_str, load_value};
use rdock_model::middleware::Middleware;
use rdock_model::values::TrustedProxy;
use rdock_model::{Config, Diagnostic};
use rdock_proxy::{DataPlane, Runtime};
use serde::Serialize;
use serde_json::Value;

use crate::validate::load_error;
use crate::zero_config::{self, Source};

mod api;

/// Where the applied configuration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Origin {
    /// The configuration file.
    File,
    /// The last-known-good copy, because the file could not be used at start.
    LastKnownGood,
}

impl Origin {
    /// The name used in logs, matching the serialised form.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::LastKnownGood => "last-known-good",
        }
    }
}

/// The outcome of one load-and-apply attempt.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Report {
    /// `applied` or `rejected`.
    pub result: &'static str,
    /// What started it: `start`, `SIGHUP`, `file change`, `api`.
    pub trigger: String,
    /// Generation in use afterwards.
    pub generation: u64,
    /// When it finished.
    pub at: String,
    /// Origin of the configuration in use.
    pub origin: Origin,
    /// Why it was rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Diagnostics of the attempt (warnings included).
    pub diagnostics: Vec<Diagnostic>,
}

impl Report {
    pub(crate) fn applied(&self) -> bool {
        self.result == "applied"
    }
}

struct Applied {
    config: Option<Config>,
    source: Option<Value>,
    /// The API provider's objects as last applied, for the history.
    api: Option<Value>,
    origin: Origin,
}

/// Providers whose snapshots the engine merges.
const PROVIDERS: [&str; 2] = ["docker", api::PROVIDER];

/// Whether the file configuration enables `provider`.
fn enabled(file: &Config, provider: &str) -> bool {
    match provider {
        "docker" => file.providers.docker.is_some(),
        api::PROVIDER => true,
        _ => false,
    }
}

/// Rounds of "leave out the provider objects that fail to compile, try again".
const COMPILE_ROUNDS: usize = 4;

/// The engine shared by signal handlers, the file watcher, providers and the admin API.
pub(crate) struct Engine {
    source: Source,
    state: StateDir,
    plane: Arc<DataPlane>,
    /// Issues and renews automatic certificates (ADR-0020).
    acme: rdock_acme::Manager,
    /// Keeps Cloudflare's edge ranges current while `trusted_proxies` contains `cloudflare`.
    cloudflare: rdock_cloudflare::IpSync,
    /// Issues local-CA certificates for private names (ADR-0020).
    local_ca: rdock_acme::LocalIssuer,
    applied: tokio::sync::Mutex<Applied>,
    ready: AtomicBool,
    metrics_enabled: AtomicBool,
    last: Mutex<Option<Report>>,
    watched: Mutex<BTreeSet<PathBuf>>,
    /// Hash of the watched files when the configuration was last applied.
    fingerprint: Mutex<Option<u64>>,
    /// The extra files (`providers.file.paths`) of the last load.
    included: Mutex<Included>,
    /// The latest snapshot of each provider, by provider name.
    snapshots: Mutex<BTreeMap<String, Snapshot>>,
    /// Why a provider cannot reach its source, while it cannot.
    degraded: Mutex<BTreeMap<String, String>>,
    started_at: SystemTime,
    /// One configuration write through the API at a time (version check and apply).
    api_writes: tokio::sync::Mutex<()>,
}

/// What the certificate manager should do for an applied configuration: nothing when
/// automatic certificates are off.
fn acme_plan(config: &Config, runtime: &Runtime) -> rdock_acme::Plan {
    let acme = config.effective_acme();
    rdock_acme::Plan {
        requests: if acme.is_some() {
            runtime.cert_requests.clone()
        } else {
            Vec::new()
        },
        acme: acme.map(std::borrow::Cow::into_owned).unwrap_or_default(),
        http01: runtime.listeners.values().any(|l| l.tls.is_none()),
        tls_alpn01: runtime.listeners.values().any(|l| l.tls.is_some()),
        alerts: config.observability.alerts.webhook.clone(),
    }
}

fn now_rfc3339() -> String {
    rdock_observability::rfc3339(SystemTime::now())
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Engine {
    pub(crate) fn new(source: Source, data_dir: &Path, plane: Arc<DataPlane>) -> Self {
        Self {
            source,
            state: StateDir::new(data_dir),
            acme: rdock_acme::Manager::spawn(rdock_acme::Services {
                default_storage: data_dir.join("acme"),
                resolver: plane.resolver(),
                challenges: plane.challenges(),
                metrics: plane.metrics().clone(),
                dns: Arc::new(rdock_cloudflare::dns::Providers),
            }),
            cloudflare: rdock_cloudflare::IpSync::spawn(
                rdock_cloudflare::Options::new(data_dir.join("cloudflare")),
                plane.cloudflare_ranges(),
            ),
            local_ca: rdock_acme::LocalIssuer::spawn(data_dir.join("pki"), plane.resolver()),
            plane,
            applied: tokio::sync::Mutex::new(Applied {
                config: None,
                source: None,
                api: None,
                origin: Origin::File,
            }),
            ready: AtomicBool::new(false),
            metrics_enabled: AtomicBool::new(true),
            last: Mutex::new(None),
            watched: Mutex::new(BTreeSet::new()),
            fingerprint: Mutex::new(None),
            included: Mutex::new(Included::default()),
            snapshots: Mutex::new(BTreeMap::new()),
            degraded: Mutex::new(BTreeMap::new()),
            started_at: SystemTime::now(),
            api_writes: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }

    /// Files whose changes should trigger a reload.
    pub(crate) fn watched_files(&self) -> BTreeSet<PathBuf> {
        self.watched
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The data plane's live feeds, for the admin API's streams.
    pub(crate) fn feeds(&self) -> rdock_observability::feed::Feeds {
        self.plane.metrics().feeds.clone()
    }

    /// The applied configuration, if any.
    pub(crate) async fn config(&self) -> Option<Config> {
        self.applied.lock().await.config.clone()
    }

    /// Drain time of the applied configuration.
    pub(crate) async fn drain_timeout(&self) -> Duration {
        self.applied
            .lock()
            .await
            .config
            .as_ref()
            .map_or(Duration::from_secs(8), |c| {
                c.lifecycle.drain_timeout.as_std()
            })
    }

    /// Takes a provider's new snapshot; the caller reloads to apply it.
    pub(crate) fn set_snapshot(&self, snapshot: Snapshot) {
        self.snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(snapshot.provider.clone(), snapshot);
    }

    /// Records whether a provider can reach its source (`None`: it can).
    pub(crate) fn set_degraded(&self, provider: &str, reason: Option<String>) {
        let mut degraded = self.degraded.lock().unwrap_or_else(PoisonError::into_inner);
        match reason {
            Some(reason) => degraded.insert(provider.to_owned(), reason),
            None => degraded.remove(provider),
        };
    }

    /// Serves the stored snapshots until the providers report, so a restart while Docker is
    /// unreachable keeps its routes (ADR-0018).
    pub(crate) fn restore_snapshots(&self) {
        for provider in PROVIDERS {
            match self.state.load_snapshot(provider) {
                Ok(Some(snapshot)) => self.set_snapshot(snapshot),
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!(%provider, error = %err, "cannot read the stored provider snapshot");
                }
            }
        }
    }

    /// The snapshots of the providers `file` enables.
    fn current_snapshots(&self, file: &Config) -> Vec<Snapshot> {
        self.snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter(|s| enabled(file, &s.provider))
            .cloned()
            .collect()
    }

    /// First load. Falls back to the last-known-good copy when the file cannot be used.
    pub(crate) async fn boot(&self) -> Result<Report, Box<Report>> {
        let report = Box::new(self.reload("start").await);
        if report.applied() {
            return Ok(*report);
        }
        let lkg = match self.state.load_lkg() {
            Ok(Some(source)) => source,
            Ok(None) => return Err(report),
            Err(err) => {
                tracing::warn!(error = %err, "cannot read the last-known-good configuration");
                return Err(report);
            }
        };
        tracing::error!(
            file = %self.source.describe(),
            "the configuration file cannot be used; serving the last-known-good configuration"
        );
        for d in &report.diagnostics {
            tracing::error!(path = %d.path, "{}", d.message);
        }
        match load_value(lkg, &System) {
            Ok(loaded) if !loaded.has_errors() => {
                let lkg_report = self.apply(loaded, "start", Origin::LastKnownGood).await;
                if lkg_report.applied() {
                    Ok(lkg_report)
                } else {
                    Err(report)
                }
            }
            _ => Err(report),
        }
    }

    /// Reloads after a file event, unless the watched files are unchanged since the last apply
    /// (editors and atomic replaces send several events for one change).
    pub(crate) async fn reload_if_changed(&self, trigger: &str) -> Option<Report> {
        let now = fingerprint(&self.watched_files());
        if *self
            .fingerprint
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            == Some(now)
        {
            return None;
        }
        Some(self.reload(trigger).await)
    }

    /// Loads the configuration file and applies it; on any problem the running configuration
    /// stays in place.
    pub(crate) async fn reload(&self, trigger: &str) -> Report {
        let loaded = match &self.source {
            Source::File(path) => load_file_with_includes(path).map(|(loaded, included)| {
                *self.included.lock().unwrap_or_else(PoisonError::into_inner) = included;
                loaded
            }),
            Source::ZeroConfig => load_str(zero_config::CONFIG, Format::Yaml),
        };
        let loaded = match loaded {
            Ok(loaded) => loaded,
            Err(err) => {
                return self
                    .rejected(trigger, Some(err.to_string()), vec![load_error(&err)])
                    .await;
            }
        };
        if loaded.has_errors() {
            return self
                .rejected(
                    trigger,
                    Some("the configuration has errors".to_owned()),
                    loaded.diagnostics,
                )
                .await;
        }
        self.apply(loaded, trigger, Origin::File).await
    }

    /// Hands the applied configuration to the tasks that work beside the data plane.
    fn update_background(
        &self,
        config: &Config,
        acme_plan: rdock_acme::Plan,
        local_names: Vec<String>,
    ) {
        self.acme.update(acme_plan);
        self.cloudflare.set_enabled(
            config
                .security
                .trusted_proxies
                .contains(&TrustedProxy::Cloudflare),
        );
        self.local_ca.update(local_names);
    }

    async fn apply(&self, loaded: Loaded, trigger: &str, origin: Origin) -> Report {
        let mut applied = self.applied.lock().await;
        let Loaded {
            config: file,
            source,
            mut diagnostics,
        } = loaded;
        let snapshots = self.current_snapshots(&file);
        for snapshot in &snapshots {
            diagnostics.extend(snapshot.diagnostics.iter().cloned());
        }
        let (config, runtime) = match self.merge_and_compile(&file, &snapshots, &mut diagnostics) {
            Ok(compiled) => compiled,
            Err(error) => {
                drop(applied);
                return self.rejected(trigger, Some(error), diagnostics).await;
            }
        };
        let generation = runtime.generation;
        let drain = config.lifecycle.drain_timeout.as_std();
        let acme_plan = acme_plan(&config, &runtime);
        let local_names = runtime.local_cert_names.clone();
        if let Err(err) = self.plane.apply(runtime, drain).await {
            drop(applied);
            return self
                .rejected(trigger, Some(err.to_string()), diagnostics)
                .await;
        }
        self.update_background(&config, acme_plan, local_names);
        let summary = summarize(applied.config.as_ref(), &config);
        let api = snapshots
            .iter()
            .find(|s| s.provider == api::PROVIDER)
            .and_then(|s| serde_json::to_value(&s.fragment).ok());
        if applied.source.as_ref() != Some(&source) || applied.api != api {
            self.record_history(generation, &summary, &source, api.as_ref());
        }
        if origin == Origin::File
            && let Err(err) = self.state.save_lkg(&source)
        {
            tracing::warn!(error = %err, "cannot write the last-known-good configuration");
        }
        for snapshot in &snapshots {
            if let Err(err) = self.state.save_snapshot(snapshot) {
                tracing::warn!(provider = %snapshot.provider, error = %err, "cannot store the provider snapshot");
            }
        }
        let files = match &self.source {
            Source::File(path) => {
                let mut files = referenced_files(path, &file);
                if file.providers.file.as_ref().is_none_or(|f| f.watch) {
                    let included = self.included.lock().unwrap_or_else(PoisonError::into_inner);
                    files.extend(included.files.iter().cloned());
                    files.extend(included.patterns.iter().cloned());
                }
                files
            }
            Source::ZeroConfig => BTreeSet::new(),
        };
        *self
            .fingerprint
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(fingerprint(&files));
        *self.watched.lock().unwrap_or_else(PoisonError::into_inner) = files;
        self.metrics_enabled
            .store(config.observability.metrics.prometheus, Ordering::SeqCst);
        applied.config = Some(config);
        applied.source = Some(source);
        applied.api = api;
        applied.origin = origin;
        drop(applied);
        for d in diagnostics.iter().filter(|d| !d.is_error()) {
            tracing::warn!(path = %d.path, "{}", d.message);
        }
        tracing::info!(generation, %trigger, %summary, "configuration applied");
        self.plane
            .metrics()
            .config_reloads
            .with_label_values(&["applied"])
            .inc();
        let report = Report {
            result: "applied",
            trigger: trigger.to_owned(),
            generation,
            at: now_rfc3339(),
            origin,
            error: None,
            diagnostics,
        };
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(report.clone());
        self.plane.metrics().feeds.events.send(serde_json::json!({
            "type": "reload",
            "result": report.result,
            "trigger": report.trigger,
            "generation": report.generation,
            "error": report.error,
            "diagnostics": report.diagnostics.len(),
        }));
        report
    }

    /// Adds an entry to the on-disk history; a failure is logged, never fatal.
    fn record_history(&self, generation: u64, summary: &str, source: &Value, api: Option<&Value>) {
        let entry = HistoryEntry {
            applied_at_ms: unix_ms(),
            generation,
            summary: summary.to_owned(),
            source: source.clone(),
            api: api.cloned(),
        };
        if let Err(err) = self.state.record(&entry, HISTORY_LIMIT) {
            tracing::warn!(error = %err, "cannot write the configuration history");
        }
    }

    /// Merges the providers' objects into the file configuration and compiles it. Provider
    /// objects that fail validation or compilation are left out with a warning; errors in the
    /// file's own objects reject the whole configuration, as without providers.
    fn merge_and_compile(
        &self,
        file: &Config,
        snapshots: &[Snapshot],
        out: &mut Vec<Diagnostic>,
    ) -> Result<(Config, Runtime), String> {
        let snapshots: Vec<&Snapshot> = snapshots.iter().collect();
        let mut excluded: BTreeSet<ObjectKey> = BTreeSet::new();
        let mut left_out = Vec::new();
        for _ in 0..COMPILE_ROUNDS {
            let merged = assemble(file, &snapshots, &excluded);
            if !merged.errors.is_empty() {
                out.extend(merged.errors);
                return Err("the configuration has errors".to_owned());
            }
            let compiled = self.plane.compile(&merged.config);
            let (failed, findings): (Vec<Diagnostic>, Vec<Diagnostic>) =
                compiled.diagnostics.into_iter().partition(|d| {
                    d.is_error() && owner(&d.path).is_some_and(|(_, key)| is_provider_owned(&key))
                });
            if failed.is_empty() {
                out.extend(left_out);
                out.extend(merged.skipped);
                out.extend(findings);
                return compiled
                    .runtime
                    .map(|runtime| (merged.config, runtime))
                    .ok_or_else(|| "the configuration cannot be compiled".to_owned());
            }
            for error in &failed {
                if let Some(key) = owner(&error.path)
                    && excluded.insert(key.clone())
                {
                    left_out.push(skipped(key.0, &key.1, error));
                }
            }
        }
        out.extend(left_out);
        Err("provider objects keep failing to compile".to_owned())
    }

    async fn rejected(
        &self,
        trigger: &str,
        error: Option<String>,
        diagnostics: Vec<Diagnostic>,
    ) -> Report {
        self.plane
            .metrics()
            .config_reloads
            .with_label_values(&["rejected"])
            .inc();
        let origin = self.applied.lock().await.origin;
        let report = Report {
            result: "rejected",
            trigger: trigger.to_owned(),
            generation: self.plane.runtime().generation,
            at: now_rfc3339(),
            origin,
            error,
            diagnostics,
        };
        if trigger != "start" {
            tracing::error!(
                %trigger,
                error = report.error.as_deref().unwrap_or_default(),
                "configuration rejected; the previous one stays in use"
            );
            for d in report.diagnostics.iter().filter(|d| d.is_error()) {
                tracing::error!(path = %d.path, "{}", d.message);
            }
        }
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(report.clone());
        self.plane.metrics().feeds.events.send(serde_json::json!({
            "type": "reload",
            "result": report.result,
            "trigger": report.trigger,
            "generation": report.generation,
            "error": report.error,
            "diagnostics": report.diagnostics.len(),
        }));
        report
    }
}

/// A one-line summary of what changed, for logs and history.
fn summarize(before: Option<&Config>, after: &Config) -> String {
    let Some(before) = before else {
        return format!(
            "{} listeners, {} routes, {} services, {} middlewares",
            after.effective_listeners().len(),
            after.routes.len(),
            after.services.len(),
            after.middlewares.len()
        );
    };
    let mut parts = Vec::new();
    diff_names(
        &mut parts,
        "listener",
        &before.effective_listeners(),
        &after.effective_listeners(),
    );
    diff_names(&mut parts, "route", &before.routes, &after.routes);
    diff_names(&mut parts, "service", &before.services, &after.services);
    diff_names(
        &mut parts,
        "middleware",
        &before.middlewares,
        &after.middlewares,
    );
    diff_names(
        &mut parts,
        "certificate",
        &before.certificates,
        &after.certificates,
    );
    if parts.is_empty() {
        "no object changed".to_owned()
    } else {
        parts.join("; ")
    }
}

fn diff_names<T: PartialEq>(
    parts: &mut Vec<String>,
    kind: &str,
    before: &std::collections::BTreeMap<String, T>,
    after: &std::collections::BTreeMap<String, T>,
) {
    let added: Vec<&str> = after
        .keys()
        .filter(|k| !before.contains_key(*k))
        .map(String::as_str)
        .collect();
    let removed: Vec<&str> = before
        .keys()
        .filter(|k| !after.contains_key(*k))
        .map(String::as_str)
        .collect();
    let changed: Vec<&str> = after
        .iter()
        .filter(|(k, v)| before.get(*k).is_some_and(|old| old != *v))
        .map(|(k, _)| k.as_str())
        .collect();
    for (verb, names) in [("added", added), ("removed", removed), ("changed", changed)] {
        if !names.is_empty() {
            parts.push(format!("{kind}s {verb}: {}", names.join(", ")));
        }
    }
}

/// A hash of the contents of `files` (missing files count as empty). A pattern
/// (`conf.d/*.yaml`) stands for the files it matches now, so adding or removing one counts.
fn fingerprint(files: &BTreeSet<PathBuf>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for file in files {
        file.hash(&mut hasher);
        if is_pattern(file) {
            for matched in expand(file).unwrap_or_default() {
                matched.hash(&mut hasher);
                std::fs::read(&matched)
                    .unwrap_or_default()
                    .hash(&mut hasher);
            }
        } else {
            std::fs::read(file).unwrap_or_default().hash(&mut hasher);
        }
    }
    hasher.finish()
}

/// Whether `path` is a pattern of `providers.file.paths` rather than a file.
pub(crate) fn is_pattern(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().contains(['*', '?']))
}

/// The configuration file and every file it refers to.
fn referenced_files(config_path: &Path, config: &Config) -> BTreeSet<PathBuf> {
    let mut files = BTreeSet::from([config_path.to_owned()]);
    for cert in config.certificates.values() {
        files.insert(cert.cert_file.clone());
        files.insert(cert.key_file.clone());
    }
    for middleware in config.middlewares.values() {
        match middleware {
            Middleware::BasicAuth(c) => files.extend(c.users_file.clone()),
            Middleware::Errors(c) => files.extend(c.file.clone()),
            Middleware::Maintenance(c) => files.extend(c.file.clone()),
            _ => {}
        }
    }
    files
}

impl Engine {
    /// Object counts, connection state and diagnostics of each provider's latest snapshot.
    fn provider_status(&self) -> Value {
        let snapshots = self
            .snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let degraded = self.degraded.lock().unwrap_or_else(PoisonError::into_inner);
        snapshots
            .iter()
            .map(|(name, s)| {
                (
                    name.clone(),
                    serde_json::json!({
                        "state": if degraded.contains_key(name) { "degraded" } else { "connected" },
                        "error": degraded.get(name),
                        "routes": s.fragment.routes.len(),
                        "services": s.fragment.services.len(),
                        "middlewares": s.fragment.middlewares.len(),
                        "diagnostics": s.diagnostics,
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>()
            .into()
    }
}

#[async_trait]
impl rdock_admin::Control for Engine {
    fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn metrics(&self) -> Option<String> {
        self.metrics_enabled
            .load(Ordering::SeqCst)
            .then(|| self.plane.metrics().render())
    }

    async fn status(&self) -> Value {
        let (origin, file) = {
            let applied = self.applied.lock().await;
            (applied.origin, self.source.describe())
        };
        let last = self
            .last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        serde_json::json!({
            "version": crate::VERSION,
            "commit": crate::COMMIT,
            "started_at": rdock_observability::rfc3339(self.started_at),
            "ready": self.ready.load(Ordering::SeqCst),
            "generation": self.plane.runtime().generation,
            "config_file": file,
            "origin": origin,
            "listeners": self.plane.listeners().await,
            "providers": self.provider_status(),
            "certificates": self.acme.status(),
            "last_reload": last,
        })
    }

    async fn reload(&self) -> (bool, Value) {
        let report = Engine::reload(self, "api").await;
        (
            report.applied(),
            serde_json::to_value(&report).unwrap_or(Value::Null),
        )
    }

    async fn effective_config(&self) -> Value {
        let config = self.applied.lock().await.config.clone();
        config
            .and_then(|c| serde_json::to_value(c).ok())
            .unwrap_or(Value::Null)
    }

    async fn api_config(&self) -> (Value, String) {
        let fragment = serde_json::to_value(self.api_fragment()).unwrap_or(Value::Null);
        (fragment, self.api_etag())
    }

    async fn dry_run(&self, candidate: Value) -> Result<(bool, Value), String> {
        let fragment = api::parse(candidate)?;
        let (ok, diagnostics) = self.api_dry_run(fragment);
        Ok((ok, serde_json::to_value(diagnostics).unwrap_or(Value::Null)))
    }

    async fn write_api(&self, candidate: Value, if_match: String) -> rdock_admin::ApiWrite {
        let fragment = match api::parse(candidate) {
            Ok(fragment) => fragment,
            Err(err) => return rdock_admin::ApiWrite::Invalid(err),
        };
        let report = |r: &Report| serde_json::to_value(r).unwrap_or(Value::Null);
        match self.api_write(fragment, &if_match).await {
            api::Write::Applied(r) => rdock_admin::ApiWrite::Applied {
                report: report(&r),
                etag: self.api_etag(),
            },
            api::Write::Rejected(r) => rdock_admin::ApiWrite::Rejected { report: report(&r) },
            api::Write::Stale => rdock_admin::ApiWrite::Stale {
                etag: self.api_etag(),
            },
        }
    }

    async fn history(&self) -> Value {
        let entries = self.state.history().unwrap_or_else(|err| {
            tracing::warn!(error = %err, "cannot read the configuration history");
            Vec::new()
        });
        let list: Vec<Value> = entries
            .iter()
            .rev()
            .map(|e| {
                serde_json::json!({
                    "id": e.applied_at_ms,
                    "generation": e.generation,
                    "applied_at": rdock_observability::rfc3339(UNIX_EPOCH + Duration::from_millis(e.applied_at_ms)),
                    "summary": e.summary,
                    "api": e.api.is_some(),
                })
            })
            .collect();
        Value::Array(list)
    }

    async fn history_api(&self, id: u64) -> Option<Value> {
        let entries = self.state.history().ok()?;
        let entry = entries.iter().find(|e| e.applied_at_ms == id)?;
        Some(entry.api.clone().unwrap_or_else(|| serde_json::json!({})))
    }

    async fn backends(&self) -> Value {
        let now = std::time::Instant::now();
        let runtime = self.plane.runtime();
        let services: Vec<Value> = runtime
            .services
            .iter()
            .map(|(name, service)| {
                let members: Vec<Value> = service
                    .members()
                    .iter()
                    .map(|m| {
                        let state = match m.state.breaker(now) {
                            rdock_balancer::BreakerState::Closed => "up",
                            rdock_balancer::BreakerState::Open => "down",
                            rdock_balancer::BreakerState::HalfOpen => "trial",
                        };
                        serde_json::json!({
                            "address": m.id,
                            "weight": m.weight,
                            "backup": m.backup,
                            "in_flight": m.state.in_flight(),
                            "state": state,
                            "drained": m.state.is_drained(),
                        })
                    })
                    .collect();
                serde_json::json!({ "service": name, "backends": members })
            })
            .collect();
        Value::Array(services)
    }

    async fn set_drained(&self, service: String, backend: String, drained: bool) -> bool {
        let runtime = self.plane.runtime();
        let Some(service) = runtime.services.get(&service) else {
            return false;
        };
        let members = service.members();
        let matching: Vec<_> = members.iter().filter(|m| m.id == backend).collect();
        for member in &matching {
            member.state.set_drained(drained);
        }
        if !matching.is_empty() {
            tracing::info!(service = %service.name, %backend, drained, "backend drain changed through the admin API");
        }
        !matching.is_empty()
    }

    async fn renew_certificate(&self, name: String) -> bool {
        self.acme.renew(&name)
    }

    async fn metrics_summary(&self, window_seconds: u64) -> Value {
        use rdock_observability::live::{Summary, combined};
        let live = self.plane.live();
        let window = Duration::from_secs(window_seconds);
        let now = SystemTime::now();
        let without_series = |mut summary: Summary| {
            summary.series.clear();
            summary
        };
        let routes: Vec<_> = live.routes.all();
        let services: Vec<_> = live.services.all();
        let route_rings: Vec<&rdock_observability::live::Ring> =
            routes.iter().map(|(_, ring)| ring.as_ref()).collect();
        let total = combined(&route_rings, window, now);
        let by_name = |list: &[(String, Arc<rdock_observability::live::Ring>)]| -> Value {
            list.iter()
                .map(|(name, ring)| {
                    (
                        name.clone(),
                        serde_json::to_value(without_series(ring.summary(window, now)))
                            .unwrap_or(Value::Null),
                    )
                })
                .collect::<serde_json::Map<_, _>>()
                .into()
        };
        serde_json::json!({
            "total": total,
            "routes": by_name(&routes),
            "services": by_name(&services),
        })
    }
}
