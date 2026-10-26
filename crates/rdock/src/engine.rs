//! The configuration engine of `rdock run`: load → validate → compile → apply, with the
//! last-known-good fallback and the on-disk history (architecture §5).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rdock_config::state::{HISTORY_LIMIT, HistoryEntry, StateDir};
use rdock_config::{Loaded, System, load_file, load_value};
use rdock_model::middleware::Middleware;
use rdock_model::{Config, Diagnostic};
use rdock_proxy::DataPlane;
use serde::Serialize;
use serde_json::Value;

use crate::validate::load_error;

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
    origin: Origin,
}

/// The engine shared by signal handlers, the file watcher and the admin API.
pub(crate) struct Engine {
    config_path: PathBuf,
    state: StateDir,
    plane: Arc<DataPlane>,
    applied: tokio::sync::Mutex<Applied>,
    ready: AtomicBool,
    metrics_enabled: AtomicBool,
    last: Mutex<Option<Report>>,
    watched: Mutex<BTreeSet<PathBuf>>,
    /// Hash of the watched files when the configuration was last applied.
    fingerprint: Mutex<Option<u64>>,
    started_at: SystemTime,
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
    pub(crate) fn new(config_path: PathBuf, data_dir: &Path, plane: Arc<DataPlane>) -> Self {
        Self {
            config_path,
            state: StateDir::new(data_dir),
            plane,
            applied: tokio::sync::Mutex::new(Applied {
                config: None,
                source: None,
                origin: Origin::File,
            }),
            ready: AtomicBool::new(false),
            metrics_enabled: AtomicBool::new(true),
            last: Mutex::new(None),
            watched: Mutex::new(BTreeSet::new()),
            fingerprint: Mutex::new(None),
            started_at: SystemTime::now(),
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
            file = %self.config_path.display(),
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
        let loaded = match load_file(&self.config_path) {
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

    async fn apply(&self, loaded: Loaded, trigger: &str, origin: Origin) -> Report {
        let mut applied = self.applied.lock().await;
        let Loaded {
            config,
            source,
            mut diagnostics,
        } = loaded;
        let compiled = self.plane.compile(&config);
        diagnostics.extend(compiled.diagnostics);
        let Some(runtime) = compiled.runtime else {
            drop(applied);
            return self
                .rejected(
                    trigger,
                    Some("the configuration cannot be compiled".to_owned()),
                    diagnostics,
                )
                .await;
        };
        let generation = runtime.generation;
        let drain = config.lifecycle.drain_timeout.as_std();
        if let Err(err) = self.plane.apply(runtime, drain).await {
            drop(applied);
            return self
                .rejected(trigger, Some(err.to_string()), diagnostics)
                .await;
        }
        let summary = summarize(applied.config.as_ref(), &config);
        if applied.source.as_ref() != Some(&source) {
            let entry = HistoryEntry {
                applied_at_ms: unix_ms(),
                generation,
                summary: summary.clone(),
                source: source.clone(),
            };
            if let Err(err) = self.state.record(&entry, HISTORY_LIMIT) {
                tracing::warn!(error = %err, "cannot write the configuration history");
            }
        }
        if origin == Origin::File
            && let Err(err) = self.state.save_lkg(&source)
        {
            tracing::warn!(error = %err, "cannot write the last-known-good configuration");
        }
        let files = referenced_files(&self.config_path, &config);
        *self
            .fingerprint
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(fingerprint(&files));
        *self.watched.lock().unwrap_or_else(PoisonError::into_inner) = files;
        self.metrics_enabled
            .store(config.observability.metrics.prometheus, Ordering::SeqCst);
        applied.config = Some(config);
        applied.source = Some(source);
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
        report
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

/// A hash of the contents of `files` (missing files count as empty).
fn fingerprint(files: &BTreeSet<PathBuf>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for file in files {
        file.hash(&mut hasher);
        std::fs::read(file).unwrap_or_default().hash(&mut hasher);
    }
    hasher.finish()
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
            (applied.origin, self.config_path.display().to_string())
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
}
