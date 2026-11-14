//! The configuration origin `control` (ADR-0031): with `cluster.control` the configuration is
//! the control plane's bundle with this instance's own sections (`cluster`, `admin`,
//! `providers`, …) from its file in place of the bundle's. Providers merge as usual. The bundle
//! in use is stored in `$RDOCK_DATA_DIR/state/control/bundle.json` before it is acknowledged,
//! and a start without the control plane serves it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use rdock_cluster::protocol::Bundle;
use rdock_config::{Loaded, System, load_value};
use rdock_model::Diagnostic;
use serde_json::{Value, json};

use super::{Engine, Origin, Report};

/// The control plane's side of the engine.
pub(crate) struct ControlState {
    path: PathBuf,
    bundle: Mutex<Option<Bundle>>,
    serving: AtomicU64,
    connection: Mutex<(bool, Option<String>)>,
    applied: tokio::sync::watch::Sender<u64>,
    /// One composition and apply at a time (a bundle and a reload of the local file).
    turn: tokio::sync::Mutex<()>,
    pub(crate) instance: String,
    pub(crate) cluster_id: String,
    pub(crate) url: String,
}

impl ControlState {
    /// Loads the stored bundle, if any.
    pub(crate) fn load(data_dir: &Path, instance: String, cluster_id: String, url: String) -> Self {
        let path = data_dir.join("state").join("control").join("bundle.json");
        let bundle = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Bundle>(&bytes) {
                Ok(bundle) if bundle.cluster_id == cluster_id => Some(bundle),
                Ok(bundle) => {
                    tracing::warn!(stored = %bundle.cluster_id, cluster = %cluster_id, "ignoring the stored bundle of another cluster");
                    None
                }
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "ignoring an unreadable stored bundle");
                    None
                }
            },
            Err(_) => None,
        };
        let serving = bundle.as_ref().map_or(0, |b| b.revision);
        Self {
            path,
            bundle: Mutex::new(bundle),
            serving: AtomicU64::new(serving),
            connection: Mutex::new((false, None)),
            applied: tokio::sync::watch::Sender::new(0),
            turn: tokio::sync::Mutex::new(()),
            instance,
            cluster_id,
            url,
        }
    }

    fn bundle(&self) -> Option<Bundle> {
        self.bundle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The revision served (`0` before the first bundle).
    pub(crate) fn serving(&self) -> u64 {
        self.serving.load(Ordering::SeqCst)
    }

    /// Records whether the control plane answers.
    pub(crate) fn set_connection(&self, connected: bool, error: Option<String>) {
        *self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = (connected, error);
    }

    /// The `cluster` part of `GET /api/v1/status`.
    pub(crate) fn status(&self) -> Value {
        let (connected, error) = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let bundle = self.bundle();
        json!({
            "instance": self.instance,
            "cluster_id": self.cluster_id,
            "control": self.url,
            "connected": connected,
            "error": error,
            "serving": self.serving(),
            "sha256": bundle.as_ref().map(|b| b.sha256.clone()),
            "published_at": bundle.as_ref().map(|b| b.published_at.clone()),
        })
    }
}

fn diagnostics_json(diagnostics: &[Diagnostic]) -> Vec<Value> {
    diagnostics
        .iter()
        .map(|d| serde_json::to_value(d).unwrap_or_else(|_| json!({ "message": d.message })))
        .collect()
}

impl Engine {
    /// The local file composed with `bundle`; errors when the file holds sections the bundle
    /// provides or the result does not load.
    fn compose(local: &Value, bundle: &Bundle) -> Result<Loaded, (String, Vec<Diagnostic>)> {
        let mut errors = rdock_model::cluster::instance_file_diagnostics(local);
        errors.extend(rdock_model::cluster::bundle_diagnostics(&bundle.document));
        if !errors.is_empty() {
            return Err((
                "the configuration cannot be composed with the bundle".to_owned(),
                errors,
            ));
        }
        let composed = rdock_model::cluster::compose(&bundle.document, local);
        match load_value(composed, &System) {
            Ok(loaded) if !loaded.has_errors() => Ok(loaded),
            Ok(loaded) => Err(("the bundle has errors here".to_owned(), loaded.diagnostics)),
            Err(err) => Err((err.to_string(), vec![crate::validate::load_error(&err)])),
        }
    }

    /// A reload in cluster mode: the local file `local` with the bundle in use.
    pub(super) async fn reload_with_bundle(&self, local: Loaded, trigger: &str) -> Report {
        let Some(control) = &self.control else {
            return self.apply(local, trigger, Origin::File).await;
        };
        let _turn = control.turn.lock().await;
        let Some(bundle) = control.bundle() else {
            let mut diagnostics = rdock_model::cluster::instance_file_diagnostics(&local.source);
            diagnostics.push(Diagnostic::warning(
                "cluster.control",
                "no configuration from the control plane yet; waiting for its first bundle",
            ));
            return self
                .rejected(
                    trigger,
                    Some("waiting for the control plane's first bundle".to_owned()),
                    diagnostics,
                )
                .await;
        };
        match Self::compose(&local.source, &bundle) {
            Ok(loaded) => self.apply(loaded, trigger, Origin::Control).await,
            Err((error, diagnostics)) => self.rejected(trigger, Some(error), diagnostics).await,
        }
    }

    /// Validates, compiles, stores and applies a bundle from the control plane: `Ok`
    /// (warnings) is an ACK, `Err` (diagnostics) a NACK with the running configuration left in
    /// place. The bundle is on disk before this returns `Ok`.
    pub(crate) async fn apply_bundle(&self, bundle: Bundle) -> Result<Vec<Value>, Vec<Value>> {
        let Some(control) = &self.control else {
            return Err(vec![json!({ "message": "not a cluster member" })]);
        };
        let local = match self.load_local() {
            Ok(local) => local,
            Err(diagnostics) => return Err(diagnostics_json(&diagnostics)),
        };
        let _turn = control.turn.lock().await;
        let loaded = match Self::compose(&local, &bundle) {
            Ok(loaded) => loaded,
            Err((error, mut diagnostics)) => {
                diagnostics.insert(0, Diagnostic::error("", error));
                return Err(diagnostics_json(&diagnostics));
            }
        };
        // Stored first, then applied: a bundle is acknowledged only once it is on disk, and a
        // refused one never replaces the stored one.
        let next = control.path.with_extension("json.next");
        let json = serde_json::to_vec_pretty(&bundle)
            .map_err(|e| vec![json!({ "message": e.to_string() })])?;
        if let Err(e) = rdock_config::state::write_atomic(&next, &json) {
            return Err(vec![
                json!({ "severity": "error", "path": "", "message": format!("cannot store the bundle: {e}") }),
            ]);
        }
        let trigger = format!("control plane revision {}", bundle.revision);
        let report = self.apply(loaded, &trigger, Origin::Control).await;
        if !report.applied() {
            let _ = std::fs::remove_file(&next);
            let mut diagnostics = report.diagnostics.clone();
            if let Some(error) = &report.error {
                diagnostics.insert(0, Diagnostic::error("", error.clone()));
            }
            return Err(diagnostics_json(&diagnostics));
        }
        if let Err(e) = std::fs::rename(&next, &control.path) {
            tracing::warn!(error = %e, "cannot keep the bundle as the stored one");
        }
        let revision = bundle.revision;
        *control
            .bundle
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(bundle);
        control.serving.store(revision, Ordering::SeqCst);
        control.applied.send_replace(revision);
        self.plane
            .metrics()
            .cluster_bundle_revision
            .set(i64::try_from(revision).unwrap_or(i64::MAX));
        Ok(diagnostics_json(&report.diagnostics))
    }

    /// The first configuration of a cluster member: the stored bundle, else the first bundle
    /// the agent delivers.
    pub(super) async fn boot_from_control(&self) -> Result<Report, Box<Report>> {
        let Some(control) = &self.control else {
            return Err(Box::new(Box::pin(self.reload("start")).await));
        };
        if control.bundle().is_some() {
            let report = Box::pin(self.reload("start")).await;
            if report.applied() {
                self.plane
                    .metrics()
                    .cluster_bundle_revision
                    .set(i64::try_from(control.serving()).unwrap_or(i64::MAX));
                tracing::info!(
                    revision = control.serving(),
                    "serving the stored bundle of the control plane"
                );
                return Ok(report);
            }
            tracing::error!(
                error = report.error.as_deref().unwrap_or_default(),
                "the stored bundle cannot be used; waiting for the control plane"
            );
            *control
                .bundle
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = None;
            control.serving.store(0, Ordering::SeqCst);
        } else {
            tracing::info!(control = %control.url, "waiting for the control plane's first bundle");
        }
        let mut applied = control.applied.subscribe();
        loop {
            if *applied.borrow_and_update() > 0 {
                break;
            }
            if applied.changed().await.is_err() {
                return Err(Box::new(Box::pin(self.reload("start")).await));
            }
        }
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                Box::new(Report {
                    result: "rejected",
                    trigger: "start".to_owned(),
                    generation: 0,
                    at: super::now_rfc3339(),
                    origin: Origin::Control,
                    error: Some("no report".to_owned()),
                    diagnostics: Vec::new(),
                })
            })
    }

    /// The local file as written, with its includes.
    fn load_local(&self) -> Result<Value, Vec<Diagnostic>> {
        match &self.source {
            crate::zero_config::Source::File(path) => {
                rdock_config::includes::load_file_with_includes(path)
                    .map(|(loaded, _)| loaded.source)
                    .map_err(|err| vec![crate::validate::load_error(&err)])
            }
            crate::zero_config::Source::ZeroConfig => Ok(json!({})),
        }
    }
}
