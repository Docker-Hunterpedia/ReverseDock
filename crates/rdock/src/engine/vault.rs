//! `${vault:<mount>/<path>#<field>}` references (W-OBS-02, ADR-0030): read before a
//! configuration is compiled and again every `secrets.vault.refresh`.
//!
//! Values live only in the process ([`vault_store`]); the configuration, its history, the
//! last-known-good copy, provider snapshots and the admin API keep the reference. Only the
//! configuration file (with its includes) may reference Vault: references are collected from
//! it, so an object from a provider cannot make rdock read a secret the file does not name.
//!
//! - At every load, each reference is read. A reference that has never been read and fails
//!   rejects the configuration, like a missing `${file:…}`.
//! - A read that fails for a reference read before keeps the last value and marks Vault
//!   degraded (`rdock status`, `GET /api/v1/status`, `rdock_vault_refresh_failures_total`).
//! - The refresh task reads the references every `refresh`; a changed value reloads.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use rdock_config::interpolate::vault_store;
use rdock_model::secrets::{VaultReference, VaultSettings, vault_references};
use rdock_model::{Config, Diagnostic};
use rdock_observability::vault::{Vault, VaultError};
use serde_json::Value;

use super::Engine;

/// How often the refresh task looks again when no Vault is configured.
const IDLE: Duration = Duration::from_secs(30);

/// The Vault client of the applied settings and what the last read found.
#[derive(Default)]
pub(crate) struct VaultState {
    client: Mutex<Option<Arc<Vault>>>,
    status: Mutex<Status>,
}

#[derive(Default, Clone)]
struct Status {
    configured: bool,
    references: usize,
    degraded: Option<String>,
    last_read: Option<SystemTime>,
}

/// Every `${vault:…}` reference in `config`, parsed. Unparsable ones were refused by the
/// loader already and are skipped.
pub(crate) fn references(config: &Config) -> Vec<VaultReference> {
    fn walk(value: &Value, out: &mut BTreeSet<VaultReference>) {
        match value {
            Value::String(text) => {
                for body in vault_references(text) {
                    if let Ok(reference) = VaultReference::parse(body) {
                        out.insert(reference);
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            Value::Object(map) => map.values().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    if let Ok(value) = serde_json::to_value(config) {
        walk(&value, &mut out);
    }
    out.into_iter().collect()
}

/// Reads `references` once with a fresh client and stores the values; for `rdock validate`.
/// Returns an error diagnostic per reference that cannot be read.
pub(crate) async fn read_once(
    settings: &VaultSettings,
    references: &[VaultReference],
) -> Vec<Diagnostic> {
    let client = match Vault::new(settings) {
        Ok(client) => client,
        Err(e) => return vec![Diagnostic::error("secrets.vault", e.to_string())],
    };
    let (values, failed) = client.read(references).await;
    vault_store::put(values);
    failed
        .into_iter()
        .map(|(body, e)| unreadable(&body, &e))
        .collect()
}

fn unreadable(body: &str, e: &VaultError) -> Diagnostic {
    Diagnostic::error(
        "secrets.vault",
        format!("`${{vault:{body}}}` cannot be read: {e}"),
    )
    .with_hint(
        "check the address, the token's policy and that the secret and field exist (KV version 2)",
    )
}

impl VaultState {
    /// The client for `settings`, kept while the settings stay the same (it holds the login).
    fn client(&self, settings: &VaultSettings) -> Result<Arc<Vault>, VaultError> {
        let mut client = self.client.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(current) = client.as_ref()
            && current.settings() == settings
        {
            return Ok(current.clone());
        }
        let fresh = Arc::new(Vault::new(settings)?);
        *client = Some(fresh.clone());
        Ok(fresh)
    }

    fn set(&self, update: impl FnOnce(&mut Status)) {
        update(&mut self.status.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// `secrets.vault` of `rdock status`, when Vault is used.
    pub(crate) fn status(&self) -> Option<Value> {
        let status = self
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        status.configured.then(|| {
            serde_json::json!({
                "state": if status.degraded.is_some() { "degraded" } else { "ok" },
                "error": status.degraded,
                "references": status.references,
                "last_read": status.last_read.map(rdock_observability::rfc3339),
            })
        })
    }
}

impl Engine {
    /// Reads the Vault references of `file` before it is compiled. Errors are diagnostics for
    /// references that cannot be read and have no earlier value.
    pub(super) async fn read_vault(&self, file: &Config) -> Result<(), Vec<Diagnostic>> {
        let wanted = references(file);
        let keep: BTreeSet<String> = wanted.iter().map(VaultReference::body).collect();
        let Some(settings) = &file.secrets.vault else {
            vault_store::retain(&keep);
            self.vault.set(|s| *s = Status::default());
            // The loader refuses references without `secrets.vault`.
            return Ok(());
        };
        if wanted.is_empty() {
            vault_store::retain(&keep);
            self.vault.set(|s| {
                *s = Status {
                    configured: true,
                    ..Status::default()
                };
            });
            return Ok(());
        }
        let client = self
            .vault
            .client(settings)
            .map_err(|e| vec![Diagnostic::error("secrets.vault", e.to_string())])?;
        let (values, failed) = client.read(&wanted).await;
        vault_store::put(values);
        let known = vault_store::references();
        let mut errors = Vec::new();
        let mut kept = Vec::new();
        for (body, e) in &failed {
            if known.contains(body) {
                kept.push(format!("`${{vault:{body}}}`: {e}"));
            } else {
                errors.push(unreadable(body, e));
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        vault_store::retain(&keep);
        self.record_vault_read(wanted.len(), &kept);
        Ok(())
    }

    /// Rejects a configuration whose Vault references cannot be read.
    pub(super) async fn vault_rejected(
        &self,
        trigger: &str,
        mut diagnostics: Vec<Diagnostic>,
        errors: Vec<Diagnostic>,
    ) -> super::Report {
        diagnostics.extend(errors);
        let error = Some("a Vault reference cannot be read".to_owned());
        self.rejected(trigger, error, diagnostics).await
    }

    fn record_vault_read(&self, references: usize, kept: &[String]) {
        let degraded = (!kept.is_empty()).then(|| {
            format!(
                "the last values stay in use; reading failed for {}",
                kept.join("; ")
            )
        });
        if let Some(reason) = &degraded {
            self.plane.metrics().vault_refresh_failures.inc();
            tracing::warn!(reason = %reason, "Vault is degraded");
        }
        self.vault.set(|s| {
            s.configured = true;
            s.references = references;
            s.last_read = Some(SystemTime::now());
            s.degraded = degraded;
        });
    }

    /// Reads the references of the applied configuration every `secrets.vault.refresh` and
    /// reloads when a value changed. Runs until `stop` fires.
    pub(crate) async fn refresh_vault(
        self: Arc<Self>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            let applied = self.config().await;
            let settings = applied.as_ref().and_then(|c| c.secrets.vault.clone());
            let wait = settings.as_ref().map_or(IDLE, |s| s.refresh.as_std());
            tokio::select! {
                _ = stop.changed() => return,
                () = tokio::time::sleep(wait) => {}
            }
            let (Some(settings), Some(config)) = (settings, applied) else {
                continue;
            };
            // The settings may have changed while waiting; the next round uses the new ones.
            if self.config().await.and_then(|c| c.secrets.vault) != Some(settings.clone()) {
                continue;
            }
            let wanted = references(&config);
            if wanted.is_empty() {
                continue;
            }
            let client = match self.vault.client(&settings) {
                Ok(client) => client,
                Err(e) => {
                    self.record_vault_read(wanted.len(), &[e.to_string()]);
                    continue;
                }
            };
            let (values, failed) = client.read(&wanted).await;
            let changed = vault_store::put(values);
            let kept: Vec<String> = failed
                .iter()
                .map(|(body, e)| format!("`${{vault:{body}}}`: {e}"))
                .collect();
            self.record_vault_read(wanted.len(), &kept);
            if changed {
                tracing::info!("a Vault value changed; reloading");
                let report = self.reload("vault").await;
                if !report.applied() {
                    tracing::warn!(
                        "the reload after a Vault change was rejected; the previous configuration stays in use"
                    );
                }
            }
        }
    }
}
