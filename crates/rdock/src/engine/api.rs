//! The API provider (ADR-0024): routes, services and middlewares written through the admin
//! API, merged like any provider's snapshot (`name@api`) and applied through the same
//! validate → compile → swap path as a file reload. Writes are conditional on the version
//! they were based on.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::PoisonError;

use rdock_config::includes::load_file_with_includes;
use rdock_config::merge::{Fragment, Snapshot, owner};
use rdock_config::{Format, load_str};
use rdock_model::middleware::Middleware;
use rdock_model::route::Route;
use rdock_model::service::Service;
use rdock_model::{Config, Diagnostic};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use serde_json::Value;

use super::Engine;
use crate::validate::load_error;
use crate::zero_config::{self, Source};

/// The provider name and the suffix of its objects.
pub(crate) const PROVIDER: &str = "api";

/// What clients send: only these three sections, unknown keys refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    routes: BTreeMap<String, Route>,
    #[serde(default)]
    services: BTreeMap<String, Service>,
    #[serde(default)]
    middlewares: BTreeMap<String, Middleware>,
}

/// A client's document as a fragment, or why it is not one.
pub(crate) fn parse(candidate: Value) -> Result<Fragment, String> {
    let document: Document = serde_path_to_error::deserialize(candidate)
        .map_err(|err| format!("{}: {}", err.path(), err.inner()))?;
    let names = document
        .routes
        .keys()
        .chain(document.services.keys())
        .chain(document.middlewares.keys());
    if let Some(bad) = names.into_iter().find(|n| n.contains('@')) {
        return Err(format!(
            "`{bad}`: names in the API configuration cannot contain `@`"
        ));
    }
    Ok(Fragment {
        routes: document.routes,
        services: document.services,
        middlewares: document.middlewares,
    })
}

/// Whether a diagnostic says an API object was left out of the merge. Provider objects that
/// fail are normally left out with a warning (ADR-0009); a write through the API is all or
/// nothing instead, so the API never applies less than it was asked to.
fn api_object_left_out(diagnostic: &Diagnostic) -> bool {
    // `skipped()` in rdock-config words provider objects that fail this way.
    diagnostic.message.starts_with("left out:")
        && owner(&diagnostic.path).is_some_and(|(_, name)| name.ends_with(&format!("@{PROVIDER}")))
}

/// The outcome of a conditional write.
pub(crate) enum Write {
    Applied(super::Report),
    Rejected(super::Report),
    Stale,
}

impl Engine {
    /// The API provider's current objects.
    pub(crate) fn api_fragment(&self) -> Fragment {
        self.snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(PROVIDER)
            .map(|s| s.fragment.clone())
            .unwrap_or_default()
    }

    /// `"g<generation>-<first 16 hex of the SHA-256 of the API objects>"`.
    pub(crate) fn api_etag(&self) -> String {
        let fragment = serde_json::to_vec(&self.api_fragment()).unwrap_or_default();
        let hash = digest(&SHA256, &fragment);
        let prefix = hash.as_ref()[..8].iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        });
        format!("\"g{}-{prefix}\"", self.plane.runtime().generation)
    }

    /// Replaces the API objects when `if_match` is the current version, and applies them; a
    /// rejected configuration leaves the previous objects in place.
    pub(crate) async fn api_write(&self, candidate: Fragment, if_match: &str) -> Write {
        let _one_writer = self.api_writes.lock().await;
        if if_match.trim() != self.api_etag() {
            return Write::Stale;
        }
        let (ok, diagnostics) = self.api_dry_run(candidate.clone());
        if !ok {
            let report = self
                .rejected(
                    "api",
                    Some("the API configuration has errors".to_owned()),
                    diagnostics,
                )
                .await;
            return Write::Rejected(report);
        }
        let previous = self
            .snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(PROVIDER)
            .cloned();
        self.set_snapshot(Snapshot {
            provider: PROVIDER.to_owned(),
            fragment: candidate,
            diagnostics: Vec::new(),
        });
        let report = self.reload("api").await;
        if report.applied() {
            return Write::Applied(report);
        }
        let mut snapshots = self
            .snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match previous {
            Some(snapshot) => snapshots.insert(PROVIDER.to_owned(), snapshot),
            None => snapshots.remove(PROVIDER),
        };
        Write::Rejected(report)
    }

    /// Validates and compiles the configuration as it would be with `candidate` as the API
    /// objects, without applying anything.
    pub(crate) fn api_dry_run(&self, candidate: Fragment) -> (bool, Vec<Diagnostic>) {
        let loaded = match &self.source {
            Source::File(path) => load_file_with_includes(path).map(|(loaded, _)| loaded),
            Source::ZeroConfig => load_str(zero_config::CONFIG, Format::Yaml),
        };
        let loaded = match loaded {
            Ok(loaded) => loaded,
            Err(err) => return (false, vec![load_error(&err)]),
        };
        let mut diagnostics = loaded.diagnostics.clone();
        if loaded.has_errors() {
            return (false, diagnostics);
        }
        let file: &Config = &loaded.config;
        let mut snapshots: Vec<Snapshot> = self
            .current_snapshots(file)
            .into_iter()
            .filter(|s| s.provider != PROVIDER)
            .collect();
        snapshots.push(Snapshot {
            provider: PROVIDER.to_owned(),
            fragment: candidate,
            diagnostics: Vec::new(),
        });
        let ok = self
            .merge_and_compile(file, &snapshots, &mut diagnostics)
            .is_ok();
        for d in &mut diagnostics {
            if api_object_left_out(d) {
                // A provider object is "left out"; an API object is refused with the reason.
                d.severity = rdock_model::Severity::Error;
                d.message = d.message.trim_start_matches("left out: ").to_owned();
            }
        }
        (
            ok && !diagnostics.iter().any(Diagnostic::is_error),
            diagnostics,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_are_strict_and_names_have_no_provider_suffix() {
        let ok = serde_json::json!({
            "routes": { "app": { "match": "Host(`app.example.com`)", "service": "app" } },
            "services": { "app": { "backends": [{ "address": "127.0.0.1:8080" }] } }
        });
        let fragment = parse(ok).unwrap();
        assert!(fragment.routes.contains_key("app"));
        assert!(
            parse(serde_json::json!({ "certificates": {} }))
                .unwrap_err()
                .contains("certificates")
        );
        let suffixed = serde_json::json!({ "services": { "x@docker": { "backends": [] } } });
        assert!(parse(suffixed).unwrap_err().contains('@'));
        assert!(
            parse(serde_json::json!({ "routes": { "a": { "match": 3 } } }))
                .unwrap_err()
                .starts_with("routes.a")
        );
    }
}
