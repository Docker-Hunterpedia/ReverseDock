//! The API provider (ADR-0024): routes, services and middlewares written through the admin
//! API, merged like any provider's snapshot (`name@api`) and applied through the same
//! validate → compile → swap path as a file reload. Writes are conditional on the version
//! they were based on.

use std::collections::{BTreeMap, BTreeSet};
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

/// What clients send: only these sections, unknown keys refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    routes: BTreeMap<String, Route>,
    #[serde(default)]
    services: BTreeMap<String, Service>,
    #[serde(default)]
    middlewares: BTreeMap<String, Middleware>,
    /// Consumers and keys (ADR-0030): hashes only, minted by `POST /api/v1/consumers/…/keys`.
    #[serde(default)]
    consumers: BTreeMap<String, rdock_model::gateway::Consumer>,
}

/// The API provider's fragment as clients read it: exactly the sections [`parse`] accepts, so
/// what `GET /api/v1/config/api` returns can be sent back unchanged. The fragment's other
/// sections belong to other providers and are always empty here.
pub(crate) fn document(fragment: &Fragment) -> Value {
    let mut document = serde_json::json!({
        "routes": fragment.routes,
        "services": fragment.services,
        "middlewares": fragment.middlewares,
    });
    // Present only once used, so documents of earlier versions read back unchanged.
    if !fragment.consumers.is_empty() {
        document["consumers"] = serde_json::json!(fragment.consumers);
    }
    document
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
    if let Some(bad) = names
        .into_iter()
        .chain(document.consumers.keys())
        .find(|n| n.contains('@'))
    {
        return Err(format!(
            "`{bad}`: names in the API configuration cannot contain `@`"
        ));
    }
    for (name, consumer) in &document.consumers {
        if consumer.keys_file.is_some() {
            return Err(format!(
                "consumers.{name}.keys_file: a keys file belongs in the configuration file"
            ));
        }
    }
    Ok(Fragment {
        routes: document.routes,
        services: document.services,
        middlewares: document.middlewares,
        consumers: document.consumers,
        ..Fragment::default()
    })
}

/// The API object a "left out" diagnostic is about (`name@api`), if it is one. Provider
/// objects that fail are normally left out with a warning (ADR-0009); a write through the API
/// is all or nothing for what it changes, so the API never applies less than it was asked to.
fn api_object_left_out(diagnostic: &Diagnostic) -> Option<(rdock_config::merge::Section, String)> {
    // `skipped()` in rdock-config words provider objects that fail this way.
    if !diagnostic.message.starts_with("left out:") {
        return None;
    }
    owner(&diagnostic.path).filter(|(_, name)| name.ends_with(&format!("@{PROVIDER}")))
}

/// Whether the object `key` (`name@api`) of `section` differs between two API fragments, or
/// exists in only one.
fn changed(
    section: rdock_config::merge::Section,
    key: &str,
    before: &Fragment,
    after: &Fragment,
) -> bool {
    use rdock_config::merge::Section;
    let name = key.strip_suffix(&format!("@{PROVIDER}")).unwrap_or(key);
    let value = |fragment: &Fragment| -> Option<Value> {
        match section {
            Section::Routes => fragment.routes.get(name).map(|o| serde_json::json!(o)),
            Section::Services => fragment.services.get(name).map(|o| serde_json::json!(o)),
            Section::Middlewares => fragment.middlewares.get(name).map(|o| serde_json::json!(o)),
            _ => None,
        }
    };
    value(before) != value(after)
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

    /// Holds the configuration-write lock for the fault's duration after its delay, so API
    /// writes queue up (H-ENG-04 isolation test).
    #[cfg(feature = "fault-injection")]
    pub(crate) async fn hold_api_writes(&self, fault: rdock_admin::fault::Fault) {
        tokio::time::sleep(fault.delay).await;
        let _held = self.api_writes.lock().await;
        tracing::warn!(
            seconds = fault.duration.as_secs(),
            "fault injection: holding the configuration-write lock"
        );
        tokio::time::sleep(fault.duration).await;
    }

    /// Replaces the API objects when `if_match` is the current version, and applies them; a
    /// rejected configuration leaves the previous objects in place.
    pub(crate) async fn api_write(&self, candidate: Fragment, if_match: &str) -> Write {
        let _one_writer = self.api_writes.lock().await;
        if if_match.trim() != self.api_etag() {
            return Write::Stale;
        }
        let (ok, diagnostics) = self.api_dry_run(&candidate);
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
            revision: None,
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
    ///
    /// An API object left out of the merge is an error only when this write is to blame: the
    /// object is new or changed, or it was in use before and the write broke it. An object the
    /// write did not touch and that is already left out today (a tenant's route whose shared
    /// service went away, an object a narrower tenant rule now refuses) stays a warning, so one
    /// tenant's stale object never blocks another's writes; its owner and administrators see
    /// the warning, other tenants never do (reports are filtered by owner).
    pub(crate) fn api_dry_run(&self, candidate: &Fragment) -> (bool, Vec<Diagnostic>) {
        let current = self.api_fragment();
        let (ok, mut diagnostics) = self.api_check(candidate.clone());
        let blamed: Vec<_> = diagnostics
            .iter()
            .filter_map(api_object_left_out)
            .filter(|(section, key)| changed(*section, key, &current, candidate))
            .collect();
        let untouched: Vec<_> = diagnostics
            .iter()
            .filter_map(api_object_left_out)
            .filter(|(section, key)| !changed(*section, key, &current, candidate))
            .collect();
        // Which untouched objects are left out already, without this write?
        let already: BTreeSet<_> = if untouched.is_empty() {
            BTreeSet::new()
        } else {
            self.api_check(current)
                .1
                .iter()
                .filter_map(api_object_left_out)
                .collect()
        };
        for d in &mut diagnostics {
            let Some(object) = api_object_left_out(d) else {
                continue;
            };
            if blamed.contains(&object) || !already.contains(&object) {
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

    /// The configuration's diagnostics with `candidate` as the API objects, "left out" ones as
    /// the merge words them.
    fn api_check(&self, candidate: Fragment) -> (bool, Vec<Diagnostic>) {
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
            revision: None,
        });
        let ok = self
            .merge_and_compile(file, &snapshots, &BTreeSet::new(), &mut diagnostics)
            .is_ok();
        (ok, diagnostics)
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
