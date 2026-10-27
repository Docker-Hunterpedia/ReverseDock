//! Merging other providers' objects into the file configuration (ADR-0009, ADR-0018).
//!
//! The file configuration owns listeners, defaults, certificates and every setting; providers
//! add routes, services and middlewares under `name@provider` keys. The merged configuration
//! goes through the model's validator, and an object with an error is left out (with the
//! objects that need it) instead of rejecting everything.

use std::collections::{BTreeMap, BTreeSet};

use rdock_model::middleware::Middleware;
use rdock_model::route::Route;
use rdock_model::service::Service;
use rdock_model::{Config, Diagnostic};
use serde::{Deserialize, Serialize};

/// Rounds of "leave out what fails, check again" before giving up on a provider.
const ROUNDS: usize = 4;

/// The objects a provider contributes, by bare name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Fragment {
    /// HTTP routes.
    pub routes: BTreeMap<String, Route>,
    /// Backend pools.
    pub services: BTreeMap<String, Service>,
    /// Middlewares.
    pub middlewares: BTreeMap<String, Middleware>,
}

/// A provider's complete view: never a diff (ADR-0009).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Provider name: `docker`, later `swarm`, `kubernetes`, `api`.
    pub provider: String,
    /// The objects.
    pub fragment: Fragment,
    /// Problems found while building it (unsupported labels, missing ports, …).
    pub diagnostics: Vec<Diagnostic>,
}

/// The configuration sections providers contribute to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    /// `routes`
    Routes,
    /// `services`
    Services,
    /// `middlewares`
    Middlewares,
}

impl Section {
    const ALL: [Self; 3] = [Self::Routes, Self::Services, Self::Middlewares];

    /// The section's key in the configuration.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routes => "routes",
            Self::Services => "services",
            Self::Middlewares => "middlewares",
        }
    }
}

/// One object of the merged configuration: its section and key (`app` or `app@docker`).
pub type ObjectKey = (Section, String);

/// The result of [`assemble`].
#[derive(Debug, Clone)]
pub struct Merged {
    /// The configuration to compile.
    pub config: Config,
    /// One warning per object left out, with the error that caused it.
    pub skipped: Vec<Diagnostic>,
    /// Errors that no object can be left out for; the merge cannot be applied.
    pub errors: Vec<Diagnostic>,
}

/// Merges `snapshots` into `base` and validates the result, leaving out `excluded` objects and
/// every object whose validation fails, together with the objects that refer to it.
///
/// `base` must be a file configuration without errors: every error found here comes from the
/// merge (a provider object, or a file object that refers to a provider object that is gone).
#[must_use]
pub fn assemble(base: &Config, snapshots: &[&Snapshot], excluded: &BTreeSet<ObjectKey>) -> Merged {
    let mut config = base.clone();
    for snapshot in snapshots {
        add(&mut config, &snapshot.provider, &snapshot.fragment);
    }
    let mut skipped = Vec::new();
    for key in excluded {
        remove(&mut config, key);
    }
    for _ in 0..ROUNDS {
        let errors: Vec<Diagnostic> = config
            .validate_merged()
            .into_iter()
            .filter(Diagnostic::is_error)
            .collect();
        if errors.is_empty() {
            return Merged {
                config,
                skipped,
                errors: Vec::new(),
            };
        }
        let (owned, unowned): (Vec<_>, Vec<_>) =
            errors.into_iter().partition(|d| owner(&d.path).is_some());
        if !unowned.is_empty() {
            return Merged {
                config,
                skipped,
                errors: unowned,
            };
        }
        skipped.extend(leave_out(&mut config, &owned));
    }
    let errors = config
        .validate_merged()
        .into_iter()
        .filter(Diagnostic::is_error)
        .collect();
    Merged {
        config,
        skipped,
        errors,
    }
}

/// Removes the objects `errors` point at and returns one warning per removed object.
fn leave_out(config: &mut Config, errors: &[Diagnostic]) -> Vec<Diagnostic> {
    let mut by_object: BTreeMap<ObjectKey, &Diagnostic> = BTreeMap::new();
    for error in errors {
        if let Some(key) = owner(&error.path) {
            by_object.entry(key).or_insert(error);
        }
    }
    by_object
        .into_iter()
        .filter(|(key, _)| remove(config, key))
        .map(|((section, name), error)| skipped(section, &name, error))
        .collect()
}

/// The warning for an object left out because of `error`.
#[must_use]
pub fn skipped(section: Section, name: &str, error: &Diagnostic) -> Diagnostic {
    let path = rdock_model::path_key(section.as_str(), name);
    let mut warning = Diagnostic::warning(
        path,
        format!(
            "left out: {} ({})",
            error.message,
            if error.path.is_empty() {
                "(top level)"
            } else {
                &error.path
            }
        ),
    );
    if let Some(hint) = &error.hint {
        warning = warning.with_hint(hint.clone());
    }
    warning
}

fn remove(config: &mut Config, (section, name): &ObjectKey) -> bool {
    match section {
        Section::Routes => config.routes.remove(name).is_some(),
        Section::Services => config.services.remove(name).is_some(),
        Section::Middlewares => config.middlewares.remove(name).is_some(),
    }
}

/// The object a diagnostic path lies under: `routes.app.tls` → (routes, `app`),
/// `services["api@docker"].backends[0]` → (services, `api@docker`).
#[must_use]
pub fn owner(path: &str) -> Option<ObjectKey> {
    Section::ALL.into_iter().find_map(|section| {
        let rest = path.strip_prefix(section.as_str())?;
        let name = if let Some(rest) = rest.strip_prefix(".") {
            rest.split(['.', '[']).next()?.to_owned()
        } else {
            let quoted = rest.strip_prefix("[\"")?;
            quoted[..quoted.find("\"]")?].to_owned()
        };
        (!name.is_empty()).then_some((section, name))
    })
}

/// Whether `key` (`app@docker`) belongs to a provider other than the file.
#[must_use]
pub fn is_provider_owned(key: &str) -> bool {
    key.contains('@')
}

/// Adds `fragment`'s objects under `name@provider`, with their references resolved
/// same-provider first: a bare `x` names this provider's `x` when it defines one, otherwise
/// the file's `x`.
fn add(config: &mut Config, provider: &str, fragment: &Fragment) {
    let qualify = |reference: &str, own: &dyn Fn(&str) -> bool| -> String {
        if !reference.contains('@') && own(reference) {
            format!("{reference}@{provider}")
        } else {
            reference.to_owned()
        }
    };
    let own_service = |name: &str| fragment.services.contains_key(name);
    let own_middleware = |name: &str| fragment.middlewares.contains_key(name);
    for (name, route) in &fragment.routes {
        let mut route = route.clone();
        route.service = qualify(&route.service, &own_service);
        for middleware in &mut route.middlewares {
            *middleware = qualify(middleware, &own_middleware);
        }
        config.routes.insert(format!("{name}@{provider}"), route);
    }
    for (name, service) in &fragment.services {
        let mut service = service.clone();
        for target in &mut service.split {
            target.service = qualify(&target.service, &own_service);
        }
        config
            .services
            .insert(format!("{name}@{provider}"), service);
    }
    for (name, middleware) in &fragment.middlewares {
        let mut middleware = middleware.clone();
        if let Middleware::Errors(errors) = &mut middleware
            && let Some(service) = &mut errors.service
        {
            *service = qualify(service, &own_service);
        }
        config
            .middlewares
            .insert(format!("{name}@{provider}"), middleware);
    }
}

#[cfg(test)]
mod tests;
