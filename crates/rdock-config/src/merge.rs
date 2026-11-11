//! Merging other providers' objects into the file configuration (ADR-0009, ADR-0018).
//!
//! The file configuration owns defaults and every setting; providers add routes, services,
//! middlewares, TCP and UDP routes and services under `name@provider` keys. Providers on
//! [`LISTENER_PROVIDERS`] may also add listeners and certificates (ADR-0029); a provider
//! listener never replaces a file listener or binds an address a file listener binds. The
//! merged configuration goes through the model's validator, and an object with an error is
//! left out (with the objects that need it) instead of rejecting everything.

use std::collections::{BTreeMap, BTreeSet};

use rdock_model::config::{Certificate, Listener, ListenerProtocol};
use rdock_model::middleware::Middleware;
use rdock_model::route::{Route, RouteTls, TcpRoute, UdpRoute};
use rdock_model::service::{Service, TcpService, UdpService};
use rdock_model::{Config, Diagnostic};
use serde::{Deserialize, Serialize};

/// Rounds of "leave out what fails, check again" before giving up on a provider.
const ROUNDS: usize = 4;

/// Providers that may contribute listeners and certificates (ADR-0029). Docker and Swarm
/// labels cannot open ports or name certificate files.
pub const LISTENER_PROVIDERS: [&str; 1] = ["kubernetes"];

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
    /// TCP routes.
    pub tcp_routes: BTreeMap<String, TcpRoute>,
    /// TCP backend pools.
    pub tcp_services: BTreeMap<String, TcpService>,
    /// UDP routes.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub udp_routes: BTreeMap<String, UdpRoute>,
    /// UDP backend pools.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub udp_services: BTreeMap<String, UdpService>,
    /// Listeners (providers on [`LISTENER_PROVIDERS`] only). Routes of the same fragment name
    /// them by their bare name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub listeners: BTreeMap<String, Listener>,
    /// Certificates as files (providers on [`LISTENER_PROVIDERS`] only); never key material
    /// itself. Listeners and routes of the same fragment name them by their bare name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub certificates: BTreeMap<String, Certificate>,
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
    /// Changes whenever files the fragment names changed although the fragment did not (the
    /// Kubernetes provider's Secret files, ADR-0029), so the engine reloads and reads them
    /// again. An opaque counter: never derived from the files' content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// What a provider reports to the engine over its watch channel: its latest snapshot and
/// whether its source is reachable. Shared by every provider (Docker, Swarm, Kubernetes).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProviderState {
    /// The latest snapshot; `None` until the provider has a complete view of its source
    /// (for Kubernetes: every watched kind listed once).
    pub snapshot: Option<Snapshot>,
    /// Why the source is unreachable, while it is.
    pub degraded: Option<String>,
}

impl ProviderState {
    /// Takes `snapshot` and clears the degraded state; returns whether anything changed, for
    /// `watch::Sender::send_if_modified`, so watchers wake only on a change.
    pub fn publish(&mut self, snapshot: Snapshot) -> bool {
        let changed = self.snapshot.as_ref() != Some(&snapshot) || self.degraded.is_some();
        self.snapshot = Some(snapshot);
        self.degraded = None;
        changed
    }
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
    /// `tcp_routes`
    TcpRoutes,
    /// `tcp_services`
    TcpServices,
    /// `udp_routes`
    UdpRoutes,
    /// `udp_services`
    UdpServices,
    /// `listeners`
    Listeners,
    /// `certificates`
    Certificates,
}

impl Section {
    const ALL: [Self; 9] = [
        Self::Routes,
        Self::Services,
        Self::Middlewares,
        Self::TcpRoutes,
        Self::TcpServices,
        Self::UdpRoutes,
        Self::UdpServices,
        Self::Listeners,
        Self::Certificates,
    ];

    /// The section's key in the configuration.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routes => "routes",
            Self::Services => "services",
            Self::Middlewares => "middlewares",
            Self::TcpRoutes => "tcp_routes",
            Self::TcpServices => "tcp_services",
            Self::UdpRoutes => "udp_routes",
            Self::UdpServices => "udp_services",
            Self::Listeners => "listeners",
            Self::Certificates => "certificates",
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
    let mut skipped = Vec::new();
    for snapshot in snapshots {
        skipped.extend(add(
            &mut config,
            base,
            &snapshot.provider,
            &snapshot.fragment,
        ));
    }
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
        Section::TcpRoutes => config.tcp_routes.remove(name).is_some(),
        Section::TcpServices => config.tcp_services.remove(name).is_some(),
        Section::UdpRoutes => config.udp_routes.remove(name).is_some(),
        Section::UdpServices => config.udp_services.remove(name).is_some(),
        // A file listener is never left out: it would take the implicit defaults' place.
        Section::Listeners => is_provider_owned(name) && config.listeners.remove(name).is_some(),
        Section::Certificates => config.certificates.remove(name).is_some(),
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
/// the file's `x`. Returns a warning for each listener or certificate that is not added.
fn add(config: &mut Config, base: &Config, provider: &str, fragment: &Fragment) -> Vec<Diagnostic> {
    let qualify = |reference: &str, own: &dyn Fn(&str) -> bool| -> String {
        if !reference.contains('@') && own(reference) {
            format!("{reference}@{provider}")
        } else {
            reference.to_owned()
        }
    };
    let (listeners, certificates, dropped) = admitted_listeners(base, provider, fragment);
    let own_service = |name: &str| fragment.services.contains_key(name);
    let own_middleware = |name: &str| fragment.middlewares.contains_key(name);
    let own_listener = |name: &str| listeners.contains_key(name);
    let own_certificate = |name: &str| certificates.contains_key(name);
    if !listeners.is_empty() && config.listeners.is_empty() {
        // The implicit `web` and `websecure` apply only while no listener is configured.
        config.listeners = base.effective_listeners().into_owned();
    }
    for (name, listener) in &listeners {
        let mut listener = (*listener).clone();
        if let Some(tls) = &mut listener.tls {
            for certificate in &mut tls.certificates {
                *certificate = qualify(certificate, &own_certificate);
            }
        }
        config
            .listeners
            .insert(format!("{name}@{provider}"), listener);
    }
    for (name, certificate) in &certificates {
        config
            .certificates
            .insert(format!("{name}@{provider}"), (*certificate).clone());
    }
    for (name, route) in &fragment.routes {
        let mut route = route.clone();
        route.service = route.service.map(|service| qualify(&service, &own_service));
        for middleware in &mut route.middlewares {
            *middleware = qualify(middleware, &own_middleware);
        }
        for listener in route.listeners.iter_mut().flatten() {
            *listener = qualify(listener, &own_listener);
        }
        if let Some(RouteTls::Options(options)) = &mut route.tls
            && let Some(certificate) = &mut options.certificate
        {
            *certificate = qualify(certificate, &own_certificate);
        }
        if let Some(mirror) = &mut route.mirror {
            mirror.service = qualify(&mirror.service, &own_service);
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
    add_l4(config, provider, fragment, &own_listener);
    dropped
}

/// Adds `fragment`'s TCP and UDP routes and services, like [`add`] does the HTTP objects.
fn add_l4(
    config: &mut Config,
    provider: &str,
    fragment: &Fragment,
    own_listener: &dyn Fn(&str) -> bool,
) {
    let qualify = |reference: &str, own: &dyn Fn(&str) -> bool| -> String {
        if !reference.contains('@') && own(reference) {
            format!("{reference}@{provider}")
        } else {
            reference.to_owned()
        }
    };
    let own_middleware = |name: &str| fragment.middlewares.contains_key(name);
    let own_tcp_service = |name: &str| fragment.tcp_services.contains_key(name);
    for (name, route) in &fragment.tcp_routes {
        let mut route = route.clone();
        route.service = qualify(&route.service, &own_tcp_service);
        for middleware in &mut route.middlewares {
            *middleware = qualify(middleware, &own_middleware);
        }
        for listener in route.listeners.iter_mut().flatten() {
            *listener = qualify(listener, own_listener);
        }
        config
            .tcp_routes
            .insert(format!("{name}@{provider}"), route);
    }
    for (name, service) in &fragment.tcp_services {
        config
            .tcp_services
            .insert(format!("{name}@{provider}"), service.clone());
    }
    let own_udp_service = |name: &str| fragment.udp_services.contains_key(name);
    for (name, route) in &fragment.udp_routes {
        let mut route = route.clone();
        route.service = qualify(&route.service, &own_udp_service);
        for middleware in &mut route.middlewares {
            *middleware = qualify(middleware, &own_middleware);
        }
        for listener in route.listeners.iter_mut().flatten() {
            *listener = qualify(listener, own_listener);
        }
        config
            .udp_routes
            .insert(format!("{name}@{provider}"), route);
    }
    for (name, service) in &fragment.udp_services {
        config
            .udp_services
            .insert(format!("{name}@{provider}"), service.clone());
    }
}

/// The listeners and certificates of `fragment` that may be merged, and a warning for each one
/// that may not: every one from a provider not on [`LISTENER_PROVIDERS`], and listeners that
/// would bind an address a file listener binds.
fn admitted_listeners<'a>(
    base: &Config,
    provider: &str,
    fragment: &'a Fragment,
) -> (
    BTreeMap<&'a str, &'a Listener>,
    BTreeMap<&'a str, &'a Certificate>,
    Vec<Diagnostic>,
) {
    let mut dropped = Vec::new();
    if !LISTENER_PROVIDERS.contains(&provider) {
        let objects = fragment
            .listeners
            .keys()
            .map(|n| (Section::Listeners, n))
            .chain(
                fragment
                    .certificates
                    .keys()
                    .map(|n| (Section::Certificates, n)),
            );
        for (section, name) in objects {
            let key = format!("{name}@{provider}");
            dropped.push(Diagnostic::warning(
                rdock_model::path_key(section.as_str(), &key),
                format!(
                    "left out: the {provider} provider cannot contribute {}",
                    section.as_str()
                ),
            ));
        }
        return (BTreeMap::new(), BTreeMap::new(), dropped);
    }
    let file = base.effective_listeners();
    let udp = |l: &Listener| l.effective_protocol() == ListenerProtocol::Udp;
    let mut listeners = BTreeMap::new();
    for (name, listener) in &fragment.listeners {
        let clash = file
            .iter()
            .find(|(_, f)| udp(f) == udp(listener) && f.address.overlaps(&listener.address));
        if let Some((file_name, file_listener)) = clash {
            let key = format!("{name}@{provider}");
            dropped.push(
                Diagnostic::warning(
                    rdock_model::path_key("listeners", &key),
                    format!(
                        "left out: `{}` is already bound by the file's listener `{file_name}` (`{}`)",
                        listener.address, file_listener.address
                    ),
                )
                .with_hint("a provider listener never replaces a file listener; move one of them to another address"),
            );
            continue;
        }
        listeners.insert(name.as_str(), listener);
    }
    let certificates = fragment
        .certificates
        .iter()
        .map(|(name, certificate)| (name.as_str(), certificate))
        .collect();
    (listeners, certificates, dropped)
}

#[cfg(test)]
mod tests;
