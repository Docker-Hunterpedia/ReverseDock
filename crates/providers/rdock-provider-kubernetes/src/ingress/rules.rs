//! Rules, paths, backends and TLS of one Ingress (`networking.k8s.io/v1`; research §4.1).
//!
//! **Paths.** `Exact` is ``Path(`/p`)``; `Prefix` and `ImplementationSpecific` (treated as
//! `Prefix`) are ``Path(`/p`) || PathPrefix(`/p/`)`` with the trailing slash of `/p` dropped
//! first, so `/p` matches `/p`, `/p/` and `/p/x` but not `/px`; `/` matches everything. Hosts
//! are `Host(…)`: exact, or `*.example.com` for exactly one label (the router's semantics, not
//! the many-label wildcard of the Gateway API); no host is any host.
//!
//! **Precedence** is an explicit priority built with [`Precedence`] (the layout of
//! [`crate::gateway::priority`]): exact host, then wildcard host, then no host; within a host
//! the longest path first and `Exact` before `Prefix` on a tie. The Ingress order differs
//! from the Gateway API's (there `Exact` beats any `Prefix`), so the path kind field stays
//! `Prefix` and the path field is `2 × length + 1` for `Exact` and `2 × length` for a prefix
//! (the length of the path without trailing slashes, at least 1). Two routes that tie on all
//! of that go to the older Ingress (`creationTimestamp`, then `namespace/name`), then the
//! earlier path. The `defaultBackend` is a catch-all with priority 1 + (65 535 − rank), below
//! every rule.
//!
//! **Listeners and TLS.** Routes carry no `listeners`, so they attach as the file
//! configuration says (`defaults.listeners`, or every plain listener of the file
//! configuration for `tls: off`, see `Config::route_listeners`; never a Gateway's internal
//! listener):
//!
//! - a host covered by a valid `spec.tls` Secret gets its routes with
//!   `tls: { auto: false, certificate }` (the file's HTTPS listeners, the Secret's certificate
//!   from `certificates`) and, on the plain listeners, one `redirect` route for the whole host
//!   (308 to `https`, port 443, since the model cannot name the file's HTTPS port): the
//!   `ssl-redirect` default of ingress-nginx. Paths under `/.well-known/acme-challenge/` also
//!   get a plain route to their backend, which outranks the redirect (cert-manager,
//!   ADR-0029); `ssl-redirect: "false"` serves every path on both sides instead;
//! - any other host gets plain routes (`tls: off`), which attach to the plain listeners only;
//!   `force-ssl-redirect` makes them redirect, challenge paths excepted;
//! - a `spec.tls` entry whose Secret is missing or invalid, or that names none, keeps its
//!   hosts' routes as plain routes and reports a diagnostic.
//!
//! The automatic http→https redirect of the file configuration is never relied on: it
//! redirects to the HTTPS listener's own port (an internal port in a cluster) and answers only
//! when no plain route matches, which a `defaultBackend` would always do.

use std::collections::BTreeMap;

use k8s_openapi::api::networking::v1::{HTTPIngressPath, Ingress, IngressBackend, IngressSpec};
use rdock_model::Diagnostic;
use rdock_model::config::Certificate;
use rdock_model::middleware::{
    IpListConfig, Middleware, RedirectConfig, RedirectScheme, ReplacePathConfig,
};
use rdock_model::route::{MatchSpec, Route, RouteTls, RouteTlsOptions, TlsMode};
use rdock_model::service::Scheme;
use rdock_rules::{Expr, Matcher};

use super::annotations::{self, Annotations};
use crate::backends::{self, PortRef};
use crate::gateway::hostnames::{covers, specificity};
use crate::gateway::http::prefix_expr;
use crate::gateway::names::object_name;
use crate::gateway::priority::{PathKind, Precedence};
use crate::gateway::{object_id, object_path};
use crate::inventory::{Inventory, ObjectKey};
use crate::translate::{Settings, Translation, secret_paths};

/// The service that answers 503: unresolvable backends, and the target of routes that only
/// redirect (never reached).
pub const UNAVAILABLE_SERVICE: &str = "ingress-unavailable";
/// The service that answers 403 (`whitelist-source-range` without a usable range).
pub const DENIED_SERVICE: &str = "ingress-denied";
/// Paths below this prefix are ACME HTTP-01 challenges: they are never redirected.
pub const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge";

/// What one translation of the Ingresses works on.
pub struct Builder<'a> {
    /// The inventory.
    pub inventory: &'a Inventory,
    /// Settings.
    pub settings: &'a Settings,
    /// The output.
    pub out: Translation,
}

impl Builder<'_> {
    /// A warning about `object` at `field` below it.
    pub fn warn(&mut self, object: &str, field: &str, message: impl Into<String>) {
        self.out
            .diagnostics
            .push(Diagnostic::warning(object_path(object, field), message));
    }
}

/// A valid `spec.tls` entry: its hosts (empty: every host of the Ingress) and the fragment
/// certificate.
struct TlsEntry {
    hosts: Vec<String>,
    certificate: String,
}

/// The Ingress being translated.
struct Ing<'a> {
    namespace: &'a str,
    name: &'a str,
    id: String,
    rank: usize,
    annotations: Annotations,
    tls: Vec<TlsEntry>,
}

/// What a path's middlewares do besides the common ones.
enum Action {
    /// `rewrite-target`, when set.
    Rewrite(Option<Box<Middleware>>),
    /// `app-root`: redirect to this path.
    AppRoot(String),
}

/// One path to emit as routes.
struct PathPlan {
    /// Index for the route name and the tie-break.
    index: usize,
    /// The path as matched: `Exact`, or a prefix without trailing slashes (`/` for all).
    value: String,
    exact: bool,
    challenge: bool,
    service: String,
    action: Action,
}

/// Translates one claimed Ingress.
pub fn translate(b: &mut Builder<'_>, key: &ObjectKey, ingress: &Ingress, rank: usize) {
    let Some(spec) = ingress.spec.as_ref() else {
        return;
    };
    let id = object_id("Ingress", &key.0, &key.1);
    let empty = BTreeMap::new();
    let (annotations, notes) = annotations::parse(
        ingress.metadata.annotations.as_ref().unwrap_or(&empty),
        b.settings.provider.ingress.nginx_annotations,
    );
    for note in notes {
        let field = format!(
            ".metadata.annotations{}",
            rdock_model::path_key("", &note.annotation)
        );
        b.warn(&id, &field, note.message);
    }
    let tls = tls_entries(b, &id, key, spec);
    let ing = Ing {
        namespace: &key.0,
        name: &key.1,
        id,
        rank,
        annotations,
        tls,
    };
    rules(b, &ing, spec);
    default_backend(b, &ing, spec);
}

/// The valid `spec.tls` entries; the others are reported.
fn tls_entries(
    b: &mut Builder<'_>,
    id: &str,
    key: &ObjectKey,
    spec: &IngressSpec,
) -> Vec<TlsEntry> {
    let mut out = Vec::new();
    for (i, entry) in spec.tls.iter().flatten().enumerate() {
        let field = format!(".spec.tls[{i}]");
        let hosts: Vec<String> = entry
            .hosts
            .iter()
            .flatten()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        let served = if hosts.is_empty() {
            "the hosts of this Ingress".to_owned()
        } else {
            hosts.join(", ")
        };
        let secret = entry.secret_name.as_deref().filter(|s| !s.is_empty());
        let Some(secret) = secret else {
            b.warn(
                id,
                &field,
                format!(
                    "the entry names no secretName (TLS routing by SNI alone is not supported); {served} are served without TLS"
                ),
            );
            continue;
        };
        let secret_key = (key.0.clone(), secret.to_owned());
        match b.inventory.secrets.get(&secret_key) {
            None => b.warn(
                id,
                &field,
                format!(
                    "Secret {}/{secret} does not exist; {served} are served without TLS until it does",
                    key.0
                ),
            ),
            Some(info) => {
                if let Err(why) = &info.valid {
                    b.warn(
                        id,
                        &field,
                        format!(
                            "Secret {}/{secret} is not a usable certificate ({why}); {served} are served without TLS",
                            key.0
                        ),
                    );
                    continue;
                }
                let certificate = certificate_name(&secret_key);
                let (cert_file, key_file) =
                    secret_paths(&b.settings.data_dir, &secret_key.0, &secret_key.1);
                b.out.fragment.certificates.insert(
                    certificate.clone(),
                    Certificate {
                        cert_file,
                        key_file,
                        key_password: None,
                    },
                );
                b.out.secrets.insert(secret_key);
                out.push(TlsEntry { hosts, certificate });
            }
        }
    }
    out
}

/// The fragment name of the certificate of Secret `key`.
#[must_use]
pub fn certificate_name(key: &ObjectKey) -> String {
    object_name(
        "icert",
        &[&key.0, &key.1],
        &format!("ingress-secret/{}/{}", key.0, key.1),
    )
}

impl Ing<'_> {
    /// The certificate of the first valid `spec.tls` entry covering `host`.
    fn certificate(&self, host: Option<&str>) -> Option<&str> {
        self.tls
            .iter()
            .find(|entry| {
                entry.hosts.is_empty()
                    || host.is_some_and(|h| {
                        entry
                            .hosts
                            .iter()
                            .any(|pattern| pattern == h || covers(pattern, h))
                    })
            })
            .map(|entry| entry.certificate.as_str())
    }

    /// Whether plain requests to a TLS host are redirected to HTTPS.
    fn ssl_redirect(&self) -> bool {
        self.annotations.force_ssl_redirect || self.annotations.ssl_redirect != Some(false)
    }

    /// The middlewares every route has first: `ip_allow` and `cors`.
    fn base(&self) -> Vec<Middleware> {
        let mut out = Vec::new();
        if !self.annotations.allow.is_empty() {
            out.push(Middleware::IpAllow(IpListConfig {
                cidrs: self.annotations.allow.clone(),
            }));
        }
        if let Some(cors) = &self.annotations.cors {
            out.push(Middleware::Cors(cors.clone()));
        }
        out
    }

    /// The middlewares of a route. A challenge path is neither redirected nor rewritten.
    /// `ssl` adds the redirect to HTTPS.
    fn chain(&self, action: &Action, challenge: bool, ssl: bool) -> Vec<Middleware> {
        let mut out = self.base();
        if challenge {
            return out;
        }
        if let Some(redirect) = &self.annotations.redirect {
            out.push(Middleware::Redirect(RedirectConfig {
                scheme: None,
                hostname: None,
                path: None,
                prefix: None,
                regex: Some("^.*$".to_owned()),
                replacement: Some(redirect.url.replace('$', "$$")),
                permanent: false,
                status: Some(redirect.status),
                port: None,
                always: false,
            }));
        } else if ssl {
            out.push(https_redirect());
        } else {
            match action {
                Action::Rewrite(Some(rewrite)) => out.push((**rewrite).clone()),
                Action::Rewrite(None) => {}
                Action::AppRoot(root) => out.push(Middleware::Redirect(RedirectConfig {
                    scheme: None,
                    hostname: None,
                    path: Some(root.clone()),
                    prefix: None,
                    regex: None,
                    replacement: None,
                    permanent: false,
                    status: Some(302),
                    port: None,
                    always: false,
                })),
            }
        }
        out
    }
}

/// A redirect to HTTPS (308, the default of ingress-nginx's `http-redirect-code`): a
/// request that already uses HTTPS is left alone, and the port is HTTPS's default.
fn https_redirect() -> Middleware {
    Middleware::Redirect(RedirectConfig {
        scheme: Some(RedirectScheme::Https),
        hostname: None,
        path: None,
        prefix: None,
        regex: None,
        replacement: None,
        permanent: false,
        status: Some(308),
        port: None,
        always: false,
    })
}

/// The path of a rule entry: its value (an `Exact` path as written, a prefix without
/// trailing slashes, `/` for all) and whether it is `Exact`; or why it is invalid.
fn path_value(path: &HTTPIngressPath) -> Result<(String, bool), String> {
    let raw = path.path.as_deref().unwrap_or_default();
    let exact = match path.path_type.as_str() {
        "Exact" => true,
        "Prefix" => false,
        "ImplementationSpecific" => {
            if raw.is_empty() {
                return Ok(("/".to_owned(), false));
            }
            false
        }
        other => return Err(format!("pathType `{other}` is not known")),
    };
    if !raw.starts_with('/') {
        return Err(format!(
            "path `{raw}` must start with `/` for pathType {}",
            path.path_type
        ));
    }
    if exact {
        return Ok((raw.to_owned(), true));
    }
    let trimmed = raw.trim_end_matches('/');
    Ok((
        if trimmed.is_empty() { "/" } else { trimmed }.to_owned(),
        false,
    ))
}

/// Whether `path` is an ACME HTTP-01 challenge path or below it.
fn is_challenge(path: &str) -> bool {
    path == CHALLENGE_PREFIX
        || path
            .strip_prefix(CHALLENGE_PREFIX)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether an `ImplementationSpecific` path looks like a regular expression, which is not
/// supported (it is matched as a literal prefix).
fn looks_like_regex(path: &str) -> bool {
    path.contains(['(', ')', '[', ']', '*', '+', '?', '^', '$', '\\', '|'])
}

/// The priority of a rule route.
fn priority(host: Option<&str>, path: &str, exact: bool, rank: usize, index: usize) -> i64 {
    Precedence {
        host: specificity(host),
        path_kind: PathKind::Prefix,
        path_len: 2 * path.len().max(1) + usize::from(exact),
        method: false,
        headers: 0,
        query: 0,
        route_rank: rank,
        rule: index,
    }
    .priority()
}

/// The priority of a `defaultBackend`: below every rule, older Ingresses first.
fn default_priority(rank: usize) -> i64 {
    1 + (65_535 - i64::try_from(rank.min(65_535)).unwrap_or(65_535))
}

fn host_expr(host: Option<&str>, path: Expr) -> Expr {
    match host {
        None => path,
        Some(h) => Expr::And(vec![Expr::Matcher(Matcher::Host(h.to_owned())), path]),
    }
}

fn path_expr(path: &str, exact: bool) -> Expr {
    if exact {
        Expr::Matcher(Matcher::Path(path.to_owned()))
    } else {
        prefix_expr(path)
    }
}

/// One route to add.
struct NewRoute {
    label: String,
    expr: Expr,
    priority: i64,
    middlewares: Vec<Middleware>,
    service: String,
    tls: RouteTls,
    field: String,
}

fn add_route(b: &mut Builder<'_>, ing: &Ing<'_>, new: NewRoute) {
    let errors = new.expr.validate(rdock_rules::Context::Http);
    if let Some(error) = errors.first() {
        b.warn(
            &ing.id,
            &new.field,
            format!("the route is left out: {error}"),
        );
        return;
    }
    let middlewares: Vec<String> = new
        .middlewares
        .into_iter()
        .map(|m| {
            let json = serde_json::to_value(&m).unwrap_or_default();
            let kind = json["type"].as_str().unwrap_or("middleware").to_owned();
            let name = object_name(
                "imw",
                &[ing.namespace, ing.name, &kind],
                &format!("imw/{}/{}/{json}", ing.namespace, ing.name),
            );
            b.out.fragment.middlewares.insert(name.clone(), m);
            name
        })
        .collect();
    let name = object_name(
        "ing",
        &[ing.namespace, ing.name, &new.label],
        &format!("ing/{}/{}/{}", ing.namespace, ing.name, new.label),
    );
    b.out.fragment.routes.insert(
        name,
        Route {
            matcher: MatchSpec::Rule(new.expr.to_string()),
            listeners: None,
            priority: new.priority,
            priority_class: rdock_model::route::PriorityClass::Normal,
            middlewares,
            service: Some(new.service),
            tls: Some(new.tls),
            timeouts: rdock_model::route::RouteTimeouts::default(),
            mirror: None,
            max_body: ing.annotations.max_body,
            errors: None,
            enabled: true,
        },
    );
}

fn plain() -> RouteTls {
    RouteTls::Mode(TlsMode::Off)
}

fn with_certificate(certificate: &str) -> RouteTls {
    RouteTls::Options(RouteTlsOptions {
        auto: false,
        dns_provider: None,
        domains: Vec::new(),
        certificate: Some(certificate.to_owned()),
    })
}

/// The fixed-answer services, added when first used.
fn ensure_unavailable(b: &mut Builder<'_>) -> String {
    b.out
        .fragment
        .services
        .entry(UNAVAILABLE_SERVICE.to_owned())
        .or_insert_with(|| backends::respond(503));
    UNAVAILABLE_SERVICE.to_owned()
}

fn ensure_denied(b: &mut Builder<'_>) -> String {
    b.out
        .fragment
        .services
        .entry(DENIED_SERVICE.to_owned())
        .or_insert_with(|| backends::respond(403));
    DENIED_SERVICE.to_owned()
}

/// The service for a backend, or `None` when the path is left out (`resource` backends).
/// A Service that cannot be used answers 503.
fn backend(
    b: &mut Builder<'_>,
    ing: &Ing<'_>,
    backend: &IngressBackend,
    field: &str,
) -> Option<String> {
    if let Some(resource) = &backend.resource {
        b.warn(
            &ing.id,
            field,
            format!(
                "resource backends (`{}` `{}`) are not supported; the path is left out",
                resource.kind, resource.name
            ),
        );
        return None;
    }
    let Some(service) = &backend.service else {
        b.warn(
            &ing.id,
            field,
            "the backend names neither a service nor a resource; the path is left out",
        );
        return None;
    };
    let port = service.port.as_ref().and_then(|p| {
        match (p.name.as_deref().filter(|n| !n.is_empty()), p.number) {
            (Some(name), _) => Some(PortRef::Name(name)),
            (None, Some(number)) => u16::try_from(number).ok().map(PortRef::Number),
            (None, None) => None,
        }
    });
    // ExternalName Services are refused: that setting belongs to the Gateway API.
    let resolved = backends::resolve(b.inventory, ing.namespace, &service.name, port, false);
    let resolved = match resolved {
        Ok(resolved) => resolved,
        Err(backends::BackendError::ExternalNameNotAllowed { .. }) => {
            b.warn(
                &ing.id,
                field,
                format!(
                    "Service {}/{} is of type ExternalName, which Ingress backends do not support; the path answers 503",
                    ing.namespace, service.name
                ),
            );
            return Some(ensure_unavailable(b));
        }
        Err(error) => {
            b.warn(&ing.id, field, format!("{error}; the path answers 503"));
            return Some(ensure_unavailable(b));
        }
    };
    b.out
        .diagnostics
        .extend(backends::refused_diagnostic(&resolved));
    let scheme = ing
        .annotations
        .scheme
        .unwrap_or_else(|| backends::scheme(resolved.app_protocol.as_deref(), Scheme::Http));
    let tag = match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
        Scheme::H2c => "h2c",
        Scheme::H3 => "h3",
    };
    let name = object_name(
        "isvc",
        &[
            ing.namespace,
            &service.name,
            &resolved.port.to_string(),
            tag,
        ],
        &format!(
            "isvc/{}/{}/{}/{tag}",
            ing.namespace, service.name, resolved.port
        ),
    );
    b.out
        .fragment
        .services
        .entry(name.clone())
        .or_insert_with(|| backends::http_service(resolved.targets.backends(), scheme));
    Some(name)
}

/// The service of a path: resolved, or a fixed answer when the Ingress denies everyone or
/// redirects (a challenge path is always resolved).
fn path_service(
    b: &mut Builder<'_>,
    ing: &Ing<'_>,
    backend_ref: &IngressBackend,
    field: &str,
    challenge: bool,
) -> Option<String> {
    if ing.annotations.deny_all {
        return Some(ensure_denied(b));
    }
    if ing.annotations.redirect.is_some() && !challenge {
        return Some(ensure_unavailable(b));
    }
    backend(b, ing, backend_ref, &format!("{field}.backend"))
}

fn rules(b: &mut Builder<'_>, ing: &Ing<'_>, spec: &IngressSpec) {
    let mut index = 0_usize;
    for (ri, rule) in spec.rules.iter().flatten().enumerate() {
        let host = rule
            .host
            .as_deref()
            .filter(|h| !h.is_empty())
            .map(str::to_ascii_lowercase);
        let host = host.as_deref();
        let certificate = ing.certificate(host).map(str::to_owned);
        let Some(http) = &rule.http else { continue };
        let mut host_redirect = false;
        let mut root = false;
        for (pi, path) in http.paths.iter().enumerate() {
            let field = format!(".spec.rules[{ri}].http.paths[{pi}]");
            let (value, exact) = match path_value(path) {
                Ok(parsed) => parsed,
                Err(message) => {
                    b.warn(&ing.id, &field, format!("{message}; the path is left out"));
                    continue;
                }
            };
            if path.path_type == "ImplementationSpecific"
                && looks_like_regex(path.path.as_deref().unwrap_or_default())
            {
                b.warn(
                    &ing.id,
                    &field,
                    "an ImplementationSpecific path is matched as a literal prefix; regular expressions are not supported",
                );
            }
            let challenge = is_challenge(&value);
            let Some(service) = path_service(b, ing, &path.backend, &field, challenge) else {
                continue;
            };
            let rewrite = rewrite(ing);
            root |= !exact && value == "/";
            let plan = PathPlan {
                index,
                value,
                exact,
                challenge,
                service,
                action: Action::Rewrite(rewrite),
            };
            index += 1;
            host_redirect |= emit(b, ing, host, certificate.as_deref(), ri, &plan, &field);
        }
        if let Some(app_root) = &ing.annotations.app_root
            && root
            && ing.annotations.redirect.is_none()
        {
            let service = ensure_unavailable(b);
            let plan = PathPlan {
                index,
                value: "/".to_owned(),
                exact: true,
                challenge: false,
                service,
                action: Action::AppRoot(app_root.clone()),
            };
            index += 1;
            let field = format!(".spec.rules[{ri}]");
            host_redirect |= emit(b, ing, host, certificate.as_deref(), ri, &plan, &field);
        }
        if host_redirect {
            let service = ensure_unavailable(b);
            let mut middlewares = ing.base();
            middlewares.push(https_redirect());
            add_route(
                b,
                ing,
                NewRoute {
                    label: format!("r{ri}-ssl"),
                    expr: host_expr(host, prefix_expr("/")),
                    priority: priority(host, "/", false, ing.rank, 31),
                    middlewares,
                    service,
                    tls: plain(),
                    field: format!(".spec.rules[{ri}]"),
                },
            );
        }
    }
}

/// The `rewrite-target` middleware for a path: the whole path becomes the target, for every
/// path type. ingress-nginx 0.22 and later rewrite the whole URI to the target and carry
/// parts of the request path over only through capture groups (which are not supported and
/// reported), so a literal target replaces the path (`/svc/abc` with target `/new` is
/// `/new`); the query string is kept.
fn rewrite(ing: &Ing<'_>) -> Option<Box<Middleware>> {
    let target = ing.annotations.rewrite_target.as_ref()?;
    Some(Box::new(Middleware::ReplacePath(ReplacePathConfig {
        path: target.clone(),
    })))
}

/// Emits the routes of one path; returns whether the host needs the plain redirect route.
fn emit(
    b: &mut Builder<'_>,
    ing: &Ing<'_>,
    host: Option<&str>,
    certificate: Option<&str>,
    rule: usize,
    plan: &PathPlan,
    field: &str,
) -> bool {
    let expr = host_expr(host, path_expr(&plan.value, plan.exact));
    let priority = priority(host, &plan.value, plan.exact, ing.rank, plan.index);
    let label = |variant: &str| format!("r{rule}p{}-{variant}", plan.index);
    let route =
        |b: &mut Builder<'_>, variant: &str, middlewares: Vec<Middleware>, tls: RouteTls| {
            add_route(
                b,
                ing,
                NewRoute {
                    label: label(variant),
                    expr: expr.clone(),
                    priority,
                    middlewares,
                    service: plan.service.clone(),
                    tls,
                    field: field.to_owned(),
                },
            );
        };
    let Some(certificate) = certificate else {
        let ssl = ing.annotations.force_ssl_redirect;
        route(
            b,
            "plain",
            ing.chain(&plan.action, plan.challenge, ssl),
            plain(),
        );
        return false;
    };
    route(
        b,
        "tls",
        ing.chain(&plan.action, plan.challenge, false),
        with_certificate(certificate),
    );
    if plan.challenge || ing.annotations.redirect.is_some() {
        route(
            b,
            "plain",
            ing.chain(&plan.action, plan.challenge, false),
            plain(),
        );
        false
    } else if ing.ssl_redirect() {
        true
    } else {
        route(b, "plain", ing.chain(&plan.action, false, false), plain());
        false
    }
}

fn default_backend(b: &mut Builder<'_>, ing: &Ing<'_>, spec: &IngressSpec) {
    let Some(default) = &spec.default_backend else {
        return;
    };
    let field = ".spec.defaultBackend";
    let Some(service) = path_service(b, ing, default, field, false) else {
        return;
    };
    let action = Action::Rewrite(None);
    let ssl = ing.annotations.force_ssl_redirect;
    add_route(
        b,
        ing,
        NewRoute {
            label: "default".to_owned(),
            expr: prefix_expr("/"),
            priority: default_priority(ing.rank),
            middlewares: ing.chain(&action, false, ssl),
            service,
            tls: plain(),
            field: field.to_owned(),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str, kind: &str) -> HTTPIngressPath {
        HTTPIngressPath {
            backend: IngressBackend::default(),
            path: Some(value.to_owned()),
            path_type: kind.to_owned(),
        }
    }

    #[test]
    fn path_values() {
        assert_eq!(
            path_value(&path("/a/b/", "Prefix")),
            Ok(("/a/b".into(), false))
        );
        assert_eq!(path_value(&path("/", "Prefix")), Ok(("/".into(), false)));
        assert_eq!(path_value(&path("//", "Prefix")), Ok(("/".into(), false)));
        assert_eq!(path_value(&path("/a/", "Exact")), Ok(("/a/".into(), true)));
        assert_eq!(
            path_value(&path("/a/", "ImplementationSpecific")),
            Ok(("/a".into(), false))
        );
        let mut empty = path("", "ImplementationSpecific");
        empty.path = None;
        assert_eq!(path_value(&empty), Ok(("/".into(), false)));
        assert!(path_value(&path("a", "Prefix")).is_err());
        assert!(path_value(&path("", "Exact")).is_err());
        assert!(path_value(&path("/a", "Regex")).is_err());
    }

    #[test]
    fn challenge_paths() {
        assert!(is_challenge("/.well-known/acme-challenge/abc"));
        assert!(is_challenge("/.well-known/acme-challenge"));
        assert!(!is_challenge("/.well-known/acme-challenger"));
        assert!(!is_challenge("/.well-known"));
    }

    #[test]
    fn precedence_of_the_ingress_specification() {
        let p = |host, path, exact, rank, index| priority(host, path, exact, rank, index);
        // Longest path first, Exact before Prefix on a tie.
        assert!(p(None, "/aaa/bbb", false, 5, 0) > p(None, "/aaa", false, 0, 0));
        assert!(p(None, "/aaa", false, 0, 0) > p(None, "/", false, 0, 0));
        assert!(p(None, "/foo", true, 9, 9) > p(None, "/foo", false, 0, 0));
        // Exact host before wildcard before no host, whatever the path.
        let exact = p(Some("a.example.com"), "/", false, 9, 9);
        let wildcard = p(Some("*.example.com"), "/long/path", true, 0, 0);
        let any = p(None, "/long/path", true, 0, 0);
        assert!(exact > wildcard && wildcard > any);
        // Older Ingress first, then the earlier path.
        assert!(p(None, "/a", false, 0, 3) > p(None, "/a", false, 1, 0));
        assert!(p(None, "/a", false, 1, 0) > p(None, "/a", false, 1, 1));
        // The default backend is below everything, oldest first.
        assert!(p(None, "/", false, 65_535, 31) > default_priority(0));
        assert!(default_priority(0) > default_priority(1));
        assert!(default_priority(70_000) >= 1);
    }

    #[test]
    fn regex_like_paths_are_noticed() {
        assert!(looks_like_regex("/foo(/|$)(.*)"));
        assert!(!looks_like_regex("/foo/bar-baz_1.html"));
    }
}
