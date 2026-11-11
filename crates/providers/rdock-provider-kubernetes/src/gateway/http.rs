//! HTTPRoute and GRPCRoute (`httproute_types.go`, `grpcroute_types.go`).
//!
//! **Matches.** Each match of each rule becomes one route per internal listener and host
//! name group (host names of equal precedence share a route), with the priority of
//! [`super::priority`]:
//! - path `Exact` → ``Path(`/a`)``; `PathPrefix` (by path segment, a trailing `/` ignored)
//!   → ``Path(`/a`) || PathPrefix(`/a/`)``, and `/` → ``PathPrefix(`/`)``;
//!   `RegularExpression` → ``PathRegexp(`^(?:…)$`)`` (a full match, as RE2 implementations
//!   do); no path → `PathPrefix /`;
//! - headers `Exact` → `Header` (names are case-insensitive), `RegularExpression` →
//!   `HeaderRegexp` (full match); query parameters likewise with `Query`/`QueryRegexp`;
//!   `method` → `Method`;
//! - GRPCRoute: service and method → ``Path(`/svc/method`)``, service only →
//!   ``PathPrefix(`/svc/`)``, method only → ``PathRegexp(`^/[^/]+/method$`)``,
//!   `RegularExpression` → ``PathRegexp(`^/(?:svc)/(?:method)$`)``; headers as above;
//! - host names: the intersection with the listener ([`super::hostnames`]); none → any host.
//!
//! **Backends.** Each `backendRef` is a Kubernetes Service port (other kinds:
//! `ResolvedRefs=False/InvalidKind`), in the route's namespace or allowed by a ReferenceGrant
//! (`RefNotPermitted`), that exists with that port (`BackendNotFound`). `ExternalName`
//! Services are `InvalidKind` unless `allow_external_name` is set. One fragment service is
//! made per (Service, port, scheme) and shared by every route that uses it; one with no
//! usable endpoint answers 503. An invalid reference keeps its weighted share and answers
//! 500 (one shared `respond: 500` service); weight 0 sends nothing; a rule whose weights are
//! all 0, or that has no `backendRefs` and no redirect, answers 500. Several targets make a
//! per-rule `split` service. HTTPRoute backends speak HTTP/1.1 unless `appProtocol` says
//! otherwise; GRPCRoute backends default to h2c.
//!
//! **Filters** (in spec order, as middlewares): `RequestHeaderModifier` and
//! `ResponseHeaderModifier` → `headers`; `RequestRedirect` → `redirect` (status 302 unless
//! set; with neither scheme nor port, the port is the Gateway listener's, as the
//! specification requires); `URLRewrite` → `headers` (`Host`), `replace_path`
//! (`ReplaceFullPath`) and an anchored `rewrite` (`ReplacePrefixMatch`); `RequestMirror` →
//! the route's `mirror` (one; the percentage rounded up to a whole percent). `CORS`,
//! `ExternalAuth`, `ExtensionRef`, several mirrors, `URLRewrite` with `RequestRedirect`
//! (`IncompatibleFilters`), unknown types and values make the **rule** invalid: it is
//! dropped (never half-applied), the route stays accepted with `PartiallyInvalid=True`
//! ("Dropped Rule …"), and when every rule is invalid the route is `Accepted=False` with
//! `UnsupportedValue` (or `IncompatibleFilters`). Filters on a `backendRef` are applied only
//! when that backend is the rule's only one with traffic (then they are equivalent to rule
//! filters); otherwise the rule is invalid.
//!
//! **Timeouts and retries.** `timeouts.backendRequest` → the route's `read` timeout.
//! `timeouts.request` (no total request deadline in the data plane), `retry` without
//! `backoff` and `sessionPersistence` are not supported: the rule is kept and a diagnostic
//! says the field is ignored. `retry.backoff` makes the rule invalid, as the specification
//! requires of implementations without backoff.

use std::collections::BTreeMap;

use rdock_model::middleware::{
    HeaderRules, HeadersConfig, Middleware, RedirectConfig, RedirectPrefix, RedirectScheme,
    ReplacePathConfig, RewriteConfig,
};
use rdock_model::route::{MatchSpec, Mirror, Route, RouteTimeouts, RouteTls, TlsMode};
use rdock_model::service::{Scheme, Service};
use rdock_model::values::Duration;
use rdock_rules::{Expr, Matcher};

use super::attach::{Parent, RouteInfo};
use super::conditions::{condition, reasons, types};
use super::hostnames::{Intersection, escape_regex, http_matcher, specificity};
use super::listeners::Failure;
use super::priority::{PathKind, Precedence};
use super::{Context, object_id};
use crate::api::{
    BackendObjectReference, GRPCRouteFilter, GRPCRouteMatch, HTTPHeaderFilter, HTTPRouteFilter,
    HTTPRouteMatch, ParentReference, filter_types, kinds, path_match, path_modifier, value_match,
};
use crate::backends::{self, BackendError, PortRef};
use crate::inventory::ObjectKey;
use crate::translate::{DesiredRouteParent, RouteKind, RouteRef};

/// The shared service that answers 500 for invalid backend references.
pub const INVALID_BACKEND_SERVICE: &str = "gateway-api-invalid-backend";

/// Translates every HTTPRoute and GRPCRoute.
pub fn translate(cx: &mut Context<'_>, ranks: &BTreeMap<(RouteKind, ObjectKey), usize>) {
    let inventory = cx.inventory;
    for (key, route) in &inventory.http_routes {
        let rules: Vec<RuleSpec<'_>> = route
            .spec
            .rules
            .iter()
            .map(|rule| RuleSpec {
                matches: rule.matches.iter().map(MatchSpecRef::Http).collect(),
                filters: rule.filters.clone(),
                backends: rule
                    .backend_refs
                    .iter()
                    .map(|b| {
                        (
                            b.backend.reference.clone(),
                            b.backend.weight,
                            b.filters.clone(),
                        )
                    })
                    .collect(),
                backend_request: rule
                    .timeouts
                    .as_ref()
                    .and_then(|t| t.backend_request.clone()),
                ignored: ignored_fields(
                    rule.timeouts
                        .as_ref()
                        .and_then(|t| t.request.as_ref())
                        .is_some(),
                    rule.retry.as_ref(),
                    rule.session_persistence.is_some(),
                ),
                retry_backoff: rule.retry.as_ref().and_then(|r| r.backoff.clone()),
                http_matches: rule.matches.clone(),
            })
            .collect();
        let spec = RouteSpec {
            kind: RouteKind::Http,
            key,
            generation: route.metadata.generation,
            parent_refs: &route.spec.parent_refs,
            hostnames: &route.spec.hostnames,
            rules,
            rank: ranks
                .get(&(RouteKind::Http, key.clone()))
                .copied()
                .unwrap_or(usize::MAX),
        };
        translate_route(cx, &spec);
    }
    for (key, route) in &inventory.grpc_routes {
        let rules: Vec<RuleSpec<'_>> = route
            .spec
            .rules
            .iter()
            .map(|rule| RuleSpec {
                matches: rule.matches.iter().map(MatchSpecRef::Grpc).collect(),
                filters: rule.filters.iter().map(grpc_filter).collect(),
                backends: rule
                    .backend_refs
                    .iter()
                    .map(|b| {
                        (
                            b.backend.reference.clone(),
                            b.backend.weight,
                            b.filters.iter().map(grpc_filter).collect(),
                        )
                    })
                    .collect(),
                backend_request: None,
                ignored: ignored_fields(false, None, rule.session_persistence.is_some()),
                retry_backoff: None,
                http_matches: Vec::new(),
            })
            .collect();
        let spec = RouteSpec {
            kind: RouteKind::Grpc,
            key,
            generation: route.metadata.generation,
            parent_refs: &route.spec.parent_refs,
            hostnames: &route.spec.hostnames,
            rules,
            rank: ranks
                .get(&(RouteKind::Grpc, key.clone()))
                .copied()
                .unwrap_or(usize::MAX),
        };
        translate_route(cx, &spec);
    }
}

fn ignored_fields(
    request_timeout: bool,
    retry: Option<&crate::api::HTTPRouteRetry>,
    session: bool,
) -> Vec<&'static str> {
    let mut ignored = Vec::new();
    if request_timeout {
        ignored.push("timeouts.request (no total request timeout yet)");
    }
    if retry.is_some_and(|r| r.backoff.is_none()) {
        ignored.push("retry");
    }
    if session {
        ignored.push("sessionPersistence");
    }
    ignored
}

/// A GRPCRoute filter as the equivalent HTTPRoute filter.
fn grpc_filter(filter: &GRPCRouteFilter) -> HTTPRouteFilter {
    HTTPRouteFilter {
        kind: filter.kind.clone(),
        request_header_modifier: filter.request_header_modifier.clone(),
        response_header_modifier: filter.response_header_modifier.clone(),
        request_mirror: filter.request_mirror.clone(),
        extension_ref: filter.extension_ref.clone(),
        ..HTTPRouteFilter::default()
    }
}

/// A match of either kind.
#[derive(Debug, Clone, Copy)]
enum MatchSpecRef<'a> {
    Http(&'a HTTPRouteMatch),
    Grpc(&'a GRPCRouteMatch),
}

/// A rule of either kind, normalised.
struct RuleSpec<'a> {
    matches: Vec<MatchSpecRef<'a>>,
    filters: Vec<HTTPRouteFilter>,
    backends: Vec<(BackendObjectReference, Option<i32>, Vec<HTTPRouteFilter>)>,
    backend_request: Option<String>,
    ignored: Vec<&'static str>,
    retry_backoff: Option<String>,
    /// HTTPRoute matches, for `ReplacePrefixMatch`.
    http_matches: Vec<HTTPRouteMatch>,
}

/// A route of either kind, normalised.
struct RouteSpec<'a> {
    kind: RouteKind,
    key: &'a ObjectKey,
    generation: Option<i64>,
    parent_refs: &'a [ParentReference],
    hostnames: &'a [String],
    rules: Vec<RuleSpec<'a>>,
    rank: usize,
}

/// One match, translated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchOut {
    /// Conditions, all of which must hold.
    pub conditions: Vec<Expr>,
    /// Path kind, for the priority.
    pub path_kind: PathKind,
    /// Path length, for the priority.
    pub path_len: usize,
    /// Whether there is a method condition.
    pub method: bool,
    /// Number of header conditions.
    pub headers: usize,
    /// Number of query conditions.
    pub query: usize,
}

/// What a filter does, before the listener port is known.
#[derive(Debug, Clone)]
enum FilterPlan {
    Middleware(Middleware),
    /// A redirect; the port defaults to the listener's.
    Redirect(RedirectConfig),
}

/// A valid rule, ready to emit.
#[derive(Debug, Clone)]
struct RulePlan {
    index: usize,
    matches: Vec<MatchOut>,
    filters: Vec<FilterPlan>,
    service: String,
    services: Vec<(String, Service)>,
    mirror: Option<Mirror>,
    timeouts: RouteTimeouts,
}

fn translate_route(cx: &mut Context<'_>, spec: &RouteSpec<'_>) {
    let (namespace, name) = (&spec.key.0, &spec.key.1);
    let kind_name = spec.kind.as_str();
    let id = object_id(kind_name, namespace, name);
    let mut plans = Vec::new();
    let mut invalid: Vec<(usize, Failure)> = Vec::new();
    let mut unresolved: Vec<Failure> = Vec::new();
    for (index, rule) in spec.rules.iter().enumerate() {
        match plan_rule(cx, spec, index, rule, &mut unresolved) {
            Ok(plan) => plans.push(plan),
            Err(failure) => invalid.push((index, failure)),
        }
        for field in &rule.ignored {
            cx.warn(
                &id,
                &format!(".spec.rules[{index}]"),
                format!("{field} is not supported and is ignored"),
            );
        }
    }
    for (index, (_, message)) in &invalid {
        cx.warn(
            &id,
            &format!(".spec.rules[{index}]"),
            format!("the rule is not programmed: {message}"),
        );
    }
    for (_, message) in &unresolved {
        cx.warn(&id, ".spec.rules", message.clone());
    }
    let all_invalid = plans.is_empty() && !invalid.is_empty();
    let info = RouteInfo {
        kind: spec.kind,
        namespace,
        name,
        hostnames: spec.hostnames,
    };
    let route_ref = RouteRef {
        kind: spec.kind,
        namespace: namespace.clone(),
        name: name.clone(),
    };
    let mut parents = Vec::new();
    // Internal listener → (Gateway listener port, host names).
    let mut targets: BTreeMap<String, (u16, Intersection)> = BTreeMap::new();
    for parent_ref in spec.parent_refs {
        let parent = super::attach::resolve(cx, &info, parent_ref);
        let accepted = match parent {
            Parent::NotOurs => continue,
            Parent::Rejected(failure) => Err(failure),
            Parent::Accepted { .. } if all_invalid => {
                let (reason, message) = &invalid[0].1;
                Err((*reason, format!("every rule is invalid: {message}")))
            }
            Parent::Accepted { gateway, listeners } => {
                record_policies(cx, spec, gateway);
                for (index, hosts) in listeners {
                    let listener = &mut cx.gateways[gateway].listeners[index];
                    listener.attached.insert(route_ref.clone());
                    if let Some(internal) = &listener.internal {
                        let entry = targets
                            .entry(internal.clone())
                            .or_insert((listener.port, Intersection::Empty));
                        entry.1 = merge(&entry.1, &hosts);
                    }
                }
                Ok(())
            }
        };
        parents.push(parent_status(
            parent_ref,
            spec.generation,
            &accepted,
            unresolved.first(),
            &invalid,
        ));
        if let Err((_, message)) = &accepted {
            cx.warn(
                &id,
                ".spec.parentRefs",
                format!("not accepted by Gateway `{}`: {message}", parent_ref.name),
            );
        }
    }
    if !parents.is_empty() {
        cx.out.status.routes.insert(route_ref, parents);
    }
    for (internal, (port, hosts)) in targets {
        emit(cx, spec, &plans, &internal, port, &hosts);
    }
}

/// Records Gateway `gateway` as an ancestor of the BackendTLSPolicies of the route's backends.
fn record_policies(cx: &mut Context<'_>, spec: &RouteSpec<'_>, gateway: usize) {
    let gateway = cx.gateways[gateway].key.clone();
    for rule in &spec.rules {
        for (reference, _, _) in &rule.backends {
            if reference.group.as_deref().is_some_and(|g| !g.is_empty())
                || reference.kind.as_deref().is_some_and(|k| k != "Service")
            {
                continue;
            }
            let namespace = reference.namespace.as_deref().unwrap_or(&spec.key.0);
            let port_name = cx
                .inventory
                .services
                .get(&(namespace.to_owned(), reference.name.clone()))
                .and_then(|s| s.spec.as_ref())
                .and_then(|s| s.ports.as_ref())
                .and_then(|ports| {
                    ports
                        .iter()
                        .find(|p| reference.port.is_some_and(|n| p.port == i32::from(n)))
                })
                .and_then(|p| p.name.clone());
            if let Some((policy, _)) =
                super::policies::backend_tls(cx, namespace, &reference.name, port_name.as_deref())
                && let Some(state) = cx.policies.get_mut(&policy)
            {
                state.ancestors.insert(gateway.clone());
            }
        }
    }
}

/// The union of two intersections.
fn merge(a: &Intersection, b: &Intersection) -> Intersection {
    match (a, b) {
        (Intersection::Any, _) | (_, Intersection::Any) => Intersection::Any,
        (Intersection::Empty, other) | (other, Intersection::Empty) => other.clone(),
        (Intersection::Hosts(x), Intersection::Hosts(y)) => {
            let mut all: Vec<String> = x.iter().chain(y).cloned().collect();
            all.sort();
            all.dedup();
            Intersection::Hosts(all)
        }
    }
}

/// Our `status.parents` entry for one parentRef.
fn parent_status(
    parent_ref: &ParentReference,
    generation: Option<i64>,
    accepted: &Result<(), Failure>,
    unresolved: Option<&Failure>,
    invalid: &[(usize, Failure)],
) -> DesiredRouteParent {
    let mut conditions = vec![match accepted {
        Ok(()) => condition(
            types::ACCEPTED,
            true,
            reasons::ACCEPTED,
            "accepted",
            generation,
        ),
        Err((reason, message)) => {
            condition(types::ACCEPTED, false, reason, message.clone(), generation)
        }
    }];
    conditions.push(match unresolved {
        None => condition(
            types::RESOLVED_REFS,
            true,
            reasons::RESOLVED_REFS,
            "references resolved",
            generation,
        ),
        Some((reason, message)) => condition(
            types::RESOLVED_REFS,
            false,
            reason,
            message.clone(),
            generation,
        ),
    });
    if accepted.is_ok() && !invalid.is_empty() {
        let dropped: Vec<String> = invalid
            .iter()
            .map(|(index, (_, message))| format!("{index} ({message})"))
            .collect();
        conditions.push(condition(
            types::PARTIALLY_INVALID,
            true,
            reasons::UNSUPPORTED_VALUE,
            format!("Dropped Rule(s): {}", dropped.join("; ")),
            generation,
        ));
    }
    DesiredRouteParent {
        parent_ref: parent_ref.clone(),
        conditions,
    }
}

/// Builds the plan of one rule; `unresolved` collects backend reference problems.
fn plan_rule(
    cx: &Context<'_>,
    spec: &RouteSpec<'_>,
    index: usize,
    rule: &RuleSpec<'_>,
    unresolved: &mut Vec<Failure>,
) -> Result<RulePlan, Failure> {
    let matches = if rule.matches.is_empty() {
        vec![default_match()]
    } else {
        rule.matches
            .iter()
            .map(|m| match m {
                MatchSpecRef::Http(m) => http_match(m),
                MatchSpecRef::Grpc(m) => grpc_match(m),
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|message| (reasons::UNSUPPORTED_VALUE, message))?
    };
    if rule.retry_backoff.is_some() {
        return Err((
            reasons::UNSUPPORTED_VALUE,
            "retry.backoff is not supported".to_owned(),
        ));
    }
    let mut timeouts = RouteTimeouts::default();
    if let Some(value) = &rule.backend_request {
        let duration = crate::api::parse_duration(value).ok_or_else(|| {
            (
                reasons::UNSUPPORTED_VALUE,
                format!("`{value}` is not a Gateway API duration"),
            )
        })?;
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        if millis > 0 {
            timeouts.read = Some(Duration::from_millis(millis));
        }
    }
    let default_scheme = if spec.kind == RouteKind::Grpc {
        Scheme::H2c
    } else {
        Scheme::Http
    };
    let mut filters = rule.filters.clone();
    // Filters on a backendRef: only when that backend gets all of the rule's traffic.
    let with_traffic: Vec<&(BackendObjectReference, Option<i32>, Vec<HTTPRouteFilter>)> = rule
        .backends
        .iter()
        .filter(|(_, weight, _)| weight.unwrap_or(1) > 0)
        .collect();
    if rule.backends.iter().any(|(_, _, f)| !f.is_empty()) {
        let single = with_traffic.len() == 1 && !with_traffic[0].2.is_empty();
        let only_headers = rule.backends.iter().flat_map(|(_, _, f)| f).all(|f| {
            f.kind == filter_types::REQUEST_HEADER_MODIFIER
                || f.kind == filter_types::RESPONSE_HEADER_MODIFIER
        });
        if !single || !only_headers {
            return Err((
                reasons::UNSUPPORTED_VALUE,
                "filters on a backendRef are supported only for header modification on the rule's only backend with traffic".to_owned(),
            ));
        }
        filters.extend(with_traffic[0].2.iter().cloned());
    }
    let (filters, mirror_ref) = plan_filters(&filters, &rule.http_matches)?;
    let mut services: Vec<(String, Service)> = Vec::new();
    let mut mirror = None;
    if let Some((reference, percent)) = mirror_ref {
        match backend(cx, spec.kind, &spec.key.0, &reference, default_scheme) {
            Ok((name, service)) => {
                services.push((name.clone(), service));
                mirror = Some(Mirror {
                    service: name,
                    percent,
                });
            }
            Err(failure) => unresolved.push(failure),
        }
    }
    let service = plan_backends(
        cx,
        spec,
        index,
        rule,
        default_scheme,
        &mut services,
        unresolved,
    );
    Ok(RulePlan {
        index,
        matches,
        filters,
        service,
        services,
        mirror,
        timeouts,
    })
}

/// The service a rule sends to: one backend, a split, or the 500 service.
fn plan_backends(
    cx: &Context<'_>,
    spec: &RouteSpec<'_>,
    index: usize,
    rule: &RuleSpec<'_>,
    default_scheme: Scheme,
    services: &mut Vec<(String, Service)>,
    unresolved: &mut Vec<Failure>,
) -> String {
    let mut targets: Vec<(String, u32)> = Vec::new();
    for (reference, weight, _) in &rule.backends {
        let weight = u32::try_from(weight.unwrap_or(1)).unwrap_or(0);
        let target = match backend(cx, spec.kind, &spec.key.0, reference, default_scheme) {
            Ok((name, service)) => {
                if weight > 0 {
                    services.push((name.clone(), service));
                }
                name
            }
            Err(failure) => {
                unresolved.push(failure);
                INVALID_BACKEND_SERVICE.to_owned()
            }
        };
        if weight == 0 {
            continue;
        }
        match targets.iter_mut().find(|(name, _)| *name == target) {
            Some((_, total)) => *total = total.saturating_add(weight),
            None => targets.push((target, weight)),
        }
    }
    let service = match targets.len() {
        // No backend with traffic: 500, or never reached behind a redirect.
        0 => INVALID_BACKEND_SERVICE.to_owned(),
        1 => targets[0].0.clone(),
        _ => {
            let name = super::names::object_name(
                "split",
                &[&spec.key.0, &spec.key.1, &index.to_string()],
                &format!(
                    "split/{:?}/{}/{}/{index}",
                    spec.kind, spec.key.0, spec.key.1
                ),
            );
            services.push((name.clone(), backends::split(targets)));
            name
        }
    };
    if service == INVALID_BACKEND_SERVICE {
        services.push((service.clone(), backends::respond(500)));
    }
    service
}

/// Resolves a backend reference of a route to a fragment service.
fn backend(
    cx: &Context<'_>,
    route_kind: RouteKind,
    route_namespace: &str,
    reference: &BackendObjectReference,
    default_scheme: Scheme,
) -> Result<(String, Service), Failure> {
    let group = reference.group.as_deref().unwrap_or_default();
    let kind = reference.kind.as_deref().unwrap_or("Service");
    if !group.is_empty() || kind != "Service" {
        return Err((
            reasons::INVALID_KIND,
            format!(
                "backendRef `{}` is a `{kind}` in group `{group}`; only core Services are supported",
                reference.name
            ),
        ));
    }
    let namespace = reference.namespace.as_deref().unwrap_or(route_namespace);
    let permitted = super::grants::allowed(
        cx.inventory,
        super::grants::Referrer {
            group: crate::api::GROUP,
            kind: route_kind.as_str(),
            namespace: route_namespace,
        },
        super::grants::Target {
            group: "",
            kind: "Service",
            namespace,
            name: &reference.name,
        },
    );
    if !permitted {
        return Err((
            reasons::REF_NOT_PERMITTED,
            format!(
                "no ReferenceGrant in namespace `{namespace}` allows a {} from `{route_namespace}` to use Service `{}`",
                route_kind.as_str(),
                reference.name
            ),
        ));
    }
    let Some(port) = reference.port else {
        return Err((
            reasons::BACKEND_NOT_FOUND,
            format!("backendRef to Service `{}` has no port", reference.name),
        ));
    };
    let resolved = backends::resolve(
        cx.inventory,
        namespace,
        &reference.name,
        Some(PortRef::Number(port)),
        cx.settings.provider.gateway.allow_external_name,
    )
    .map_err(|e| match e {
        BackendError::ExternalNameNotAllowed { .. } => (reasons::INVALID_KIND, e.to_string()),
        _ => (reasons::BACKEND_NOT_FOUND, e.to_string()),
    })?;
    if let Some(diagnostic) = backends::refused_diagnostic(&resolved) {
        cx.note(diagnostic);
    }
    let scheme = backends::scheme(resolved.app_protocol.as_deref(), default_scheme);
    match super::policies::backend_tls(
        cx,
        namespace,
        &reference.name,
        resolved.port_name.as_deref(),
    ) {
        None => {}
        // A policy that cannot be honoured: the backend fails rather than going unverified.
        Some((_, Err(()))) => {
            return Ok((INVALID_BACKEND_SERVICE.to_owned(), backends::respond(500)));
        }
        Some((policy, Ok(tls))) => {
            let name = super::names::object_name(
                "svc",
                &[namespace, &reference.name, &port.to_string()],
                &format!(
                    "svc/{namespace}/{}/{port}/https/policy/{}/{}",
                    reference.name, policy.0, policy.1
                ),
            );
            let mut service = backends::http_service(resolved.targets.backends(), Scheme::Https);
            if service.respond.is_none() {
                service.tls = Some(tls);
            }
            return Ok((name, service));
        }
    }
    let name = service_name(namespace, &reference.name, port, scheme);
    Ok((
        name,
        backends::http_service(resolved.targets.backends(), scheme),
    ))
}

/// The fragment name of the service for port `port` of Service `namespace/name`.
#[must_use]
pub fn service_name(namespace: &str, name: &str, port: u16, scheme: Scheme) -> String {
    let scheme = match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
        Scheme::H2c => "h2c",
    };
    super::names::object_name(
        "svc",
        &[namespace, name, &port.to_string()],
        &format!("svc/{namespace}/{name}/{port}/{scheme}"),
    )
}

/// The match of a rule without matches: `PathPrefix /`.
fn default_match() -> MatchOut {
    MatchOut {
        conditions: vec![Expr::Matcher(Matcher::PathPrefix("/".to_owned()))],
        path_kind: PathKind::Prefix,
        path_len: 1,
        method: false,
        headers: 0,
        query: 0,
    }
}

/// RFC 9110 token, for header names.
fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

/// A full-match regular expression.
fn anchored(pattern: &str) -> String {
    format!("^(?:{pattern})$")
}

fn check_regex(pattern: &str) -> Result<(), String> {
    let rule = Expr::Matcher(Matcher::PathRegexp(pattern.to_owned()));
    let errors = rule.validate(rdock_rules::Context::Http);
    match errors.first() {
        None => Ok(()),
        Some(e) => Err(e.to_string()),
    }
}

/// The path part of an HTTPRoute match.
fn path_conditions(kind: &str, value: &str) -> Result<(Expr, PathKind, usize), String> {
    match kind {
        path_match::EXACT => {
            if !value.starts_with('/') {
                return Err(format!("path `{value}` must start with `/`"));
            }
            Ok((
                Expr::Matcher(Matcher::Path(value.to_owned())),
                PathKind::Exact,
                value.len(),
            ))
        }
        path_match::PATH_PREFIX => {
            if !value.starts_with('/') {
                return Err(format!("path `{value}` must start with `/`"));
            }
            Ok((prefix_expr(value), PathKind::Prefix, value.len()))
        }
        path_match::REGULAR_EXPRESSION => {
            let pattern = anchored(value);
            check_regex(&pattern)?;
            Ok((
                Expr::Matcher(Matcher::PathRegexp(pattern)),
                PathKind::Regex,
                value.len(),
            ))
        }
        other => Err(format!("path match type `{other}` is not supported")),
    }
}

/// A `PathPrefix` match by path segment: `/a` matches `/a`, `/a/` and `/a/b`, not `/ab`.
#[must_use]
pub fn prefix_expr(value: &str) -> Expr {
    let trimmed = value.trim_end_matches('/');
    if trimmed.is_empty() {
        return Expr::Matcher(Matcher::PathPrefix("/".to_owned()));
    }
    Expr::Or(vec![
        Expr::Matcher(Matcher::Path(trimmed.to_owned())),
        Expr::Matcher(Matcher::PathPrefix(format!("{trimmed}/"))),
    ])
}

/// A header condition.
fn header_condition(kind: Option<&str>, name: &str, value: &str) -> Result<Expr, String> {
    if !is_token(name) {
        return Err(format!("`{name}` is not a valid header name"));
    }
    match kind.unwrap_or(value_match::EXACT) {
        value_match::EXACT => Ok(Expr::Matcher(Matcher::Header {
            name: name.to_owned(),
            value: value.to_owned(),
        })),
        value_match::REGULAR_EXPRESSION => {
            let pattern = anchored(value);
            check_regex(&pattern)?;
            Ok(Expr::Matcher(Matcher::HeaderRegexp {
                name: name.to_owned(),
                regexp: pattern,
            }))
        }
        other => Err(format!("header match type `{other}` is not supported")),
    }
}

/// Translates an HTTPRoute match.
///
/// # Errors
///
/// An unsupported type or an invalid value, for the `UnsupportedValue` reason.
pub fn http_match(m: &HTTPRouteMatch) -> Result<MatchOut, String> {
    let kind = m
        .path
        .as_ref()
        .and_then(|p| p.kind.as_deref())
        .unwrap_or(path_match::PATH_PREFIX);
    let value = m
        .path
        .as_ref()
        .and_then(|p| p.value.as_deref())
        .unwrap_or("/");
    let (path, path_kind, path_len) = path_conditions(kind, value)?;
    let mut conditions = vec![path];
    if let Some(method) = &m.method {
        if !is_token(method) {
            return Err(format!("`{method}` is not a valid method"));
        }
        conditions.push(Expr::Matcher(Matcher::Method(method.to_ascii_uppercase())));
    }
    // Of entries with equivalent names only the first counts (header names compare without
    // case, query parameter names exactly), for matching and for precedence.
    let headers = first_of_each(&m.headers, |h| h.name.to_ascii_lowercase());
    let query_params = first_of_each(&m.query_params, |q| q.name.clone());
    for h in &headers {
        conditions.push(header_condition(h.kind.as_deref(), &h.name, &h.value)?);
    }
    for q in &query_params {
        if q.name.is_empty() {
            return Err("a query parameter match needs a name".to_owned());
        }
        let value = (!q.value.is_empty()).then(|| q.value.clone());
        conditions.push(match q.kind.as_deref().unwrap_or(value_match::EXACT) {
            value_match::EXACT => Expr::Matcher(Matcher::Query {
                key: q.name.clone(),
                value,
            }),
            value_match::REGULAR_EXPRESSION => {
                let pattern = anchored(&q.value);
                check_regex(&pattern)?;
                Expr::Matcher(Matcher::QueryRegexp {
                    key: q.name.clone(),
                    regexp: pattern,
                })
            }
            other => return Err(format!("query match type `{other}` is not supported")),
        });
    }
    Ok(MatchOut {
        conditions,
        path_kind,
        path_len,
        method: m.method.is_some(),
        headers: headers.len(),
        query: query_params.len(),
    })
}

/// The entries of `items` whose `key` was not seen before, in order.
fn first_of_each<T>(items: &[T], key: impl Fn(&T) -> String) -> Vec<&T> {
    let mut seen = std::collections::BTreeSet::new();
    items.iter().filter(|item| seen.insert(key(item))).collect()
}

/// Translates a GRPCRoute match.
///
/// # Errors
///
/// An unsupported type or an invalid value, for the `UnsupportedValue` reason.
pub fn grpc_match(m: &GRPCRouteMatch) -> Result<MatchOut, String> {
    let (path, path_kind, path_len) = match &m.method {
        None => (
            Expr::Matcher(Matcher::PathPrefix("/".to_owned())),
            PathKind::Prefix,
            0,
        ),
        Some(method) => {
            let service = method.service.as_deref().filter(|s| !s.is_empty());
            let name = method.method.as_deref().filter(|s| !s.is_empty());
            match method.kind.as_deref().unwrap_or(value_match::EXACT) {
                value_match::EXACT => match (service, name) {
                    (Some(s), Some(n)) => (
                        Expr::Matcher(Matcher::Path(format!("/{s}/{n}"))),
                        PathKind::Exact,
                        s.len() + n.len(),
                    ),
                    (Some(s), None) => (
                        Expr::Matcher(Matcher::PathPrefix(format!("/{s}/"))),
                        PathKind::Prefix,
                        s.len(),
                    ),
                    (None, Some(n)) => (
                        Expr::Matcher(Matcher::PathRegexp(format!("^/[^/]+/{}$", escape_regex(n)))),
                        PathKind::Regex,
                        n.len(),
                    ),
                    (None, None) => (
                        Expr::Matcher(Matcher::PathPrefix("/".to_owned())),
                        PathKind::Prefix,
                        0,
                    ),
                },
                value_match::REGULAR_EXPRESSION => {
                    let pattern = format!(
                        "^/(?:{})/(?:{})$",
                        service.unwrap_or("[^/]+"),
                        name.unwrap_or("[^/]+")
                    );
                    check_regex(&pattern)?;
                    (
                        Expr::Matcher(Matcher::PathRegexp(pattern)),
                        PathKind::Regex,
                        service.map_or(0, str::len) + name.map_or(0, str::len),
                    )
                }
                other => return Err(format!("method match type `{other}` is not supported")),
            }
        }
    };
    let mut conditions = vec![path];
    // Only the first of entries with equivalent (case-insensitive) names counts.
    let headers = first_of_each(&m.headers, |h| h.name.to_ascii_lowercase());
    for h in &headers {
        conditions.push(header_condition(h.kind.as_deref(), &h.name, &h.value)?);
    }
    Ok(MatchOut {
        conditions,
        path_kind,
        path_len,
        method: false,
        headers: headers.len(),
        query: 0,
    })
}

/// Header changes as `headers` rules: `set` replaces, `add` appends (several values of one
/// name are joined with `,`), `remove` removes.
fn header_rules(filter: &HTTPHeaderFilter) -> Result<HeaderRules, String> {
    let mut rules = HeaderRules::default();
    for h in filter.set.iter().chain(&filter.add) {
        if !is_token(&h.name) {
            return Err(format!("`{}` is not a valid header name", h.name));
        }
    }
    for h in &filter.set {
        rules.set.insert(h.name.clone(), h.value.clone());
    }
    for h in &filter.add {
        rules
            .add
            .entry(h.name.clone())
            .and_modify(|v| {
                v.push(',');
                v.push_str(&h.value);
            })
            .or_insert_with(|| h.value.clone());
    }
    rules.remove.clone_from(&filter.remove);
    Ok(rules)
}

/// The single `PathPrefix` value of a rule, for `ReplacePrefixMatch`.
fn single_prefix(matches: &[HTTPRouteMatch]) -> Result<String, Failure> {
    let unsupported = || {
        (
            reasons::UNSUPPORTED_VALUE,
            "ReplacePrefixMatch needs exactly one PathPrefix match".to_owned(),
        )
    };
    match matches {
        [] => Ok("/".to_owned()),
        [only] => {
            let kind = only
                .path
                .as_ref()
                .and_then(|p| p.kind.as_deref())
                .unwrap_or(path_match::PATH_PREFIX);
            if kind != path_match::PATH_PREFIX {
                return Err(unsupported());
            }
            Ok(only
                .path
                .as_ref()
                .and_then(|p| p.value.clone())
                .unwrap_or_else(|| "/".to_owned()))
        }
        _ => Err(unsupported()),
    }
}

/// The anchored `rewrite` that replaces path prefix `from` by `to`, by path segment, as the
/// table of `HTTPPathModifier.ReplacePrefixMatch`.
#[must_use]
pub fn prefix_rewrite(from: &str, to: &str) -> RewriteConfig {
    let from = from.trim_end_matches('/');
    let to = to.trim_end_matches('/').replace('$', "$$");
    RewriteConfig {
        regex: format!("^{}(/.*)?$", escape_regex(from)),
        replacement: format!("{to}${{1}}"),
    }
}

/// The filters of a rule: middlewares and redirects in order, and the mirror target.
#[allow(clippy::type_complexity)]
fn plan_filters(
    filters: &[HTTPRouteFilter],
    matches: &[HTTPRouteMatch],
) -> Result<(Vec<FilterPlan>, Option<(BackendObjectReference, u32)>), Failure> {
    let has = |kind: &str| filters.iter().any(|f| f.kind == kind);
    if has(filter_types::URL_REWRITE) && has(filter_types::REQUEST_REDIRECT) {
        return Err((
            reasons::INCOMPATIBLE_FILTERS,
            "URLRewrite and RequestRedirect cannot be combined".to_owned(),
        ));
    }
    let mut plans = Vec::new();
    let mut mirror = None;
    let mut mirrors = 0;
    for filter in filters {
        match plan_filter(filter, matches)? {
            Planned::Filters(more) => plans.extend(more),
            Planned::Mirror(target) => {
                mirrors += 1;
                if mirrors > 1 {
                    return Err((
                        reasons::UNSUPPORTED_VALUE,
                        "only one RequestMirror filter per rule is supported".to_owned(),
                    ));
                }
                mirror = target;
            }
        }
    }
    Ok((plans, mirror))
}

/// What one filter becomes.
enum Planned {
    /// Middlewares (possibly none).
    Filters(Vec<FilterPlan>),
    /// The mirror target and percentage (`None`: 0 %).
    Mirror(Option<(BackendObjectReference, u32)>),
}

/// Plans a `RequestRedirect` filter.
fn plan_redirect(
    f: &crate::api::HTTPRequestRedirectFilter,
    matches: &[HTTPRouteMatch],
) -> Result<FilterPlan, Failure> {
    let unsupported = |message: String| (reasons::UNSUPPORTED_VALUE, message);
    let scheme = match f.scheme.as_deref() {
        None => None,
        Some("http") => Some(RedirectScheme::Http),
        Some("https") => Some(RedirectScheme::Https),
        Some(other) => {
            return Err(unsupported(format!(
                "redirect scheme `{other}` is not supported"
            )));
        }
    };
    let status = f.status_code.unwrap_or(302);
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return Err(unsupported(format!(
            "redirect status {status} is not supported"
        )));
    }
    let (path, prefix) = match &f.path {
        None => (None, None),
        Some(m) => match m.kind.as_str() {
            path_modifier::REPLACE_FULL_PATH => (
                Some(
                    m.replace_full_path
                        .clone()
                        .unwrap_or_else(|| "/".to_owned()),
                ),
                None,
            ),
            path_modifier::REPLACE_PREFIX_MATCH => (
                None,
                Some(RedirectPrefix {
                    from: single_prefix(matches)?,
                    to: m.replace_prefix_match.clone().unwrap_or_default(),
                }),
            ),
            other => {
                return Err(unsupported(format!(
                    "path modifier `{other}` is not supported"
                )));
            }
        },
    };
    Ok(FilterPlan::Redirect(RedirectConfig {
        scheme,
        hostname: f.hostname.clone(),
        path,
        prefix,
        regex: None,
        replacement: None,
        permanent: false,
        status: Some(status),
        port: f.port,
        // The specification redirects whatever the request's scheme.
        always: true,
    }))
}

/// Plans a `URLRewrite` filter.
fn plan_rewrite(
    f: &crate::api::HTTPURLRewriteFilter,
    matches: &[HTTPRouteMatch],
) -> Result<Vec<FilterPlan>, Failure> {
    let unsupported = |message: String| (reasons::UNSUPPORTED_VALUE, message);
    let mut out = Vec::new();
    if let Some(host) = &f.hostname {
        let mut request = HeaderRules::default();
        request.set.insert("Host".to_owned(), host.clone());
        out.push(FilterPlan::Middleware(Middleware::Headers(HeadersConfig {
            request,
            ..HeadersConfig::default()
        })));
    }
    if let Some(m) = &f.path {
        match m.kind.as_str() {
            path_modifier::REPLACE_FULL_PATH => {
                out.push(FilterPlan::Middleware(Middleware::ReplacePath(
                    ReplacePathConfig {
                        path: m
                            .replace_full_path
                            .clone()
                            .unwrap_or_else(|| "/".to_owned()),
                    },
                )));
            }
            path_modifier::REPLACE_PREFIX_MATCH => {
                let from = single_prefix(matches)?;
                let to = m.replace_prefix_match.clone().unwrap_or_default();
                out.push(FilterPlan::Middleware(Middleware::Rewrite(prefix_rewrite(
                    &from, &to,
                ))));
            }
            other => {
                return Err(unsupported(format!(
                    "path modifier `{other}` is not supported"
                )));
            }
        }
    }
    Ok(out)
}

/// Plans one filter.
fn plan_filter(filter: &HTTPRouteFilter, matches: &[HTTPRouteMatch]) -> Result<Planned, Failure> {
    let unsupported = |message: String| (reasons::UNSUPPORTED_VALUE, message);
    let missing = |kind: &str| unsupported(format!("filter `{kind}` has no settings"));
    let mut out = Vec::new();
    match filter.kind.as_str() {
        filter_types::REQUEST_HEADER_MODIFIER => {
            let f = filter
                .request_header_modifier
                .as_ref()
                .ok_or_else(|| missing(&filter.kind))?;
            out.push(FilterPlan::Middleware(Middleware::Headers(HeadersConfig {
                request: header_rules(f).map_err(unsupported)?,
                ..HeadersConfig::default()
            })));
        }
        filter_types::RESPONSE_HEADER_MODIFIER => {
            let f = filter
                .response_header_modifier
                .as_ref()
                .ok_or_else(|| missing(&filter.kind))?;
            out.push(FilterPlan::Middleware(Middleware::Headers(HeadersConfig {
                response: header_rules(f).map_err(unsupported)?,
                ..HeadersConfig::default()
            })));
        }
        filter_types::REQUEST_REDIRECT => {
            let f = filter
                .request_redirect
                .as_ref()
                .ok_or_else(|| missing(&filter.kind))?;
            out.push(plan_redirect(f, matches)?);
        }
        filter_types::URL_REWRITE => {
            let f = filter
                .url_rewrite
                .as_ref()
                .ok_or_else(|| missing(&filter.kind))?;
            out.extend(plan_rewrite(f, matches)?);
        }
        filter_types::REQUEST_MIRROR => {
            let f = filter
                .request_mirror
                .as_ref()
                .ok_or_else(|| missing(&filter.kind))?;
            let percent = match (&f.percent, &f.fraction) {
                (Some(p), _) => u32::try_from(*p).unwrap_or(0).min(100),
                (None, Some(fraction)) => {
                    let denominator = i64::from(fraction.denominator.unwrap_or(100).max(1));
                    let numerator = i64::from(fraction.numerator.max(0));
                    let percent = (numerator * 100 + denominator - 1) / denominator;
                    u32::try_from(percent.min(100)).unwrap_or(100)
                }
                (None, None) => 100,
            };
            return Ok(Planned::Mirror(
                (percent > 0).then(|| (f.backend_ref.clone(), percent)),
            ));
        }
        filter_types::CORS | filter_types::EXTERNAL_AUTH | filter_types::EXTENSION_REF => {
            return Err(unsupported(format!(
                "filter `{}` is not supported",
                filter.kind
            )));
        }
        other => return Err(unsupported(format!("filter type `{other}` is unknown"))),
    }
    Ok(Planned::Filters(out))
}

/// Registers the middlewares of a rule for a listener on `listener_port` and returns their
/// names (content-addressed, so one middleware serves every listener it is equal on).
fn emit_middlewares(
    cx: &mut Context<'_>,
    spec: &RouteSpec<'_>,
    plan: &RulePlan,
    listener_port: u16,
) -> Vec<String> {
    plan.filters
        .iter()
        .enumerate()
        .map(|(i, filter)| {
            let middleware = match filter {
                FilterPlan::Middleware(m) => m.clone(),
                FilterPlan::Redirect(r) => {
                    let mut r = r.clone();
                    if r.scheme.is_none() && r.port.is_none() {
                        r.port = Some(listener_port);
                    }
                    Middleware::Redirect(r)
                }
            };
            let content = serde_json::to_string(&middleware).unwrap_or_default();
            let name = super::names::object_name(
                "mw",
                &[&spec.key.0, &spec.key.1, &format!("r{}f{i}", plan.index)],
                &format!(
                    "mw/{:?}/{}/{}/{}/{i}/{content}",
                    spec.kind, spec.key.0, spec.key.1, plan.index
                ),
            );
            cx.out.fragment.middlewares.insert(name.clone(), middleware);
            name
        })
        .collect()
}

/// Emits the routes of every valid rule on one internal listener.
fn emit(
    cx: &mut Context<'_>,
    spec: &RouteSpec<'_>,
    plans: &[RulePlan],
    internal: &str,
    listener_port: u16,
    hosts: &Intersection,
) {
    // Host names of equal precedence share a route.
    let mut groups: BTreeMap<(usize, usize), Vec<String>> = BTreeMap::new();
    match hosts {
        Intersection::Any | Intersection::Empty => {
            groups.insert((0, 0), Vec::new());
        }
        Intersection::Hosts(list) => {
            for host in list {
                groups
                    .entry(specificity(Some(host)))
                    .or_default()
                    .push(host.clone());
            }
        }
    }
    let prefix = if spec.kind == RouteKind::Grpc {
        "grpc"
    } else {
        "http"
    };
    for plan in plans {
        for (name, service) in &plan.services {
            cx.out
                .fragment
                .services
                .entry(name.clone())
                .or_insert_with(|| service.clone());
        }
        let middlewares = emit_middlewares(cx, spec, plan, listener_port);
        for (m, matched) in plan.matches.iter().enumerate() {
            for (host_key, group) in &groups {
                let mut conditions = Vec::new();
                match group.len() {
                    0 => {}
                    1 => conditions.push(Expr::Matcher(http_matcher(&group[0]))),
                    _ => conditions.push(Expr::Or(
                        group
                            .iter()
                            .map(|h| Expr::Matcher(http_matcher(h)))
                            .collect(),
                    )),
                }
                conditions.extend(matched.conditions.iter().cloned());
                let expr = if conditions.len() == 1 {
                    conditions.remove(0)
                } else {
                    Expr::And(conditions)
                };
                let precedence = Precedence {
                    host: *host_key,
                    path_kind: matched.path_kind,
                    path_len: matched.path_len,
                    method: matched.method,
                    headers: matched.headers,
                    query: matched.query,
                    route_rank: spec.rank,
                    rule: plan.index,
                };
                let name = super::names::object_name(
                    prefix,
                    &[&spec.key.0, &spec.key.1, &format!("r{}m{m}", plan.index)],
                    &format!(
                        "route/{:?}/{}/{}/{}/{m}/{internal}/{}",
                        spec.kind,
                        spec.key.0,
                        spec.key.1,
                        plan.index,
                        group.join(",")
                    ),
                );
                cx.out.fragment.routes.insert(
                    name,
                    Route {
                        matcher: MatchSpec::Rule(expr.to_string()),
                        listeners: Some(vec![internal.to_owned()]),
                        priority: precedence.priority(),
                        middlewares: middlewares.clone(),
                        service: Some(plan.service.clone()),
                        tls: Some(RouteTls::Mode(TlsMode::Off)),
                        timeouts: plan.timeouts,
                        mirror: plan.mirror.clone(),
                        max_body: None,
                        enabled: true,
                    },
                );
            }
        }
    }
}

/// The `kind` value of a route kind, for messages.
#[must_use]
pub fn kind_name(kind: RouteKind) -> &'static str {
    match kind {
        RouteKind::Http => kinds::HTTP_ROUTE,
        RouteKind::Grpc => kinds::GRPC_ROUTE,
        RouteKind::Tls => kinds::TLS_ROUTE,
        RouteKind::Tcp => kinds::TCP_ROUTE,
        RouteKind::Udp => kinds::UDP_ROUTE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{GRPCMethodMatch, HTTPHeaderMatch, HTTPPathMatch, HTTPQueryParamMatch};

    fn path(kind: &str, value: &str) -> HTTPRouteMatch {
        HTTPRouteMatch {
            path: Some(HTTPPathMatch {
                kind: Some(kind.to_owned()),
                value: Some(value.to_owned()),
            }),
            ..HTTPRouteMatch::default()
        }
    }

    fn rule(m: &MatchOut) -> String {
        Expr::And(m.conditions.clone()).to_string()
    }

    #[test]
    fn prefixes_match_by_segment() {
        assert_eq!(prefix_expr("/").to_string(), "PathPrefix(`/`)");
        assert_eq!(prefix_expr("///").to_string(), "PathPrefix(`/`)");
        assert_eq!(
            prefix_expr("/v2").to_string(),
            "Path(`/v2`) || PathPrefix(`/v2/`)"
        );
        assert_eq!(
            prefix_expr("/match/prefix/").to_string(),
            "Path(`/match/prefix`) || PathPrefix(`/match/prefix/`)"
        );
    }

    #[test]
    fn http_matches() {
        let m = http_match(&HTTPRouteMatch {
            method: Some("get".into()),
            headers: vec![HTTPHeaderMatch {
                kind: None,
                name: "Version".into(),
                value: "two".into(),
            }],
            query_params: vec![
                HTTPQueryParamMatch {
                    kind: Some("RegularExpression".into()),
                    name: "id".into(),
                    value: "[0-9]+".into(),
                },
                HTTPQueryParamMatch {
                    kind: None,
                    name: "flag".into(),
                    value: String::new(),
                },
            ],
            ..path("Exact", "/one")
        })
        .unwrap();
        assert_eq!(
            rule(&m),
            "Path(`/one`) && Method(`GET`) && Header(`Version`, `two`) && QueryRegexp(`id`, `^(?:[0-9]+)$`) && Query(`flag`)"
        );
        assert_eq!(
            (m.path_kind, m.path_len, m.method, m.headers, m.query),
            (PathKind::Exact, 4, true, 1, 2)
        );
        let regex = http_match(&path("RegularExpression", "/v[0-9]+/.*")).unwrap();
        assert_eq!(rule(&regex), "PathRegexp(`^(?:/v[0-9]+/.*)$`)");
        assert!(http_match(&path("Bogus", "/")).is_err());
        assert!(http_match(&path("Exact", "no-slash")).is_err());
        assert!(http_match(&path("RegularExpression", "(")).is_err());
        let bad_header = HTTPRouteMatch {
            headers: vec![HTTPHeaderMatch {
                kind: None,
                name: "bad header".into(),
                value: "x".into(),
            }],
            ..HTTPRouteMatch::default()
        };
        assert!(http_match(&bad_header).is_err());
        // A value with a backtick still makes a rule that parses back.
        let tricky = HTTPRouteMatch {
            headers: vec![HTTPHeaderMatch {
                kind: None,
                name: "x".into(),
                value: "a`b\"c".into(),
            }],
            ..HTTPRouteMatch::default()
        };
        let text = rule(&http_match(&tricky).unwrap());
        assert_eq!(rdock_rules::parse(&text).unwrap().to_string(), text);
    }

    #[test]
    fn only_the_first_of_equivalent_header_and_query_names_counts() {
        let header = |name: &str, value: &str| HTTPHeaderMatch {
            kind: None,
            name: name.into(),
            value: value.into(),
        };
        let query = |name: &str, value: &str| HTTPQueryParamMatch {
            kind: None,
            name: name.into(),
            value: value.into(),
        };
        let m = http_match(&HTTPRouteMatch {
            headers: vec![
                header("Version", "one"),
                header("version", "two"),
                header("Other", "x"),
            ],
            query_params: vec![query("a", "1"), query("a", "2"), query("A", "3")],
            ..path("PathPrefix", "/")
        })
        .unwrap();
        assert_eq!(
            rule(&m),
            "PathPrefix(`/`) && Header(`Version`, `one`) && Header(`Other`, `x`) && Query(`a`, `1`) && Query(`A`, `3`)"
        );
        assert_eq!((m.headers, m.query), (2, 2));
        let g = grpc_match(&GRPCRouteMatch {
            method: None,
            headers: vec![
                crate::api::GRPCHeaderMatch {
                    kind: None,
                    name: "Version".into(),
                    value: "one".into(),
                },
                crate::api::GRPCHeaderMatch {
                    kind: None,
                    name: "VERSION".into(),
                    value: "two".into(),
                },
            ],
        })
        .unwrap();
        assert_eq!(rule(&g), "PathPrefix(`/`) && Header(`Version`, `one`)");
        assert_eq!(g.headers, 1);
    }

    #[test]
    fn grpc_method_forms() {
        let method = |kind: Option<&str>, service: Option<&str>, name: Option<&str>| {
            let m = grpc_match(&GRPCRouteMatch {
                method: Some(GRPCMethodMatch {
                    kind: kind.map(str::to_owned),
                    service: service.map(str::to_owned),
                    method: name.map(str::to_owned),
                }),
                headers: Vec::new(),
            })
            .unwrap();
            (rule(&m), m.path_kind)
        };
        assert_eq!(
            method(None, Some("pkg.Svc"), Some("Echo")),
            ("Path(`/pkg.Svc/Echo`)".to_owned(), PathKind::Exact)
        );
        assert_eq!(
            method(None, Some("pkg.Svc"), None),
            ("PathPrefix(`/pkg.Svc/`)".to_owned(), PathKind::Prefix)
        );
        assert_eq!(
            method(None, None, Some("Echo")),
            (r"PathRegexp(`^/[^/]+/Echo$`)".to_owned(), PathKind::Regex)
        );
        assert_eq!(
            method(Some("RegularExpression"), Some(r"pkg\..*"), None),
            (
                r"PathRegexp(`^/(?:pkg\..*)/(?:[^/]+)$`)".to_owned(),
                PathKind::Regex
            )
        );
        let all = grpc_match(&GRPCRouteMatch::default()).unwrap();
        assert_eq!(rule(&all), "PathPrefix(`/`)");
    }

    #[test]
    fn prefix_rewrites_follow_the_specification_table() {
        // (request path, prefix match, replacement, modified path) from
        // `HTTPPathModifier.ReplacePrefixMatch`.
        let table = [
            ("/foo/bar", "/foo", "/xyz", "/xyz/bar"),
            ("/foo/bar", "/foo", "/xyz/", "/xyz/bar"),
            ("/foo/bar", "/foo/", "/xyz", "/xyz/bar"),
            ("/foo/bar", "/foo/", "/xyz/", "/xyz/bar"),
            ("/foo", "/foo", "/xyz", "/xyz"),
            ("/foo/", "/foo", "/xyz", "/xyz/"),
            ("/foo/bar", "/foo", "", "/bar"),
            ("/foo/", "/foo", "", "/"),
            ("/foo", "/foo", "", "/"),
            ("/foo/", "/foo", "/", "/"),
            ("/foo", "/foo", "/", "/"),
        ];
        for (request, from, to, expected) in table {
            let config = prefix_rewrite(from, to);
            let regex = regex_lite(&config.regex);
            let rewritten = regex.replace_all(request, config.replacement.as_str());
            // The middleware turns an empty result into `/`.
            let rewritten = if rewritten.is_empty() {
                "/".to_owned()
            } else {
                rewritten.into_owned()
            };
            assert_eq!(rewritten, expected, "{request} {from} {to}");
        }
    }

    fn regex_lite(pattern: &str) -> regex::Regex {
        regex::Regex::new(pattern).unwrap()
    }

    #[test]
    fn header_modifiers_and_filter_errors() {
        let f = HTTPHeaderFilter {
            set: vec![crate::api::HTTPHeader {
                name: "X-Set".into(),
                value: "1".into(),
            }],
            add: vec![
                crate::api::HTTPHeader {
                    name: "X-Add".into(),
                    value: "a".into(),
                },
                crate::api::HTTPHeader {
                    name: "X-Add".into(),
                    value: "b".into(),
                },
            ],
            remove: vec!["X-Gone".into()],
        };
        let rules = header_rules(&f).unwrap();
        assert_eq!(rules.set["X-Set"], "1");
        assert_eq!(rules.add["X-Add"], "a,b");
        assert_eq!(rules.remove, vec!["X-Gone".to_owned()]);

        let filter = |kind: &str| HTTPRouteFilter {
            kind: kind.to_owned(),
            ..HTTPRouteFilter::default()
        };
        // Missing settings, unsupported and incompatible filters.
        assert!(plan_filters(&[filter("RequestHeaderModifier")], &[]).is_err());
        assert_eq!(
            plan_filters(&[filter("ExtensionRef")], &[]).unwrap_err().0,
            reasons::UNSUPPORTED_VALUE
        );
        let rewrite = HTTPRouteFilter {
            url_rewrite: Some(crate::api::HTTPURLRewriteFilter::default()),
            ..filter("URLRewrite")
        };
        let redirect = HTTPRouteFilter {
            request_redirect: Some(crate::api::HTTPRequestRedirectFilter::default()),
            ..filter("RequestRedirect")
        };
        assert_eq!(
            plan_filters(&[rewrite, redirect.clone()], &[])
                .unwrap_err()
                .0,
            reasons::INCOMPATIBLE_FILTERS
        );
        // A redirect defaults to 302.
        let (plans, _) = plan_filters(&[redirect], &[]).unwrap();
        assert!(matches!(&plans[0], FilterPlan::Redirect(r) if r.status == Some(302)));
        // Two mirrors.
        let mirror = HTTPRouteFilter {
            request_mirror: Some(crate::api::HTTPRequestMirrorFilter {
                fraction: Some(crate::api::Fraction {
                    numerator: 1,
                    denominator: Some(3),
                }),
                ..crate::api::HTTPRequestMirrorFilter::default()
            }),
            ..filter("RequestMirror")
        };
        let (_, m) = plan_filters(std::slice::from_ref(&mirror), &[]).unwrap();
        assert_eq!(m.unwrap().1, 34);
        assert!(plan_filters(&[mirror.clone(), mirror], &[]).is_err());
    }
}
