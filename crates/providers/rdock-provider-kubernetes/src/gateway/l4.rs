//! TLSRoute, TCPRoute and UDPRoute (`tlsroute_types.go`, `tcproute_types.go`,
//! `udproute_types.go`).
//!
//! - **TLSRoute** attaches to `TLS` listeners in `Passthrough` mode. Per internal listener it
//!   becomes one TCP route matching the intersected host names by SNI (``HostSNI(`a`)``,
//!   wildcards as `HostSNIRegexp`) with `tls.passthrough`, on the port's `tcp` listener (or
//!   its `https` listener when HTTPS listeners share the port). Exact names beat wildcards,
//!   longer names shorter ones, then older routes ([`super::priority`]).
//! - **TCPRoute** attaches to `TCP` listeners and becomes ``HostSNI(`*`)`` on the port's
//!   `tcp` listener; when several attach to one listener, the oldest wins.
//! - **UDPRoute** has no listener to attach to (UDP listeners are not supported until
//!   v0.8): its parentRefs to our Gateways are `Accepted=False/NotAllowedByListeners` (or
//!   `NoMatchingParent`).
//!
//! The backends of every rule are pooled into one TCP service (the model has no weighted TCP
//! split): each endpoint of a `backendRef` gets that reference's weight multiplied by 1000
//! and divided by the reference's number of endpoints, so each Service receives about its
//! weighted share whatever its size. A backend reference that cannot be resolved makes
//! `ResolvedRefs=False` and contributes nothing; a route with no usable endpoint at all gets
//! no TCP route, so its connections are refused, as the conformance tests expect.

use std::collections::BTreeMap;

use rdock_model::route::{TcpRoute, TcpRouteTls};
use rdock_model::service::Backend;
use rdock_rules::{Expr, Matcher};

use super::attach::{Parent, RouteInfo};
use super::conditions::{condition, reasons, types};
use super::hostnames::{Intersection, sni_matcher, specificity};
use super::listeners::{Failure, Protocol};
use super::priority::{PathKind, Precedence};
use super::{Context, object_id};
use crate::api::{BackendRef, L4RouteRule, ParentReference};
use crate::backends::{self, BackendError, PortRef};
use crate::inventory::ObjectKey;
use crate::translate::{DesiredRouteParent, RouteKind, RouteRef};

/// Translates every TLSRoute, TCPRoute and UDPRoute.
pub fn translate(cx: &mut Context<'_>, ranks: &BTreeMap<(RouteKind, ObjectKey), usize>) {
    let inventory = cx.inventory;
    for (key, route) in &inventory.tls_routes {
        let rank = ranks.get(&(RouteKind::Tls, key.clone())).copied();
        translate_route(
            cx,
            &L4Spec {
                kind: RouteKind::Tls,
                key,
                generation: route.metadata.generation,
                parent_refs: &route.spec.parent_refs,
                hostnames: &route.spec.hostnames,
                rules: &route.spec.rules,
                rank: rank.unwrap_or(usize::MAX),
            },
        );
    }
    for (key, route) in &inventory.tcp_routes {
        let rank = ranks.get(&(RouteKind::Tcp, key.clone())).copied();
        translate_route(
            cx,
            &L4Spec {
                kind: RouteKind::Tcp,
                key,
                generation: route.metadata.generation,
                parent_refs: &route.spec.parent_refs,
                hostnames: &[],
                rules: &route.spec.rules,
                rank: rank.unwrap_or(usize::MAX),
            },
        );
    }
    for (key, route) in &inventory.udp_routes {
        translate_route(
            cx,
            &L4Spec {
                kind: RouteKind::Udp,
                key,
                generation: route.metadata.generation,
                parent_refs: &route.spec.parent_refs,
                hostnames: &[],
                rules: &route.spec.rules,
                rank: usize::MAX,
            },
        );
    }
}

struct L4Spec<'a> {
    kind: RouteKind,
    key: &'a ObjectKey,
    generation: Option<i64>,
    parent_refs: &'a [ParentReference],
    hostnames: &'a [String],
    rules: &'a [L4RouteRule],
    rank: usize,
}

fn translate_route(cx: &mut Context<'_>, spec: &L4Spec<'_>) {
    let (namespace, name) = (&spec.key.0, &spec.key.1);
    let id = object_id(spec.kind.as_str(), namespace, name);
    let mut unresolved: Vec<Failure> = Vec::new();
    let mut pool: Vec<Backend> = Vec::new();
    for rule in spec.rules {
        for reference in &rule.backend_refs {
            match backend(cx, spec.kind, namespace, reference) {
                Ok(backends) => pool.extend(backends),
                Err(failure) => unresolved.push(failure),
            }
        }
    }
    for (_, message) in &unresolved {
        cx.warn(&id, ".spec.rules", message.clone());
    }
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
    // Internal listener → (whether it is an https listener, host names).
    let mut targets: BTreeMap<String, (bool, Intersection)> = BTreeMap::new();
    for parent_ref in spec.parent_refs {
        let accepted = match super::attach::resolve(cx, &info, parent_ref) {
            Parent::NotOurs => continue,
            Parent::Rejected(failure) => Err(failure),
            Parent::Accepted { gateway, listeners } => {
                for (index, hosts) in listeners {
                    let gw = &cx.gateways[gateway];
                    let https_port = gw.listeners.iter().any(|l| {
                        l.port == gw.listeners[index].port
                            && l.protocol == Protocol::Https
                            && l.internal.is_some()
                    });
                    let listener = &mut cx.gateways[gateway].listeners[index];
                    listener.attached.insert(route_ref.clone());
                    if let Some(internal) = &listener.internal {
                        let entry = targets
                            .entry(internal.clone())
                            .or_insert((https_port, Intersection::Empty));
                        entry.1 = merge(&entry.1, &hosts);
                    }
                }
                Ok(())
            }
        };
        if let Err((_, message)) = &accepted {
            cx.warn(
                &id,
                ".spec.parentRefs",
                format!(
                    "not accepted by {} `{}`: {message}",
                    parent_ref.kind.as_deref().unwrap_or("Gateway"),
                    parent_ref.name
                ),
            );
        }
        parents.push(parent_status(
            parent_ref,
            spec.generation,
            &accepted,
            unresolved.first(),
        ));
    }
    if !parents.is_empty() {
        cx.out.status.routes.insert(route_ref, parents);
    }
    if targets.is_empty() {
        return;
    }
    if pool.is_empty() {
        cx.warn(
            &id,
            "",
            "no backend has a usable endpoint; connections are refused",
        );
        return;
    }
    let service_name = super::names::object_name(
        "tcp",
        &[namespace, name],
        &format!("tcpsvc/{:?}/{namespace}/{name}", spec.kind),
    );
    cx.out
        .fragment
        .tcp_services
        .insert(service_name.clone(), backends::tcp_service(pool));
    for (internal, (https, hosts)) in targets {
        emit(cx, spec, &id, &internal, https, &hosts, &service_name);
    }
}

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

fn emit(
    cx: &mut Context<'_>,
    spec: &L4Spec<'_>,
    id: &str,
    internal: &str,
    https: bool,
    hosts: &Intersection,
    service: &str,
) {
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
    let passthrough = spec.kind == RouteKind::Tls;
    for (host_key, group) in groups {
        let expr = match group.len() {
            0 => Expr::Matcher(Matcher::HostSni("*".to_owned())),
            1 => Expr::Matcher(sni_matcher(&group[0])),
            _ => Expr::Or(
                group
                    .iter()
                    .map(|h| Expr::Matcher(sni_matcher(h)))
                    .collect(),
            ),
        };
        if https && group.is_empty() {
            cx.warn(
                id,
                "",
                "a TLSRoute without host names cannot share a port with HTTPS listeners; it is left out there",
            );
            continue;
        }
        let precedence = Precedence {
            host: host_key,
            path_kind: PathKind::Prefix,
            path_len: 0,
            method: false,
            headers: 0,
            query: 0,
            route_rank: spec.rank,
            rule: 0,
        };
        let name = super::names::object_name(
            if passthrough { "tls" } else { "tcp" },
            &[&spec.key.0, &spec.key.1],
            &format!(
                "l4/{:?}/{}/{}/{internal}/{}",
                spec.kind,
                spec.key.0,
                spec.key.1,
                group.join(",")
            ),
        );
        cx.out.fragment.tcp_routes.insert(
            name,
            TcpRoute {
                matcher: expr.to_string(),
                listeners: Some(vec![internal.to_owned()]),
                priority: precedence.priority(),
                service: service.to_owned(),
                tls: passthrough.then_some(TcpRouteTls { passthrough: true }),
                middlewares: Vec::new(),
            },
        );
    }
}

/// The weighted endpoints of a backend reference of an L4 route.
fn backend(
    cx: &Context<'_>,
    kind: RouteKind,
    route_namespace: &str,
    reference: &BackendRef,
) -> Result<Vec<Backend>, Failure> {
    let r = &reference.reference;
    let group = r.group.as_deref().unwrap_or_default();
    let object_kind = r.kind.as_deref().unwrap_or("Service");
    if !group.is_empty() || object_kind != "Service" {
        return Err((
            reasons::INVALID_KIND,
            format!(
                "backendRef `{}` is a `{object_kind}` in group `{group}`; only core Services are supported",
                r.name
            ),
        ));
    }
    let namespace = r.namespace.as_deref().unwrap_or(route_namespace);
    let permitted = super::grants::allowed(
        cx.inventory,
        super::grants::Referrer {
            group: crate::api::GROUP,
            kind: kind.as_str(),
            namespace: route_namespace,
        },
        super::grants::Target {
            group: "",
            kind: "Service",
            namespace,
            name: &r.name,
        },
    );
    if !permitted {
        return Err((
            reasons::REF_NOT_PERMITTED,
            format!(
                "no ReferenceGrant in namespace `{namespace}` allows a {} from `{route_namespace}` to use Service `{}`",
                kind.as_str(),
                r.name
            ),
        ));
    }
    let Some(port) = r.port else {
        return Err((
            reasons::BACKEND_NOT_FOUND,
            format!("backendRef to Service `{}` has no port", r.name),
        ));
    };
    let resolved = backends::resolve(
        cx.inventory,
        namespace,
        &r.name,
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
    let weight = u32::try_from(reference.weight.unwrap_or(1)).unwrap_or(0);
    let mut backends = resolved.targets.backends();
    if weight == 0 {
        return Ok(Vec::new());
    }
    let count = u32::try_from(backends.len().max(1)).unwrap_or(u32::MAX);
    let each = (weight.saturating_mul(1000) / count).max(1);
    for b in &mut backends {
        b.weight = each;
    }
    Ok(backends)
}

fn parent_status(
    parent_ref: &ParentReference,
    generation: Option<i64>,
    accepted: &Result<(), Failure>,
    unresolved: Option<&Failure>,
) -> DesiredRouteParent {
    let accepted = match accepted {
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
    };
    let resolved = match unresolved {
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
    };
    DesiredRouteParent {
        parent_ref: parent_ref.clone(),
        conditions: vec![accepted, resolved],
    }
}
