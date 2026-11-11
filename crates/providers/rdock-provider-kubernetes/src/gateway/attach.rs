//! Route attachment (`shared_types.go`, `ParentReference` and `RouteConditionReason`).
//!
//! A parentRef is ours when it names a Gateway (group `gateway.networking.k8s.io`, kind
//! `Gateway`, both the defaults) that exists and belongs to a GatewayClass of ours, or a
//! ListenerSet (kind `ListenerSet`) whose parent is such a Gateway; any other parentRef gets
//! no `status.parents` entry from this controller (it may be another controller's). For a
//! Gateway, the candidate listeners are its own (not those of its ListenerSets); for a
//! ListenerSet, its own listeners, and a ListenerSet that is not accepted refuses the route
//! with `NotAllowedByListeners`. Of those, the candidates are the listeners named by
//! `sectionName` and on `port` (when set); then, in this order, the first check that leaves
//! no listener decides the `Accepted=False` reason:
//!
//! 1. no candidate: `NoMatchingParent`;
//! 2. no candidate that is accepted, unconflicted and allows the route's kind and namespace
//!    (`allowedRoutes`, where `Same` is the namespace of the listener's Gateway or
//!    ListenerSet): `NotAllowedByListeners`;
//! 3. no candidate whose host name intersects the route's: `NoMatchingListenerHostname`.
//!
//! Otherwise the route is accepted on every listener that passed, with the intersected host
//! names of each ([`super::hostnames::intersect`]). Attachment does not depend on the
//! listener's references resolving: a route attaches to an HTTPS listener whose certificate
//! is missing (and counts in its `attachedRoutes`), it is just not served there.

use super::Context;
use super::conditions::reasons;
use super::hostnames::{Intersection, intersect};
use super::listeners::{Failure, ListenerState, Namespaces};
use crate::api::{GROUP, ParentReference, kinds};
use crate::translate::RouteKind;

/// The route being attached.
#[derive(Debug, Clone, Copy)]
pub struct RouteInfo<'a> {
    /// Kind.
    pub kind: RouteKind,
    /// Namespace.
    pub namespace: &'a str,
    /// Name.
    pub name: &'a str,
    /// Host names (none for TCP and UDP routes).
    pub hostnames: &'a [String],
}

/// What a parentRef resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parent {
    /// Not a Gateway of ours: no status entry.
    NotOurs,
    /// Ours, not accepted.
    Rejected(Failure),
    /// Accepted on these listeners of `gateway` (an index into the context's Gateways).
    Accepted {
        /// The Gateway.
        gateway: usize,
        /// Listener index and the host names served there.
        listeners: Vec<(usize, Intersection)>,
    },
}

/// Resolves `parent` of `route`.
#[must_use]
pub fn resolve(cx: &Context<'_>, route: &RouteInfo<'_>, parent: &ParentReference) -> Parent {
    let group = parent.group.as_deref().unwrap_or(GROUP);
    let kind = parent.kind.as_deref().unwrap_or(kinds::GATEWAY);
    let namespace = parent.namespace.as_deref().unwrap_or(route.namespace);
    if group != GROUP {
        return Parent::NotOurs;
    }
    let key = (namespace.to_owned(), parent.name.clone());
    if kind == kinds::LISTENER_SET {
        let Some(&set) = cx.listener_set_index.get(&key) else {
            return Parent::NotOurs;
        };
        let state = &cx.listener_sets[set];
        if let Err((_, message)) = &state.accepted {
            return Parent::Rejected((
                reasons::NOT_ALLOWED_BY_LISTENERS,
                format!("the ListenerSet is not accepted: {message}"),
            ));
        }
        return attach(cx, route, parent, state.gateway, Some(set), &state.key.0);
    }
    if kind != kinds::GATEWAY {
        return Parent::NotOurs;
    }
    let Some(&index) = cx.gateway_index.get(&key) else {
        return Parent::NotOurs;
    };
    attach(cx, route, parent, index, None, namespace)
}

/// Attaches `route` to the listeners of Gateway `index` that belong to ListenerSet `set`
/// (the Gateway's own listeners when `None`); `home` is the namespace of that Gateway or
/// ListenerSet, the one `allowedRoutes` `Same` means.
fn attach(
    cx: &Context<'_>,
    route: &RouteInfo<'_>,
    parent: &ParentReference,
    index: usize,
    set: Option<usize>,
    home: &str,
) -> Parent {
    let gateway = &cx.gateways[index];
    let owner = if set.is_some() {
        kinds::LISTENER_SET
    } else {
        kinds::GATEWAY
    };
    let candidates: Vec<(usize, &ListenerState)> = gateway
        .listeners
        .iter()
        .enumerate()
        .filter(|(_, l)| l.set == set)
        .filter(|(_, l)| parent.section_name.as_deref().is_none_or(|s| s == l.name))
        .filter(|(_, l)| parent.port.is_none_or(|p| p == l.port))
        .collect();
    if candidates.is_empty() {
        return Parent::Rejected((
            reasons::NO_MATCHING_PARENT,
            format!("no listener of the {owner} matches the parentRef's sectionName and port"),
        ));
    }
    let allowed: Vec<(usize, &ListenerState)> = candidates
        .into_iter()
        .filter(|(_, l)| gateway.accepted.is_ok() && l.active())
        .filter(|(_, l)| l.kinds.contains(&route.kind))
        .filter(|(_, l)| namespace_allowed(cx, &l.namespaces, home, route.namespace))
        .collect();
    if allowed.is_empty() {
        return Parent::Rejected((
            reasons::NOT_ALLOWED_BY_LISTENERS,
            format!(
                "no listener allows {} from namespace `{}`",
                route.kind.as_str(),
                route.namespace
            ),
        ));
    }
    let listeners: Vec<(usize, Intersection)> = allowed
        .into_iter()
        .map(|(i, l)| (i, intersect(l.hostname.as_deref(), route.hostnames)))
        .filter(|(_, hosts)| *hosts != Intersection::Empty)
        .collect();
    if listeners.is_empty() {
        return Parent::Rejected((
            reasons::NO_MATCHING_LISTENER_HOSTNAME,
            "no listener host name intersects the route's host names".to_owned(),
        ));
    }
    Parent::Accepted {
        gateway: index,
        listeners,
    }
}

/// Whether a listener with `policy` on a Gateway (or ListenerSet) in `gateway_namespace`
/// takes routes from `route_namespace`; also whether a Gateway with `allowedListeners`
/// `policy` takes ListenerSets from that namespace.
#[must_use]
pub fn namespace_allowed(
    cx: &Context<'_>,
    policy: &Namespaces,
    gateway_namespace: &str,
    route_namespace: &str,
) -> bool {
    match policy {
        Namespaces::Same => gateway_namespace == route_namespace,
        Namespaces::All => true,
        Namespaces::Selector(selector) => cx
            .inventory
            .namespaces
            .get(route_namespace)
            .is_some_and(|labels| super::selectors::matches(selector, labels)),
        Namespaces::None => false,
    }
}
