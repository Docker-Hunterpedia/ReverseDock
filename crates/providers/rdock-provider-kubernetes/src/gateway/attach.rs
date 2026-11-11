//! Route attachment (`shared_types.go`, `ParentReference` and `RouteConditionReason`).
//!
//! A parentRef is ours when it names a Gateway (group `gateway.networking.k8s.io`, kind
//! `Gateway`, both the defaults) that exists and belongs to a GatewayClass of ours; any other
//! parentRef gets no `status.parents` entry from this controller (it may be another
//! controller's). For ours, the candidate listeners are those named by `sectionName` and on
//! `port` (when set); then, in this order, the first check that leaves no listener decides the
//! `Accepted=False` reason:
//!
//! 1. no candidate: `NoMatchingParent`;
//! 2. no candidate that is accepted, unconflicted and allows the route's kind and namespace
//!    (`allowedRoutes`): `NotAllowedByListeners`;
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
    if kind == kinds::LISTENER_SET {
        return listener_set(cx, namespace, &parent.name);
    }
    if kind != kinds::GATEWAY {
        return Parent::NotOurs;
    }
    let Some(&index) = cx
        .gateway_index
        .get(&(namespace.to_owned(), parent.name.clone()))
    else {
        return Parent::NotOurs;
    };
    let gateway = &cx.gateways[index];
    let candidates: Vec<(usize, &ListenerState)> = gateway
        .listeners
        .iter()
        .enumerate()
        .filter(|(_, l)| parent.section_name.as_deref().is_none_or(|s| s == l.name))
        .filter(|(_, l)| parent.port.is_none_or(|p| p == l.port))
        .collect();
    if candidates.is_empty() {
        return Parent::Rejected((
            reasons::NO_MATCHING_PARENT,
            "no listener of the Gateway matches the parentRef's sectionName and port".to_owned(),
        ));
    }
    let allowed: Vec<(usize, &ListenerState)> = candidates
        .into_iter()
        .filter(|(_, l)| gateway.accepted.is_ok() && l.active())
        .filter(|(_, l)| l.kinds.contains(&route.kind))
        .filter(|(_, l)| namespace_allowed(cx, &l.namespaces, &gateway.key.0, route.namespace))
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

/// A parentRef to a ListenerSet: ours when its parent Gateway is ours. ListenerSets are not
/// supported yet, so such a parentRef is refused.
fn listener_set(cx: &Context<'_>, namespace: &str, name: &str) -> Parent {
    let Some(set) = cx
        .inventory
        .listener_sets
        .get(&(namespace.to_owned(), name.to_owned()))
    else {
        return Parent::NotOurs;
    };
    let gateway_namespace = set
        .spec
        .parent_ref
        .namespace
        .as_deref()
        .unwrap_or(namespace);
    let ours = cx.gateway_index.contains_key(&(
        gateway_namespace.to_owned(),
        set.spec.parent_ref.name.clone(),
    ));
    if ours {
        Parent::Rejected((
            reasons::NO_MATCHING_PARENT,
            "ListenerSets are not supported yet".to_owned(),
        ))
    } else {
        Parent::NotOurs
    }
}

/// Whether a listener with `policy` on a Gateway in `gateway_namespace` takes routes from
/// `route_namespace`.
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
