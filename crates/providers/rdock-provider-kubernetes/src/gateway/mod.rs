//! Gateway API translation (W-K8S-01, ADR-0029, "Translating the Gateway API").
//!
//! **Owner:** the Gateway API translator. Only this module (and files below `src/gateway/`)
//! changes for it; the shared types live in [`crate::api`], [`crate::inventory`] and
//! [`mod@crate::translate`].
//!
//! It turns GatewayClasses with our controller name, their Gateways, the routes attached to
//! them, ReferenceGrants, Services and EndpointSlices into fragment listeners, certificates,
//! routes, services and middlewares, the desired status of every object of ours, the
//! per-Gateway Services, and the Secrets to write as files. The steps:
//!
//! 1. [`classes`]: GatewayClasses whose `controllerName` is ours get `Accepted`,
//!    `SupportedVersion` and `supportedFeatures`; others are not touched.
//! 2. [`listeners`]: each Gateway of an accepted class of ours is validated listener by
//!    listener (protocol, route kinds, certificates, conflicts); the listeners of the
//!    ListenerSets it allows are merged into it ([`listener_sets`]); one internal listener is
//!    opened per Gateway port once the Gateway's Service maps it to an internal port; the
//!    Service itself is desired as soon as the Gateway is accepted.
//! 3. [`attach`]: every parentRef of every route is matched against the listeners
//!    (`sectionName`, `port`, `allowedRoutes`, host names) and gets its `status.parents`
//!    entry; parentRefs to anything that is not a Gateway (or a ListenerSet of a Gateway) of
//!    ours get none.
//! 4. [`http`] (HTTPRoute, GRPCRoute) and [`l4`] (TLSRoute, TCPRoute, UDPRoute) turn the
//!    rules of accepted routes into routes, services and middlewares on the internal
//!    listeners they attach to, with priorities from [`priority`].
//! 5. The listener, Gateway and ListenerSet status is completed (`attachedRoutes`,
//!    `attachedListenerSets`).
//!
//! Object names are built by [`names`]; every object left out gets a warning whose path
//! starts with `kubernetes["<Kind>/<namespace>/<name>"]`.
//!
//! BackendTLSPolicies are applied to the backends of HTTPRoutes and GRPCRoutes
//! ([`policies`]), not claimed yet. Not supported yet, and reported: static Gateway
//! addresses, `tls.mode: Terminate` on `TLS` listeners (the listener is not accepted,
//! `UnsupportedValue`).

pub mod attach;
pub mod classes;
pub mod conditions;
pub mod grants;
pub mod hostnames;
pub mod http;
pub mod l4;
pub mod listener_sets;
pub mod listeners;
pub mod names;
pub mod policies;
pub mod priority;
pub mod selectors;

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
use rdock_model::Diagnostic;

use crate::inventory::{Inventory, ObjectKey};
use crate::translate::{RouteKind, Settings, Translation};

/// Translates the Gateway API objects of `inventory`.
#[must_use]
pub fn translate(inventory: &Inventory, settings: &Settings) -> Translation {
    let mut cx = Context::new(inventory, settings);
    let ours = classes::translate(&mut cx);
    listeners::evaluate(&mut cx, &ours);
    policies::evaluate(&mut cx);
    let ranks = route_ranks(inventory);
    http::translate(&mut cx, &ranks);
    l4::translate(&mut cx, &ranks);
    listeners::finish(&mut cx);
    policies::finish(&mut cx);
    listener_sets::finish(&mut cx);
    let notes = cx.notes.take();
    cx.out.diagnostics.extend(notes);
    cx.out
}

/// Everything one translation works on.
pub struct Context<'a> {
    /// The inventory.
    pub inventory: &'a Inventory,
    /// Settings.
    pub settings: &'a Settings,
    /// The output being built.
    pub out: Translation,
    /// The Gateways of our accepted classes, in key order.
    pub gateways: Vec<listeners::GatewayState<'a>>,
    /// Index into `gateways` by key.
    pub gateway_index: BTreeMap<ObjectKey, usize>,
    /// The ListenerSets whose parent is one of `gateways`, in precedence order.
    pub listener_sets: Vec<listener_sets::ListenerSetState>,
    /// Index into `listener_sets` by key.
    pub listener_set_index: BTreeMap<ObjectKey, usize>,
    /// BackendTLSPolicies, evaluated.
    pub policies: BTreeMap<ObjectKey, policies::PolicyState>,
    /// Warnings found where only a shared borrow of the context is at hand (backend
    /// resolution); moved into `out` at the end ([`Context::note`]).
    notes: std::cell::Cell<Vec<rdock_model::Diagnostic>>,
}

impl<'a> Context<'a> {
    fn new(inventory: &'a Inventory, settings: &'a Settings) -> Self {
        Self {
            inventory,
            settings,
            out: Translation::default(),
            gateways: Vec::new(),
            gateway_index: BTreeMap::new(),
            listener_sets: Vec::new(),
            listener_set_index: BTreeMap::new(),
            policies: BTreeMap::new(),
            notes: std::cell::Cell::default(),
        }
    }

    /// Records `diagnostic` through a shared borrow; it joins `out.diagnostics` when the
    /// translation ends.
    pub fn note(&self, diagnostic: rdock_model::Diagnostic) {
        let mut notes = self.notes.take();
        notes.push(diagnostic);
        self.notes.set(notes);
    }

    /// Adds a warning about `object` (`Kind/namespace/name`), at `field` below it.
    pub fn warn(&mut self, object: &str, field: &str, message: impl Into<String>) {
        self.out
            .diagnostics
            .push(Diagnostic::warning(object_path(object, field), message));
    }
}

/// The diagnostic path of a Kubernetes object: `kubernetes["HTTPRoute/ns/name"]`, then
/// `field` (e.g. `.spec.rules[0]`).
#[must_use]
pub fn object_path(object: &str, field: &str) -> String {
    format!("{}{field}", rdock_model::path_key("kubernetes", object))
}

/// `Kind/namespace/name`.
#[must_use]
pub fn object_id(kind: &str, namespace: &str, name: &str) -> String {
    format!("{kind}/{namespace}/{name}")
}

/// The `metadata.generation` of an object.
#[must_use]
pub fn generation(meta: &ObjectMeta) -> Option<i64> {
    meta.generation
}

/// The rank of every route for precedence ([`priority`]; the oldest UDPRoute of a listener
/// wins it): oldest
/// `creationTimestamp` first, then `{namespace}/{name}` in alphabetical order (a missing
/// timestamp sorts last). HTTPRoutes and GRPCRoutes share one ranking because they can
/// attach to the same listener.
#[must_use]
pub fn route_ranks(inventory: &Inventory) -> BTreeMap<(RouteKind, ObjectKey), usize> {
    let mut all: Vec<(bool, Option<&Time>, &ObjectKey, RouteKind)> = Vec::new();
    for (key, route) in &inventory.http_routes {
        let created = route.metadata.creation_timestamp.as_ref();
        all.push((created.is_none(), created, key, RouteKind::Http));
    }
    for (key, route) in &inventory.grpc_routes {
        let created = route.metadata.creation_timestamp.as_ref();
        all.push((created.is_none(), created, key, RouteKind::Grpc));
    }
    for (key, route) in &inventory.tls_routes {
        let created = route.metadata.creation_timestamp.as_ref();
        all.push((created.is_none(), created, key, RouteKind::Tls));
    }
    for (key, route) in &inventory.tcp_routes {
        let created = route.metadata.creation_timestamp.as_ref();
        all.push((created.is_none(), created, key, RouteKind::Tcp));
    }
    for (key, route) in &inventory.udp_routes {
        let created = route.metadata.creation_timestamp.as_ref();
        all.push((created.is_none(), created, key, RouteKind::Udp));
    }
    all.sort();
    all.into_iter()
        .enumerate()
        .map(|(rank, (_, _, key, kind))| ((kind, key.clone()), rank))
        .collect()
}

/// The namespaces whose labels are known, for `allowedRoutes` selectors.
#[must_use]
pub fn namespace_labels<'a>(
    inventory: &'a Inventory,
    namespace: &str,
) -> Option<&'a BTreeMap<String, String>> {
    inventory.namespaces.get(namespace)
}

/// A set of route keys (for `attachedRoutes`).
pub type RouteSet = BTreeSet<crate::translate::RouteRef>;
