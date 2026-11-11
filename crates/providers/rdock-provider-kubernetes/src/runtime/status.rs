//! The status writer (ADR-0029, "Status and leader election"), leader only.
//!
//! For every object in the translation's [`DesiredStatus`] the writer merges the desired
//! status into the live one from the store and writes only when the result differs:
//!
//! - conditions are merged by `type`: ours replace the live ones of the same type, the Gateway
//!   API's own types that we no longer want are dropped (they would keep a stale
//!   `observedGeneration`), and every other type is another controller's and stays as it is;
//! - `lastTransitionTime` is kept when `status` did not change and set to now when it flips or
//!   the condition is new; `observedGeneration` is the translator's;
//! - in `status.parents[]` (routes) and `status.ancestors[]` (policies) only the entries whose
//!   `controllerName` is ours are replaced (matched by the reference with its defaults), every
//!   other controller's entry stays exactly where and as it is, and our entries that are no
//!   longer wanted are dropped.
//!
//! The write is a JSON merge patch on `/status` carrying the full merged lists (a merge patch
//! replaces arrays) and `metadata.resourceVersion`, so a concurrent writer causes a 409 and a
//! retry on the next pass instead of a lost update. Objects that are not in
//! [`DesiredStatus`] are never written.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use k8s_openapi::api::networking::v1::{Ingress, IngressLoadBalancerIngress};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::api::{
    GROUP, GatewayClassStatus, GatewayStatus, GatewayStatusAddress, ListenerEntryStatus,
    ListenerSetStatus, ListenerStatus, ParentReference, PolicyAncestorStatus, RouteGroupKind,
    RouteParentStatus, kinds,
};
use crate::inventory::Inventory;
use crate::translate::{
    DesiredCondition, DesiredGateway, DesiredGatewayClass, DesiredListener, DesiredListenerSet,
    DesiredPolicyAncestor, DesiredRouteParent, DesiredStatus, LoadBalancerAddress, RouteKind,
};

/// Condition types of the Gateway API for a GatewayClass: ours to set and to remove.
pub const GATEWAY_CLASS_TYPES: &[&str] = &["Accepted", "SupportedVersion"];
/// Condition types of the Gateway API for a Gateway.
pub const GATEWAY_TYPES: &[&str] = &[
    "Accepted",
    "Programmed",
    "ResolvedRefs",
    "AddressesAssigned",
    "InsecureFrontendValidationMode",
    "Scheduled",
    "Ready",
];
/// Condition types of the Gateway API for a listener (of a Gateway or a ListenerSet).
pub const LISTENER_TYPES: &[&str] = &[
    "Accepted",
    "Programmed",
    "ResolvedRefs",
    "Conflicted",
    "OverlappingTLSConfig",
    "Detached",
    "Ready",
];
/// Condition types of the Gateway API for a ListenerSet.
pub const LISTENER_SET_TYPES: &[&str] = &["Accepted", "Programmed", "ResolvedRefs", "Ready"];

/// Now, to the second (what the API server stores for a `Time`).
#[must_use]
pub fn now() -> Time {
    let now = Timestamp::now();
    Time(Timestamp::from_second(now.as_second()).unwrap_or(now))
}

fn status_word(status: bool) -> &'static str {
    if status { "True" } else { "False" }
}

/// One desired condition as a metav1 Condition, keeping the live `lastTransitionTime` when
/// the status is unchanged.
fn condition(desired: &DesiredCondition, live: Option<&Condition>, now: &Time) -> Condition {
    let status = status_word(desired.status);
    let last_transition_time = match live {
        Some(live) if live.status == status => live.last_transition_time.clone(),
        _ => now.clone(),
    };
    Condition {
        type_: desired.kind.clone(),
        status: status.to_owned(),
        reason: desired.reason.clone(),
        message: desired.message.clone(),
        observed_generation: desired.observed_generation,
        last_transition_time,
    }
}

fn first_by_type(desired: &[DesiredCondition]) -> Vec<&DesiredCondition> {
    let mut seen = std::collections::BTreeSet::new();
    desired
        .iter()
        .filter(|c| seen.insert(c.kind.as_str()))
        .collect()
}

/// Merges `desired` into the live conditions of an object shared with other controllers:
/// the desired types replace the live ones in place, the types in `owned` that are not
/// desired are dropped, every other type is kept as it is; new types are appended.
#[must_use]
pub fn merge_conditions(
    live: &[Condition],
    desired: &[DesiredCondition],
    owned: &[&str],
    now: &Time,
) -> Vec<Condition> {
    let desired = first_by_type(desired);
    let mut out = Vec::with_capacity(live.len().max(desired.len()));
    let mut placed = std::collections::BTreeSet::new();
    for existing in live {
        if let Some(want) = desired.iter().find(|d| d.kind == existing.type_) {
            if placed.insert(want.kind.as_str()) {
                out.push(condition(want, Some(existing), now));
            }
        } else if !owned.contains(&existing.type_.as_str()) {
            out.push(existing.clone());
        }
    }
    for want in desired {
        if !placed.contains(want.kind.as_str()) {
            out.push(condition(want, None, now));
        }
    }
    out
}

/// The conditions of an entry that is ours alone (a route parent entry with our
/// `controllerName`): exactly the desired ones, with the live transition times.
#[must_use]
pub fn own_conditions(
    live: &[Condition],
    desired: &[DesiredCondition],
    now: &Time,
) -> Vec<Condition> {
    first_by_type(desired)
        .into_iter()
        .map(|want| condition(want, live.iter().find(|c| c.type_ == want.kind), now))
        .collect()
}

/// A route kind with its group defaulted, as the CRD stores it.
fn normalise_kinds(kinds: &[RouteGroupKind]) -> Vec<RouteGroupKind> {
    kinds
        .iter()
        .map(|k| RouteGroupKind {
            group: Some(k.group.clone().unwrap_or_else(|| GROUP.to_owned())),
            kind: k.kind.clone(),
        })
        .collect()
}

fn normalise_addresses(addresses: &[GatewayStatusAddress]) -> Vec<GatewayStatusAddress> {
    addresses
        .iter()
        .map(|a| GatewayStatusAddress {
            kind: Some(a.kind.clone().unwrap_or_else(|| "IPAddress".to_owned())),
            value: a.value.clone(),
        })
        .collect()
}

/// The merged status of a GatewayClass.
#[must_use]
pub fn merge_gateway_class(
    live: Option<&GatewayClassStatus>,
    desired: &DesiredGatewayClass,
    now: &Time,
) -> GatewayClassStatus {
    let live_conditions = live.map(|s| s.conditions.as_slice()).unwrap_or_default();
    let mut features = desired.supported_features.clone();
    features.sort();
    features.dedup();
    GatewayClassStatus {
        conditions: merge_conditions(
            live_conditions,
            &desired.conditions,
            GATEWAY_CLASS_TYPES,
            now,
        ),
        supported_features: features,
    }
}

fn merge_listener(
    live: Option<&ListenerStatus>,
    desired: &DesiredListener,
    now: &Time,
) -> ListenerStatus {
    let live_conditions = live.map(|l| l.conditions.as_slice()).unwrap_or_default();
    ListenerStatus {
        name: desired.name.clone(),
        supported_kinds: normalise_kinds(&desired.supported_kinds),
        attached_routes: desired.attached_routes,
        conditions: merge_conditions(live_conditions, &desired.conditions, LISTENER_TYPES, now),
    }
}

/// The merged status of a Gateway: conditions merged, listeners (one per desired listener, in
/// its order) with their conditions merged, addresses and attached ListenerSets as desired.
#[must_use]
pub fn merge_gateway(
    live: Option<&GatewayStatus>,
    desired: &DesiredGateway,
    now: &Time,
) -> GatewayStatus {
    let empty = GatewayStatus::default();
    let live = live.unwrap_or(&empty);
    GatewayStatus {
        addresses: normalise_addresses(&desired.addresses),
        conditions: merge_conditions(&live.conditions, &desired.conditions, GATEWAY_TYPES, now),
        listeners: desired
            .listeners
            .iter()
            .map(|l| merge_listener(live.listeners.iter().find(|x| x.name == l.name), l, now))
            .collect(),
        attached_listener_sets: desired.attached_listener_sets,
    }
}

/// The merged status of a ListenerSet.
#[must_use]
pub fn merge_listener_set(
    live: Option<&ListenerSetStatus>,
    desired: &DesiredListenerSet,
    now: &Time,
) -> ListenerSetStatus {
    let empty = ListenerSetStatus::default();
    let live = live.unwrap_or(&empty);
    ListenerSetStatus {
        conditions: merge_conditions(
            &live.conditions,
            &desired.conditions,
            LISTENER_SET_TYPES,
            now,
        ),
        listeners: desired
            .listeners
            .iter()
            .map(|l| {
                let live_conditions = live
                    .listeners
                    .iter()
                    .find(|x| x.name == l.name)
                    .map(|x| x.conditions.as_slice())
                    .unwrap_or_default();
                ListenerEntryStatus {
                    name: l.name.clone(),
                    supported_kinds: normalise_kinds(&l.supported_kinds),
                    attached_routes: l.attached_routes,
                    conditions: merge_conditions(
                        live_conditions,
                        &l.conditions,
                        LISTENER_TYPES,
                        now,
                    ),
                }
            })
            .collect(),
    }
}

/// A parent reference with the defaults the specification gives it (group
/// `gateway.networking.k8s.io`, kind `Gateway`, the referrer's namespace), for matching.
fn parent_key(reference: &ParentReference, namespace: &str) -> ParentReference {
    ParentReference {
        group: Some(reference.group.clone().unwrap_or_else(|| GROUP.to_owned())),
        kind: Some(
            reference
                .kind
                .clone()
                .unwrap_or_else(|| kinds::GATEWAY.to_owned()),
        ),
        namespace: Some(
            reference
                .namespace
                .clone()
                .unwrap_or_else(|| namespace.to_owned()),
        ),
        name: reference.name.clone(),
        section_name: reference.section_name.clone(),
        port: reference.port,
    }
}

/// The reference as we write it: as desired, with group and kind filled in as the CRD would.
fn written_ref(reference: &ParentReference) -> ParentReference {
    ParentReference {
        group: Some(reference.group.clone().unwrap_or_else(|| GROUP.to_owned())),
        kind: Some(
            reference
                .kind
                .clone()
                .unwrap_or_else(|| kinds::GATEWAY.to_owned()),
        ),
        ..reference.clone()
    }
}

/// Merges our entries into a list shared by controllers (`status.parents`,
/// `status.ancestors`). `entry` builds our entry from the desired one and the live one it
/// replaces.
fn merge_entries<L: Clone, D>(
    live: &[L],
    desired: &[D],
    namespace: &str,
    controller: &str,
    live_parts: impl Fn(&L) -> (&ParentReference, &str),
    desired_ref: impl Fn(&D) -> &ParentReference,
    entry: impl Fn(&D, Option<&L>) -> L,
) -> Vec<L> {
    let mut wanted: Vec<(ParentReference, &D)> = Vec::new();
    for d in desired {
        let key = parent_key(desired_ref(d), namespace);
        if !wanted.iter().any(|(k, _)| *k == key) {
            wanted.push((key, d));
        }
    }
    let mut placed = vec![false; wanted.len()];
    let mut out = Vec::with_capacity(live.len().max(wanted.len()));
    for existing in live {
        let (reference, owner) = live_parts(existing);
        if owner != controller {
            out.push(existing.clone());
            continue;
        }
        let key = parent_key(reference, namespace);
        if let Some(i) = wanted.iter().position(|(k, _)| *k == key)
            && !placed[i]
        {
            placed[i] = true;
            out.push(entry(wanted[i].1, Some(existing)));
        }
    }
    for (i, (_, d)) in wanted.iter().enumerate() {
        if !placed[i] {
            out.push(entry(d, None));
        }
    }
    out
}

/// The merged `status.parents` of a route in namespace `namespace`.
#[must_use]
pub fn merge_route_parents(
    live: &[RouteParentStatus],
    desired: &[DesiredRouteParent],
    namespace: &str,
    controller: &str,
    now: &Time,
) -> Vec<RouteParentStatus> {
    merge_entries(
        live,
        desired,
        namespace,
        controller,
        |l| (&l.parent_ref, l.controller_name.as_str()),
        |d| &d.parent_ref,
        |d, l| RouteParentStatus {
            parent_ref: written_ref(&d.parent_ref),
            controller_name: controller.to_owned(),
            conditions: own_conditions(
                l.map(|l| l.conditions.as_slice()).unwrap_or_default(),
                &d.conditions,
                now,
            ),
        },
    )
}

/// The merged `status.ancestors` of a policy in namespace `namespace`.
#[must_use]
pub fn merge_policy_ancestors(
    live: &[PolicyAncestorStatus],
    desired: &[DesiredPolicyAncestor],
    namespace: &str,
    controller: &str,
    now: &Time,
) -> Vec<PolicyAncestorStatus> {
    merge_entries(
        live,
        desired,
        namespace,
        controller,
        |l| (&l.ancestor_ref, l.controller_name.as_str()),
        |d| &d.ancestor_ref,
        |d, l| PolicyAncestorStatus {
            ancestor_ref: written_ref(&d.ancestor_ref),
            controller_name: controller.to_owned(),
            conditions: own_conditions(
                l.map(|l| l.conditions.as_slice()).unwrap_or_default(),
                &d.conditions,
                now,
            ),
        },
    )
}

/// The desired `status.loadBalancer.ingress` of an Ingress, or `None` when the live one
/// already says the same (ports and errors, which we never set, are ignored).
#[must_use]
pub fn ingress_addresses(
    live: &[IngressLoadBalancerIngress],
    desired: &[LoadBalancerAddress],
) -> Option<Vec<LoadBalancerAddress>> {
    let mut want: Vec<LoadBalancerAddress> = desired.to_vec();
    want.sort();
    want.dedup();
    let mut have: Vec<LoadBalancerAddress> = live
        .iter()
        .map(|i| LoadBalancerAddress {
            ip: i.ip.clone(),
            hostname: i.hostname.clone(),
        })
        .collect();
    have.sort();
    (have != want).then_some(want)
}

/// Failed writes: logged once per object and error, retried with exponential backoff
/// (1 s doubling, capped at 30 s).
#[derive(Debug, Default)]
pub struct ErrorLog {
    entries: HashMap<String, (String, u32, Instant)>,
}

const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

impl ErrorLog {
    /// Whether `key` may be written now.
    #[must_use]
    pub fn due(&self, key: &str) -> bool {
        self.entries
            .get(key)
            .is_none_or(|(_, _, next)| *next <= Instant::now())
    }

    /// Records a failed write of `key`.
    pub fn failed(&mut self, key: &str, message: &str) {
        let entry = self
            .entries
            .entry(key.to_owned())
            .or_insert_with(|| (String::new(), 0, Instant::now()));
        if entry.0 != message {
            tracing::warn!(provider = crate::PROVIDER, object = %key, error = %message,
                "cannot write to the cluster; retrying with backoff");
            message.clone_into(&mut entry.0);
        }
        entry.1 = entry.1.saturating_add(1);
        let delay = RETRY_MIN
            .saturating_mul(1 << entry.1.saturating_sub(1).min(5))
            .min(RETRY_MAX);
        entry.2 = Instant::now() + delay;
    }

    /// Records a conflict (409): someone wrote first; retried on the next pass.
    pub fn conflict(&mut self, key: &str) {
        tracing::debug!(provider = crate::PROVIDER, object = %key, "write conflict; retrying on the next pass");
        self.entries.insert(
            key.to_owned(),
            ("conflict".to_owned(), 1, Instant::now() + RETRY_MIN),
        );
    }

    /// Records a successful write (or nothing to write) for `key`.
    pub fn clear(&mut self, key: &str) {
        if let Some((message, _, _)) = self.entries.remove(key)
            && message != "conflict"
        {
            tracing::info!(provider = crate::PROVIDER, object = %key, "writing to the cluster works again");
        }
    }

    /// When the earliest retry is due.
    #[must_use]
    pub fn next_due(&self) -> Option<Instant> {
        self.entries.values().map(|(_, _, next)| *next).min()
    }
}

/// Patches `/status` of `name` with `status` (a JSON object of the fields to set) under
/// optimistic concurrency.
async fn patch_status<K>(
    api: &Api<K>,
    name: &str,
    resource_version: Option<&str>,
    status: Value,
) -> Result<(), String>
where
    K: Resource + Clone + DeserializeOwned + std::fmt::Debug,
{
    let mut body = json!({ "status": status });
    if let Some(rv) = resource_version {
        body["metadata"] = json!({ "resourceVersion": rv });
    }
    let params = PatchParams::default();
    let patch = Patch::Merge(&body);
    let call = api.patch_status(name, &params, &patch);
    match tokio::time::timeout(super::CALL_TIMEOUT, call).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(kube::Error::Api(status))) if status.code == 409 => Err("409".to_owned()),
        Ok(Err(kube::Error::Api(status))) if status.code == 404 => Err("404".to_owned()),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err("the request timed out".to_owned()),
    }
}

fn to_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// A list for a merge patch: `null` deletes the field when empty.
fn list_or_null<T: Serialize>(items: &[T]) -> Value {
    if items.is_empty() {
        Value::Null
    } else {
        to_value(&items)
    }
}

/// The writes of one pass.
pub struct Writer<'a> {
    pub(crate) client: &'a Client,
    pub(crate) controller: &'a str,
    pub(crate) errors: &'a mut ErrorLog,
    /// Number of writes sent in this pass (tests and logs).
    pub(crate) writes: usize,
}

impl Writer<'_> {
    async fn send<K>(&mut self, api: Api<K>, key: String, object: &K, status: Value)
    where
        K: Resource + Clone + DeserializeOwned + std::fmt::Debug,
    {
        if !self.errors.due(&key) {
            return;
        }
        self.writes += 1;
        tracing::debug!(provider = crate::PROVIDER, object = %key, "writing status");
        match patch_status(
            &api,
            &object.name_any(),
            object.resource_version().as_deref(),
            status,
        )
        .await
        {
            Ok(()) => self.errors.clear(&key),
            Err(e) if e == "409" => self.errors.conflict(&key),
            // The object was deleted meanwhile: nothing to write.
            Err(e) if e == "404" => self.errors.clear(&key),
            Err(e) => self.errors.failed(&key, &e),
        }
    }

    /// Writes every object of `desired` whose merged status differs from the live one in
    /// `live`.
    pub async fn write(&mut self, live: &Inventory, desired: &DesiredStatus) {
        let now = now();
        self.write_gateways(live, desired, &now).await;
        self.write_attached(live, desired, &now).await;
    }

    /// GatewayClasses, Gateways and ListenerSets.
    async fn write_gateways(&mut self, live: &Inventory, desired: &DesiredStatus, now: &Time) {
        for (name, want) in &desired.gateway_classes {
            let Some(object) = live.gateway_classes.get(name) else {
                continue;
            };
            let merged = merge_gateway_class(object.status.as_ref(), want, now);
            if object
                .status
                .as_ref()
                .unwrap_or(&GatewayClassStatus::default())
                == &merged
            {
                continue;
            }
            let status = json!({
                "conditions": to_value(&merged.conditions),
                "supportedFeatures": list_or_null(&merged.supported_features),
            });
            let api = Api::all(self.client.clone());
            self.send(api, format!("GatewayClass {name}"), object, status)
                .await;
        }
        for ((ns, name), want) in &desired.gateways {
            let Some(object) = live.gateways.get(&(ns.clone(), name.clone())) else {
                continue;
            };
            let merged = merge_gateway(object.status.as_ref(), want, now);
            if object.status.as_ref().unwrap_or(&GatewayStatus::default()) == &merged {
                continue;
            }
            let status = json!({
                "addresses": list_or_null(&merged.addresses),
                "conditions": to_value(&merged.conditions),
                "listeners": list_or_null(&merged.listeners),
                "attachedListenerSets": merged.attached_listener_sets,
            });
            let api = Api::namespaced(self.client.clone(), ns);
            self.send(api, format!("Gateway {ns}/{name}"), object, status)
                .await;
        }
        for ((ns, name), want) in &desired.listener_sets {
            let Some(object) = live.listener_sets.get(&(ns.clone(), name.clone())) else {
                continue;
            };
            let merged = merge_listener_set(object.status.as_ref(), want, now);
            if object
                .status
                .as_ref()
                .unwrap_or(&ListenerSetStatus::default())
                == &merged
            {
                continue;
            }
            let status = json!({
                "conditions": to_value(&merged.conditions),
                "listeners": list_or_null(&merged.listeners),
            });
            let api = Api::namespaced(self.client.clone(), ns);
            self.send(api, format!("ListenerSet {ns}/{name}"), object, status)
                .await;
        }
    }

    /// Routes, policies and Ingresses.
    async fn write_attached(&mut self, live: &Inventory, desired: &DesiredStatus, now: &Time) {
        let controller = self.controller.to_owned();
        for (route, want) in &desired.routes {
            let key = (route.namespace.clone(), route.name.clone());
            let label = format!("{} {}/{}", route.kind.as_str(), route.namespace, route.name);
            macro_rules! route {
                ($map:ident) => {{
                    let Some(object) = live.$map.get(&key) else { continue };
                    let live_parents = object.status.as_ref().map(|s| s.parents.as_slice()).unwrap_or_default();
                    let merged = merge_route_parents(live_parents, want, &route.namespace, &controller, now);
                    if live_parents == merged.as_slice() {
                        continue;
                    }
                    let api = Api::namespaced(self.client.clone(), &route.namespace);
                    self.send(api, label, object, json!({ "parents": to_value(&merged) })).await;
                }};
            }
            match route.kind {
                RouteKind::Http => route!(http_routes),
                RouteKind::Grpc => route!(grpc_routes),
                RouteKind::Tls => route!(tls_routes),
                RouteKind::Tcp => route!(tcp_routes),
                RouteKind::Udp => route!(udp_routes),
            }
        }
        for ((ns, name), want) in &desired.backend_tls_policies {
            let Some(object) = live.backend_tls_policies.get(&(ns.clone(), name.clone())) else {
                continue;
            };
            let live_ancestors = object
                .status
                .as_ref()
                .map(|s| s.ancestors.as_slice())
                .unwrap_or_default();
            let merged = merge_policy_ancestors(live_ancestors, want, ns, &controller, now);
            if live_ancestors == merged.as_slice() {
                continue;
            }
            let api = Api::namespaced(self.client.clone(), ns);
            self.send(
                api,
                format!("BackendTLSPolicy {ns}/{name}"),
                object,
                json!({ "ancestors": to_value(&merged) }),
            )
            .await;
        }
        for ((ns, name), want) in &desired.ingresses {
            let Some(object) = live.ingresses.get(&(ns.clone(), name.clone())) else {
                continue;
            };
            let live_ingress = object
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|l| l.ingress.clone())
                .unwrap_or_default();
            let Some(addresses) = ingress_addresses(&live_ingress, want) else {
                continue;
            };
            let ingress: Vec<Value> = addresses
                .iter()
                .map(|a| {
                    let mut entry = serde_json::Map::new();
                    if let Some(ip) = &a.ip {
                        entry.insert("ip".to_owned(), json!(ip));
                    }
                    if let Some(host) = &a.hostname {
                        entry.insert("hostname".to_owned(), json!(host));
                    }
                    Value::Object(entry)
                })
                .collect();
            let api: Api<Ingress> = Api::namespaced(self.client.clone(), ns);
            let status = json!({ "loadBalancer": { "ingress": if ingress.is_empty() { Value::Null } else { Value::Array(ingress) } } });
            self.send(api, format!("Ingress {ns}/{name}"), object, status)
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: i64) -> Time {
        Time(Timestamp::from_second(1_800_000_000 + s).unwrap())
    }

    fn want(kind: &str, status: bool, reason: &str, generation: i64) -> DesiredCondition {
        DesiredCondition {
            kind: kind.to_owned(),
            status,
            reason: reason.to_owned(),
            message: String::new(),
            observed_generation: Some(generation),
        }
    }

    fn have(kind: &str, status: &str, reason: &str, generation: i64, at: Time) -> Condition {
        Condition {
            type_: kind.to_owned(),
            status: status.to_owned(),
            reason: reason.to_owned(),
            message: String::new(),
            observed_generation: Some(generation),
            last_transition_time: at,
        }
    }

    const FOREIGN: &str = "conformance.gateway.networking.k8s.io/StaleCondition";

    #[test]
    fn conditions_merge_by_type_and_keep_foreign_ones() {
        let live = vec![
            have("Accepted", "True", "Accepted", 1, t(0)),
            have(FOREIGN, "True", "Seeded", 1, t(1)),
            have("Programmed", "False", "Pending", 1, t(2)),
            have("Scheduled", "True", "Scheduled", 1, t(3)),
        ];
        let desired = vec![
            want("Accepted", true, "Accepted", 2),
            want("Programmed", true, "Programmed", 2),
        ];
        let merged = merge_conditions(&live, &desired, GATEWAY_TYPES, &t(100));
        assert_eq!(
            merged,
            vec![
                // Unchanged status: the transition time stays, the generation follows.
                have("Accepted", "True", "Accepted", 2, t(0)),
                // Another controller's condition: byte for byte.
                have(FOREIGN, "True", "Seeded", 1, t(1)),
                // Flipped: the transition time is now.
                have("Programmed", "True", "Programmed", 2, t(100)),
                // `Scheduled` is a Gateway API type we no longer set: dropped.
            ]
        );
        // New types are appended; merging the result again changes nothing.
        let more = vec![
            want("Accepted", true, "Accepted", 2),
            want("Programmed", true, "Programmed", 2),
            want("ResolvedRefs", true, "ResolvedRefs", 2),
        ];
        let again = merge_conditions(&merged, &more, GATEWAY_TYPES, &t(200));
        assert_eq!(
            again.last().unwrap(),
            &have("ResolvedRefs", "True", "ResolvedRefs", 2, t(200))
        );
        assert_eq!(
            merge_conditions(&again, &more, GATEWAY_TYPES, &t(300)),
            again
        );
    }

    #[test]
    fn a_changed_reason_with_the_same_status_keeps_the_transition_time() {
        let live = vec![have("Accepted", "False", "Pending", 1, t(0))];
        let merged = merge_conditions(
            &live,
            &[want("Accepted", false, "Invalid", 1)],
            GATEWAY_TYPES,
            &t(9),
        );
        assert_eq!(merged[0].reason, "Invalid");
        assert_eq!(merged[0].last_transition_time, t(0));
    }

    fn gw_ref(name: &str) -> ParentReference {
        ParentReference {
            name: name.to_owned(),
            ..ParentReference::default()
        }
    }

    fn entry(
        reference: ParentReference,
        controller: &str,
        conditions: Vec<Condition>,
    ) -> RouteParentStatus {
        RouteParentStatus {
            parent_ref: reference,
            controller_name: controller.to_owned(),
            conditions,
        }
    }

    const OURS: &str = "reversedock.dev/gateway-controller";
    const THEIRS: &str = "example.com/other";

    #[test]
    fn route_parents_replace_only_our_entries() {
        let explicit = ParentReference {
            group: Some(GROUP.to_owned()),
            kind: Some("Gateway".to_owned()),
            namespace: Some("apps".to_owned()),
            name: "web".to_owned(),
            section_name: None,
            port: None,
        };
        let foreign = entry(
            ParentReference {
                name: "unmanaged-gateway".to_owned(),
                namespace: Some("apps".to_owned()),
                ..explicit.clone()
            },
            THEIRS,
            vec![have("Accepted", "True", "Accepted", 1, t(5))],
        );
        let live = vec![
            entry(
                explicit.clone(),
                OURS,
                vec![have("Accepted", "True", "Accepted", 1, t(0))],
            ),
            foreign.clone(),
            entry(
                gw_ref("old"),
                OURS,
                vec![have("Accepted", "True", "Accepted", 1, t(0))],
            ),
        ];
        // The desired entry names the same parent with defaults left out: it matches.
        let desired = vec![
            DesiredRouteParent {
                parent_ref: gw_ref("web"),
                conditions: vec![want("Accepted", true, "Accepted", 2)],
            },
            DesiredRouteParent {
                parent_ref: ParentReference {
                    section_name: Some("https".to_owned()),
                    ..gw_ref("web")
                },
                conditions: vec![want("Accepted", false, "NoMatchingParent", 2)],
            },
        ];
        let merged = merge_route_parents(&live, &desired, "apps", OURS, &t(50));
        assert_eq!(merged.len(), 3);
        // Ours, in place, transition time kept, generation updated.
        assert_eq!(merged[0].controller_name, OURS);
        assert_eq!(
            merged[0].conditions,
            vec![have("Accepted", "True", "Accepted", 2, t(0))]
        );
        assert_eq!(merged[0].parent_ref.group.as_deref(), Some(GROUP));
        // The foreign entry, untouched and where it was.
        assert_eq!(merged[1], foreign);
        // Our stale entry (`old`) is gone; the new one (section `https`) is appended.
        assert_eq!(merged[2].parent_ref.section_name.as_deref(), Some("https"));
        assert_eq!(merged[2].conditions[0].last_transition_time, t(50));
        // Stable: merging again yields the same list.
        assert_eq!(
            merge_route_parents(&merged, &desired, "apps", OURS, &t(60)),
            merged
        );
    }

    #[test]
    fn parent_refs_differ_by_namespace_section_and_port() {
        let live = vec![entry(
            ParentReference {
                namespace: Some("infra".to_owned()),
                ..gw_ref("web")
            },
            OURS,
            vec![],
        )];
        // Same name, but defaulted to the route's namespace `apps`: another parent.
        let desired = vec![DesiredRouteParent {
            parent_ref: gw_ref("web"),
            conditions: vec![],
        }];
        let merged = merge_route_parents(&live, &desired, "apps", OURS, &t(0));
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].parent_ref.namespace, None);
        let with_port = vec![DesiredRouteParent {
            parent_ref: ParentReference {
                port: Some(80),
                ..gw_ref("web")
            },
            conditions: vec![],
        }];
        let merged2 = merge_route_parents(&merged, &with_port, "apps", OURS, &t(0));
        assert_eq!(merged2.len(), 1);
        assert_eq!(merged2[0].parent_ref.port, Some(80));
    }

    #[test]
    fn our_entries_hold_exactly_the_desired_conditions() {
        let live = vec![entry(
            gw_ref("web"),
            OURS,
            vec![
                have("Accepted", "True", "Accepted", 1, t(0)),
                have("PartiallyInvalid", "True", "UnsupportedValue", 1, t(0)),
            ],
        )];
        let desired = vec![DesiredRouteParent {
            parent_ref: gw_ref("web"),
            conditions: vec![want("Accepted", true, "Accepted", 2)],
        }];
        let merged = merge_route_parents(&live, &desired, "apps", OURS, &t(9));
        assert_eq!(merged[0].conditions.len(), 1);
    }

    #[test]
    fn gateway_status_merges_listeners_and_normalises_defaults() {
        let live = GatewayStatus {
            conditions: vec![have(FOREIGN, "True", "Seeded", 1, t(1))],
            listeners: vec![ListenerStatus {
                name: "http".to_owned(),
                supported_kinds: vec![],
                attached_routes: 0,
                conditions: vec![
                    have(FOREIGN, "True", "Seeded", 1, t(1)),
                    have("Accepted", "True", "Accepted", 1, t(0)),
                ],
            }],
            ..GatewayStatus::default()
        };
        let desired = DesiredGateway {
            conditions: vec![want("Accepted", true, "Accepted", 2)],
            addresses: vec![GatewayStatusAddress {
                kind: None,
                value: "10.0.0.1".to_owned(),
            }],
            listeners: vec![DesiredListener {
                name: "http".to_owned(),
                supported_kinds: vec![RouteGroupKind {
                    group: None,
                    kind: "HTTPRoute".to_owned(),
                }],
                attached_routes: 3,
                conditions: vec![want("Accepted", true, "Accepted", 2)],
            }],
            attached_listener_sets: None,
        };
        let merged = merge_gateway(Some(&live), &desired, &t(10));
        assert_eq!(merged.conditions[0], live.conditions[0]);
        assert_eq!(merged.conditions[1].type_, "Accepted");
        assert_eq!(merged.addresses[0].kind.as_deref(), Some("IPAddress"));
        let listener = &merged.listeners[0];
        assert_eq!(listener.attached_routes, 3);
        assert_eq!(listener.supported_kinds[0].group.as_deref(), Some(GROUP));
        assert_eq!(listener.conditions[0], live.listeners[0].conditions[0]);
        assert_eq!(
            listener.conditions[1],
            have("Accepted", "True", "Accepted", 2, t(0))
        );
        assert_eq!(merge_gateway(Some(&merged), &desired, &t(20)), merged);
    }

    #[test]
    fn gateway_class_features_are_sorted_and_unique() {
        use crate::api::SupportedFeature;
        let f = |n: &str| SupportedFeature { name: n.to_owned() };
        let desired = DesiredGatewayClass {
            conditions: vec![want("Accepted", true, "Accepted", 1)],
            supported_features: vec![f("HTTPRoute"), f("Gateway"), f("HTTPRoute")],
        };
        let merged = merge_gateway_class(None, &desired, &t(0));
        assert_eq!(
            merged.supported_features,
            vec![f("Gateway"), f("HTTPRoute")]
        );
    }

    #[test]
    fn ingress_addresses_are_compared_as_sets() {
        let live = vec![IngressLoadBalancerIngress {
            ip: Some("10.0.0.1".to_owned()),
            ..Default::default()
        }];
        let same = vec![LoadBalancerAddress {
            ip: Some("10.0.0.1".to_owned()),
            hostname: None,
        }];
        assert_eq!(ingress_addresses(&live, &same), None);
        let other = vec![LoadBalancerAddress {
            ip: None,
            hostname: Some("lb.example".to_owned()),
        }];
        assert_eq!(ingress_addresses(&live, &other), Some(other.clone()));
    }

    #[test]
    fn failures_back_off_and_recover() {
        let mut log = ErrorLog::default();
        assert!(log.due("x"));
        log.failed("x", "boom");
        assert!(!log.due("x"));
        assert!(log.next_due().is_some());
        log.clear("x");
        assert!(log.due("x"));
        assert!(log.next_due().is_none());
    }
}
