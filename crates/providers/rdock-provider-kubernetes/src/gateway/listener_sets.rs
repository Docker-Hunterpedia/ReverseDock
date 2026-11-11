//! ListenerSets (`listenerset_types.go`, `gateway_types.go` `AllowedListeners`).
//!
//! A ListenerSet is ours when its `parentRef` names a Gateway of ours (group
//! `gateway.networking.k8s.io` and kind `Gateway`, the defaults; the ListenerSet's namespace
//! when `namespace` is unset). A ListenerSet whose parent is missing or not ours gets no
//! status from this controller, like a route whose parent is not ours.
//!
//! ListenerSets are taken in the specification's precedence order, after the parent's own
//! listeners: oldest `creationTimestamp` first, then `{namespace}/{name}` (a missing
//! timestamp sorts last). Each one is, in this order:
//!
//! 1. `Accepted=False/NotAllowed` unless the parent's `allowedListeners.namespaces` selects
//!    the ListenerSet's namespace (`None`, the default, selects none; `Same`, `All`,
//!    `Selector`, where a missing selector selects nothing, as for `allowedRoutes`);
//! 2. `Accepted=False/ParentNotAccepted` when the parent Gateway is not accepted;
//! 3. otherwise its listeners are evaluated like a Gateway's
//!    ([`super::listeners::evaluate_listener`]), with certificate references relative to the
//!    ListenerSet's namespace and checked against ReferenceGrants `from` kind `ListenerSet`
//!    (a Gateway's grants are not inherited). A listener that conflicts with one that takes
//!    precedence (the parent's, an earlier ListenerSet's, or an earlier one of the same set)
//!    is `Conflicted=True` and not accepted, with the conflict as the reason of `Accepted`
//!    and `Programmed`; the listener that takes precedence keeps working
//!    ([`super::listeners::conflict_with`]);
//! 4. `Accepted=False/ListenersNotValid` when no listener is valid (accepted, unconflicted and
//!    with its references resolved); otherwise `Accepted=True` (`Accepted`, or
//!    `ListenersNotValid` when some are not valid), and its listeners join the parent's list:
//!    they share the internal listener of their port with the parent's listeners and get a
//!    port on the parent's Service.
//!
//! `Programmed` is `True` once every valid listener is programmed, `False/ParentNotProgrammed`
//! while the parent's Service has no address, `False/Pending` while a port is not mapped yet;
//! a ListenerSet that is not accepted has `Programmed=False` with the reason of `Accepted`.
//! A ListenerSet that is not accepted has no `status.listeners`, except for
//! `ListenersNotValid`, where every listener says why. The parent's
//! `status.attachedListenerSets` counts the accepted ListenerSets; it is written when the
//! Gateway allows ListenerSets (or any are attached) and left unset otherwise.
//!
//! Routes attach to a ListenerSet with a parentRef of kind `ListenerSet` ([`super::attach`]):
//! its `sectionName` names a listener of that set, and `allowedRoutes.namespaces: Same` means
//! the ListenerSet's namespace. A parentRef to the Gateway reaches only the Gateway's own
//! listeners.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

use super::conditions::{condition, reasons, types};
use super::listeners::{
    Failure, ListenerState, Namespaces, conflict_with, evaluate_listener, listener_status,
};
use super::{Context, object_id};
use crate::api::{GROUP, Listener, ListenerEntry, kinds};
use crate::inventory::ObjectKey;
use crate::translate::{DesiredCondition, DesiredListener, DesiredListenerSet};

/// A ListenerSet of ours, evaluated.
#[derive(Debug, Clone)]
pub struct ListenerSetState {
    /// Key.
    pub key: ObjectKey,
    /// `metadata.generation`.
    pub generation: Option<i64>,
    /// The parent Gateway (an index into the context's Gateways).
    pub gateway: usize,
    /// `Accepted`.
    pub accepted: Result<(), Failure>,
    /// The listeners of a ListenerSet that is `Accepted=False/ListenersNotValid`, evaluated
    /// but not merged into the parent (for their status). An accepted ListenerSet's listeners
    /// are in the parent's list, with [`ListenerState::set`] naming it.
    pub rejected: Vec<ListenerState>,
}

/// Evaluates the ListenerSets whose parent is a Gateway of ours, in precedence order, and
/// merges the listeners of the accepted ones into their parent (before the internal
/// listeners are opened).
pub fn merge(cx: &mut Context<'_>) {
    let inventory = cx.inventory;
    let mut order: Vec<(bool, Option<&Time>, &ObjectKey)> = inventory
        .listener_sets
        .iter()
        .map(|(key, set)| {
            let created = set.metadata.creation_timestamp.as_ref();
            (created.is_none(), created, key)
        })
        .collect();
    order.sort();
    for (_, _, key) in order {
        let Some(set) = inventory.listener_sets.get(key) else {
            continue;
        };
        let parent = &set.spec.parent_ref;
        if parent.group.as_deref().is_some_and(|g| g != GROUP)
            || parent.kind.as_deref().is_some_and(|k| k != kinds::GATEWAY)
        {
            continue;
        }
        let gateway_namespace = parent.namespace.as_deref().unwrap_or(&key.0);
        let Some(&gateway) = cx
            .gateway_index
            .get(&(gateway_namespace.to_owned(), parent.name.clone()))
        else {
            continue;
        };
        let id = object_id(kinds::LISTENER_SET, &key.0, &key.1);
        let index = cx.listener_sets.len();
        let gw = &cx.gateways[gateway];
        let allowed =
            super::attach::namespace_allowed(cx, &gw.allowed_listeners, &gw.key.0, &key.0);
        let mut accepted = if !allowed {
            let why = if gw.allowed_listeners == Namespaces::None {
                "the Gateway does not allow ListenerSets (`allowedListeners`)".to_owned()
            } else {
                format!(
                    "the Gateway's `allowedListeners` does not select namespace `{}`",
                    key.0
                )
            };
            Err((reasons::NOT_ALLOWED, why))
        } else if let Err((_, message)) = &gw.accepted {
            Err((
                reasons::PARENT_NOT_ACCEPTED,
                format!("the parent Gateway is not accepted: {message}"),
            ))
        } else {
            Ok(())
        };
        let mut rejected = Vec::new();
        if accepted.is_ok() {
            let mut entries: Vec<ListenerState> = Vec::with_capacity(set.spec.listeners.len());
            for (i, entry) in set.spec.listeners.iter().enumerate() {
                let listener = as_listener(entry);
                let mut l =
                    evaluate_listener(cx, &id, (kinds::LISTENER_SET, key.0.as_str()), i, &listener);
                l.set = Some(index);
                if l.accepted.is_ok() {
                    l.conflict = conflict_with(
                        cx.gateways[gateway].listeners.iter().chain(entries.iter()),
                        &l,
                    );
                }
                if let Some(reason) = l.conflict {
                    cx.warn(
                        &id,
                        &format!(".spec.listeners[{i}]"),
                        format!(
                            "listener `{}` conflicts with a listener that takes precedence ({reason}); it is not used",
                            l.name
                        ),
                    );
                }
                entries.push(l);
            }
            if entries.iter().any(valid) {
                cx.gateways[gateway].listeners.extend(entries);
            } else {
                accepted = Err((
                    reasons::LISTENERS_NOT_VALID,
                    "no listener is valid".to_owned(),
                ));
                rejected = entries;
            }
        }
        if let Err((_, message)) = &accepted {
            cx.warn(&id, "", format!("not attached to its Gateway: {message}"));
        }
        cx.listener_set_index.insert(key.clone(), index);
        cx.listener_sets.push(ListenerSetState {
            key: key.clone(),
            generation: set.metadata.generation,
            gateway,
            accepted,
            rejected,
        });
    }
}

/// A listener that produces configuration: accepted, unconflicted, references resolved.
fn valid(l: &ListenerState) -> bool {
    l.active() && l.resolved.is_ok()
}

/// A ListenerSet entry as a Gateway listener (the fields are the same).
fn as_listener(entry: &ListenerEntry) -> Listener {
    Listener {
        name: entry.name.clone(),
        hostname: entry.hostname.clone(),
        port: entry.port,
        protocol: entry.protocol.clone(),
        tls: entry.tls.clone(),
        allowed_routes: entry.allowed_routes.clone(),
    }
}

/// `status.attachedListenerSets` of Gateway `gateway`: the accepted ListenerSets; unset when
/// the Gateway allows none and none is attached.
#[must_use]
pub fn attached_count(cx: &Context<'_>, gateway: usize) -> Option<i32> {
    let count = cx
        .listener_sets
        .iter()
        .filter(|s| s.gateway == gateway && s.accepted.is_ok())
        .count();
    if count == 0 && cx.gateways[gateway].allowed_listeners == Namespaces::None {
        None
    } else {
        Some(i32::try_from(count).unwrap_or(i32::MAX))
    }
}

/// Writes the status of every ListenerSet of ours, once routes have attached.
pub fn finish(cx: &mut Context<'_>) {
    let mut out = Vec::with_capacity(cx.listener_sets.len());
    for (index, state) in cx.listener_sets.iter().enumerate() {
        let generation = state.generation;
        let gw = &cx.gateways[state.gateway];
        let merged: Vec<&ListenerState> = gw
            .listeners
            .iter()
            .filter(|l| l.set == Some(index))
            .collect();
        let entries: Vec<&ListenerState> = match &state.accepted {
            Ok(()) => merged,
            Err(_) => state.rejected.iter().collect(),
        };
        let listeners: Vec<DesiredListener> = entries
            .iter()
            .map(|l| entry_status(l, generation))
            .collect();
        let conditions = if let Err((reason, message)) = &state.accepted {
            vec![
                condition(types::ACCEPTED, false, reason, message.clone(), generation),
                condition(
                    types::PROGRAMMED,
                    false,
                    reason,
                    message.clone(),
                    generation,
                ),
            ]
        } else {
            let invalid = entries.iter().filter(|l| !valid(l)).count();
            let accepted = if invalid == 0 {
                condition(
                    types::ACCEPTED,
                    true,
                    reasons::ACCEPTED,
                    "accepted",
                    generation,
                )
            } else {
                condition(
                    types::ACCEPTED,
                    true,
                    reasons::LISTENERS_NOT_VALID,
                    format!("{invalid} of {} listeners are not valid", entries.len()),
                    generation,
                )
            };
            vec![accepted, programmed(gw, &entries, generation)]
        };
        out.push((
            state.key.clone(),
            DesiredListenerSet {
                conditions,
                listeners,
            },
        ));
    }
    cx.out.status.listener_sets.extend(out);
}

/// `Programmed` of an accepted ListenerSet.
fn programmed(
    gw: &super::listeners::GatewayState<'_>,
    entries: &[&ListenerState],
    generation: Option<i64>,
) -> DesiredCondition {
    let addressed = gw.service.is_some_and(|s| !s.addresses.is_empty());
    let pending: std::collections::BTreeSet<u16> = entries
        .iter()
        .filter(|l| valid(l) && l.programmed.is_err())
        .map(|l| l.port)
        .collect();
    if !addressed {
        condition(
            types::PROGRAMMED,
            false,
            reasons::PARENT_NOT_PROGRAMMED,
            "waiting for the parent Gateway's Service to get an address",
            generation,
        )
    } else if !pending.is_empty() {
        condition(
            types::PROGRAMMED,
            false,
            reasons::PENDING,
            format!("waiting for the Gateway's Service to map ports {pending:?}"),
            generation,
        )
    } else {
        condition(
            types::PROGRAMMED,
            true,
            reasons::PROGRAMMED,
            "programmed",
            generation,
        )
    }
}

/// The status of one ListenerSet listener: as a Gateway listener's, except that a conflicted
/// listener's `Programmed` carries the conflict as its reason.
fn entry_status(l: &ListenerState, generation: Option<i64>) -> DesiredListener {
    let mut status = listener_status(l, generation);
    if let Some(reason) = l.conflict {
        for c in &mut status.conditions {
            if c.kind == types::PROGRAMMED {
                reason.clone_into(&mut c.reason);
                "the listener conflicts with a listener that takes precedence"
                    .clone_into(&mut c.message);
            }
        }
    }
    status
}
