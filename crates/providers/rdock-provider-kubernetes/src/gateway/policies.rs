//! BackendTLSPolicy (`backendtlspolicy_types.go`): TLS from the Gateway to a Service.
//!
//! A policy targets Services of its namespace (`targetRefs`, group `""`, kind `Service`),
//! optionally one port by name (`sectionName`). A backendRef of an HTTPRoute or GRPCRoute to
//! a targeted Service port is then spoken to over TLS (`scheme: https`), with
//! `validation.hostname` as SNI and verified name, and the CA bundle of the referenced
//! ConfigMap (`ca.crt`, written to [`crate::translate::config_map_path`]) or the system roots
//! (`wellKnownCACertificates: System`).
//!
//! - A policy naming the port wins over one for the whole Service; among policies for the
//!   same target the oldest wins (then the name) and the others are `Accepted=False/Conflicted`.
//! - A CA reference that is not a ConfigMap is `ResolvedRefs=False/InvalidKind`; a missing
//!   ConfigMap or one without a usable `ca.crt` is `InvalidCACertificateRef`; with no valid
//!   reference left the policy is also `Accepted=False/NoValidCACertificate` and, as the
//!   specification requires, requests to the backend fail with 500 instead of being sent
//!   without verification. Only one CA bundle is used (the first valid reference).
//! - `subjectAltNames` are not supported: such a policy is `Accepted=False/Invalid` and its
//!   backends answer 500 for the same reason.
//! - The status has one ancestor entry per Gateway of ours with a route using a targeted
//!   Service; policies no route of ours uses get no entry.
//!
//! The feature is not claimed (`BackendTLSPolicy` stays out of `supportedFeatures`) until the
//! upstream tests run in CI.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use rdock_model::service::UpstreamTls;

use super::Context;
use super::conditions::{condition, reasons, types};
use crate::api::{GROUP, ParentReference, kinds};
use crate::inventory::ObjectKey;
use crate::translate::{DesiredPolicyAncestor, config_map_path};

/// A policy, evaluated.
#[derive(Debug, Clone)]
pub struct PolicyState {
    /// Conflicted with an older policy for the same target.
    pub conflicted: bool,
    /// The TLS settings, or why the policy is not usable.
    pub tls: Result<UpstreamTls, PolicyFailure>,
    /// The ConfigMap whose bundle is used.
    pub config_map: Option<ObjectKey>,
    /// Gateways of ours whose routes use a targeted Service.
    pub ancestors: BTreeSet<ObjectKey>,
}

/// The TLS a backend gets from a policy: the policy and its settings, or an error (the
/// backend must then fail).
pub type BackendTls = (ObjectKey, Result<UpstreamTls, ()>);

/// Why a policy is not usable: (`Accepted` reason, `ResolvedRefs` reason or `None` when the
/// references resolve, message).
pub type PolicyFailure = (&'static str, Option<&'static str>, String);

/// Target (namespace, Service, section) → policies with their creation time.
type Targets<'a> =
    BTreeMap<(String, String, Option<String>), Vec<(Option<&'a Time>, &'a ObjectKey)>>;

/// Evaluates every BackendTLSPolicy.
pub fn evaluate(cx: &mut Context<'_>) {
    let inventory = cx.inventory;
    let conflicted = conflicts(inventory);
    for (key, policy) in &inventory.backend_tls_policies {
        let id = super::object_id(kinds::BACKEND_TLS_POLICY, &key.0, &key.1);
        let (tls, config_map, warning) = policy_tls(
            inventory,
            &cx.settings.data_dir,
            key,
            &policy.spec.validation,
        );
        if let Some(message) = warning {
            cx.warn(&id, ".spec.validation.caCertificateRefs", message);
        }
        if let Err((_, _, message)) = &tls {
            cx.warn(&id, ".spec.validation", message.clone());
        }
        cx.policies.insert(
            key.clone(),
            PolicyState {
                conflicted: conflicted.contains(key),
                tls,
                config_map,
                ancestors: BTreeSet::new(),
            },
        );
    }
}

/// The policies that lose to an older one for the same target.
fn conflicts(inventory: &crate::inventory::Inventory) -> BTreeSet<ObjectKey> {
    let mut targets: Targets<'_> = BTreeMap::new();
    for (key, policy) in &inventory.backend_tls_policies {
        for target in &policy.spec.target_refs {
            if target.group.is_empty() && target.kind == "Service" {
                targets
                    .entry((
                        key.0.clone(),
                        target.name.clone(),
                        target.section_name.clone(),
                    ))
                    .or_default()
                    .push((policy.metadata.creation_timestamp.as_ref(), key));
            }
        }
    }
    let mut conflicted = BTreeSet::new();
    for policies in targets.values_mut() {
        policies.sort();
        for (_, key) in policies.iter().skip(1) {
            conflicted.insert((*key).clone());
        }
    }
    conflicted
}

/// The TLS settings of a policy, the ConfigMap it uses, and a warning about ignored CA
/// references.
fn policy_tls(
    inventory: &crate::inventory::Inventory,
    data_dir: &std::path::Path,
    key: &ObjectKey,
    validation: &crate::api::BackendTLSPolicyValidation,
) -> (
    Result<UpstreamTls, PolicyFailure>,
    Option<ObjectKey>,
    Option<String>,
) {
    let settings = |ca_file| UpstreamTls {
        verify: true,
        server_name: Some(validation.hostname.clone()),
        ca_file,
        cert_file: None,
        key_file: None,
    };
    if !validation.subject_alt_names.is_empty() {
        let failure = (
            reasons::INVALID,
            None,
            "subjectAltNames are not supported".to_owned(),
        );
        return (Err(failure), None, None);
    }
    if validation.ca_certificate_refs.is_empty() {
        return match validation.well_known_ca_certificates.as_deref() {
            Some("System") => (Ok(settings(None)), None, None),
            other => {
                let message = format!(
                    "wellKnownCACertificates `{}` is not supported",
                    other.unwrap_or_default()
                );
                (Err((reasons::INVALID, None, message)), None, None)
            }
        };
    }
    let mut config_map = None;
    let mut failure = None;
    for r in &validation.ca_certificate_refs {
        let problem = if !r.group.is_empty() || r.kind != "ConfigMap" {
            Some((
                reasons::INVALID_CA_CERTIFICATE_KIND,
                format!(
                    "CA certificate reference to a `{}` is not supported",
                    r.kind
                ),
            ))
        } else {
            match inventory.config_maps.get(&(key.0.clone(), r.name.clone())) {
                None => Some((
                    reasons::INVALID_CA_CERTIFICATE_REF,
                    format!("ConfigMap {}/{} does not exist", key.0, r.name),
                )),
                Some(cm) => cm.ca_bundle.as_ref().err().map(|why| {
                    (
                        reasons::INVALID_CA_CERTIFICATE_REF,
                        format!("ConfigMap {}/{}: {why}", key.0, r.name),
                    )
                }),
            }
        };
        match problem {
            None if config_map.is_none() => config_map = Some((key.0.clone(), r.name.clone())),
            Some(p) if failure.is_none() => failure = Some(p),
            _ => {}
        }
    }
    match (config_map, failure) {
        (None, failure) => {
            let (resolved, message) = failure.unwrap_or((
                reasons::INVALID_CA_CERTIFICATE_REF,
                "no CA certificate".to_owned(),
            ));
            (
                Err((reasons::NO_VALID_CA_CERTIFICATE, Some(resolved), message)),
                None,
                None,
            )
        }
        (Some(cm), failure) => {
            let file = config_map_path(data_dir, &cm.0, &cm.1);
            let warning = failure.map(|(_, m)| format!("{m}; the first valid CA bundle is used"));
            (Ok(settings(Some(file))), Some(cm), warning)
        }
    }
}

/// The policy for port `port_name` of Service `namespace/service`, if any.
#[must_use]
pub fn backend_tls(
    cx: &Context<'_>,
    namespace: &str,
    service: &str,
    port_name: Option<&str>,
) -> Option<BackendTls> {
    let applies = |section: Option<&str>| {
        cx.inventory
            .backend_tls_policies
            .iter()
            .filter(|((ns, _), _)| ns == namespace)
            .filter(|(key, _)| cx.policies.get(*key).is_some_and(|p| !p.conflicted))
            .find(|(_, policy)| {
                policy.spec.target_refs.iter().any(|t| {
                    t.group.is_empty()
                        && t.kind == "Service"
                        && t.name == service
                        && t.section_name.as_deref() == section
                })
            })
            .map(|(key, _)| key.clone())
    };
    let key = port_name
        .and_then(|p| applies(Some(p)))
        .or_else(|| applies(None))?;
    let state = cx.policies.get(&key)?;
    Some((key, state.tls.clone().map_err(|_| ())))
}

/// Writes the status of the policies used by routes of ours, and names their CA bundles.
pub fn finish(cx: &mut Context<'_>) {
    for (key, state) in &cx.policies {
        if state.ancestors.is_empty() {
            continue;
        }
        let generation = cx
            .inventory
            .backend_tls_policies
            .get(key)
            .and_then(|p| p.metadata.generation);
        let (accepted, resolved) = match (&state.tls, state.conflicted) {
            (_, true) => (
                condition(
                    types::ACCEPTED,
                    false,
                    reasons::CONFLICTED,
                    "an older policy targets the same Service port",
                    generation,
                ),
                condition(
                    types::RESOLVED_REFS,
                    true,
                    reasons::RESOLVED_REFS,
                    "",
                    generation,
                ),
            ),
            (Ok(_), false) => (
                condition(
                    types::ACCEPTED,
                    true,
                    reasons::ACCEPTED,
                    "accepted",
                    generation,
                ),
                condition(
                    types::RESOLVED_REFS,
                    true,
                    reasons::RESOLVED_REFS,
                    "references resolved",
                    generation,
                ),
            ),
            (Err((accepted, resolved, message)), false) => (
                condition(
                    types::ACCEPTED,
                    false,
                    accepted,
                    message.clone(),
                    generation,
                ),
                match resolved {
                    Some(reason) => condition(
                        types::RESOLVED_REFS,
                        false,
                        reason,
                        message.clone(),
                        generation,
                    ),
                    None => condition(
                        types::RESOLVED_REFS,
                        true,
                        reasons::RESOLVED_REFS,
                        "references resolved",
                        generation,
                    ),
                },
            ),
        };
        let entries = state
            .ancestors
            .iter()
            .map(|gw| DesiredPolicyAncestor {
                ancestor_ref: ParentReference {
                    group: Some(GROUP.to_owned()),
                    kind: Some(kinds::GATEWAY.to_owned()),
                    namespace: Some(gw.0.clone()),
                    name: gw.1.clone(),
                    section_name: None,
                    port: None,
                },
                conditions: vec![accepted.clone(), resolved.clone()],
            })
            .collect();
        cx.out
            .status
            .backend_tls_policies
            .insert(key.clone(), entries);
        if state.tls.is_ok()
            && !state.conflicted
            && let Some(cm) = &state.config_map
        {
            cx.out.config_maps.insert(cm.clone());
        }
    }
}
