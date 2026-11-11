//! Ingress translation (W-K8S-02, ADR-0029, "Ingress").
//!
//! **Owner:** the Ingress translator. Only this module (and files below `src/ingress/`)
//! changes for it; the shared types live in [`crate::inventory`] and [`mod@crate::translate`].
//!
//! It turns the Ingresses we claim into routes on the file configuration's default
//! listeners ([`rules`]), services, middlewares for the supported ingress-nginx annotations
//! ([`annotations`]) and certificates for `spec.tls` Secrets, plus the desired
//! `status.loadBalancer` of each claimed Ingress. Ingress opens no ports. Called only when
//! `providers.kubernetes.ingress.enabled` is true.
//!
//! **Claiming.** An Ingress is ours when
//! - `spec.ingressClassName` names an IngressClass of ours (`spec.controller` is
//!   [`INGRESS_CONTROLLER`]); the field wins over the deprecated annotation, which the API
//!   server does not let be set together with it anyway; or
//! - there is no such field and `kubernetes.io/ingress.class` equals `ingress.class`; or
//! - it names no class at all, and one of our IngressClasses is the cluster default
//!   (`ingressclass.kubernetes.io/is-default-class: "true"`) or `ingress.claim_without_class`
//!   is on.
//!
//! An Ingress of another class is untouched: no routes, no status, no diagnostics.
//!
//! **Status.** Each claimed Ingress gets the addresses of `ingress.publish_address` (an IP or
//! a host name), else of Service `ingress.publish_service` (`namespace/name`: its
//! load-balancer ingress, or its cluster IP for a `ClusterIP` Service). With neither
//! configured the list is empty (nothing is written) and one diagnostic says so.

pub mod annotations;
pub mod rules;

use std::collections::BTreeMap;
use std::net::IpAddr;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::Ingress;
use rdock_model::Diagnostic;

use crate::gateway::{object_id, object_path};
use crate::inventory::{Inventory, ObjectKey};
use crate::translate::{INGRESS_CONTROLLER, LoadBalancerAddress, Settings, Translation};

/// The annotation that marks the default IngressClass.
pub const DEFAULT_CLASS_ANNOTATION: &str = "ingressclass.kubernetes.io/is-default-class";

/// Translates the Ingress objects of `inventory`.
#[must_use]
pub fn translate(inventory: &Inventory, settings: &Settings) -> Translation {
    let claimed: Vec<(&ObjectKey, &Ingress)> = inventory
        .ingresses
        .iter()
        .filter(|(_, ingress)| is_claimed(inventory, settings, ingress))
        .collect();
    let mut builder = rules::Builder {
        inventory,
        settings,
        out: Translation::default(),
    };
    let ranks = ranks(&claimed);
    for (key, ingress) in &claimed {
        let rank = ranks.get(*key).copied().unwrap_or(usize::MAX);
        rules::translate(&mut builder, key, ingress, rank);
    }
    status(&mut builder, &claimed);
    builder.out
}

/// The rank of every claimed Ingress for precedence: oldest `creationTimestamp` first (a
/// missing one last), then `namespace/name`.
fn ranks(claimed: &[(&ObjectKey, &Ingress)]) -> BTreeMap<ObjectKey, usize> {
    let mut all: Vec<_> = claimed
        .iter()
        .map(|(key, ingress)| {
            let created = ingress.metadata.creation_timestamp.as_ref();
            (created.is_none(), created, (*key).clone())
        })
        .collect();
    all.sort();
    all.into_iter()
        .enumerate()
        .map(|(rank, (_, _, key))| (key, rank))
        .collect()
}

/// Whether `ingress` is one of ours (see the module documentation).
#[must_use]
pub fn is_claimed(inventory: &Inventory, settings: &Settings, ingress: &Ingress) -> bool {
    let ours = |class: &k8s_openapi::api::networking::v1::IngressClass| {
        class
            .spec
            .as_ref()
            .and_then(|spec| spec.controller.as_deref())
            == Some(INGRESS_CONTROLLER)
    };
    let field = ingress
        .spec
        .as_ref()
        .and_then(|spec| spec.ingress_class_name.as_deref())
        .filter(|name| !name.is_empty());
    if let Some(name) = field {
        return inventory.ingress_classes.get(name).is_some_and(ours);
    }
    let annotation = ingress
        .metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(annotations::CLASS_ANNOTATION))
        .filter(|value| !value.is_empty());
    if let Some(value) = annotation {
        return *value == settings.provider.ingress.class;
    }
    settings.provider.ingress.claim_without_class
        || inventory.ingress_classes.values().any(|class| {
            ours(class)
                && class
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get(DEFAULT_CLASS_ANNOTATION))
                    .is_some_and(|v| v == "true")
        })
}

/// The desired `status.loadBalancer.ingress` of every claimed Ingress.
fn status(b: &mut rules::Builder<'_>, claimed: &[(&ObjectKey, &Ingress)]) {
    if claimed.is_empty() {
        return;
    }
    let ingress = &b.settings.provider.ingress;
    let addresses = if let Some(address) =
        ingress.publish_address.as_deref().filter(|a| !a.is_empty())
    {
        vec![address_of(address)]
    } else if let Some(service) = ingress.publish_service.as_deref().filter(|s| !s.is_empty()) {
        service_addresses(b, service)
    } else {
        b.out.diagnostics.push(
            Diagnostic::warning(
                "providers.kubernetes.ingress",
                "neither `publish_address` nor `publish_service` is set: the status of Ingresses is not written",
            )
            .with_hint("set `providers.kubernetes.ingress.publish_service` to the namespace/name of the Service that exposes ReverseDock, or `publish_address`"),
        );
        Vec::new()
    };
    for (key, _) in claimed {
        b.out
            .status
            .ingresses
            .insert((*key).clone(), addresses.clone());
    }
}

/// An IP address or a host name.
fn address_of(value: &str) -> LoadBalancerAddress {
    if value.parse::<IpAddr>().is_ok() {
        LoadBalancerAddress {
            ip: Some(value.to_owned()),
            hostname: None,
        }
    } else {
        LoadBalancerAddress {
            ip: None,
            hostname: Some(value.to_owned()),
        }
    }
}

/// The addresses of Service `reference` (`namespace/name`).
fn service_addresses(b: &mut rules::Builder<'_>, reference: &str) -> Vec<LoadBalancerAddress> {
    let path = "providers.kubernetes.ingress.publish_service";
    let Some((namespace, name)) = reference
        .split_once('/')
        .filter(|(n, s)| !n.is_empty() && !s.is_empty())
    else {
        b.out.diagnostics.push(Diagnostic::warning(
            path,
            format!(
                "`{reference}` is not `namespace/name`: the status of Ingresses is not written"
            ),
        ));
        return Vec::new();
    };
    let service: Option<&Service> = b
        .inventory
        .services
        .get(&(namespace.to_owned(), name.to_owned()));
    let Some(service) = service else {
        b.out.diagnostics.push(Diagnostic::warning(
            object_path(&object_id("Service", namespace, name), ""),
            "the publish_service does not exist: the status of Ingresses is not written until it does",
        ));
        return Vec::new();
    };
    let mut addresses: Vec<LoadBalancerAddress> = service
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .into_iter()
        .flatten()
        .flat_map(|entry| {
            [
                entry.ip.as_deref().map(|ip| LoadBalancerAddress {
                    ip: Some(ip.to_owned()),
                    hostname: None,
                }),
                entry
                    .hostname
                    .as_deref()
                    .map(|hostname| LoadBalancerAddress {
                        ip: None,
                        hostname: Some(hostname.to_owned()),
                    }),
            ]
        })
        .flatten()
        .collect();
    if addresses.is_empty() {
        let spec = service.spec.as_ref();
        let cluster_ip = spec
            .filter(|s| matches!(s.type_.as_deref(), None | Some("ClusterIP")))
            .and_then(|s| s.cluster_ip.as_deref())
            .filter(|ip| !ip.is_empty() && *ip != "None");
        if let Some(ip) = cluster_ip {
            addresses.push(LoadBalancerAddress {
                ip: Some(ip.to_owned()),
                hostname: None,
            });
        }
    }
    if addresses.is_empty() {
        b.out.diagnostics.push(Diagnostic::warning(
            object_path(&object_id("Service", namespace, name), ".status.loadBalancer"),
            "the publish_service has no address yet: the status of Ingresses is not written until it has",
        ));
    }
    addresses.sort();
    addresses.dedup();
    addresses
}
