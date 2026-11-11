//! GatewayClasses (`gatewayclass_types.go`).
//!
//! A class is ours when its `spec.controllerName` equals `providers.kubernetes.controller_name`;
//! only those get a status. Ours is `Accepted=True` unless it names `parametersRef` (no
//! parameters kind is supported: `Accepted=False/InvalidParameters`).
//!
//! `SupportedVersion` compares the installed CRD bundle (`gateway.networking.k8s.io/bundle-version`)
//! with [`crate::api::BUNDLE_VERSION`]: the same major and minor version is supported (patch
//! releases of the Gateway API do not change the API), anything else, or an unknown bundle,
//! is `SupportedVersion=False/UnsupportedVersion` while the class stays accepted: the
//! specification allows this "best effort" support, and every field is read leniently.

use std::collections::BTreeSet;

use super::Context;
use super::conditions::{condition, reasons, types};
use crate::api::{BUNDLE_VERSION, SupportedFeature};
use crate::translate::DesiredGatewayClass;

/// Writes the status of our classes and returns the names of the accepted ones.
pub fn translate(cx: &mut Context<'_>) -> BTreeSet<String> {
    let mut accepted = BTreeSet::new();
    let controller = cx.settings.provider.controller_name.as_str();
    for (name, class) in &cx.inventory.gateway_classes {
        if class.spec.controller_name != controller {
            continue;
        }
        let generation = class.metadata.generation;
        let mut conditions = Vec::new();
        if class.spec.parameters_ref.is_some() {
            conditions.push(condition(
                types::ACCEPTED,
                false,
                reasons::INVALID_PARAMETERS,
                "parametersRef is not supported by this controller",
                generation,
            ));
            cx.warn(
                &format!("GatewayClass/{name}"),
                ".spec.parametersRef",
                "parametersRef is not supported; the class is not accepted",
            );
        } else {
            conditions.push(condition(
                types::ACCEPTED,
                true,
                reasons::ACCEPTED,
                "accepted by ReverseDock",
                generation,
            ));
            accepted.insert(name.clone());
        }
        let (supported, message) = version_supported(cx.inventory.crd_bundle_version.as_deref());
        conditions.push(condition(
            types::SUPPORTED_VERSION,
            supported,
            if supported {
                reasons::SUPPORTED_VERSION
            } else {
                reasons::UNSUPPORTED_VERSION
            },
            message,
            generation,
        ));
        if !supported {
            cx.warn(
                &format!("GatewayClass/{name}"),
                "",
                version_supported(cx.inventory.crd_bundle_version.as_deref()).1,
            );
        }
        cx.out.status.gateway_classes.insert(
            name.clone(),
            DesiredGatewayClass {
                conditions,
                supported_features: crate::features::SUPPORTED
                    .iter()
                    .map(|name| SupportedFeature {
                        name: (*name).to_owned(),
                    })
                    .collect(),
            },
        );
    }
    accepted
}

/// Whether the installed bundle version is supported, and the message for the condition.
#[must_use]
pub fn version_supported(installed: Option<&str>) -> (bool, String) {
    let Some(installed) = installed else {
        return (
            false,
            format!(
                "the installed Gateway API bundle version is unknown; ReverseDock supports {BUNDLE_VERSION}"
            ),
        );
    };
    let minor = |v: &str| -> Option<(u32, u32)> {
        let mut parts = v.trim_start_matches('v').split(['.', '-']);
        Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
    };
    if minor(installed).is_some() && minor(installed) == minor(BUNDLE_VERSION) {
        (
            true,
            format!("Gateway API {installed} is supported (ReverseDock follows {BUNDLE_VERSION})"),
        )
    } else {
        (
            false,
            format!(
                "Gateway API {installed} is installed; ReverseDock supports {BUNDLE_VERSION} (same minor version)"
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_minor_version_is_supported() {
        assert!(version_supported(Some("v1.7.0")).0);
        assert!(version_supported(Some("v1.7.3")).0);
        assert!(version_supported(Some("v1.7.0-rc.1")).0);
        assert!(!version_supported(Some("v1.6.3")).0);
        assert!(!version_supported(Some("v2.7.0")).0);
        assert!(!version_supported(Some("garbage")).0);
        assert!(!version_supported(None).0);
    }
}
