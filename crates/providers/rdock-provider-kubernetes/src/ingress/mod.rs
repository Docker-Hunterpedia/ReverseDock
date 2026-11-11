//! Ingress translation (W-K8S-02, ADR-0029, "Ingress").
//!
//! **Owner:** the Ingress translator. Only this module (and files below `src/ingress/`)
//! changes for it; the shared types live in [`crate::inventory`] and [`mod@crate::translate`].
//!
//! It turns the Ingresses we claim (by IngressClass, the deprecated class annotation, or no
//! class) into routes on the file configuration's default listeners, services, middlewares
//! for the supported ingress-nginx annotations and certificates for `spec.tls` Secrets, plus
//! the desired `status.loadBalancer` of each claimed Ingress. Ingress opens no ports.
//! Called only when `providers.kubernetes.ingress.enabled` is true.
//!
//! Status: a stub that translates nothing yet.

use crate::inventory::Inventory;
use crate::translate::{Settings, Translation};

/// Translates the Ingress objects of `inventory`.
#[must_use]
pub fn translate(inventory: &Inventory, settings: &Settings) -> Translation {
    let _ = (inventory, settings);
    Translation::default()
}
