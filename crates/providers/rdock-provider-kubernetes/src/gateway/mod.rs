//! Gateway API translation (W-K8S-01, ADR-0029, "Translating the Gateway API").
//!
//! **Owner:** the Gateway API translator. Only this module (and files below `src/gateway/`)
//! changes for it; the shared types live in [`crate::api`], [`crate::inventory`] and
//! [`mod@crate::translate`].
//!
//! It turns GatewayClasses with our controller name, their Gateways (and ListenerSets), the
//! routes attached to them, ReferenceGrants, BackendTLSPolicies, Services and EndpointSlices
//! into fragment listeners, certificates, routes, services and middlewares, the desired
//! status of every object of ours, the per-Gateway Services, and the Secrets and ConfigMaps
//! to write as files.
//!
//! Status: a stub that translates nothing yet.

use crate::inventory::Inventory;
use crate::translate::{Settings, Translation};

/// Translates the Gateway API objects of `inventory`.
#[must_use]
pub fn translate(inventory: &Inventory, settings: &Settings) -> Translation {
    let _ = (inventory, settings);
    Translation::default()
}
