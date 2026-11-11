//! `TLSRoute`, `TCPRoute` and `UDPRoute`.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{BackendRef, ParentReference, RouteStatus};

/// One rule of a TLS, TCP or UDP route: backends only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct L4RouteRule {
    /// Rule name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Weighted backends.
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
}

/// `gateway.networking.k8s.io/v1` TLSRoute: routes TLS connections by SNI (passthrough, or
/// terminated on a `Terminate` listener).
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "TLSRoute",
    namespaced,
    status = "RouteStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct TLSRouteSpec {
    /// Gateways (or ListenerSets) and their listeners this route attaches to.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,
    /// SNI host names.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Rules.
    #[serde(default)]
    pub rules: Vec<L4RouteRule>,
}

/// `gateway.networking.k8s.io/v1` TCPRoute.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "TCPRoute",
    namespaced,
    status = "RouteStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct TCPRouteSpec {
    /// Gateways (or ListenerSets) and their listeners this route attaches to.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,
    /// Rules.
    #[serde(default)]
    pub rules: Vec<L4RouteRule>,
}

/// `gateway.networking.k8s.io/v1` UDPRoute (UDP is planned for v0.8; the listener reports
/// `UnsupportedProtocol`).
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "UDPRoute",
    namespaced,
    status = "RouteStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct UDPRouteSpec {
    /// Gateways (or ListenerSets) and their listeners this route attaches to.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,
    /// Rules.
    #[serde(default)]
    pub rules: Vec<L4RouteRule>,
}
