//! `GRPCRoute`.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    BackendRef, HTTPHeaderFilter, HTTPRequestMirrorFilter, LocalObjectReference, ParentReference,
    RouteStatus, SessionPersistence,
};

/// `gateway.networking.k8s.io/v1` GRPCRoute.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "GRPCRoute",
    namespaced,
    status = "RouteStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct GRPCRouteSpec {
    /// Gateways (or ListenerSets) and their listeners this route attaches to.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,
    /// Host names; every host the listener accepts when empty.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Rules.
    #[serde(default)]
    pub rules: Vec<GRPCRouteRule>,
}

/// One rule of a GRPCRoute.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCRouteRule {
    /// Rule name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Matches, any of which selects the rule; every request when empty.
    #[serde(default)]
    pub matches: Vec<GRPCRouteMatch>,
    /// Filters applied in order.
    #[serde(default)]
    pub filters: Vec<GRPCRouteFilter>,
    /// Backends (`h2c` unless the Service's `appProtocol` says otherwise).
    #[serde(default)]
    pub backend_refs: Vec<GRPCBackendRef>,
    /// Session persistence (not supported yet; reported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_persistence: Option<SessionPersistence>,
}

/// One match of a GRPCRoute rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCRouteMatch {
    /// Service and method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<GRPCMethodMatch>,
    /// Headers (`Exact` or `RegularExpression`).
    #[serde(default)]
    pub headers: Vec<GRPCHeaderMatch>,
}

/// A gRPC service and method match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCMethodMatch {
    /// `Exact` (default) or `RegularExpression`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Fully qualified service, e.g. `foo.bar.Greeter`; every service when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Method; every method when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// A gRPC header match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCHeaderMatch {
    /// `Exact` (default) or `RegularExpression`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Header name.
    #[serde(default)]
    pub name: String,
    /// Value or pattern.
    #[serde(default)]
    pub value: String,
}

/// A filter of a GRPCRoute rule or backendRef.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCRouteFilter {
    /// `RequestHeaderModifier`, `ResponseHeaderModifier`, `RequestMirror`, `ExtensionRef`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// For `RequestHeaderModifier`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_header_modifier: Option<HTTPHeaderFilter>,
    /// For `ResponseHeaderModifier`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_header_modifier: Option<HTTPHeaderFilter>,
    /// For `RequestMirror`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_mirror: Option<HTTPRequestMirrorFilter>,
    /// For `ExtensionRef` (not supported; the rule is rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_ref: Option<LocalObjectReference>,
}

/// A weighted backend of a GRPCRoute rule, with its own filters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GRPCBackendRef {
    /// The backend and its weight.
    #[serde(flatten)]
    pub backend: BackendRef,
    /// Filters for requests to this backend only.
    #[serde(default)]
    pub filters: Vec<GRPCRouteFilter>,
}
