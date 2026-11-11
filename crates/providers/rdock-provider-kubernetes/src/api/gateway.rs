//! `Gateway`.

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    LabelSelector, LocalObjectReference, ObjectReference, RouteGroupKind, SecretObjectReference,
};

/// Listener protocols (`Listener.protocol`), as the Gateway API writes them.
pub mod protocols {
    /// `HTTP`.
    pub const HTTP: &str = "HTTP";
    /// `HTTPS`.
    pub const HTTPS: &str = "HTTPS";
    /// `TLS`.
    pub const TLS: &str = "TLS";
    /// `TCP`.
    pub const TCP: &str = "TCP";
    /// `UDP`.
    pub const UDP: &str = "UDP";
}

/// TLS modes of a listener (`ListenerTLSConfig.mode`).
pub mod tls_modes {
    /// `Terminate` (the default).
    pub const TERMINATE: &str = "Terminate";
    /// `Passthrough`.
    pub const PASSTHROUGH: &str = "Passthrough";
}

/// `FromNamespaces` values of `allowedRoutes.namespaces.from` and
/// `allowedListeners.namespaces.from`.
pub mod from_namespaces {
    /// `Same` (the default for routes).
    pub const SAME: &str = "Same";
    /// `All`.
    pub const ALL: &str = "All";
    /// `Selector`.
    pub const SELECTOR: &str = "Selector";
    /// `None` (the default for ListenerSets).
    pub const NONE: &str = "None";
}

/// `gateway.networking.k8s.io/v1` Gateway.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "Gateway",
    namespaced,
    status = "GatewayStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// The GatewayClass this Gateway belongs to.
    #[serde(default)]
    pub gateway_class_name: String,
    /// Listeners: name, port, protocol, hostname, TLS and allowed routes.
    #[serde(default)]
    pub listeners: Vec<Listener>,
    /// Requested addresses (static addresses are not supported; they are reported).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<GatewaySpecAddress>,
    /// Labels and annotations for the resources the controller creates (the per-Gateway
    /// Service).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infrastructure: Option<GatewayInfrastructure>,
    /// Which ListenerSets may attach to this Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_listeners: Option<AllowedListeners>,
    /// Gateway-wide TLS settings (backend client certificate, frontend validation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<GatewayTlsConfig>,
    /// `All` or `None`: whether routes may attach without a parentRef (Experimental).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_scope: Option<String>,
}

/// One listener of a Gateway.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    /// Unique name within the Gateway (a route's `sectionName`).
    #[serde(default)]
    pub name: String,
    /// Host name (`app.example.com` or `*.example.com`); every host when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Port.
    #[serde(default)]
    pub port: u16,
    /// `HTTP`, `HTTPS`, `TLS`, `TCP`, `UDP` ([`protocols`]) or an implementation-specific
    /// value, which is reported as unsupported.
    #[serde(default)]
    pub protocol: String,
    /// TLS settings for `HTTPS` and `TLS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ListenerTlsConfig>,
    /// Which routes may attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_routes: Option<AllowedRoutes>,
}

/// TLS settings of a listener.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListenerTlsConfig {
    /// `Terminate` (default) or `Passthrough` ([`tls_modes`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Certificates (normally `kubernetes.io/tls` Secrets).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_refs: Vec<SecretObjectReference>,
    /// Implementation-specific options (none are supported).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
}

/// Which routes may attach to a listener.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllowedRoutes {
    /// Namespaces routes may come from; `Same` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<RouteNamespaces>,
    /// Route kinds; when empty, the kinds the listener's protocol supports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<RouteGroupKind>,
}

/// Namespaces routes (or ListenerSets) may come from.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteNamespaces {
    /// `Same`, `All`, `Selector` ([`from_namespaces`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Label selector of the namespaces, for `Selector`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(skip)]
    pub selector: Option<LabelSelector>,
}

/// Which ListenerSets may attach to a Gateway.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllowedListeners {
    /// Namespaces ListenerSets may come from; `None` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<RouteNamespaces>,
}

/// A requested Gateway address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpecAddress {
    /// `IPAddress`, `Hostname` or `NamedAddress`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The address; empty lets the implementation choose.
    #[serde(default)]
    pub value: String,
}

/// Infrastructure settings of a Gateway.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayInfrastructure {
    /// Labels for the per-Gateway Service.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Annotations for the per-Gateway Service.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// Implementation-specific parameters (none are supported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters_ref: Option<LocalObjectReference>,
}

/// Gateway-wide TLS settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayTlsConfig {
    /// TLS towards backends: the client certificate the Gateway presents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<GatewayBackendTls>,
    /// TLS towards clients: client certificate validation, by default and per port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend: Option<FrontendTlsConfig>,
}

/// The client certificate a Gateway presents to backends.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayBackendTls {
    /// A `kubernetes.io/tls` Secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_ref: Option<SecretObjectReference>,
}

/// Client certificate validation of a Gateway.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrontendTlsConfig {
    /// Settings for every port.
    #[serde(default)]
    pub default: FrontendTls,
    /// Settings for some ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_port: Vec<FrontendTlsPort>,
}

/// Client certificate validation settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrontendTls {
    /// The CA certificates and the mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<FrontendTlsValidation>,
}

/// Client certificate validation for one port.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrontendTlsPort {
    /// Port.
    #[serde(default)]
    pub port: u16,
    /// Settings.
    #[serde(default)]
    pub tls: FrontendTls,
}

/// CA certificates for client certificate validation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrontendTlsValidation {
    /// ConfigMaps (or Secrets) with `ca.crt`.
    #[serde(default)]
    pub ca_certificate_refs: Vec<ObjectReference>,
    /// `AllowValidOnly` (default) or `AllowInsecureFallback`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// Status of a Gateway.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatus {
    /// Addresses the Gateway is reachable at (the per-Gateway Service's).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<GatewayStatusAddress>,
    /// `Accepted`, `Programmed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
    /// One entry per listener.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<ListenerStatus>,
    /// ListenerSets attached to this Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_listener_sets: Option<i32>,
}

/// An address in a Gateway's status.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatusAddress {
    /// `IPAddress` or `Hostname`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The address.
    #[serde(default)]
    pub value: String,
}

/// Status of one listener.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    /// Listener name.
    #[serde(default)]
    pub name: String,
    /// Route kinds the listener accepts.
    #[serde(default)]
    pub supported_kinds: Vec<RouteGroupKind>,
    /// Routes attached (accepted) to this listener.
    #[serde(default)]
    pub attached_routes: i32,
    /// `Accepted`, `Programmed`, `ResolvedRefs`, `Conflicted`.
    #[serde(default)]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}
