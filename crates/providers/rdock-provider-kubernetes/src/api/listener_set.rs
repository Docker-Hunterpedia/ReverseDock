//! `ListenerSet`.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{AllowedRoutes, ListenerTlsConfig, ParentGatewayReference, RouteGroupKind};

/// `gateway.networking.k8s.io/v1` ListenerSet: listeners merged into a parent Gateway that
/// allows them (`allowedListeners`).
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "ListenerSet",
    namespaced,
    status = "ListenerSetStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct ListenerSetSpec {
    /// The Gateway the listeners join.
    #[serde(default)]
    pub parent_ref: ParentGatewayReference,
    /// The listeners.
    #[serde(default)]
    pub listeners: Vec<ListenerEntry>,
}

/// A listener of a ListenerSet (the fields of a Gateway listener).
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListenerEntry {
    /// Unique name within the ListenerSet.
    #[serde(default)]
    pub name: String,
    /// Host name; every host when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Port.
    #[serde(default)]
    pub port: u16,
    /// `HTTP`, `HTTPS`, `TLS`, `TCP`, `UDP`.
    #[serde(default)]
    pub protocol: String,
    /// TLS settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ListenerTlsConfig>,
    /// Which routes may attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_routes: Option<AllowedRoutes>,
}

/// Status of a ListenerSet.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListenerSetStatus {
    /// `Accepted`, `Programmed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
    /// One entry per listener.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<ListenerEntryStatus>,
}

/// Status of one ListenerSet listener.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListenerEntryStatus {
    /// Listener name.
    #[serde(default)]
    pub name: String,
    /// Route kinds the listener accepts.
    #[serde(default)]
    pub supported_kinds: Vec<RouteGroupKind>,
    /// Routes attached.
    #[serde(default)]
    pub attached_routes: i32,
    /// `Accepted`, `Programmed`, `ResolvedRefs`, `Conflicted`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}
