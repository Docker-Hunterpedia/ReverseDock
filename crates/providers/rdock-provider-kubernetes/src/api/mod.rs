//! Our own Gateway API v1 types (ADR-0029): `gateway.networking.k8s.io/v1` as of v1.7.0,
//! Standard channel. Field names follow the upstream Go types
//! (`sigs.k8s.io/gateway-api/apis/v1`); only the fields the translator reads are modelled,
//! and unknown fields are ignored.
//!
//! Robustness rules, so that a newer API never makes a whole object fail to deserialise:
//! - every optional field has `#[serde(default)]`;
//! - enumerations (protocols, match types, filter types, modes) are plain `String`s, compared
//!   with the constants next to them, and unknown values are reported by the translator;
//! - durations are kept as the Gateway API's strings (`"1h2m3s"`, see [`parse_duration`]).
//!
//! `JsonSchema` is derived only because `#[derive(CustomResource)]` requires it; the schema
//! is disabled. Fields of k8s-openapi types that have no `JsonSchema` are `#[schemars(skip)]`.

mod backend_tls_policy;
mod gateway;
mod gateway_class;
mod grpc_route;
mod http_route;
mod l4_routes;
mod listener_set;
mod reference_grant;

pub use backend_tls_policy::*;
pub use gateway::*;
pub use gateway_class::*;
pub use grpc_route::*;
pub use http_route::*;
pub use l4_routes::*;
pub use listener_set::*;
pub use reference_grant::*;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The API group of every kind in this module.
pub const GROUP: &str = "gateway.networking.k8s.io";
/// The API version this crate reads.
pub const VERSION: &str = "v1";
/// The Gateway API release the types follow.
pub const BUNDLE_VERSION: &str = "v1.7.0";
/// The core API group, written as the empty string in references.
pub const CORE_GROUP: &str = "";

/// A reference from a route to its parent (a `Gateway`, or a `ListenerSet`).
#[derive(
    Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct ParentReference {
    /// API group of the parent; `gateway.networking.k8s.io` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind of the parent; `Gateway` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Namespace of the parent; the route's own when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Name of the parent.
    pub name: String,
    /// A listener name of the parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    /// A listener port of the parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// A reference from a ListenerSet to its parent Gateway.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ParentGatewayReference {
    /// API group; `gateway.networking.k8s.io` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind; `Gateway` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the Gateway.
    #[serde(default)]
    pub name: String,
    /// Namespace of the Gateway; the ListenerSet's own when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// A reference to a backend (normally a core `Service`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendObjectReference {
    /// API group; the core group (`""`) when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind; `Service` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name of the backend.
    pub name: String,
    /// Namespace; the route's own when unset (another one needs a `ReferenceGrant`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Port of the Service; required for Services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// A weighted backend reference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    /// The backend.
    #[serde(flatten)]
    pub reference: BackendObjectReference,
    /// Relative weight; 1 when unset, 0 sends no traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<i32>,
}

/// A reference to a Secret (or another kind holding a certificate).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretObjectReference {
    /// API group; the core group when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind; `Secret` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name.
    pub name: String,
    /// Namespace; the referrer's own when unset (another one needs a `ReferenceGrant`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// A reference to an object in the same namespace, with group and kind.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LocalObjectReference {
    /// API group (`""` for the core group).
    #[serde(default)]
    pub group: String,
    /// Kind.
    #[serde(default)]
    pub kind: String,
    /// Name.
    #[serde(default)]
    pub name: String,
}

/// A reference to an object, possibly in another namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectReference {
    /// API group (`""` for the core group).
    #[serde(default)]
    pub group: String,
    /// Kind.
    #[serde(default)]
    pub kind: String,
    /// Name.
    #[serde(default)]
    pub name: String,
    /// Namespace; the referrer's own when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// A route kind (group and kind).
#[derive(
    Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct RouteGroupKind {
    /// API group; `gateway.networking.k8s.io` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Kind, e.g. `HTTPRoute`.
    #[serde(default)]
    pub kind: String,
}

/// The status of a route for one parent.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteParentStatus {
    /// The parent this entry describes.
    #[serde(default)]
    pub parent_ref: ParentReference,
    /// The controller that wrote this entry.
    #[serde(default)]
    pub controller_name: String,
    /// `Accepted`, `ResolvedRefs`, …
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}

/// The status shared by all route kinds.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RouteStatus {
    /// One entry per parent and controller.
    #[serde(default)]
    pub parents: Vec<RouteParentStatus>,
}

/// A fraction (`numerator / denominator`, denominator 100 when unset).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Fraction {
    /// Numerator.
    #[serde(default)]
    pub numerator: i32,
    /// Denominator; 100 when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denominator: Option<i32>,
}

/// Session persistence of a route rule (Extended; not supported yet, read to report it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionPersistence {
    /// Session name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    /// Absolute timeout (a Gateway API duration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute_timeout: Option<String>,
    /// Idle timeout (a Gateway API duration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,
    /// `Cookie` or `Header`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Cookie settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_config: Option<serde_json::Value>,
}

/// A label selector, as Kubernetes writes it.
pub type LabelSelector = k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

/// The metav1 condition type used in every status.
pub type ApiCondition = Condition;

/// Kinds of the Gateway API this crate models, as written in `kind`.
pub mod kinds {
    /// `GatewayClass`.
    pub const GATEWAY_CLASS: &str = "GatewayClass";
    /// `Gateway`.
    pub const GATEWAY: &str = "Gateway";
    /// `HTTPRoute`.
    pub const HTTP_ROUTE: &str = "HTTPRoute";
    /// `GRPCRoute`.
    pub const GRPC_ROUTE: &str = "GRPCRoute";
    /// `TLSRoute`.
    pub const TLS_ROUTE: &str = "TLSRoute";
    /// `TCPRoute`.
    pub const TCP_ROUTE: &str = "TCPRoute";
    /// `UDPRoute`.
    pub const UDP_ROUTE: &str = "UDPRoute";
    /// `ReferenceGrant`.
    pub const REFERENCE_GRANT: &str = "ReferenceGrant";
    /// `ListenerSet`.
    pub const LISTENER_SET: &str = "ListenerSet";
    /// `BackendTLSPolicy`.
    pub const BACKEND_TLS_POLICY: &str = "BackendTLSPolicy";
}

/// Parses a Gateway API duration (`GEP-2257`: one or more `<number><unit>` pairs, units `h`,
/// `m`, `s`, `ms`, e.g. `1h`, `500ms`, `1m30s`; `0s` is zero). `None` when it is not one.
#[must_use]
pub fn parse_duration(value: &str) -> Option<std::time::Duration> {
    if value.is_empty() || value.len() > 32 {
        return None;
    }
    let mut total_ms: u64 = 0;
    let mut rest = value;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || digits > 5 {
            return None;
        }
        let number: u64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let (unit_ms, unit_len) = if rest.starts_with("ms") {
            (1, 2)
        } else if rest.starts_with('h') {
            (3_600_000, 1)
        } else if rest.starts_with('m') {
            (60_000, 1)
        } else if rest.starts_with('s') {
            (1_000, 1)
        } else {
            return None;
        };
        rest = &rest[unit_len..];
        total_ms = total_ms.checked_add(number.checked_mul(unit_ms)?)?;
    }
    Some(std::time::Duration::from_millis(total_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gateway_api_durations() {
        let ms = |v: &str| parse_duration(v).map(|d| d.as_millis());
        assert_eq!(ms("1h"), Some(3_600_000));
        assert_eq!(ms("1m30s"), Some(90_000));
        assert_eq!(ms("500ms"), Some(500));
        assert_eq!(ms("0s"), Some(0));
        assert_eq!(ms("1h2m3s4ms"), Some(3_723_004));
        for bad in ["", "1", "s", "1d", "1.5s", "-1s", "123456s"] {
            assert_eq!(ms(bad), None, "{bad}");
        }
    }
}
