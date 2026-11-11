//! `GatewayClass` (cluster-scoped).

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `gateway.networking.k8s.io/v1` GatewayClass: which controller serves the Gateways of the
/// class. We serve those whose `controllerName` is `providers.kubernetes.controller_name`.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "GatewayClass",
    status = "GatewayClassStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassSpec {
    /// The controller that manages Gateways of this class.
    #[serde(default)]
    pub controller_name: String,
    /// Implementation-specific parameters (none are supported; a reference is reported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters_ref: Option<ParametersReference>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A reference to an implementation-specific parameters object.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ParametersReference {
    /// API group.
    #[serde(default)]
    pub group: String,
    /// Kind.
    #[serde(default)]
    pub kind: String,
    /// Name.
    #[serde(default)]
    pub name: String,
    /// Namespace, for namespaced kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Status of a GatewayClass.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassStatus {
    /// `Accepted`, `SupportedVersion`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
    /// The features this controller supports (exactly those with a passing test,
    /// [`crate::features::SUPPORTED`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_features: Vec<SupportedFeature>,
}

/// One supported feature.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct SupportedFeature {
    /// Feature name, e.g. `HTTPRouteQueryParamMatching`.
    #[serde(default)]
    pub name: String,
}
