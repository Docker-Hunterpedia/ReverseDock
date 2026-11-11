//! `ReferenceGrant`.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `gateway.networking.k8s.io/v1` ReferenceGrant: allows objects of other namespaces to refer
/// to objects in this one. It has no status.
#[derive(
    CustomResource, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "ReferenceGrant",
    namespaced,
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceGrantSpec {
    /// Who may refer.
    #[serde(default)]
    pub from: Vec<ReferenceGrantFrom>,
    /// What they may refer to (in this grant's namespace).
    #[serde(default)]
    pub to: Vec<ReferenceGrantTo>,
}

/// A referrer allowed by a grant.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceGrantFrom {
    /// API group of the referrer.
    #[serde(default)]
    pub group: String,
    /// Kind of the referrer.
    #[serde(default)]
    pub kind: String,
    /// Namespace of the referrer.
    #[serde(default)]
    pub namespace: String,
}

/// A target allowed by a grant.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceGrantTo {
    /// API group of the target (`""` for the core group).
    #[serde(default)]
    pub group: String,
    /// Kind of the target.
    #[serde(default)]
    pub kind: String,
    /// One target by name; every object of the kind when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
