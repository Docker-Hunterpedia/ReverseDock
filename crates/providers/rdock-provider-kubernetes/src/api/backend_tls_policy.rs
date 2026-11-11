//! `BackendTLSPolicy`.

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{LocalObjectReference, ParentReference};

/// `gateway.networking.k8s.io/v1` BackendTLSPolicy: TLS from the Gateway to a Service.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "BackendTLSPolicy",
    namespaced,
    status = "PolicyStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct BackendTLSPolicySpec {
    /// The Services (and optionally their ports, by `sectionName`) the policy applies to.
    #[serde(default)]
    pub target_refs: Vec<PolicyTargetReference>,
    /// How the backend's certificate is verified.
    #[serde(default)]
    pub validation: BackendTLSPolicyValidation,
    /// Implementation-specific options (none are supported).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
}

/// A local policy target, optionally narrowed to a section (a Service port name).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTargetReference {
    /// API group (`""` for Services).
    #[serde(default)]
    pub group: String,
    /// Kind (`Service`).
    #[serde(default)]
    pub kind: String,
    /// Name.
    #[serde(default)]
    pub name: String,
    /// A port name of the Service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
}

/// Certificate verification of a BackendTLSPolicy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendTLSPolicyValidation {
    /// ConfigMaps with `ca.crt`; or set `well_known_ca_certificates`.
    #[serde(default)]
    pub ca_certificate_refs: Vec<LocalObjectReference>,
    /// `System`: the system's roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub well_known_ca_certificates: Option<String>,
    /// SNI and the name the certificate must carry (unless `subject_alt_names` is set).
    #[serde(default)]
    pub hostname: String,
    /// Names the certificate must carry instead of `hostname`.
    #[serde(default)]
    pub subject_alt_names: Vec<SubjectAltName>,
}

/// A subject alternative name a backend certificate must carry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubjectAltName {
    /// `Hostname` or `URI`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// For `Hostname`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// For `URI`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// Status of a policy: one entry per ancestor (Gateway) and controller.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStatus {
    /// Ancestors.
    #[serde(default)]
    pub ancestors: Vec<PolicyAncestorStatus>,
}

/// Status of a policy for one ancestor.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAncestorStatus {
    /// The ancestor (a Gateway).
    #[serde(default)]
    pub ancestor_ref: ParentReference,
    /// The controller that wrote this entry.
    #[serde(default)]
    pub controller_name: String,
    /// `Accepted`, `ResolvedRefs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}
