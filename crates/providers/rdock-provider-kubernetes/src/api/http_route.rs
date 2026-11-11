//! `HTTPRoute` and the filters it shares with `GRPCRoute`.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    BackendObjectReference, BackendRef, Fraction, LocalObjectReference, ParentReference,
    RouteStatus, SessionPersistence,
};

/// Path match types (`HTTPPathMatch.type`).
pub mod path_match {
    /// `Exact`.
    pub const EXACT: &str = "Exact";
    /// `PathPrefix` (the default), by path segment.
    pub const PATH_PREFIX: &str = "PathPrefix";
    /// `RegularExpression`.
    pub const REGULAR_EXPRESSION: &str = "RegularExpression";
}

/// Header and query-parameter match types.
pub mod value_match {
    /// `Exact` (the default).
    pub const EXACT: &str = "Exact";
    /// `RegularExpression`.
    pub const REGULAR_EXPRESSION: &str = "RegularExpression";
}

/// Filter types (`HTTPRouteFilter.type`, `GRPCRouteFilter.type`).
pub mod filter_types {
    /// `RequestHeaderModifier`.
    pub const REQUEST_HEADER_MODIFIER: &str = "RequestHeaderModifier";
    /// `ResponseHeaderModifier`.
    pub const RESPONSE_HEADER_MODIFIER: &str = "ResponseHeaderModifier";
    /// `RequestMirror`.
    pub const REQUEST_MIRROR: &str = "RequestMirror";
    /// `RequestRedirect`.
    pub const REQUEST_REDIRECT: &str = "RequestRedirect";
    /// `URLRewrite`.
    pub const URL_REWRITE: &str = "URLRewrite";
    /// `CORS`.
    pub const CORS: &str = "CORS";
    /// `ExternalAuth`.
    pub const EXTERNAL_AUTH: &str = "ExternalAuth";
    /// `ExtensionRef`.
    pub const EXTENSION_REF: &str = "ExtensionRef";
}

/// Path modifier types (`HTTPPathModifier.type`).
pub mod path_modifier {
    /// `ReplaceFullPath`.
    pub const REPLACE_FULL_PATH: &str = "ReplaceFullPath";
    /// `ReplacePrefixMatch`.
    pub const REPLACE_PREFIX_MATCH: &str = "ReplacePrefixMatch";
}

/// `gateway.networking.k8s.io/v1` HTTPRoute.
#[derive(CustomResource, Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "HTTPRoute",
    namespaced,
    status = "RouteStatus",
    schema = "disabled",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteSpec {
    /// Gateways (or ListenerSets) and their listeners this route attaches to.
    #[serde(default)]
    pub parent_refs: Vec<ParentReference>,
    /// Host names; every host the listener accepts when empty.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Rules; one rule matching `/` that answers 404 when empty.
    #[serde(default)]
    pub rules: Vec<HTTPRouteRule>,
}

/// One rule of an HTTPRoute.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteRule {
    /// Rule name (a `sectionName` for policies and status).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Matches, any of which selects the rule; `PathPrefix /` when empty.
    #[serde(default)]
    pub matches: Vec<HTTPRouteMatch>,
    /// Filters applied in order.
    #[serde(default)]
    pub filters: Vec<HTTPRouteFilter>,
    /// Backends; none answers 500 (or what a filter answers).
    #[serde(default)]
    pub backend_refs: Vec<HTTPBackendRef>,
    /// Timeouts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<HTTPRouteTimeouts>,
    /// Retries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<HTTPRouteRetry>,
    /// Session persistence (not supported yet; reported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_persistence: Option<SessionPersistence>,
}

/// Timeouts of a rule (Gateway API durations).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteTimeouts {
    /// The whole request, from the client's request to the end of the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// One request to a backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_request: Option<String>,
}

/// Retries of a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteRetry {
    /// Status codes that are retried (500–599).
    #[serde(default)]
    pub codes: Vec<u16>,
    /// Attempts after the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    /// Wait between attempts (a Gateway API duration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff: Option<String>,
}

/// One match of a rule; all of its conditions must hold.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteMatch {
    /// Path; `PathPrefix /` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathMatch>,
    /// Headers.
    #[serde(default)]
    pub headers: Vec<HTTPHeaderMatch>,
    /// Query parameters.
    #[serde(default)]
    pub query_params: Vec<HTTPQueryParamMatch>,
    /// Method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// A path match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPPathMatch {
    /// [`path_match`]; `PathPrefix` when unset.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The path or pattern; `/` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// A header match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPHeaderMatch {
    /// [`value_match`]; `Exact` when unset.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Header name (case-insensitive).
    #[serde(default)]
    pub name: String,
    /// Value or pattern.
    #[serde(default)]
    pub value: String,
}

/// A query-parameter match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPQueryParamMatch {
    /// [`value_match`]; `Exact` when unset.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Parameter name (case-sensitive).
    #[serde(default)]
    pub name: String,
    /// Value or pattern.
    #[serde(default)]
    pub value: String,
}

/// A filter of a rule or backendRef.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteFilter {
    /// [`filter_types`].
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
    /// For `RequestRedirect`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_redirect: Option<HTTPRequestRedirectFilter>,
    /// For `URLRewrite`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_rewrite: Option<HTTPURLRewriteFilter>,
    /// For `CORS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors: Option<HTTPCORSFilter>,
    /// For `ExternalAuth` (not supported; the rule is rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_auth: Option<serde_json::Value>,
    /// For `ExtensionRef` (not supported; the rule is rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_ref: Option<LocalObjectReference>,
}

/// One header to set or add.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPHeader {
    /// Name.
    #[serde(default)]
    pub name: String,
    /// Value.
    #[serde(default)]
    pub value: String,
}

/// Header changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPHeaderFilter {
    /// Replace or create.
    #[serde(default)]
    pub set: Vec<HTTPHeader>,
    /// Append.
    #[serde(default)]
    pub add: Vec<HTTPHeader>,
    /// Remove these names.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// A path change of a redirect or rewrite.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPPathModifier {
    /// [`path_modifier`].
    #[serde(default, rename = "type")]
    pub kind: String,
    /// For `ReplaceFullPath`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_full_path: Option<String>,
    /// For `ReplacePrefixMatch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_prefix_match: Option<String>,
}

/// A redirect.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRequestRedirectFilter {
    /// `http` or `https`; the request's when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Host name; the request's when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Path change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathModifier>,
    /// Port (see the port rules of the specification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// 301, 302 (default), 303, 307 or 308.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
}

/// A rewrite before forwarding.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPURLRewriteFilter {
    /// New `Host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Path change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<HTTPPathModifier>,
}

/// A mirror.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRequestMirrorFilter {
    /// The backend receiving copies.
    #[serde(default)]
    pub backend_ref: BackendObjectReference,
    /// Share of requests copied, 0–100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<i32>,
    /// Share of requests copied, as a fraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fraction: Option<Fraction>,
}

/// CORS.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPCORSFilter {
    /// Allowed origins (`*`, or `scheme://host[:port]`, with `*` wildcards in the host).
    #[serde(default)]
    pub allow_origins: Vec<String>,
    /// Allow credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<bool>,
    /// Allowed methods (`*` for all).
    #[serde(default)]
    pub allow_methods: Vec<String>,
    /// Allowed request headers.
    #[serde(default)]
    pub allow_headers: Vec<String>,
    /// Response headers exposed to scripts.
    #[serde(default)]
    pub expose_headers: Vec<String>,
    /// Preflight cache time in seconds; 5 when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i32>,
}

/// A weighted backend of an HTTPRoute rule, with its own filters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPBackendRef {
    /// The backend and its weight.
    #[serde(flatten)]
    pub backend: BackendRef,
    /// Filters for requests to this backend only (header modification is supported).
    #[serde(default)]
    pub filters: Vec<HTTPRouteFilter>,
}
