//! Request validation (`type: validate`, F-GW-03, ADR-0030): request parameters and JSON bodies
//! checked against JSON Schema 2020-12, inline or from an OpenAPI 3.1 document.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::values::ByteSize;

/// Request validation (`type: validate`).
///
/// Either inline schemas (`path`, `query`, `headers`, `cookies`, `body`) or an OpenAPI 3.1
/// document (`openapi`), not both. Schemas are compiled when the configuration is loaded; a
/// schema that does not compile, or one that refers to anything outside its own document, is a
/// configuration error. Failures answer `400` with the problem type `validation-failed` and at
/// most `max_errors` entries `{ pointer, message }`; messages name the failing keyword, never
/// the offending value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(inline)]
pub struct ValidateConfig {
    /// An OpenAPI 3.1 document (JSON or YAML), read on every reload. Requests are matched to
    /// its operations by method and path template; each operation's parameters and its
    /// `application/json` request body are checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openapi: Option<PathBuf>,
    /// With `openapi`: requests that match no operation of the document. `deny` (the
    /// default) answers `404` or `405`; `allow` lets them through unchecked.
    pub unknown_operations: UnknownOperations,
    /// With `openapi`: a prefix the document's paths are relative to (`/api` when the
    /// document's server URL is `https://example.com/api`). Requests outside it are unknown
    /// operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_path: Option<String>,
    /// Path parameters: a regular expression for the path with named groups, and a schema for
    /// the object of the groups' values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathParameters>,
    /// A schema for the object of query parameters (`{ name: value }`; a repeated name gives
    /// an array). Values are strings, converted to the `type` the schema declares for the
    /// property (`integer`, `number`, `boolean`, `array`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<Value>,
    /// A schema for the object of request headers, keyed by lower-case name. Converted like
    /// `query`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    /// A schema for the object of request cookies. Converted like `query`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookies: Option<Value>,
    /// A schema for the JSON request body. A body with another content type is answered
    /// `415`, a body that is not JSON `400`, a body over `max_body` `413`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    /// With `body`: a request without a body is refused. Off by default, as OpenAPI's
    /// `requestBody.required`.
    pub body_required: bool,
    /// Largest body checked, at most 64MiB; the body is held until it is complete. The
    /// route's `max_body` applies when it is smaller.
    pub max_body: ByteSize,
    /// Most errors listed in an answer (1 to 100).
    pub max_errors: u32,
    /// Check `format` (`date-time`, `email`, `uuid`, …) as an assertion. JSON Schema 2020-12
    /// treats it as an annotation unless asked; rdock asks by default.
    pub formats: bool,
    /// `enforce` (the default) refuses invalid requests; `report` only logs and counts them,
    /// to try a schema on live traffic.
    pub mode: ValidationMode,
}

impl Default for ValidateConfig {
    fn default() -> Self {
        Self {
            openapi: None,
            unknown_operations: UnknownOperations::Deny,
            base_path: None,
            path: None,
            query: None,
            headers: None,
            cookies: None,
            body: None,
            body_required: false,
            max_body: ByteSize::mib(1),
            max_errors: 5,
            formats: true,
            mode: ValidationMode::Enforce,
        }
    }
}

impl ValidateConfig {
    /// Largest `max_body` accepted.
    pub const MAX_BODY: ByteSize = ByteSize::mib(64);
    /// Largest `max_errors` accepted.
    pub const MAX_ERRORS: u32 = 100;

    /// Whether any inline schema is set.
    #[must_use]
    pub fn has_inline(&self) -> bool {
        self.path.is_some()
            || self.query.is_some()
            || self.headers.is_some()
            || self.cookies.is_some()
            || self.body.is_some()
    }

    /// Whether the middleware may need the request body.
    #[must_use]
    pub fn checks_body(&self) -> bool {
        self.openapi.is_some() || self.body.is_some()
    }
}

/// Path parameters of `validate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathParameters {
    /// A regular expression for the whole path, with named groups (`(?<id>[^/]+)`). A path it
    /// does not match fails validation.
    pub regex: String,
    /// A schema for the object of the groups' values, converted like `query`.
    pub schema: Value,
}

/// What `validate` does with requests outside the OpenAPI document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownOperations {
    /// Answer `404` (no path template matches) or `405` (the path exists, the method not).
    #[default]
    Deny,
    /// Let them through unchecked.
    Allow,
}

/// Whether `validate` refuses invalid requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMode {
    /// Refuse invalid requests.
    #[default]
    Enforce,
    /// Log and count invalid requests, and let them through.
    Report,
}

/// Every `$ref`/`$dynamicRef` in `schema` that points outside the document: anything but a
/// fragment (`#…`). With the location of each, as a JSON Pointer into `schema`.
#[must_use]
pub fn external_references(schema: &Value) -> Vec<(String, String)> {
    fn walk(value: &Value, at: &mut String, out: &mut Vec<(String, String)>) {
        match value {
            Value::Object(map) => {
                for (key, item) in map {
                    let len = at.len();
                    at.push('/');
                    at.push_str(&crate::json_patch::escape_token(key));
                    if matches!(key.as_str(), "$ref" | "$dynamicRef")
                        && let Value::String(target) = item
                        && !target.starts_with('#')
                    {
                        out.push((at.clone(), target.clone()));
                    }
                    walk(item, at, out);
                    at.truncate(len);
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let len = at.len();
                    at.push('/');
                    at.push_str(&i.to_string());
                    walk(item, at, out);
                    at.truncate(len);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(schema, &mut String::new(), &mut out);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn external_references_are_found() {
        let schema = json!({
            "$defs": { "a": { "type": "string" } },
            "properties": {
                "x": { "$ref": "#/$defs/a" },
                "y": { "$ref": "https://example.com/s.json" },
                "z": { "items": [{ "$ref": "other.json#/a" }] }
            }
        });
        let found = external_references(&schema);
        assert_eq!(
            found,
            vec![
                (
                    "/properties/y/$ref".to_owned(),
                    "https://example.com/s.json".to_owned()
                ),
                (
                    "/properties/z/items/0/$ref".to_owned(),
                    "other.json#/a".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn defaults_are_safe() {
        let config: ValidateConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(config.max_body, ByteSize::mib(1));
        assert_eq!(config.max_errors, 5);
        assert_eq!(config.unknown_operations, UnknownOperations::Deny);
        assert_eq!(config.mode, ValidationMode::Enforce);
        assert!(config.formats && !config.body_required);
    }
}
