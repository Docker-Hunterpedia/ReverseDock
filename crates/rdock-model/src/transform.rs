//! Request and response transformation (`type: transform`, F-GW-04, ADR-0030): header rules
//! and JSON Patch (RFC 6902) on JSON bodies up to a size. No template or query language.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::json_patch::PatchOp;
use crate::middleware::HeaderRules;
use crate::values::ByteSize;

/// Request and response transformation (`type: transform`).
///
/// Request bodies are held until complete (up to `max_body`), patched and forwarded with the
/// new length. Response bodies are patched only when they are JSON, not encoded
/// (`Content-Encoding` absent or `identity`) and at most `max_body`; anything else passes
/// unchanged and is counted in `rdock_transform_skipped_total`. Patches run on every response,
/// including cache hits: the cache stores what the backend sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(inline)]
pub struct TransformConfig {
    /// Changes to the request sent to the backend.
    pub request: TransformSide,
    /// Changes to the response sent to the client.
    pub response: TransformSide,
    /// Largest body patched, request or response, at most 64MiB (default 1MiB). A larger
    /// request body is refused with `413`; a larger response body passes unchanged.
    #[serde(default = "one_mib")]
    pub max_body: ByteSize,
    /// A request patch that cannot be applied (a `test` operation fails, a location is
    /// missing): `reject` (the default) answers `422`; `pass` forwards the body unchanged.
    /// A response patch that fails always leaves the body unchanged (the status is sent).
    pub on_error: OnPatchError,
    /// A request body that is not JSON when `request.body.patch` is set: `pass` (the
    /// default) forwards it unchanged; `reject` answers `415` (wrong content type) or `400`
    /// (not valid JSON).
    pub on_non_json: OnNonJson,
}

fn one_mib() -> ByteSize {
    ByteSize::mib(1)
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            request: TransformSide::default(),
            response: TransformSide::default(),
            max_body: one_mib(),
            on_error: OnPatchError::default(),
            on_non_json: OnNonJson::default(),
        }
    }
}

impl TransformConfig {
    /// Largest `max_body` accepted.
    pub const MAX_BODY: ByteSize = ByteSize::mib(64);

    /// Whether request bodies are patched.
    #[must_use]
    pub fn patches_requests(&self) -> bool {
        !self.request.body.patch.is_empty()
    }

    /// Whether response bodies are patched.
    #[must_use]
    pub fn patches_responses(&self) -> bool {
        !self.response.body.patch.is_empty()
    }
}

/// One direction of `transform`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TransformSide {
    /// Header operations, applied in the order remove, set, add (as `headers` does).
    pub headers: HeaderRules,
    /// Body changes.
    pub body: BodyTransform,
}

/// Body changes of `transform`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct BodyTransform {
    /// A JSON Patch (RFC 6902): operations `add`, `remove`, `replace`, `move`, `copy` and
    /// `test` with JSON Pointers (RFC 6901), applied in order, all or nothing.
    pub patch: Vec<PatchOp>,
}

/// What `transform` does when a request patch cannot be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnPatchError {
    /// Answer `422` (problem type `patch-failed`).
    #[default]
    Reject,
    /// Forward the body unchanged.
    Pass,
}

/// What `transform` does with a request body that is not JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnNonJson {
    /// Forward it unchanged.
    #[default]
    Pass,
    /// Answer `415` or `400`.
    Reject,
}

/// Whether `content_type` (a `Content-Type` value) names JSON: `application/json` or a
/// `+json` type, parameters ignored.
#[must_use]
pub fn is_json_media_type(content_type: &str) -> bool {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media == "application/json" || (media.starts_with("application/") && media.ends_with("+json"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn json_media_types() {
        for yes in [
            "application/json",
            "Application/JSON; charset=utf-8",
            "application/problem+json",
            "application/vnd.api+json",
        ] {
            assert!(is_json_media_type(yes), "{yes}");
        }
        for no in ["text/json", "application/jsonx", "text/plain", ""] {
            assert!(!is_json_media_type(no), "{no}");
        }
    }

    #[test]
    fn parses_with_defaults() {
        let config: TransformConfig = serde_json::from_value(json!({
            "request": {
                "headers": { "set": { "x-api-version": "2" } },
                "body": { "patch": [{ "op": "remove", "path": "/debug" }] }
            }
        }))
        .unwrap();
        assert!(config.patches_requests() && !config.patches_responses());
        assert_eq!(config.max_body, ByteSize::mib(1));
        assert_eq!(config.on_error, OnPatchError::Reject);
        assert_eq!(config.on_non_json, OnNonJson::Pass);
    }
}
