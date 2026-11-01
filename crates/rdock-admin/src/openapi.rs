//! The OpenAPI 3.1 document of the admin API (F-MGMT-01, ADR-0024), generated from the
//! handlers' `#[utoipa::path]` attributes and the routes that register them, so the two
//! cannot drift apart. A copy is committed as `schema/openapi.json`.

use std::sync::OnceLock;

use serde::Serialize;
use serde_json::{Map, Value, json};
use utoipa::ToSchema;

use crate::sessions::Stage;
use crate::users::Role;

/// Prefix of the configuration model's schemas among the components.
const MODEL: &str = "rdock.";

/// Operations anyone may call; every other one needs a session or an API token.
const PUBLIC: [&str; 4] = ["/healthz", "/readyz", "/api/v1/setup", "/api/v1/auth/login"];

/// Operations that take from the shared configuration-work budget (`config_api::over_budget`).
const CONFIG_WORK: [&str; 4] = [
    "/api/v1/config/api",
    "/api/v1/config/validate",
    "/api/v1/config/rollback",
    "/api/v1/config/import",
];

/// A refusal or failure.
#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorBody {
    /// What went wrong, in a sentence.
    error: String,
}

/// The caller's session.
#[derive(Serialize, ToSchema)]
pub(crate) struct SessionInfo {
    name: String,
    role: Role,
    stage: Stage,
    /// Send it in `X-CSRF-Token` with every unsafe request.
    csrf_token: String,
}

/// How an audited action ended.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[expect(
    dead_code,
    reason = "documents `audit::Outcome::as_str` for the schema only"
)]
pub(crate) enum AuditResult {
    Ok,
    Denied,
    Failed,
}

/// One audit record; `prev` is the SHA-256 of the record before it.
#[derive(Serialize, ToSchema)]
pub(crate) struct AuditRecord {
    /// RFC 3339.
    time: String,
    seq: u64,
    actor: String,
    method: String,
    client: Option<String>,
    action: String,
    resource: Option<String>,
    result: AuditResult,
    reason: Option<String>,
    prev: String,
    config_before: Option<String>,
    config_after: Option<String>,
}

/// The OpenAPI document as pretty JSON with a final newline, built once.
#[must_use]
pub fn json() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| {
        serde_json::to_string_pretty(&document()).map_or_else(|_| String::new(), |t| t + "\n")
    })
}

/// The document: the generated paths, then the security schemes, the shared refusals, the
/// configuration model's schemas and the summaries taken from the handlers' docs.
fn document() -> Value {
    let generated = crate::routes::documented(|api| api).into_openapi();
    let mut document = serde_json::to_value(generated).unwrap_or_default();
    document["info"] = json!({
        "title": "ReverseDock admin API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Manage a running rdock. Every call except health, setup and login needs a dashboard session (cookie and `X-CSRF-Token` on unsafe methods) or an API token (`Authorization: Bearer rdk_pat_…`). The \"Configuration API\" guide in the documentation walks through it.",
        "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
    });
    add_model(&mut document);
    add_security(&mut document);
    tidy_texts(&mut document);
    document
}

/// The configuration model's JSON Schema, with its `$defs` moved to the components.
fn add_model(document: &mut Value) {
    let mut model = serde_json::to_value(rdock_model::json_schema()).unwrap_or_default();
    let defs = model
        .as_object_mut()
        .and_then(|m| m.remove("$defs"))
        .and_then(|d| d.as_object().cloned())
        .unwrap_or_default();
    if let Some(root) = model.as_object_mut() {
        root.remove("$schema");
        root.remove("$id");
    }
    let schemas = &mut document["components"]["schemas"];
    for (name, mut schema) in defs {
        rewrite_refs(&mut schema);
        schemas[format!("{MODEL}{name}")] = schema;
    }
    rewrite_refs(&mut model);
    schemas[format!("{MODEL}Config")] = model;
}

fn rewrite_refs(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(target)) = map.get_mut("$ref")
                && let Some(name) = target.strip_prefix("#/$defs/")
            {
                *target = format!("#/components/schemas/{MODEL}{name}");
            }
            map.values_mut().for_each(rewrite_refs);
        }
        Value::Array(items) => items.iter_mut().for_each(rewrite_refs),
        _ => {}
    }
}

/// The two ways to call the API, required on every operation but the public ones, which
/// also get the refusals any authenticated call may meet.
fn add_security(document: &mut Value) {
    document["components"]["securitySchemes"] = json!({
        "token": {
            "type": "http",
            "scheme": "bearer",
            "description": "An API token (`rdk_pat_…`) from `rdock tokens create` or the dashboard.",
        },
        "session": {
            "type": "apiKey",
            "in": "cookie",
            "name": crate::sessions::COOKIE,
            "description": "A dashboard session from `POST /api/v1/auth/login`; unsafe methods also need `X-CSRF-Token`.",
        },
    });
    document["components"]["responses"] = json!({
        "Unauthenticated": { "description": "No valid session or token.", "content": error_content() },
        "Forbidden": { "description": "The caller's role does not allow this, or a password check is due.", "content": error_content() },
        "WrongStage": { "description": "The session is not at the stage this step needs, for example already logged in.", "content": error_content() },
        "ConfigBusy": {
            "description": "More than 5 configuration writes or dry runs a second across all callers (bursts of 10); try again after `Retry-After` seconds.",
            "headers": { "Retry-After": { "schema": { "type": "integer" }, "description": "Seconds until the next write is accepted" } },
            "content": error_content(),
        },
    });
    let Some(paths) = document["paths"].as_object_mut() else {
        return;
    };
    for (path, item) in paths {
        if PUBLIC.contains(&path.as_str()) {
            continue;
        }
        for operation in item.as_object_mut().into_iter().flat_map(Map::values_mut) {
            if operation.get("security").is_none() {
                operation["security"] = json!([{ "token": [] }, { "session": [] }]);
            }
            // Session-only operations share one gate that also checks the login stage.
            let stage_gated = operation["security"] == json!([{ "session": [] }]);
            let config_work =
                CONFIG_WORK.contains(&path.as_str()) && operation["operationId"] != "get_api";
            let responses = &mut operation["responses"];
            if stage_gated && responses.get("409").is_none() {
                responses["409"] = json!({ "$ref": "#/components/responses/WrongStage" });
            }
            if config_work && responses.get("429").is_none() {
                responses["429"] = json!({ "$ref": "#/components/responses/ConfigBusy" });
            }
            for (status, name) in [("401", "Unauthenticated"), ("403", "Forbidden")] {
                if responses.get(status).is_none() {
                    responses[status] = json!({ "$ref": format!("#/components/responses/{name}") });
                }
            }
        }
    }
}

fn error_content() -> Value {
    json!({ "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } })
}

/// Handlers document themselves as "`GET /api/v1/x`: what it does"; the method and path are
/// already in the document, so they are dropped and the first sentence becomes the summary.
fn tidy_texts(document: &mut Value) {
    let Some(paths) = document["paths"].as_object_mut() else {
        return;
    };
    for operation in paths
        .values_mut()
        .filter_map(Value::as_object_mut)
        .flat_map(Map::values_mut)
    {
        let text = [&operation["summary"], &operation["description"]]
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let text = without_route(&text);
        let text = capitalized(&text);
        let summary = text
            .split(". ")
            .next()
            .unwrap_or_default()
            .trim_end_matches('.');
        operation["summary"] = summary.into();
        operation["description"] = text.into();
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

fn without_route(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let Some(rest) = text.strip_prefix('`') else {
        return text;
    };
    match rest.find('`') {
        Some(end) => rest[end + 1..]
            .trim_start_matches([':', '.'])
            .trim()
            .to_owned(),
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_document_is_up_to_date() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema/openapi.json");
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            committed == json(),
            "schema/openapi.json is out of date; run `just schema` and commit the result"
        );
    }

    #[test]
    fn every_operation_has_a_summary_and_unique_id() {
        let document = document();
        let mut ids = std::collections::BTreeSet::new();
        for (path, item) in document["paths"].as_object().unwrap() {
            for (method, operation) in item.as_object().unwrap() {
                let summary = operation["summary"].as_str().unwrap_or_default();
                assert!(!summary.is_empty(), "{method} {path} has no summary");
                let id = operation["operationId"].as_str().unwrap().to_owned();
                assert!(ids.insert(id.clone()), "operationId {id} is used twice");
            }
        }
    }

    #[test]
    fn model_refs_resolve() {
        let text = json();
        let document: Value = serde_json::from_str(text).unwrap();
        assert!(!text.contains("#/$defs/"));
        for name in text
            .match_indices("#/components/schemas/")
            .map(|(at, _)| &text[at + 21..])
            .map(|rest| &rest[..rest.find('"').unwrap()])
        {
            assert!(
                document["components"]["schemas"].get(name).is_some(),
                "{name} is referenced but not defined"
            );
        }
    }

    #[test]
    fn route_prefixes_are_dropped() {
        assert_eq!(
            without_route("`GET /api/v1/users`: every user."),
            "every user."
        );
        assert_eq!(without_route("`GET /api/v1/backends`."), "");
        assert_eq!(without_route("Plain text."), "Plain text.");
    }
}
