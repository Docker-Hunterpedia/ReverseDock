//! The configuration API (ADR-0024, "Configuration through the API"): the effective
//! configuration with owners and masked secrets, and the API provider's objects, changed only
//! with `If-Match` (428 without, 412 when stale), validated by a dry run with a line diff, and
//! applied through the same path as a file reload. History, rollback, export and import.
//! `admin.api_writes: false` refuses every write (`GitOps`).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, State as Extract};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use rdock_model::interpolation::{FieldKind, field_kind};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::audit::{Event, Outcome};
use crate::caller::{Access, Caller, need, need_recent};
use crate::routes::{Denied, error};
use crate::{ApiWrite, State};

/// How long a diff may take before it falls back to a coarser one (ADR-0024).
const DIFF_DEADLINE: Duration = Duration::from_millis(200);

macro_rules! check {
    ($result:expr) => {
        if let Err(denied) = $result {
            return denied.into_response();
        }
    };
}

/// Secret values written in place are shown as `***`; `${file:…}` and `${env:…}` references
/// are shown as written.
fn mask(value: &mut Value, path: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(key.clone());
                mask(child, path);
                path.pop();
            }
        }
        Value::Array(items) => {
            for item in items {
                path.push("*".into());
                mask(item, path);
                path.pop();
            }
        }
        Value::String(text) => {
            let keys: Vec<&str> = path.iter().map(String::as_str).collect();
            if field_kind(&keys) == FieldKind::Secret && !text.starts_with("${") {
                *text = "***".into();
            }
        }
        _ => {}
    }
}

fn masked(mut value: Value, root: &[&str]) -> Value {
    let mut path: Vec<String> = root.iter().map(|s| (*s).to_owned()).collect();
    mask(&mut value, &mut path);
    value
}

/// Which provider owns each route, service and middleware (`name@provider`, else `file`).
fn owners(config: &Value) -> Value {
    let mut out = Map::new();
    for section in ["routes", "services", "middlewares"] {
        let names = config[section].as_object().map(|m| {
            m.keys()
                .map(|name| {
                    let owner = name
                        .rsplit_once('@')
                        .map_or("file", |(_, provider)| provider);
                    (name.clone(), Value::String(owner.to_owned()))
                })
                .collect::<Map<_, _>>()
        });
        out.insert(section.to_owned(), Value::Object(names.unwrap_or_default()));
    }
    Value::Object(out)
}

/// A unified line diff of two documents, pretty-printed.
fn diff(current: &Value, candidate: &Value) -> String {
    let a = serde_json::to_string_pretty(current).unwrap_or_default();
    let b = serde_json::to_string_pretty(candidate).unwrap_or_default();
    similar::TextDiff::configure()
        .timeout(DIFF_DEADLINE)
        .diff_lines(&a, &b)
        .unified_diff()
        .context_radius(3)
        .header("current", "candidate")
        .to_string()
}

/// RFC 7396 JSON Merge Patch.
fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(changes) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Map::new());
    }
    if let Value::Object(map) = target {
        for (key, change) in changes {
            if change.is_null() {
                map.remove(key);
            } else {
                merge_patch(map.entry(key.clone()).or_insert(Value::Null), change);
            }
        }
    }
}

fn with_etag(mut response: Response, etag: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

fn writes_allowed(state: &State) -> Result<(), Denied> {
    if state.api_writes {
        Ok(())
    } else {
        Err(Denied(
            StatusCode::FORBIDDEN,
            "configuration writes through the API are off (admin.api_writes: false)",
        ))
    }
}

fn if_match(headers: &HeaderMap) -> Result<String, Denied> {
    headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .ok_or(Denied(
            StatusCode::PRECONDITION_REQUIRED,
            "send If-Match with the ETag from GET /api/v1/config/api",
        ))
}

fn hash_of(etag: &str) -> String {
    etag.trim_matches('"')
        .rsplit('-')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Applies a candidate through [`crate::Control::write_api`] and answers it, auditing as
/// `action`.
async fn write(
    state: &State,
    caller: &Caller,
    candidate: Value,
    if_match: String,
    action: &'static str,
) -> Response {
    let before = hash_of(&if_match);
    let control = state.control.clone();
    let outcome = state
        .main
        .spawn(async move { control.write_api(candidate, if_match).await })
        .await;
    let Ok(outcome) = outcome else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down");
    };
    match outcome {
        ApiWrite::Applied { report, etag } => {
            state.audit.record(Event {
                config: Some((before, hash_of(&etag))),
                ..caller.event(action)
            });
            with_etag(axum::Json(report).into_response(), &etag)
        }
        ApiWrite::Rejected { report } => {
            state.audit.record(Event {
                outcome: Outcome::Failed,
                reason: Some("the configuration was rejected".into()),
                ..caller.event(action)
            });
            (StatusCode::UNPROCESSABLE_ENTITY, axum::Json(report)).into_response()
        }
        ApiWrite::Stale { etag } => with_etag(
            error(
                StatusCode::PRECONDITION_FAILED,
                "the configuration changed since you read it; fetch it again",
            ),
            &etag,
        ),
        ApiWrite::Invalid(message) => error(StatusCode::UNPROCESSABLE_ENTITY, &message),
    }
}

async fn api_config(state: &State) -> Option<(Value, String)> {
    let control = state.control.clone();
    state
        .main
        .spawn(async move { control.api_config().await })
        .await
        .ok()
}

/// `GET /api/v1/config`: the effective configuration, the owner of every object, secrets
/// masked.
pub(crate) async fn effective(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let control = state.control.clone();
    let Ok(config) = state
        .main
        .spawn(async move { control.effective_config().await })
        .await
    else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down");
    };
    let owners = owners(&config);
    axum::Json(json!({ "config": masked(config, &[]), "owners": owners })).into_response()
}

/// `GET /api/v1/config/api`: the API provider's objects, with their `ETag`.
pub(crate) async fn get_api(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    match api_config(&state).await {
        Some((fragment, etag)) => {
            with_etag(axum::Json(masked(fragment, &[])).into_response(), &etag)
        }
        None => error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down"),
    }
}

/// `PUT /api/v1/config/api`: replaces the API provider's objects.
pub(crate) async fn put_api(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    axum::Json(candidate): axum::Json<Value>,
) -> Response {
    check!(need(&caller, Access::Operator));
    check!(writes_allowed(&state));
    let if_match = match if_match(&headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    write(&state, &caller, candidate, if_match, "config.apply").await
}

/// `PATCH /api/v1/config/api` with `application/merge-patch+json` (RFC 7396) or
/// `application/json-patch+json` (RFC 6902).
pub(crate) async fn patch_api(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    check!(need(&caller, Access::Operator));
    check!(writes_allowed(&state));
    let if_match = match if_match(&headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    let kind = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let Ok(patch) = serde_json::from_slice::<Value>(&body) else {
        return error(StatusCode::BAD_REQUEST, "the body is not JSON");
    };
    let Some((mut current, _)) = api_config(&state).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down");
    };
    match kind.as_str() {
        "application/merge-patch+json" => merge_patch(&mut current, &patch),
        "application/json-patch+json" => {
            let operations: json_patch::Patch = match serde_json::from_value(patch) {
                Ok(ops) => ops,
                Err(err) => {
                    return error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        &format!("not a JSON Patch: {err}"),
                    );
                }
            };
            if let Err(err) = json_patch::patch(&mut current, &operations) {
                return error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("the patch does not apply: {err}"),
                );
            }
        }
        _ => {
            return error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "use application/merge-patch+json or application/json-patch+json",
            );
        }
    }
    write(&state, &caller, current, if_match, "config.apply").await
}

/// `POST /api/v1/config/validate`: a dry run of a candidate for the API objects, with the
/// diagnostics and a line diff against the current ones.
pub(crate) async fn validate(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(candidate): axum::Json<Value>,
) -> Response {
    check!(need(&caller, Access::Operator));
    let Some((current, _)) = api_config(&state).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down");
    };
    let changes = diff(&masked(current, &[]), &masked(candidate.clone(), &[]));
    let control = state.control.clone();
    let checked = state
        .main
        .spawn(async move { control.dry_run(candidate).await })
        .await;
    match checked {
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down"),
        Ok(Err(message)) => error(StatusCode::UNPROCESSABLE_ENTITY, &message),
        Ok(Ok((valid, diagnostics))) => {
            axum::Json(json!({ "valid": valid, "diagnostics": diagnostics, "diff": changes }))
                .into_response()
        }
    }
}

/// `GET /api/v1/config/history`: applied configurations, newest first.
pub(crate) async fn history(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.history().await })
        .await
    {
        Ok(list) => axum::Json(list).into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rollback {
    /// The `id` of a history entry.
    id: u64,
}

/// `POST /api/v1/config/rollback`: restores the API objects of a history entry, as a
/// conditional write; people confirm their password first.
pub(crate) async fn rollback(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Rollback>,
) -> Response {
    check!(need(&caller, Access::Operator));
    check!(need_recent(&caller));
    check!(writes_allowed(&state));
    let if_match = match if_match(&headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    let control = state.control.clone();
    let id = body.id;
    let found = state
        .main
        .spawn(async move { control.history_api(id).await })
        .await
        .ok()
        .flatten();
    let Some(fragment) = found else {
        return error(StatusCode::NOT_FOUND, "no history entry with this id");
    };
    write(&state, &caller, fragment, if_match, "config.rollback").await
}

/// `GET /api/v1/config/export`: the API objects to move to another instance, secrets masked
/// unless written as references. Admins, after a password check.
pub(crate) async fn export(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Admin));
    check!(need_recent(&caller));
    let Some((fragment, etag)) = api_config(&state).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down");
    };
    state.audit.record(caller.event("config.export"));
    let document = json!({ "version": 1, "api": masked(fragment, &[]) });
    with_etag(axum::Json(document).into_response(), &etag)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Import {
    version: u32,
    api: Value,
}

/// `POST /api/v1/config/import`: replaces the API objects with an exported document.
pub(crate) async fn import(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Import>,
) -> Response {
    check!(need(&caller, Access::Admin));
    check!(need_recent(&caller));
    check!(writes_allowed(&state));
    if body.version != 1 {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported export version",
        );
    }
    if body.api.to_string().contains("\"***\"") {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "the document has masked secrets (***); write them as ${file:…} or ${env:…} references",
        );
    }
    let if_match = match if_match(&headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    write(&state, &caller, body.api, if_match, "config.import").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_masked_unless_they_are_references() {
        let config = json!({
            "services": {
                "a": { "sticky": { "cookie": { "secret": "plain-text", "name": "s" } } },
                "b": { "sticky": { "cookie": { "secret": "${file:/run/secrets/k}" } } }
            },
            "certificates": { "main": { "key_password": "hunter2" } }
        });
        let out = masked(config, &[]);
        assert_eq!(out["services"]["a"]["sticky"]["cookie"]["secret"], "***");
        assert_eq!(out["services"]["a"]["sticky"]["cookie"]["name"], "s");
        assert_eq!(
            out["services"]["b"]["sticky"]["cookie"]["secret"],
            "${file:/run/secrets/k}"
        );
        assert_eq!(out["certificates"]["main"]["key_password"], "***");
    }

    #[test]
    fn owners_come_from_the_provider_suffix() {
        let config = json!({ "routes": { "web": {}, "app@docker": {}, "x@api": {} } });
        let owners = owners(&config);
        assert_eq!(owners["routes"]["web"], "file");
        assert_eq!(owners["routes"]["app@docker"], "docker");
        assert_eq!(owners["routes"]["x@api"], "api");
    }

    #[test]
    fn merge_patch_follows_rfc_7396() {
        // RFC 7396 Appendix A, a few of the examples.
        let mut doc = json!({ "a": "b", "c": { "d": "e", "f": "g" } });
        merge_patch(&mut doc, &json!({ "a": "z", "c": { "f": null } }));
        assert_eq!(doc, json!({ "a": "z", "c": { "d": "e" } }));
        let mut doc = json!({ "a": [{ "b": "c" }] });
        merge_patch(&mut doc, &json!({ "a": [1] }));
        assert_eq!(doc, json!({ "a": [1] }));
    }

    #[test]
    fn diffs_are_unified() {
        let out = diff(&json!({ "routes": {} }), &json!({ "routes": { "a": {} } }));
        assert!(out.starts_with("--- current\n+++ candidate\n"), "{out}");
        assert!(out.contains("+    \"a\": {}"), "{out}");
    }
}
