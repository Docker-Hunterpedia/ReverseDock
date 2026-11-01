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
use utoipa::ToSchema;

use crate::audit::{Event, Outcome};
use crate::caller::{Access, Caller, need, need_recent};
use crate::routes::{Denied, error};
use crate::{ApiWrite, State};

/// How long a diff may take before it falls back to a coarser one (ADR-0024).
const DIFF_DEADLINE: Duration = Duration::from_millis(200);

/// Configuration writes and dry runs per second across all callers, and the burst above it.
/// The isolation test measured ~195 applies a second raising the proxy's p99 from 0.7 to
/// 12.6 ms on 2 CPUs; 5 a second is about 2.5 % of that work.
const WRITES_PER_SECOND: u32 = 5;
const WRITE_BURST: u32 = 10;

/// The budget shared by every caller for configuration writes and dry runs.
pub(crate) fn work_limiter() -> rdock_limits::RateLimiter {
    rdock_limits::RateLimiter::new(WRITES_PER_SECOND, Duration::from_secs(1), WRITE_BURST, 1)
}

/// Takes one unit of the configuration-work budget; when it is spent, how long to wait.
fn over_budget(state: &State) -> Option<Duration> {
    match state.config_work.check(&(), std::time::Instant::now()) {
        rdock_limits::Decision::Allow => None,
        rdock_limits::Decision::Deny { retry_after } => Some(retry_after),
    }
}

macro_rules! check {
    ($result:expr) => {
        if let Err(denied) = $result {
            return denied.into_response();
        }
    };
}

/// Values hidden like secrets although the loader resolves their references: password hashes
/// of basic auth and the v0.3 alert webhook URL, which carries its own credential.
const ALSO_MASKED: [&[&str]; 1] = [&["observability", "alerts", "webhook", "url"]];

/// Basic-auth `users` entries, `name:hash`: only the hash is masked, so entries can still be
/// told apart, reordered and removed.
const USERS: [&str; 4] = ["middlewares", "*", "users", "*"];

fn is_users_entry(keys: &[&str]) -> bool {
    keys.len() == USERS.len() && USERS.iter().zip(keys).all(|(p, k)| *p == "*" || p == k)
}

fn also_masked(keys: &[&str]) -> bool {
    ALSO_MASKED.iter().any(|pattern| {
        pattern.len() == keys.len() && pattern.iter().zip(keys).all(|(p, k)| *p == "*" || p == k)
    })
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
            let secret = field_kind(&keys) == FieldKind::Secret || also_masked(&keys);
            if is_users_entry(&keys) {
                if let Some((name, _)) = text.split_once(':') {
                    *text = format!("{name}:***");
                }
            } else if secret && !text.starts_with("${") {
                *text = "***".into();
            }
        }
        _ => {}
    }
}

fn is_users_path(keys: &[String]) -> bool {
    is_users_entry(&keys.iter().map(String::as_str).collect::<Vec<_>>())
}

/// Puts back the hash of a `name:***` basic-auth entry from the current list, by name.
fn restore_user(entry: &mut Value, current: &Value, path: &[String]) -> Result<(), String> {
    let Some(name) = entry.as_str().and_then(|e| e.strip_suffix(":***")) else {
        return Ok(());
    };
    let kept = current
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find(|e| e.split_once(':').is_some_and(|(n, _)| n == name));
    match kept {
        Some(kept) => {
            *entry = Value::String(kept.to_owned());
            Ok(())
        }
        None => Err(format!(
            "{}: user {name} has no current password hash to keep; write name:hash",
            path.join(".")
        )),
    }
}

fn is_masked_field(keys: &[String]) -> bool {
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    field_kind(&keys) == FieldKind::Secret || also_masked(&keys)
}

/// Puts the current value back wherever the candidate kept a secret as `***`, the masked
/// value it was read with, so saving a document read through the API never stores `***`.
/// Fails with the path of a `***` that has no current value to keep.
fn restore_masked(
    candidate: &mut Value,
    current: &Value,
    path: &mut Vec<String>,
) -> Result<(), String> {
    match candidate {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(key.clone());
                restore_masked(child, &current[key.as_str()], path)?;
                path.pop();
            }
        }
        Value::Array(items) => {
            path.push("*".into());
            let users = is_users_path(path);
            for (i, item) in items.iter_mut().enumerate() {
                if users {
                    restore_user(item, current, path)?;
                } else {
                    restore_masked(item, &current[i], path)?;
                }
            }
            path.pop();
        }
        Value::String(text) if text == "***" && is_masked_field(path) => match current {
            Value::String(kept) => kept.clone_into(text),
            _ => {
                return Err(format!(
                    "{} is `***`, the masked value; write the secret or a ${{file:…}} reference",
                    path.join(".")
                ));
            }
        },
        _ => {}
    }
    Ok(())
}

pub(crate) fn masked(mut value: Value, root: &[&str]) -> Value {
    let mut path: Vec<String> = root.iter().map(|s| (*s).to_owned()).collect();
    mask(&mut value, &mut path);
    value
}

/// Which provider owns each route, service and middleware (`name@provider`, else `file`).
pub(crate) fn owners(config: &Value) -> Value {
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

pub(crate) fn writes_allowed(state: &State) -> Result<(), Denied> {
    if state.api_writes {
        Ok(())
    } else {
        Err(Denied(
            StatusCode::FORBIDDEN,
            "configuration writes through the API are off (admin.api_writes: false)",
        ))
    }
}

pub(crate) fn if_match(headers: &HeaderMap) -> Result<String, Denied> {
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
pub(crate) async fn write(
    state: &State,
    caller: &Caller,
    candidate: Value,
    if_match: String,
    action: &'static str,
) -> Response {
    if let Some(wait) = over_budget(state) {
        return crate::auth::too_many(wait);
    }
    let mut candidate = candidate;
    let Some((current, _)) = api_config(state).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down");
    };
    if let Err(message) = restore_masked(&mut candidate, &current, &mut Vec::new()) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, &message);
    }
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

pub(crate) async fn api_config(state: &State) -> Option<(Value, String)> {
    let control = state.control.clone();
    state
        .main
        .spawn(async move { control.api_config().await })
        .await
        .ok()
}

/// `GET /api/v1/config`: the effective configuration, the owner of every object, secrets
/// masked.
#[utoipa::path(get, path = "/config", tag = "config",
    responses((status = OK, description = "`config` and `owners`", body = Object)))]
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
#[utoipa::path(get, path = "/config/api", tag = "config",
    responses((status = OK, description = "The API objects, secrets masked", body = Object,
        headers(("ETag" = String, description = "Send it back in `If-Match` to change them")))))]
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

/// `PUT /api/v1/config/api`: replaces the API provider's objects (operator role).
#[utoipa::path(put, path = "/config/api", tag = "config", request_body = Object,
    params(("If-Match" = String, Header, description = "The `ETag` from `GET /api/v1/config/api`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object, headers(("ETag" = String, description = "The new version of the API objects"))),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Rejected; the report or message says why", body = Object),
        (status = PRECONDITION_REQUIRED, description = "`If-Match` is missing", body = crate::openapi::ErrorBody),
    ))]
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

/// `PATCH /api/v1/config/api`: changes some of the API provider's objects, as a JSON Merge
/// Patch (`application/merge-patch+json`, RFC 7396) or a JSON Patch
/// (`application/json-patch+json`, RFC 6902). Operator role.
#[utoipa::path(patch, path = "/config/api", tag = "config",
    request_body(content(
        (Object = "application/merge-patch+json"),
        (Vec<Object> = "application/json-patch+json"),
    )),
    params(("If-Match" = String, Header, description = "The `ETag` from `GET /api/v1/config/api`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object, headers(("ETag" = String, description = "The new version of the API objects"))),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Rejected; the report or message says why", body = Object),
        (status = PRECONDITION_REQUIRED, description = "`If-Match` is missing", body = crate::openapi::ErrorBody),
        (status = BAD_REQUEST, description = "The body is not JSON", body = crate::openapi::ErrorBody),
        (status = UNSUPPORTED_MEDIA_TYPE, description = "Neither patch format", body = crate::openapi::ErrorBody),
    ))]
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
/// diagnostics and a line diff against the current ones. Nothing is applied.
#[utoipa::path(post, path = "/config/validate", tag = "config", request_body = Object,
    responses(
        (status = OK, description = "`valid`, `diagnostics` and `diff`", body = Object),
        (status = UNPROCESSABLE_ENTITY, description = "Not a configuration document", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn validate(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(candidate): axum::Json<Value>,
) -> Response {
    check!(need(&caller, Access::Operator));
    if let Some(wait) = over_budget(&state) {
        return crate::auth::too_many(wait);
    }
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
#[utoipa::path(get, path = "/config/history", tag = "config",
    responses((status = OK, description = "History entries with their `id`", body = [Object])))]
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

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rollback {
    /// The `id` of a history entry.
    id: u64,
}

/// `POST /api/v1/config/rollback`: restores the API objects of a history entry, as a
/// conditional write; people confirm their password first.
#[utoipa::path(post, path = "/config/rollback", tag = "config", request_body = Rollback,
    params(("If-Match" = String, Header, description = "The `ETag` from `GET /api/v1/config/api`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object, headers(("ETag" = String, description = "The new version of the API objects"))),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Rejected; the report or message says why", body = Object),
        (status = PRECONDITION_REQUIRED, description = "`If-Match` is missing", body = crate::openapi::ErrorBody),
        (status = NOT_FOUND, description = "No history entry with this id", body = crate::openapi::ErrorBody),
    ))]
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
#[utoipa::path(get, path = "/config/export", tag = "config",
    responses((status = OK, description = "`version` and `api`", body = Import)))]
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

/// An exported document.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Import {
    /// Always `1`.
    version: u32,
    /// The API objects.
    #[schema(value_type = Object)]
    api: Value,
}

/// `POST /api/v1/config/import`: replaces the API objects with an exported document.
/// Admins, after a password check.
#[utoipa::path(post, path = "/config/import", tag = "config", request_body = Import,
    params(("If-Match" = String, Header, description = "The `ETag` from `GET /api/v1/config/api`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object, headers(("ETag" = String, description = "The new version of the API objects"))),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Rejected; the report or message says why", body = Object),
        (status = PRECONDITION_REQUIRED, description = "`If-Match` is missing", body = crate::openapi::ErrorBody),
    ))]
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
    fn basic_auth_hashes_and_the_old_webhook_url_are_masked() {
        let config = json!({
            "middlewares": { "auth": { "type": "basic_auth", "users": ["ann:$2y$05$abc"] } },
            "observability": { "alerts": { "webhook": { "url": "https://hooks.example/T0/B0/xyz" } } }
        });
        let out = masked(config, &[]);
        assert_eq!(out["middlewares"]["auth"]["users"][0], "ann:***");
        assert_eq!(out["observability"]["alerts"]["webhook"]["url"], "***");
    }

    #[test]
    fn masked_values_written_back_keep_the_current_secret() {
        let current = json!({
            "middlewares": {
                "auth": { "type": "basic_auth", "users": ["ann:$2y$05$abc", "bob:$2y$05$def"] },
                "sign": { "type": "hmac", "hmac_secret": "s3cret" }
            }
        });
        let mut candidate = masked(current.clone(), &[]);
        candidate["middlewares"]["auth"]["realm"] = json!("staff");
        // Ann is removed: Bob keeps his own hash, not the one at his old position.
        candidate["middlewares"]["auth"]["users"] = json!(["bob:***", "cy:$2y$05$new"]);
        restore_masked(&mut candidate, &current, &mut Vec::new()).unwrap();
        assert_eq!(
            candidate["middlewares"]["auth"]["users"],
            json!(["bob:$2y$05$def", "cy:$2y$05$new"])
        );
        assert_eq!(candidate["middlewares"]["sign"]["hmac_secret"], "s3cret");
        assert_eq!(candidate["middlewares"]["auth"]["realm"], "staff");

        // A new object cannot keep a secret it never had; `***` in an ordinary field is text.
        let mut fresh =
            json!({ "middlewares": { "new": { "type": "hmac", "hmac_secret": "***" } } });
        let err = restore_masked(&mut fresh, &current, &mut Vec::new()).unwrap_err();
        assert!(
            err.starts_with("middlewares.new.hmac_secret is `***`"),
            "{err}"
        );
        let mut unknown = json!({ "middlewares": { "auth": { "users": ["dan:***"] } } });
        let err = restore_masked(&mut unknown, &current, &mut Vec::new()).unwrap_err();
        assert!(
            err.contains("user dan has no current password hash"),
            "{err}"
        );
        let mut plain = json!({ "routes": { "r": { "match": "***" } } });
        restore_masked(&mut plain, &current, &mut Vec::new()).unwrap();
        assert_eq!(plain["routes"]["r"]["match"], "***");
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
