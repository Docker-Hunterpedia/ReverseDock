//! Consumers, their API keys and quota counters (F-GW-01, F-GW-02, ADR-0030).
//!
//! Consumers and keys written here live in the `api` provider's document (`consumers`), so
//! every change is a conditional write (`If-Match`) applied through the same validate →
//! compile → swap path as any configuration change, recorded in the history and audited. Only
//! the key's ID and the SHA-256 of its secret are stored; the clear-text key is in the answer
//! to its creation and nowhere else: not in the document, the history, the audit log or a log
//! line. Viewers list consumers without hashes; operators manage them.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State as Extract};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};

use crate::State;
use crate::audit::Event;
use crate::caller::{Access, Caller, need};
use crate::config_api::{api_config, if_match, write_as, writes_allowed};
use crate::routes::error;

macro_rules! check {
    ($result:expr) => {
        if let Err(denied) = $result {
            return denied.into_response();
        }
    };
}

/// Longest lifetime a key may be minted with through the API, in days.
const MAX_DAYS: u32 = 3650;

fn gone() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down")
}

async fn effective(state: &State) -> Option<Value> {
    let control = state.control.clone();
    state
        .main
        .spawn(async move { control.effective_config().await })
        .await
        .ok()
}

/// The consumers of the effective configuration, with the owner of each key (`file` or
/// `api`); hashes only for operators.
fn listing(effective: &Value, api: &Value, hashes: bool) -> Vec<Value> {
    let api_ids = |name: &str| -> Vec<String> {
        api["consumers"][name]["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|k| k["id"].as_str().map(str::to_owned))
            .collect()
    };
    effective["consumers"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, consumer)| {
            let ours = api_ids(name);
            let keys: Vec<Value> = consumer["keys"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|key| {
                    let id = key["id"].as_str().unwrap_or_default();
                    let mut entry = json!({
                        "id": id,
                        "expires": key.get("expires"),
                        "note": key.get("note"),
                        "owner": if ours.iter().any(|o| o == id) { "api" } else { "file" },
                    });
                    if hashes {
                        entry["hash"] = key["hash"].clone();
                    }
                    entry
                })
                .collect();
            let owner = if api["consumers"].get(name).is_some()
                && api["consumers"][name]["groups"].is_array()
            {
                "api"
            } else if api["consumers"].get(name).is_some() {
                "file+api"
            } else {
                "file"
            };
            json!({
                "name": name,
                "groups": consumer.get("groups").cloned().unwrap_or_else(|| json!([])),
                "keys_file": consumer.get("keys_file"),
                "keys": keys,
                "owner": owner,
            })
        })
        .collect()
}

/// `GET /api/v1/consumers`: every consumer with its groups and keys (IDs, expiry, notes);
/// key hashes for operators only.
#[utoipa::path(get, path = "/consumers", tag = "consumers", operation_id = "list_consumers",
    responses((status = OK, description = "`consumers`: name, groups, keys (id, expires, note, owner, hash for operators), owner", body = Object)))]
pub(crate) async fn list(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let (Some(config), Some((api, etag))) = (effective(&state).await, api_config(&state).await)
    else {
        return gone();
    };
    let hashes = caller.access() >= Access::Operator;
    crate::config_api::with_etag(
        axum::Json(json!({ "consumers": listing(&config, &api, hashes) })).into_response(),
        &etag,
    )
}

/// `GET /api/v1/consumers/{name}`: one consumer.
#[utoipa::path(get, path = "/consumers/{name}", tag = "consumers", operation_id = "get_consumer",
    params(("name" = String, Path, description = "Consumer name")),
    responses(
        (status = OK, description = "The consumer", body = Object),
        (status = NOT_FOUND, description = "No such consumer", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn get(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let (Some(config), Some((api, etag))) = (effective(&state).await, api_config(&state).await)
    else {
        return gone();
    };
    let hashes = caller.access() >= Access::Operator;
    match listing(&config, &api, hashes)
        .into_iter()
        .find(|c| c["name"] == name)
    {
        Some(consumer) => crate::config_api::with_etag(axum::Json(consumer).into_response(), &etag),
        None => error(StatusCode::NOT_FOUND, "no such consumer"),
    }
}

/// A consumer as the API defines it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumerSpec {
    /// Groups, in order of precedence.
    #[serde(default)]
    groups: Vec<String>,
}

/// The API document with its `consumers` section as an object.
fn consumers_of(document: &mut Value) -> Option<&mut serde_json::Map<String, Value>> {
    if !document["consumers"].is_object() {
        document["consumers"] = json!({});
    }
    document["consumers"].as_object_mut()
}

/// Whether the configuration file defines `name`: the API document holds no groups for it
/// (at most keys the API added).
fn defined_in_file(effective: &Value, api: &Value, name: &str) -> bool {
    effective["consumers"].get(name).is_some() && !api["consumers"][name]["groups"].is_array()
}

/// `PUT /api/v1/consumers/{name}` (operator): creates or changes an API-owned consumer's
/// groups; its keys stay. A consumer of the configuration file is changed there.
#[utoipa::path(put, path = "/consumers/{name}", tag = "consumers", operation_id = "put_consumer",
    request_body = ConsumerSpec,
    params(("name" = String, Path, description = "Consumer name"), ("If-Match" = String, Header, description = "The `ETag` from `GET /api/v1/config/api` or `GET /api/v1/consumers`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object),
        (status = FORBIDDEN, description = "The consumer belongs to the configuration file", body = crate::openapi::ErrorBody),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Rejected", body = Object),
    ))]
pub(crate) async fn put(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
    headers: HeaderMap,
    axum::Json(spec): axum::Json<ConsumerSpec>,
) -> Response {
    check!(need(&caller, Access::Operator));
    check!(writes_allowed(&state));
    let tag = match if_match(&headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    let (Some(config), Some((mut api, _))) = (effective(&state).await, api_config(&state).await)
    else {
        return gone();
    };
    if defined_in_file(&config, &api, &name) {
        return error(
            StatusCode::FORBIDDEN,
            "this consumer belongs to the configuration file; change its groups there (keys can still be added here)",
        );
    }
    let Some(consumers) = consumers_of(&mut api) else {
        return gone();
    };
    let entry = consumers.entry(name.clone()).or_insert_with(|| json!({}));
    entry["groups"] = json!(spec.groups);
    write_as(
        &state,
        &caller,
        api,
        tag,
        ("consumer.update", Some(name)),
        |report, _| axum::Json(report).into_response(),
    )
    .await
}

/// `DELETE /api/v1/consumers/{name}` (operator): removes an API-owned consumer and the keys
/// the API minted for it.
#[utoipa::path(delete, path = "/consumers/{name}", tag = "consumers", operation_id = "delete_consumer",
    params(("name" = String, Path, description = "Consumer name"), ("If-Match" = String, Header, description = "The current `ETag`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object),
        (status = NOT_FOUND, description = "No such API consumer", body = crate::openapi::ErrorBody),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn delete(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    check!(need(&caller, Access::Operator));
    check!(writes_allowed(&state));
    let tag = match if_match(&headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    let Some((mut api, _)) = api_config(&state).await else {
        return gone();
    };
    let Some(consumers) = consumers_of(&mut api) else {
        return gone();
    };
    if consumers.remove(&name).is_none() {
        return error(StatusCode::NOT_FOUND, "no such API consumer");
    }
    write_as(
        &state,
        &caller,
        api,
        tag,
        ("consumer.delete", Some(name)),
        |report, _| axum::Json(report).into_response(),
    )
    .await
}

/// A key to mint.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewKey {
    /// Days until the key expires (1–3650); never when neither this nor `expires` is set.
    #[serde(default)]
    expires_in_days: Option<u32>,
    /// When the key expires, RFC 3339.
    #[serde(default)]
    expires: Option<String>,
    /// What the key is for.
    #[serde(default)]
    note: Option<String>,
}

fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = rdock_model::gateway::civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `POST /api/v1/consumers/{name}/keys` (operator): mints an API key for a consumer of the
/// file or the API. The clear-text key is in this answer only; what is stored is its ID and
/// the SHA-256 of its secret.
#[utoipa::path(post, path = "/consumers/{name}/keys", tag = "consumers", operation_id = "create_consumer_key",
    request_body = NewKey,
    params(("name" = String, Path, description = "Consumer name"), ("If-Match" = String, Header, description = "The current `ETag`")),
    responses(
        (status = CREATED, description = "`key` (shown once), `id`, `expires`, `report`", body = Object),
        (status = NOT_FOUND, description = "No such consumer", body = crate::openapi::ErrorBody),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Rejected", body = Object),
    ))]
pub(crate) async fn create_key(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Option<axum::Json<NewKey>>,
) -> Response {
    check!(need(&caller, Access::Operator));
    check!(writes_allowed(&state));
    let tag = match if_match(&headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    let request = body.map(|b| b.0).unwrap_or_default();
    let expires = match (&request.expires_in_days, &request.expires) {
        (Some(_), Some(_)) => {
            return error(
                StatusCode::BAD_REQUEST,
                "set `expires_in_days` or `expires`, not both",
            );
        }
        (Some(days), None) if (1..=MAX_DAYS).contains(days) => {
            Some(rfc3339(now() + i64::from(*days) * 86_400))
        }
        (Some(_), None) => {
            return error(StatusCode::BAD_REQUEST, "`expires_in_days` is 1 to 3650");
        }
        (None, Some(at)) => match rdock_model::gateway::parse_rfc3339(at) {
            Some(t) if t > now() => Some(at.clone()),
            Some(_) => return error(StatusCode::BAD_REQUEST, "`expires` is in the past"),
            None => return error(StatusCode::BAD_REQUEST, "`expires` is not an RFC 3339 time"),
        },
        (None, None) => None,
    };
    let (Some(config), Some((mut api, _))) = (effective(&state).await, api_config(&state).await)
    else {
        return gone();
    };
    if config["consumers"].get(&name).is_none() && api["consumers"].get(&name).is_none() {
        return error(StatusCode::NOT_FOUND, "no such consumer");
    }
    let Some(made) = rdock_credentials::API_KEY.generate() else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the random generator failed",
        );
    };
    let mut stored = json!({ "id": made.id, "hash": made.secret_sha256 });
    if let Some(at) = &expires {
        stored["expires"] = json!(at);
    }
    if let Some(note) = &request.note {
        stored["note"] = json!(note);
    }
    let Some(consumers) = consumers_of(&mut api) else {
        return gone();
    };
    let entry = consumers.entry(name.clone()).or_insert_with(|| json!({}));
    if !entry["keys"].is_array() {
        entry["keys"] = json!([]);
    }
    if let Some(keys) = entry["keys"].as_array_mut() {
        keys.push(stored);
    }
    let id = made.id.clone();
    let value = made.value;
    write_as(
        &state,
        &caller,
        api,
        tag,
        ("consumer.key.create", Some(format!("{name}/{id}"))),
        move |report, _| {
            (
                StatusCode::CREATED,
                axum::Json(json!({
                    "consumer": name,
                    "id": id,
                    "key": value.expose(),
                    "expires": expires,
                    "report": report,
                })),
            )
                .into_response()
        },
    )
    .await
}

/// `DELETE /api/v1/consumers/{name}/keys/{id}` (operator): revokes a key the API minted. It
/// stops working with the configuration this applies. Keys of the configuration file are
/// removed there.
#[utoipa::path(delete, path = "/consumers/{name}/keys/{id}", tag = "consumers", operation_id = "revoke_consumer_key",
    params(("name" = String, Path, description = "Consumer name"), ("id" = String, Path, description = "Key ID"), ("If-Match" = String, Header, description = "The current `ETag`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object),
        (status = FORBIDDEN, description = "The key belongs to the configuration file", body = crate::openapi::ErrorBody),
        (status = NOT_FOUND, description = "No such key", body = crate::openapi::ErrorBody),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn revoke_key(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path((name, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    check!(need(&caller, Access::Operator));
    check!(writes_allowed(&state));
    let tag = match if_match(&headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    let (Some(config), Some((mut api, _))) = (effective(&state).await, api_config(&state).await)
    else {
        return gone();
    };
    let Some(consumers) = consumers_of(&mut api) else {
        return gone();
    };
    let removed = consumers
        .get_mut(&name)
        .and_then(|c| c["keys"].as_array_mut())
        .is_some_and(|keys| {
            let before = keys.len();
            keys.retain(|k| k["id"] != id);
            keys.len() != before
        });
    if !removed {
        let in_file = config["consumers"][&name]["keys"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|k| k["id"] == id));
        return if in_file {
            error(
                StatusCode::FORBIDDEN,
                "this key belongs to the configuration file; remove it there",
            )
        } else {
            error(StatusCode::NOT_FOUND, "no such key")
        };
    }
    // A consumer the API only held keys for disappears with its last key.
    if consumers
        .get(&name)
        .is_some_and(|c| c["groups"].is_null() && c["keys"].as_array().is_some_and(Vec::is_empty))
    {
        consumers.remove(&name);
    }
    write_as(
        &state,
        &caller,
        api,
        tag,
        ("consumer.key.revoke", Some(format!("{name}/{id}"))),
        |report, _| axum::Json(report).into_response(),
    )
    .await
}

/// Which quota counters to reset.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct QuotaScope {
    /// Only this `quota` middleware's counters.
    #[serde(default)]
    middleware: Option<String>,
}

/// `GET /api/v1/quota`: every `quota` middleware of this instance with its window and the
/// counts of the current window.
#[utoipa::path(get, path = "/quota", tag = "consumers", operation_id = "list_quotas",
    responses((status = OK, description = "`quotas`: middleware, window, window_start, window_end, usage (key, used, limit)", body = Object)))]
pub(crate) async fn quotas(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.quotas(None).await })
        .await
    {
        Ok(value) => axum::Json(value).into_response(),
        Err(_) => gone(),
    }
}

/// `GET /api/v1/quota/{consumer}`: one consumer's counts in every quota.
#[utoipa::path(get, path = "/quota/{consumer}", tag = "consumers", operation_id = "get_quota",
    params(("consumer" = String, Path, description = "Consumer name")),
    responses((status = OK, description = "`quotas` with this consumer's use only", body = Object)))]
pub(crate) async fn quota(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(consumer): Path<String>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.quotas(Some(consumer)).await })
        .await
    {
        Ok(value) => axum::Json(value).into_response(),
        Err(_) => gone(),
    }
}

/// `DELETE /api/v1/quota/{consumer}` (operator): forgets the consumer's counts on this
/// instance, in every quota or in `?middleware=` only. Audited.
#[utoipa::path(delete, path = "/quota/{consumer}", tag = "consumers", operation_id = "reset_quota",
    params(("consumer" = String, Path, description = "Consumer name"), QuotaScope),
    responses((status = OK, description = "`reset`: how many counters were removed", body = Object)))]
pub(crate) async fn reset_quota(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(consumer): Path<String>,
    Query(scope): Query<QuotaScope>,
) -> Response {
    check!(need(&caller, Access::Operator));
    let control = state.control.clone();
    let (who, which) = (consumer.clone(), scope.middleware.clone());
    let Ok(reset) = state
        .main
        .spawn(async move { control.reset_quota(who, which).await })
        .await
    else {
        return gone();
    };
    let resource = match &scope.middleware {
        Some(m) => format!("{consumer} in {m}"),
        None => consumer,
    };
    state.audit.record(Event {
        resource: Some(resource),
        ..caller.event("quota.reset")
    });
    axum::Json(json!({ "reset": reset })).into_response()
}
