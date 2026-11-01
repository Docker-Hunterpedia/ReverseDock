//! Per-resource endpoints (ADR-0024, F-UI-03): routes, services and middlewares with their
//! owner, writable one by one when the API owns them and read-only otherwise; certificates
//! with renewal; backends with drain; providers and listeners.

use std::sync::Arc;

use axum::extract::{Extension, Path, State as Extract};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};

use crate::State;
use crate::audit::Event;
use crate::caller::{Access, Caller, need};
use crate::config_api::{api_config, if_match, masked, owners, write, writes_allowed};
use crate::routes::error;

macro_rules! check {
    ($result:expr) => {
        if let Err(denied) = $result {
            return denied.into_response();
        }
    };
}

const SECTIONS: [&str; 3] = ["routes", "services", "middlewares"];

fn section(name: &str) -> Option<&'static str> {
    SECTIONS.into_iter().find(|s| *s == name)
}

async fn effective(state: &State) -> Option<Value> {
    let control = state.control.clone();
    state
        .main
        .spawn(async move { control.effective_config().await })
        .await
        .ok()
}

async fn status(state: &State) -> Option<Value> {
    let control = state.control.clone();
    state
        .main
        .spawn(async move { control.status().await })
        .await
        .ok()
}

fn gone() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down")
}

/// The sections of the configuration the object endpoints serve.
#[derive(ToSchema)]
#[schema(rename_all = "lowercase")]
#[expect(
    dead_code,
    reason = "documents the `kind` path segment; `section` parses it"
)]
pub(crate) enum Section {
    Routes,
    Services,
    Middlewares,
}

/// One object and the provider that owns it, secrets masked.
#[derive(serde::Serialize, ToSchema)]
pub(crate) struct Owned {
    name: String,
    /// `file`, `api`, `docker` …
    owner: String,
    #[schema(value_type = Object)]
    spec: Value,
}

/// `GET /api/v1/{routes|services|middlewares}`: every object with its owner.
#[utoipa::path(get, path = "/{kind}", tag = "objects", operation_id = "list_objects",
    params(("kind" = inline(Section), Path, description = "Which section")),
    responses(
        (status = OK, description = "The objects", body = [Owned]),
        (status = NOT_FOUND, description = "Not a section", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn list(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(kind): Path<String>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let Some(kind) = section(&kind) else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    let Some(config) = effective(&state).await else {
        return gone();
    };
    let owners = owners(&config);
    let config = masked(config, &[]);
    let items: Vec<Value> = config[kind]
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(name, object)| {
                    json!({ "name": name, "owner": owners[kind][name], "spec": object })
                })
                .collect()
        })
        .unwrap_or_default();
    axum::Json(items).into_response()
}

/// `GET /api/v1/{section}/{name}`: one object with its owner.
#[utoipa::path(get, path = "/{kind}/{name}", tag = "objects", operation_id = "get_object",
    params(("kind" = inline(Section), Path, description = "Which section"), ("name" = String, Path, description = "Object name, `name@provider` for provider objects")),
    responses(
        (status = OK, description = "The object", body = Owned),
        (status = NOT_FOUND, description = "No such object", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn get(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path((kind, name)): Path<(String, String)>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let Some(kind) = section(&kind) else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    let Some(config) = effective(&state).await else {
        return gone();
    };
    let owners = owners(&config);
    let config = masked(config, &[]);
    match config[kind].get(&name) {
        Some(object) => {
            axum::Json(json!({ "name": name, "owner": owners[kind][&name], "spec": object }))
                .into_response()
        }
        None => error(StatusCode::NOT_FOUND, "no such object"),
    }
}

/// The bare API name for `name` (`x` or `x@api`), or the provider that owns it instead.
fn api_name(name: &str) -> Result<String, String> {
    match name.rsplit_once('@') {
        None => Ok(name.to_owned()),
        Some((bare, "api")) => Ok(bare.to_owned()),
        Some((_, owner)) => Err(owner.to_owned()),
    }
}

/// `PUT /api/v1/{section}/{name}` (body: the object) and `DELETE`: change one API-owned
/// object, conditional on the version of the API objects (`If-Match`).
async fn change(
    state: &State,
    caller: &Caller,
    headers: &HeaderMap,
    target: (String, String),
    object: Option<Value>,
) -> Response {
    check!(need(caller, Access::Operator));
    check!(writes_allowed(state));
    let tag = match if_match(headers) {
        Ok(tag) => tag,
        Err(denied) => return denied.into_response(),
    };
    let Some(kind) = section(&target.0) else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    let name = match api_name(&target.1) {
        Ok(name) => name,
        Err(owner) => {
            return error(
                StatusCode::FORBIDDEN,
                &format!("this object belongs to the {owner} provider; change it there"),
            );
        }
    };
    let file_owned = effective(state)
        .await
        .is_some_and(|c| c[kind].get(&name).is_some());
    if file_owned {
        return error(
            StatusCode::FORBIDDEN,
            "this object belongs to the configuration file; change it there",
        );
    }
    let Some((mut fragment, _)) = api_config(state).await else {
        return gone();
    };
    if !fragment[kind].is_object() {
        fragment[kind] = json!({});
    }
    let Some(map) = fragment[kind].as_object_mut() else {
        return gone();
    };
    match object {
        Some(object) => {
            map.insert(name, object);
        }
        None => {
            if map.remove(&name).is_none() {
                return error(StatusCode::NOT_FOUND, "no such object");
            }
        }
    }
    write(state, caller, fragment, tag, "config.apply").await
}

/// Creates or replaces an API-owned object (operator role), as a conditional write.
#[utoipa::path(put, path = "/{kind}/{name}", tag = "objects", operation_id = "put_object",
    request_body = Object, params(("kind" = inline(Section), Path, description = "Which section"), ("name" = String, Path, description = "Object name, `name@provider` for provider objects"), ("If-Match" = String, Header, description = "The `ETag` from `GET /api/v1/config/api`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object),
        (status = FORBIDDEN, description = "The object belongs to another provider or the file", body = crate::openapi::ErrorBody),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "Rejected", body = Object),
    ))]
pub(crate) async fn put(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(target): Path<(String, String)>,
    headers: HeaderMap,
    axum::Json(object): axum::Json<Value>,
) -> Response {
    change(&state, &caller, &headers, target, Some(object)).await
}

/// Deletes an API-owned object (operator role), as a conditional write.
#[utoipa::path(delete, path = "/{kind}/{name}", tag = "objects", operation_id = "delete_object",
    params(("kind" = inline(Section), Path, description = "Which section"), ("name" = String, Path, description = "Object name, `name@provider` for provider objects"), ("If-Match" = String, Header, description = "The `ETag` from `GET /api/v1/config/api`")),
    responses(
        (status = OK, description = "Applied; the reload report", body = Object),
        (status = NOT_FOUND, description = "No such API object", body = crate::openapi::ErrorBody),
        (status = FORBIDDEN, description = "The object belongs to another provider or the file", body = crate::openapi::ErrorBody),
        (status = PRECONDITION_FAILED, description = "The API objects changed since they were read", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn delete(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(target): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    change(&state, &caller, &headers, target, None).await
}

/// `GET /api/v1/certificates`: configured certificates (key passwords masked) and the state
/// of automatic ones.
#[utoipa::path(get, path = "/certificates", tag = "certificates",
    responses((status = OK, description = "Configured and automatic certificates", body = Object)))]
pub(crate) async fn certificates(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let (Some(config), Some(status)) = (effective(&state).await, status(&state).await) else {
        return gone();
    };
    let config = masked(config, &[]);
    axum::Json(json!({
        "configured": config["certificates"],
        "automatic": status["certificates"],
    }))
    .into_response()
}

/// `POST /api/v1/certificates/{name}/renew`: renew the automatic certificate covering
/// `name` now (operator role).
#[utoipa::path(post, path = "/certificates/{name}/renew", tag = "certificates",
    params(("name" = String, Path, description = "A name the certificate covers")),
    responses(
        (status = ACCEPTED, description = "Renewal requested", body = Object),
        (status = NOT_FOUND, description = "No automatic certificate covers the name", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn renew(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
) -> Response {
    check!(need(&caller, Access::Operator));
    let control = state.control.clone();
    let asked = name.clone();
    let Ok(found) = state
        .main
        .spawn(async move { control.renew_certificate(asked).await })
        .await
    else {
        return gone();
    };
    if !found {
        return error(
            StatusCode::NOT_FOUND,
            "no automatic certificate covers this name",
        );
    }
    state.audit.record(Event {
        resource: Some(name),
        ..caller.event("certificate.renew")
    });
    (
        StatusCode::ACCEPTED,
        axum::Json(json!({ "result": "renewal requested" })),
    )
        .into_response()
}

/// `GET /api/v1/backends`: every service's backends with their health, load and state.
#[utoipa::path(get, path = "/backends", tag = "backends",
    responses((status = OK, description = "Each service with its backends", body = [Object])))]
pub(crate) async fn backends(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.backends().await })
        .await
    {
        Ok(list) => axum::Json(list).into_response(),
        Err(_) => gone(),
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackendRef {
    service: String,
    backend: String,
}

async fn set_drained(
    state: &State,
    caller: &Caller,
    target: BackendRef,
    drained: bool,
) -> Response {
    check!(need(caller, Access::Operator));
    let control = state.control.clone();
    let (service, backend) = (target.service.clone(), target.backend.clone());
    let Ok(found) = state
        .main
        .spawn(async move { control.set_drained(service, backend, drained).await })
        .await
    else {
        return gone();
    };
    if !found {
        return error(
            StatusCode::NOT_FOUND,
            "no such backend in the running configuration",
        );
    }
    state.audit.record(Event {
        resource: Some(format!("{}/{}", target.service, target.backend)),
        ..caller.event(if drained {
            "backend.drain"
        } else {
            "backend.undrain"
        })
    });
    axum::Json(json!({ "service": target.service, "backend": target.backend, "drained": drained }))
        .into_response()
}

/// `POST /api/v1/backends/drain`: no new requests to the backend; open ones finish
/// (operator role).
#[utoipa::path(post, path = "/backends/drain", tag = "backends", request_body = BackendRef,
    responses(
        (status = OK, description = "`service`, `backend` and `drained`", body = Object),
        (status = NOT_FOUND, description = "No such backend", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn drain(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(target): axum::Json<BackendRef>,
) -> Response {
    set_drained(&state, &caller, target, true).await
}

/// `POST /api/v1/backends/undrain`: the backend takes new requests again (operator role).
#[utoipa::path(post, path = "/backends/undrain", tag = "backends", request_body = BackendRef,
    responses(
        (status = OK, description = "`service`, `backend` and `drained`", body = Object),
        (status = NOT_FOUND, description = "No such backend", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn undrain(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(target): axum::Json<BackendRef>,
) -> Response {
    set_drained(&state, &caller, target, false).await
}

/// `GET /api/v1/providers`: each provider's state and the diagnostics of the last reload
/// about its objects.
#[utoipa::path(get, path = "/providers", tag = "status",
    responses((status = OK, description = "`providers` and `diagnostics`", body = Object)))]
pub(crate) async fn providers(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let Some(status) = status(&state).await else {
        return gone();
    };
    let diagnostics: Vec<Value> = status["last_reload"]["diagnostics"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|d| d["path"].as_str().is_some_and(|p| p.contains('@')))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    axum::Json(json!({ "providers": status["providers"], "diagnostics": diagnostics }))
        .into_response()
}

/// `GET /api/v1/listeners`: the listeners. Changing them needs a restart (ADR-0008).
#[utoipa::path(get, path = "/listeners", tag = "status",
    responses((status = OK, description = "The listeners", body = [Object])))]
pub(crate) async fn listeners(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    match status(&state).await {
        Some(status) => axum::Json(status["listeners"].clone()).into_response(),
        None => gone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bare_and_api_names_are_writable() {
        assert_eq!(api_name("shop").ok().as_deref(), Some("shop"));
        assert_eq!(api_name("shop@api").ok().as_deref(), Some("shop"));
        assert!(api_name("shop@docker").is_err());
    }
}

#[derive(Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub(crate) struct Window {
    /// Seconds, 1–900; 300 by default.
    #[serde(default)]
    window: Option<u64>,
}

/// `GET /api/v1/metrics/summary?window=300`: requests, rates, status classes, errors, bytes
/// and p50/p95/p99 for the whole proxy (one point per second) and every route and service,
/// from the 15-minute ring buffers.
#[utoipa::path(get, path = "/metrics/summary", tag = "metrics", params(Window),
    responses((status = OK, description = "`total`, `routes` and `services`", body = Object)))]
pub(crate) async fn metrics_summary(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::extract::Query(query): axum::extract::Query<Window>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let window = query.window.unwrap_or(300).clamp(1, 900);
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.metrics_summary(window).await })
        .await
    {
        Ok(summary) => axum::Json(summary).into_response(),
        Err(_) => gone(),
    }
}

/// `POST /api/v1/routes/explain`: how a request would be routed, never sent (viewer role).
#[utoipa::path(post, path = "/routes/explain", tag = "objects", request_body = Object,
    responses(
        (status = OK, description = "The matched route, the candidates and the backend", body = Object),
        (status = UNPROCESSABLE_ENTITY, description = "Not a valid request description", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn explain(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(request): axum::Json<Value>,
) -> Response {
    check!(need(&caller, Access::Viewer));
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.explain(request).await })
        .await
    {
        Ok(Ok(answer)) => axum::Json(answer).into_response(),
        Ok(Err(message)) => error(StatusCode::UNPROCESSABLE_ENTITY, &message),
        Err(_) => gone(),
    }
}
