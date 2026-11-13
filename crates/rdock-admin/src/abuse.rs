//! Abuse bans of this instance (H-SEC-01, ADR-0031): list them, lift one.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State as Extract};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use utoipa::IntoParams;

use crate::State;
use crate::audit::Event;
use crate::caller::{Access, Caller, need};
use crate::routes::error;

/// Which middleware's ban to lift.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct BanScope {
    /// Only this `abuse` middleware's ban; every middleware's when omitted.
    #[serde(default)]
    middleware: Option<String>,
}

/// `GET /api/v1/abuse/bans`: the keys banned on this instance now.
#[utoipa::path(get, path = "/abuse/bans", tag = "security", operation_id = "list_bans",
    responses((status = OK, description = "`bans`: middleware, key, since and until (RFC 3339), remaining_seconds", body = Object)))]
pub(crate) async fn bans(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Viewer) {
        return denied.into_response();
    }
    let control = state.control.clone();
    match state.main.spawn(async move { control.bans().await }).await {
        Ok(value) => match caller.scope() {
            // A tenant sees the bans of its own `abuse` middlewares only.
            Some(scope) => {
                axum::Json(crate::tenancy::by_middleware(scope, value, "bans")).into_response()
            }
            None => axum::Json(value).into_response(),
        },
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down"),
    }
}

/// `DELETE /api/v1/abuse/bans/{key}` (operator): lifts the ban of `key` (as listed, e.g.
/// `ip:192.0.2.7` or `ip:2001:db8:1:2::/64`) in every `abuse` middleware, or in
/// `?middleware=` only. Audited. `404` when no such ban exists.
#[utoipa::path(delete, path = "/abuse/bans/{key}", tag = "security", operation_id = "remove_ban",
    params(("key" = String, Path, description = "The banned key, URL-encoded"), BanScope),
    responses(
        (status = OK, description = "`removed`: how many bans were lifted", body = Object),
        (status = NOT_FOUND, description = "No such ban", body = Object)))]
pub(crate) async fn remove_ban(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Query(scope): Query<BanScope>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Operator) {
        return denied.into_response();
    }
    if let Some(tenant) = caller.scope()
        && !scope
            .middleware
            .as_deref()
            .is_some_and(|m| tenant.owns_merged(m))
    {
        return crate::caller::tenant_denied(
            &state,
            &caller,
            format!("/api/v1/abuse/bans/{key}"),
            "name one of the tenant's own `abuse` middlewares in `?middleware=`",
        );
    }
    let control = state.control.clone();
    let (which, middleware) = (key.clone(), scope.middleware.clone());
    let Ok(removed) = state
        .main
        .spawn(async move { control.unban(which, middleware).await })
        .await
    else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down");
    };
    if removed == 0 {
        return error(StatusCode::NOT_FOUND, "no such ban");
    }
    let resource = match &scope.middleware {
        Some(m) => format!("{key} in {m}"),
        None => key,
    };
    state.audit.record(Event {
        resource: Some(resource),
        ..caller.event("abuse.unban")
    });
    axum::Json(json!({ "removed": removed })).into_response()
}
