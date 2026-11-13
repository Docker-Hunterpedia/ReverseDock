//! The control plane's cluster API (H-HA-01…03, ADR-0031), served only by `rdock control run`:
//! enrolled instances and their state, revocation, join tokens, published revisions,
//! publication and rollback. A data plane answers `404` to all of it.

use std::sync::Arc;

use axum::extract::{Extension, Path, State as Extract};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::State;
use crate::audit::{Event, Outcome};
use crate::caller::{Access, Caller, need};
use crate::routes::error;

const NOT_A_CONTROL_PLANE: &str =
    "this is a data plane; the cluster API is served by the control plane (`rdock control run`)";

/// The outcome of a publication.
#[derive(Debug)]
pub enum ClusterPublish {
    /// Published: the new revision's summary.
    Published(Value),
    /// Refused (does not validate, empty, another cluster's sections): the diagnostics.
    Refused(Value),
    /// Not a valid request (an unknown revision to roll back to).
    Invalid(String),
}

/// `POST /api/v1/cluster/tokens`.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct JoinTokenRequest {
    /// How long the token stays usable, in seconds (60 to 2,592,000); `control.join_token_ttl`
    /// when omitted.
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

/// `POST /api/v1/cluster/revisions`: a document to publish, or a revision to roll back to.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ClusterPublishRequest {
    /// The configuration to publish (an `rdock.yaml` as JSON, without `cluster` and
    /// `control`).
    #[serde(default)]
    document: Option<Value>,
    /// Publish this earlier revision's document again, as a new revision.
    #[serde(default)]
    rollback_to: Option<u64>,
}

async fn on_main<T: Send + 'static>(
    state: &State,
    work: impl std::future::Future<Output = T> + Send + 'static,
) -> Result<T, Box<Response>> {
    state.main.spawn(work).await.map_err(|_| {
        Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "rdock is shutting down",
        ))
    })
}

/// `GET /api/v1/cluster/instances`: every enrolled data plane with its state (`synced`,
/// `stale`, `error`, `away`, `revoked`), the revision it serves and its last report.
#[utoipa::path(get, path = "/cluster/instances", tag = "cluster", operation_id = "list_cluster_instances",
    responses(
        (status = OK, description = "`cluster_id`, `latest` and `instances`", body = Object),
        (status = NOT_FOUND, description = "Not a control plane", body = crate::openapi::ErrorBody)))]
pub(crate) async fn instances(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Viewer) {
        return denied.into_response();
    }
    let control = state.control.clone();
    match on_main(&state, async move { control.cluster_instances().await }).await {
        Ok(Some(value)) => axum::Json(value).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, NOT_A_CONTROL_PLANE),
        Err(response) => *response,
    }
}

/// `POST /api/v1/cluster/instances/{name}/revoke` (operator): the instance can no longer
/// fetch bundles or use the store; it keeps serving its last bundle. Audited.
#[utoipa::path(post, path = "/cluster/instances/{name}/revoke", tag = "cluster", operation_id = "revoke_cluster_instance",
    params(("name" = String, Path, description = "The instance's name")),
    responses(
        (status = OK, description = "`revoked`: the name", body = Object),
        (status = NOT_FOUND, description = "No such instance, or not a control plane", body = crate::openapi::ErrorBody)))]
pub(crate) async fn revoke(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Operator) {
        return denied.into_response();
    }
    let control = state.control.clone();
    let which = name.clone();
    let outcome = match on_main(&state, async move { control.cluster_revoke(which).await }).await {
        Ok(outcome) => outcome,
        Err(response) => return *response,
    };
    match outcome {
        None => error(StatusCode::NOT_FOUND, NOT_A_CONTROL_PLANE),
        Some(Ok(false)) => error(StatusCode::NOT_FOUND, "no such instance"),
        Some(Ok(true)) => {
            state.audit.record(Event {
                resource: Some(name.clone()),
                ..caller.event("cluster.revoke")
            });
            axum::Json(json!({ "revoked": name })).into_response()
        }
        Some(Err(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// `POST /api/v1/cluster/tokens` (operator): a single-use join token, shown once, and the
/// cluster CA's pin for `cluster.control.ca_pin`. Audited (the token's id, never its value).
#[utoipa::path(post, path = "/cluster/tokens", tag = "cluster", operation_id = "create_join_token",
    request_body = JoinTokenRequest,
    responses(
        (status = CREATED, description = "`token` (shown once), `id`, `expires_at`, `ca_pin`, `cluster_id`", body = Object),
        (status = BAD_REQUEST, description = "A lifetime out of range", body = crate::openapi::ErrorBody),
        (status = NOT_FOUND, description = "Not a control plane", body = crate::openapi::ErrorBody)))]
pub(crate) async fn create_token(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(request): axum::Json<JoinTokenRequest>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Operator) {
        return denied.into_response();
    }
    if request
        .ttl_seconds
        .is_some_and(|t| !(60..=30 * 24 * 3600).contains(&t))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "`ttl_seconds` must be between 60 and 2592000",
        );
    }
    let control = state.control.clone();
    let actor = caller.name().to_owned();
    let ttl = request.ttl_seconds;
    let outcome = match on_main(&state, async move {
        control.cluster_create_token(ttl, actor).await
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(response) => return *response,
    };
    match outcome {
        None => error(StatusCode::NOT_FOUND, NOT_A_CONTROL_PLANE),
        Some(Ok(value)) => {
            state.audit.record(Event {
                resource: value["id"].as_str().map(str::to_owned),
                ..caller.event("cluster.token")
            });
            (StatusCode::CREATED, axum::Json(value)).into_response()
        }
        Some(Err(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// `GET /api/v1/cluster/revisions`: published revisions, newest first, with the instances
/// that refused each and why.
#[utoipa::path(get, path = "/cluster/revisions", tag = "cluster", operation_id = "list_cluster_revisions",
    responses(
        (status = OK, description = "`cluster_id`, `latest` and `revisions`", body = Object),
        (status = NOT_FOUND, description = "Not a control plane", body = crate::openapi::ErrorBody)))]
pub(crate) async fn revisions(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Viewer) {
        return denied.into_response();
    }
    let control = state.control.clone();
    match on_main(&state, async move { control.cluster_revisions().await }).await {
        Ok(Some(value)) => axum::Json(value).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, NOT_A_CONTROL_PLANE),
        Err(response) => *response,
    }
}

/// `POST /api/v1/cluster/revisions` (operator): validates and publishes `document` as the
/// next revision, or publishes `rollback_to`'s document again as a new revision. Data planes
/// pull it. Audited.
#[utoipa::path(post, path = "/cluster/revisions", tag = "cluster", operation_id = "publish_cluster_revision",
    request_body = ClusterPublishRequest,
    responses(
        (status = CREATED, description = "`revision`, `sha256`, `published_at`, `rollback_of`, `warnings`", body = Object),
        (status = BAD_REQUEST, description = "Neither or both of `document` and `rollback_to`, or an unknown revision", body = crate::openapi::ErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "The document does not validate or is empty: `diagnostics`", body = Object),
        (status = NOT_FOUND, description = "Not a control plane", body = crate::openapi::ErrorBody)))]
pub(crate) async fn publish(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    axum::Json(request): axum::Json<ClusterPublishRequest>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Operator) {
        return denied.into_response();
    }
    let rollback = request.rollback_to.is_some();
    let body = match (request.document, request.rollback_to) {
        (Some(document), None) => json!({ "document": document }),
        (None, Some(revision)) => json!({ "rollback_to": revision }),
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "send either `document` or `rollback_to`",
            );
        }
    };
    let control = state.control.clone();
    let actor = caller.name().to_owned();
    let outcome = match on_main(
        &state,
        async move { control.cluster_publish(body, actor).await },
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(response) => return *response,
    };
    let action = if rollback {
        "cluster.rollback"
    } else {
        "cluster.publish"
    };
    match outcome {
        None => error(StatusCode::NOT_FOUND, NOT_A_CONTROL_PLANE),
        Some(ClusterPublish::Published(value)) => {
            state.audit.record(Event {
                resource: value["revision"].as_u64().map(|r| format!("revision {r}")),
                ..caller.event(action)
            });
            (StatusCode::CREATED, axum::Json(value)).into_response()
        }
        Some(ClusterPublish::Refused(value)) => {
            state.audit.record(Event {
                outcome: Outcome::Failed,
                reason: Some("the configuration was refused".to_owned()),
                ..caller.event(action)
            });
            (StatusCode::UNPROCESSABLE_ENTITY, axum::Json(value)).into_response()
        }
        Some(ClusterPublish::Invalid(message)) => error(StatusCode::BAD_REQUEST, &message),
    }
}
