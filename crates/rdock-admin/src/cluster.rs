//! The control plane's cluster API (H-HA-01…03, ADR-0031), served only by `rdock control run`:
//! enrolled instances and their state, revocation, join tokens, published revisions,
//! publication and rollback. A data plane answers `404` to all of it.

use std::sync::Arc;

use axum::extract::{Extension, Path, State as Extract};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::{Deserialize, Serialize};
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

/// How an instance stands.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[expect(
    dead_code,
    reason = "documents the control plane's JSON for the schema only"
)]
pub(crate) enum ClusterInstanceState {
    /// Serves the newest revision.
    Synced,
    /// Serves an older revision and has not refused the newest; a running rollout may hold it
    /// on the stable revision (`target`).
    Behind,
    /// Refused the newest revision (`last_error` says why).
    Error,
    /// Has not called for longer than `control.offline_after`.
    Offline,
    /// Revoked: it keeps serving its last bundle and receives no other.
    Revoked,
}

/// A data plane's last report on a bundle.
#[derive(Serialize, ToSchema)]
pub(crate) struct ClusterReport {
    /// The revision reported on.
    revision: u64,
    /// `ack` or `nack`.
    verdict: String,
    /// The data plane's diagnostics (`severity`, `path`, `message`, `hint`) for a NACK, or
    /// its warnings.
    #[schema(value_type = Vec<Object>)]
    diagnostics: Vec<Value>,
    /// RFC 3339.
    at: String,
}

/// One enrolled data plane.
#[derive(Serialize, ToSchema)]
pub(crate) struct ClusterInstance {
    /// Its name in the cluster.
    name: String,
    state: ClusterInstanceState,
    /// The revision it serves, as it last reported.
    serving: u64,
    /// The revision the rollout gives it now (the newest, or the stable one while a canary
    /// runs or after a halt).
    target: u64,
    /// The newest published revision.
    latest: u64,
    /// The rdock version it last reported.
    version: Option<String>,
    /// RFC 3339.
    enrolled_at: String,
    /// When it last called the control plane, RFC 3339.
    last_seen: Option<String>,
    /// Expiry of its client certificate (its cluster identity), RFC 3339.
    certificate_not_after: String,
    revoked: bool,
    /// The reason of its last refusal, `revision N: message`.
    last_error: Option<String>,
    last_report: Option<ClusterReport>,
}

/// Why a rollout halted.
#[derive(Serialize, ToSchema)]
pub(crate) struct ClusterHalt {
    /// RFC 3339.
    at: String,
    /// The instance that refused, or the canary that did not report.
    instance: Option<String>,
    reason: String,
}

/// Where a rollout stands.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[expect(
    dead_code,
    reason = "documents the control plane's JSON for the schema only"
)]
pub(crate) enum ClusterRolloutPhase {
    /// Nothing published yet.
    None,
    /// The canary has the revision and has not acknowledged it (or no instance is online).
    Canary,
    /// The canary acknowledged; the rest follow at `soak_ends_at`.
    Soaking,
    /// Every instance is given the revision.
    Complete,
    /// Stopped by a refusal or a silent canary; resume or abandon it.
    Halted,
}

/// The rollout settings in effect (`control.rollout`).
#[derive(Serialize, ToSchema)]
pub(crate) struct ClusterRolloutSettings {
    /// `canary` or `all`.
    mode: String,
    canary: Option<String>,
    soak_seconds: u64,
    canary_timeout_seconds: u64,
}

/// The rollout of the newest revision.
#[derive(Serialize, ToSchema)]
pub(crate) struct ClusterRollout {
    /// The revision being rolled out.
    revision: u64,
    /// The last revision whose rollout completed; instances not given `revision` serve it.
    stable: u64,
    /// `canary`, or `all` (mode `all`, the first revision, rollbacks).
    mode: String,
    phase: ClusterRolloutPhase,
    canary: Option<String>,
    started_at: Option<String>,
    canary_acked_at: Option<String>,
    /// While soaking: when the rest are given the revision.
    soak_ends_at: Option<String>,
    completed_at: Option<String>,
    /// Instances given `revision`.
    offered: Vec<String>,
    halt: Option<ClusterHalt>,
    /// Who resumed it.
    resumed_by: Option<String>,
    settings: ClusterRolloutSettings,
}

/// `GET /api/v1/cluster/instances`.
#[derive(Serialize, ToSchema)]
pub(crate) struct ClusterInstances {
    cluster_id: String,
    /// `control.name`.
    name: Option<String>,
    /// The newest published revision.
    latest: u64,
    rollout: ClusterRollout,
    instances: Vec<ClusterInstance>,
}

/// One published revision.
#[derive(Serialize, ToSchema)]
pub(crate) struct ClusterRevision {
    revision: u64,
    /// SHA-256 of the document's canonical JSON.
    sha256: String,
    published_at: String,
    published_by: Option<String>,
    /// The revision whose document this one republishes.
    rollback_of: Option<u64>,
    /// Instances whose last report refused this revision, with their diagnostics.
    #[schema(value_type = Vec<Object>)]
    refused_by: Vec<Value>,
    /// How its rollout ended or stands: `state` (`canary`, `soaking`, `halted`, `complete`,
    /// `abandoned`, `superseded`), `reason`, `at`.
    #[schema(value_type = Option<Object>)]
    rollout: Option<Value>,
}

/// `GET /api/v1/cluster/revisions`.
#[derive(Serialize, ToSchema)]
pub(crate) struct ClusterRevisions {
    cluster_id: String,
    latest: u64,
    rollout: ClusterRollout,
    revisions: Vec<ClusterRevision>,
}

/// The outcome of resuming or abandoning a rollout.
#[derive(Debug)]
pub enum RolloutAction {
    /// Done: the rollout's new state (resume) or the published rollback (abandon).
    Done(Value),
    /// Nothing to resume or abandon (`409`).
    Conflict(String),
    /// The control plane failed.
    Failed(String),
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
/// `behind`, `error`, `offline`, `revoked`), the revision it serves and is given, its version,
/// identity expiry and last error; and the rollout.
#[utoipa::path(get, path = "/cluster/instances", tag = "cluster", operation_id = "list_cluster_instances",
    responses(
        (status = OK, description = "The instances and the rollout", body = ClusterInstances),
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
        (status = OK, description = "Revisions and the rollout", body = ClusterRevisions),
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

/// `GET /api/v1/cluster/rollout`: the rollout of the newest revision.
#[utoipa::path(get, path = "/cluster/rollout", tag = "cluster", operation_id = "get_cluster_rollout",
    responses(
        (status = OK, description = "The rollout", body = ClusterRollout),
        (status = NOT_FOUND, description = "Not a control plane", body = crate::openapi::ErrorBody)))]
pub(crate) async fn rollout(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Viewer) {
        return denied.into_response();
    }
    let control = state.control.clone();
    match on_main(&state, async move { control.cluster_rollout().await }).await {
        Ok(Some(value)) => axum::Json(value).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, NOT_A_CONTROL_PLANE),
        Err(response) => *response,
    }
}

async fn rollout_action(state: &Arc<State>, caller: &Caller, resume: bool) -> Response {
    if let Err(denied) = need(caller, Access::Operator) {
        return denied.into_response();
    }
    let control = state.control.clone();
    let actor = caller.name().to_owned();
    let outcome = match on_main(state, async move {
        if resume {
            control.cluster_rollout_resume(actor).await
        } else {
            control.cluster_rollout_abandon(actor).await
        }
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(response) => return *response,
    };
    let action = if resume {
        "cluster.rollout.resume"
    } else {
        "cluster.rollout.abandon"
    };
    match outcome {
        None => error(StatusCode::NOT_FOUND, NOT_A_CONTROL_PLANE),
        Some(RolloutAction::Done(value)) => {
            let resource = if resume {
                value["revision"].as_u64().map(|r| format!("revision {r}"))
            } else {
                value["rollback_of"]
                    .as_u64()
                    .map(|r| format!("revision {} (rollback to {r})", value["revision"]))
            };
            state.audit.record(Event {
                resource,
                ..caller.event(action)
            });
            axum::Json(value).into_response()
        }
        Some(RolloutAction::Conflict(message)) => {
            state.audit.record(Event {
                outcome: Outcome::Failed,
                reason: Some(message.clone()),
                ..caller.event(action)
            });
            error(StatusCode::CONFLICT, &message)
        }
        Some(RolloutAction::Failed(message)) => error(StatusCode::INTERNAL_SERVER_ERROR, &message),
    }
}

/// `POST /api/v1/cluster/rollout/resume` (operator): a halted (or still soaking) rollout goes
/// on: every instance is given the revision now. Audited.
#[utoipa::path(post, path = "/cluster/rollout/resume", tag = "cluster", operation_id = "resume_cluster_rollout",
    responses(
        (status = OK, description = "The rollout, now complete", body = ClusterRollout),
        (status = CONFLICT, description = "Nothing to resume (the rollout is complete)", body = crate::openapi::ErrorBody),
        (status = NOT_FOUND, description = "Not a control plane", body = crate::openapi::ErrorBody)))]
pub(crate) async fn resume(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    rollout_action(&state, &caller, true).await
}

/// `POST /api/v1/cluster/rollout/abandon` (operator): the stable revision's document is
/// published again as a new revision, which every instance takes at once; instances already
/// given the abandoned revision are sent back. Audited.
#[utoipa::path(post, path = "/cluster/rollout/abandon", tag = "cluster", operation_id = "abandon_cluster_rollout",
    responses(
        (status = OK, description = "The rollback: `revision`, `sha256`, `published_at`, `rollback_of`", body = Object),
        (status = CONFLICT, description = "Nothing to abandon, or no complete revision to return to", body = crate::openapi::ErrorBody),
        (status = NOT_FOUND, description = "Not a control plane", body = crate::openapi::ErrorBody)))]
pub(crate) async fn abandon(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    rollout_action(&state, &caller, false).await
}
