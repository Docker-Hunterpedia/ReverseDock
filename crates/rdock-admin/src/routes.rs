//! The admin endpoints. Engine calls run on the proxy's runtime (`State::main`).

use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Request, State as Extract};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use http::{StatusCode, header};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::caller::{self, Access, Caller};
use crate::{
    State, Transport, account, auth, config_api, guard, manage, resources, stream, telemetry,
};

/// Largest request body (ADR-0024); larger ones get 413.
const MAX_BODY: usize = 1024 * 1024;

pub(crate) fn error(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
}

/// A refusal with a fixed message, kept small so `Result<_, Denied>` stays cheap; it becomes
/// the JSON error, with `WWW-Authenticate: Bearer` on 401.
#[derive(Debug)]
pub(crate) struct Denied(pub(crate) StatusCode, pub(crate) &'static str);

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        let mut response = error(self.0, self.1);
        if self.0 == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                http::HeaderValue::from_static("Bearer"),
            );
        }
        response
    }
}

fn text(status: StatusCode, content_type: &'static str, body: impl Into<String>) -> Response {
    (status, [(header::CONTENT_TYPE, content_type)], body.into()).into_response()
}

type Api = OpenApiRouter<Arc<State>>;

/// Every documented endpoint; `guard` wraps `/api/v1/*` except setup and the auth endpoints,
/// which check sessions themselves. [`router`] adds the layers and the dashboard fallback,
/// and [`crate::openapi`] the rest of the document.
pub(crate) fn documented(guard: impl FnOnce(Api) -> Api) -> Api {
    let api = Api::new()
        .routes(routes!(status))
        .routes(routes!(reload))
        .routes(routes!(manage::users, manage::create_user))
        .routes(routes!(manage::change_user, manage::delete_user))
        .routes(routes!(manage::tokens, manage::create_token))
        .routes(routes!(manage::revoke_token))
        .routes(routes!(manage::audit))
        .routes(routes!(config_api::effective))
        .routes(routes!(
            config_api::get_api,
            config_api::put_api,
            config_api::patch_api
        ))
        .routes(routes!(config_api::validate))
        .routes(routes!(config_api::history))
        .routes(routes!(config_api::rollback))
        .routes(routes!(config_api::export))
        .routes(routes!(config_api::import))
        .routes(routes!(resources::certificates))
        .routes(routes!(resources::renew))
        .routes(routes!(resources::backends))
        .routes(routes!(resources::drain))
        .routes(routes!(resources::undrain))
        .routes(routes!(resources::providers))
        .routes(routes!(resources::listeners))
        .routes(routes!(resources::metrics_summary))
        .routes(routes!(resources::explain))
        .routes(routes!(stream::logs))
        .routes(routes!(stream::events))
        .routes(routes!(resources::list))
        .routes(routes!(resources::get, resources::put, resources::delete));
    Api::new()
        .routes(routes!(healthz))
        .routes(routes!(ready))
        .routes(routes!(metrics))
        .routes(routes!(openapi_document))
        .routes(routes!(auth::setup_needed, auth::setup))
        .routes(routes!(auth::login))
        .routes(routes!(account::session))
        .routes(routes!(account::mfa_state, account::mfa))
        .routes(routes!(account::new_recovery_codes))
        .routes(routes!(account::enrol, account::unenrol))
        .routes(routes!(account::confirm))
        .routes(routes!(account::reauth))
        .routes(routes!(account::change_password))
        .routes(routes!(account::logout))
        .routes(routes!(account::sessions))
        .routes(routes!(account::end_session))
        .nest("/api/v1", guard(api))
}

pub(crate) fn router(state: Arc<State>) -> Router {
    let authenticate = middleware::from_fn_with_state(state.clone(), caller::authenticate);
    let (router, _) = documented(|api| api.route_layer(authenticate)).split_for_parts();
    router
        .fallback(fallback)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            telemetry::count,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), guard::checks))
        .with_state(state)
}

/// Liveness: the admin listener answers.
#[utoipa::path(get, path = "/healthz", tag = "health",
    responses((status = OK, description = "`ok`", body = String, content_type = "text/plain")))]
async fn healthz() -> Response {
    text(StatusCode::OK, "text/plain", "ok\n")
}

/// The OpenAPI 3.1 document of this API.
#[utoipa::path(get, path = "/api/openapi.json", tag = "health",
    responses((status = OK, description = "This document", body = Object)))]
async fn openapi_document(Extract(state): Extract<Arc<State>>, request: Request) -> Response {
    let transport = request.extensions().get::<Transport>().copied();
    let peer = request.extensions().get::<auth::Peer>().copied();
    let allowed = caller::identify(&state, request.method(), request.headers(), transport, peer)
        .and_then(|caller| caller::need(&caller, Access::Viewer));
    match allowed {
        Ok(()) => text(StatusCode::OK, "application/json", crate::openapi::json()),
        Err(denied) => denied.into_response(),
    }
}

/// Dashboard pages and files for `GET`/`HEAD` outside `/api/`, when the dashboard is on;
/// JSON 404 otherwise.
async fn fallback(
    Extract(state): Extract<Arc<State>>,
    method: http::Method,
    uri: http::Uri,
    headers: http::HeaderMap,
) -> Response {
    let page = matches!(method, http::Method::GET | http::Method::HEAD)
        && !uri.path().starts_with("/api/");
    if state.dashboard && page {
        crate::dashboard::serve(uri.path(), &headers)
    } else {
        error(StatusCode::NOT_FOUND, "not found")
    }
}

/// Readiness: a configuration is applied, listeners are bound and no shutdown has started.
#[utoipa::path(get, path = "/readyz", tag = "health",
    responses(
        (status = OK, description = "`ready`", body = String, content_type = "text/plain"),
        (status = SERVICE_UNAVAILABLE, description = "`not ready`", body = String, content_type = "text/plain"),
    ))]
async fn ready(Extract(state): Extract<Arc<State>>) -> Response {
    if state.control.ready() {
        text(StatusCode::OK, "text/plain", "ready\n")
    } else {
        text(StatusCode::SERVICE_UNAVAILABLE, "text/plain", "not ready\n")
    }
}

/// Prometheus metrics. Needs a token with at least the `metrics` role, unless
/// `admin.metrics_unauthenticated_on_loopback` opens it on a loopback listener.
#[utoipa::path(get, path = "/metrics", tag = "health",
    responses(
        (status = OK, description = "Prometheus text exposition", body = String, content_type = "text/plain; version=0.0.4"),
        (status = NOT_FOUND, description = "Metrics are disabled", body = crate::openapi::ErrorBody),
    ))]
async fn metrics(Extract(state): Extract<Arc<State>>, request: Request) -> Response {
    if !state.metrics_open {
        let transport = request.extensions().get::<Transport>().copied();
        let peer = request.extensions().get::<auth::Peer>().copied();
        let allowed =
            caller::identify(&state, request.method(), request.headers(), transport, peer)
                .and_then(|caller| caller::need(&caller, Access::Metrics));
        if let Err(denied) = allowed {
            return denied.into_response();
        }
    }
    match state.control.metrics() {
        Some(body) => text(
            StatusCode::OK,
            "text/plain; version=0.0.4",
            body + &telemetry::render(&state),
        ),
        None => error(StatusCode::NOT_FOUND, "metrics are disabled"),
    }
}

/// The running process: version, configuration generation, listeners, providers and the
/// last reload.
#[utoipa::path(get, path = "/status", tag = "status",
    responses(
        (status = OK, description = "The status document", body = Object),
        (status = SERVICE_UNAVAILABLE, description = "Shutting down", body = crate::openapi::ErrorBody),
    ))]
async fn status(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Err(denied) = caller::need(&caller, Access::Viewer) {
        return denied.into_response();
    }
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.status().await })
        .await
    {
        Ok(document) => axum::Json(document).into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down"),
    }
}

/// Reloads the configuration from its files and providers (operator role).
#[utoipa::path(post, path = "/config/reload", tag = "config",
    responses(
        (status = OK, description = "Applied; the reload report", body = Object),
        (status = UNPROCESSABLE_ENTITY, description = "Rejected; the report has the diagnostics", body = Object),
        (status = SERVICE_UNAVAILABLE, description = "Shutting down", body = crate::openapi::ErrorBody),
    ))]
async fn reload(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Err(denied) = caller::need(&caller, Access::Operator) {
        return denied.into_response();
    }
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.reload().await })
        .await
    {
        Ok((true, report)) => {
            state.audit.record(caller.event("config.reload"));
            axum::Json(report).into_response()
        }
        Ok((false, report)) => {
            state.audit.record(crate::audit::Event {
                outcome: crate::audit::Outcome::Failed,
                reason: Some("the configuration was rejected".into()),
                ..caller.event("config.reload")
            });
            (StatusCode::UNPROCESSABLE_ENTITY, axum::Json(report)).into_response()
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down"),
    }
}
