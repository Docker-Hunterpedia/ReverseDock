//! The admin endpoints. Engine calls run on the proxy's runtime (`State::main`).

use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Request, State as Extract};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::{StatusCode, header};

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

pub(crate) fn router(state: Arc<State>) -> Router {
    let api = Router::new()
        .route("/status", get(status))
        .route("/config/reload", post(reload))
        .route("/users", get(manage::users).post(manage::create_user))
        .route(
            "/users/{name}",
            axum::routing::patch(manage::change_user).delete(manage::delete_user),
        )
        .route("/tokens", get(manage::tokens).post(manage::create_token))
        .route("/tokens/{id}", axum::routing::delete(manage::revoke_token))
        .route("/audit", get(manage::audit))
        .route("/config", get(config_api::effective))
        .route(
            "/config/api",
            get(config_api::get_api)
                .put(config_api::put_api)
                .patch(config_api::patch_api),
        )
        .route("/config/validate", post(config_api::validate))
        .route("/config/history", get(config_api::history))
        .route("/config/rollback", post(config_api::rollback))
        .route("/config/export", get(config_api::export))
        .route("/config/import", post(config_api::import))
        .route("/certificates", get(resources::certificates))
        .route("/certificates/{name}/renew", post(resources::renew))
        .route("/backends", get(resources::backends))
        .route("/backends/drain", post(resources::drain))
        .route("/backends/undrain", post(resources::undrain))
        .route("/providers", get(resources::providers))
        .route("/listeners", get(resources::listeners))
        .route("/metrics/summary", get(resources::metrics_summary))
        .route("/logs/stream", get(stream::logs))
        .route("/events/stream", get(stream::events))
        .route("/{kind}", get(resources::list))
        .route(
            "/{kind}/{name}",
            get(resources::get)
                .put(resources::put)
                .delete(resources::delete),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            caller::authenticate,
        ));
    Router::new()
        .route(
            "/healthz",
            get(|| async { text(StatusCode::OK, "text/plain", "ok\n") }),
        )
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/setup", get(auth::setup_needed).post(auth::setup))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/session", get(account::session))
        .route(
            "/api/v1/auth/mfa",
            get(account::mfa_state).post(account::mfa),
        )
        .route(
            "/api/v1/auth/recovery-codes",
            post(account::new_recovery_codes),
        )
        .route(
            "/api/v1/auth/totp",
            post(account::enrol).delete(account::unenrol),
        )
        .route("/api/v1/auth/totp/confirm", post(account::confirm))
        .route("/api/v1/auth/reauth", post(account::reauth))
        .route("/api/v1/auth/logout", post(account::logout))
        .route("/api/v1/auth/sessions", get(account::sessions))
        .route(
            "/api/v1/auth/sessions/{id}",
            axum::routing::delete(account::end_session),
        )
        .nest("/api/v1", api)
        .fallback(fallback)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            telemetry::count,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), guard::checks))
        .with_state(state)
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

async fn ready(Extract(state): Extract<Arc<State>>) -> Response {
    if state.control.ready() {
        text(StatusCode::OK, "text/plain", "ready\n")
    } else {
        text(StatusCode::SERVICE_UNAVAILABLE, "text/plain", "not ready\n")
    }
}

/// `/metrics` needs a token with at least the `metrics` role, unless
/// `admin.metrics_unauthenticated_on_loopback` opens it on a loopback listener.
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
