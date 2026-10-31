//! The admin endpoints. Engine calls run on the proxy's runtime (`State::main`).

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State as Extract};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::{HeaderValue, StatusCode, header};
use subtle::ConstantTimeEq;

use crate::{State, Transport, auth, guard};

/// Largest request body (ADR-0024); larger ones get 413.
const MAX_BODY: usize = 1024 * 1024;

pub(crate) fn error(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
}

fn text(status: StatusCode, content_type: &'static str, body: impl Into<String>) -> Response {
    (status, [(header::CONTENT_TYPE, content_type)], body.into()).into_response()
}

pub(crate) fn router(state: Arc<State>) -> Router {
    let api = Router::new()
        .route("/status", get(status))
        .route("/config/reload", post(reload))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    Router::new()
        .route(
            "/healthz",
            get(|| async { text(StatusCode::OK, "text/plain", "ok\n") }),
        )
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/setup", post(auth::setup))
        .route("/api/v1/auth/login", post(auth::login))
        .nest("/api/v1", api)
        .fallback(|| async { error(StatusCode::NOT_FOUND, "not found") })
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), guard::checks))
        .with_state(state)
}

/// The Unix socket is trusted like the data directory; TCP needs the bearer token.
async fn authenticate(
    Extract(state): Extract<Arc<State>>,
    request: Request,
    next: Next,
) -> Response {
    if request.extensions().get::<Transport>() == Some(&Transport::Socket) {
        return next.run(request).await;
    }
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !state.token.is_empty() && bool::from(presented.as_bytes().ct_eq(state.token.as_bytes())) {
        return next.run(request).await;
    }
    let mut response = error(StatusCode::UNAUTHORIZED, "a valid admin token is required");
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

async fn ready(Extract(state): Extract<Arc<State>>) -> Response {
    if state.control.ready() {
        text(StatusCode::OK, "text/plain", "ready\n")
    } else {
        text(StatusCode::SERVICE_UNAVAILABLE, "text/plain", "not ready\n")
    }
}

async fn metrics(Extract(state): Extract<Arc<State>>) -> Response {
    match state.control.metrics() {
        Some(body) => text(StatusCode::OK, "text/plain; version=0.0.4", body),
        None => error(StatusCode::NOT_FOUND, "metrics are disabled"),
    }
}

async fn status(Extract(state): Extract<Arc<State>>) -> Response {
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

async fn reload(Extract(state): Extract<Arc<State>>) -> Response {
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.reload().await })
        .await
    {
        Ok((true, report)) => axum::Json(report).into_response(),
        Ok((false, report)) => {
            (StatusCode::UNPROCESSABLE_ENTITY, axum::Json(report)).into_response()
        }
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down"),
    }
}
