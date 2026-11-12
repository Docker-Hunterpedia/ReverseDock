//! The HTTP cache (F-WEB-03, ADR-0030): store statistics and purges. A purge reaches this
//! instance only; every replica has its own cache.

use std::sync::Arc;

use axum::extract::{Extension, Path, State as Extract};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::State;
use crate::audit::{Event, Outcome};
use crate::caller::{Access, Caller, need};
use crate::routes::error;

/// What a purge removes; set exactly one field.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PurgeRequest {
    /// Every variant of this absolute URL (`https://app.example.com/a?b=1`).
    #[serde(default)]
    url: Option<String>,
    /// Every object whose URL starts with this absolute URL.
    #[serde(default)]
    prefix: Option<String>,
    /// Every object with this tag (from `Cache-Tag` or `Surrogate-Key`).
    #[serde(default)]
    tag: Option<String>,
    /// Everything in the store.
    #[serde(default)]
    all: Option<bool>,
}

/// What a purge selects, as the engine applies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachePurge {
    /// One URL, all its variants.
    Url(String),
    /// URLs starting with this.
    Prefix(String),
    /// A tag.
    Tag(String),
    /// Everything.
    All,
}

/// The outcome of a purge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// Done: how many objects were removed.
    Purged(u64),
    /// No store has that name.
    NoStore,
    /// The selector is not valid (a URL that is not absolute `http`/`https`).
    Invalid(String),
    /// The store failed.
    Failed(String),
}

/// The result of a purge.
#[derive(Serialize, ToSchema)]
pub(crate) struct Purged {
    store: String,
    /// Objects removed. Fills in progress that the purge covers are discarded too.
    purged: u64,
}

impl PurgeRequest {
    fn selector(self) -> Result<CachePurge, &'static str> {
        let all = self.all.unwrap_or(false);
        let mut chosen = Vec::new();
        if let Some(url) = self.url {
            chosen.push(CachePurge::Url(url));
        }
        if let Some(prefix) = self.prefix {
            chosen.push(CachePurge::Prefix(prefix));
        }
        if let Some(tag) = self.tag {
            chosen.push(CachePurge::Tag(tag));
        }
        if self.all == Some(false) && chosen.is_empty() {
            return Err("`all` must be true to purge everything");
        }
        if all {
            chosen.push(CachePurge::All);
        }
        let mut chosen = chosen.into_iter();
        match (chosen.next(), chosen.next()) {
            (Some(one), None) => Ok(one),
            _ => Err("set exactly one of `url`, `prefix`, `tag` or `all: true`"),
        }
    }
}

fn describe(selector: &CachePurge) -> String {
    match selector {
        CachePurge::Url(u) => format!("url={u}"),
        CachePurge::Prefix(p) => format!("prefix={p}"),
        CachePurge::Tag(t) => format!("tag={t}"),
        CachePurge::All => "all".to_owned(),
    }
}

/// `GET /api/v1/cache`: every cache store with its objects, bytes, limits and counters.
#[utoipa::path(get, path = "/cache", tag = "cache", operation_id = "list_caches",
    responses((status = OK, description = "`stores`: name, kind, objects, bytes, max_size, max_objects, hits, misses, stored, evictions, purged, dropped", body = Object)))]
pub(crate) async fn stores(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Viewer) {
        return denied.into_response();
    }
    let control = state.control.clone();
    match state
        .main
        .spawn(async move { control.caches().await })
        .await
    {
        Ok(stores) => axum::Json(json!({ "stores": stores })).into_response(),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down"),
    }
}

/// `POST /api/v1/cache/{store}/purge`: remove objects from one store of this instance, by
/// URL, URL prefix, tag or all (operator role). Audited; shares the configuration-work rate
/// limit, because purging everything sends every following request to the origins.
#[utoipa::path(post, path = "/cache/{store}/purge", tag = "cache", operation_id = "purge_cache",
    params(("store" = String, Path, description = "Store name, under `caches`")),
    request_body = PurgeRequest,
    responses(
        (status = OK, description = "Purged", body = Purged),
        (status = BAD_REQUEST, description = "Not exactly one selector, or not an absolute URL", body = crate::openapi::ErrorBody),
        (status = NOT_FOUND, description = "No such store", body = crate::openapi::ErrorBody),
        (status = INTERNAL_SERVER_ERROR, description = "The store failed", body = crate::openapi::ErrorBody),
    ))]
pub(crate) async fn purge(
    Extract(state): Extract<Arc<State>>,
    Extension(caller): Extension<Caller>,
    Path(store): Path<String>,
    axum::Json(request): axum::Json<PurgeRequest>,
) -> Response {
    if let Err(denied) = need(&caller, Access::Operator) {
        return denied.into_response();
    }
    let selector = match request.selector() {
        Ok(selector) => selector,
        Err(message) => return error(StatusCode::BAD_REQUEST, message),
    };
    if let Some(wait) = crate::config_api::over_budget(&state) {
        return crate::auth::too_many(wait);
    }
    let resource = format!("{store}: {}", describe(&selector));
    let control = state.control.clone();
    let name = store.clone();
    let Ok(outcome) = state
        .main
        .spawn(async move { control.purge_cache(name, selector).await })
        .await
    else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "rdock is shutting down");
    };
    let (response, failure) = match outcome {
        PurgeOutcome::Purged(purged) => (
            axum::Json(Purged {
                store: store.clone(),
                purged,
            })
            .into_response(),
            None,
        ),
        PurgeOutcome::NoStore => (
            error(StatusCode::NOT_FOUND, "no such cache store"),
            Some("no such store".to_owned()),
        ),
        PurgeOutcome::Invalid(message) => {
            let response = error(StatusCode::BAD_REQUEST, &message);
            (response, Some(message))
        }
        PurgeOutcome::Failed(message) => {
            let response = error(StatusCode::INTERNAL_SERVER_ERROR, &message);
            (response, Some(message))
        }
    };
    state.audit.record(Event {
        resource: Some(resource),
        outcome: if failure.is_some() {
            Outcome::Failed
        } else {
            Outcome::Ok
        },
        reason: failure,
        ..caller.event("cache.purge")
    });
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(value: serde_json::Value) -> Result<CachePurge, &'static str> {
        serde_json::from_value::<PurgeRequest>(value)
            .unwrap()
            .selector()
    }

    #[test]
    fn exactly_one_selector() {
        assert_eq!(
            request(json!({ "url": "https://a.test/x" })),
            Ok(CachePurge::Url("https://a.test/x".into()))
        );
        assert_eq!(
            request(json!({ "tag": "t" })),
            Ok(CachePurge::Tag("t".into()))
        );
        assert_eq!(request(json!({ "all": true })), Ok(CachePurge::All));
        assert!(request(json!({})).is_err());
        assert!(request(json!({ "all": false })).is_err());
        assert!(request(json!({ "url": "https://a.test/", "tag": "t" })).is_err());
        assert!(request(json!({ "prefix": "https://a.test/", "all": true })).is_err());
        assert!(serde_json::from_value::<PurgeRequest>(json!({ "everything": true })).is_err());
    }
}
