//! The HTTP cache hooks (F-WEB-03, ADR-0030): thin glue between Pingora's cache phases and
//! the policy and stores of `rdock-cache`.
//!
//! Pingora 0.9.1 runs `request_filter` (every middleware's `request` phase), then the cache
//! (`request_cache_filter`, `cache_key_callback`, lookup, `cache_hit_filter`), and only on a
//! miss `proxy_upstream_filter`, `upstream_peer` and `upstream_request_filter` (the
//! `upstream_request` phase). `response_filter`, `response_body_filter` and `logging` run on
//! hits and misses alike (`pingora-proxy` `lib.rs` `process_request`, `proxy_cache.rs`
//! `proxy_cache` and `proxy_cache_hit`). So authentication, IP filters and rate limits apply
//! to every hit, and the store holds the origin's response before any response middleware
//! (`compress`, `headers`) changed it.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use http::{HeaderMap, Method};
use pingora::Error;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use rdock_cache::RoutePolicy;
use rdock_cache::pingora_types::{
    CacheKey, CacheMeta, CacheOptionOverrides, CachePhase, ForcedFreshness, HashBinary,
    NoCacheReason, RespCacheable,
};
use rdock_cache::policy::status::{CacheStatus, Fwd};
use rdock_cache::policy::{invalidate, key, query, request, revalidate, storable, tags, vary};

/// The cache state of one request on a caching route.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent facts gathered across the cache phases, read by `status`"
)]
pub(crate) struct CacheCtx {
    pub policy: Arc<RoutePolicy>,
    /// The public URL objects are recorded and purged by.
    pub url: String,
    /// When the request arrived (for the age of the response, RFC 9111 §4.2.3).
    request_time: SystemTime,
    /// Why the cache was not used for this request.
    bypass: Option<(Fwd, &'static str)>,
    /// The query as it enters the key.
    key_query: String,
    /// `only-if-cached`.
    only_if_cached: bool,
    /// Nothing usable was stored for an `only-if-cached` request.
    pub only_if_cached_miss: bool,
    /// The client's directives forced revalidation.
    forced: bool,
    /// The client accepted a stale response (`max-stale`).
    max_stale: bool,
    /// A stored response was found stale (or forced stale).
    found_stale: bool,
    /// What kind of miss it was.
    miss: Option<Fwd>,
    /// The origin's status, when it answered.
    upstream_status: Option<u16>,
    /// The headers of a `304` from the origin, for the full update (RFC 9111 §4.3.4).
    not_modified: Option<HeaderMap>,
    /// The response was admitted to the store.
    stored: bool,
    /// Why it was not.
    not_stored: Option<&'static str>,
    /// An unsafe method: invalidate on success (RFC 9111 §4.4).
    invalidate: bool,
    /// The origin failed and a stale response was allowed.
    stale_on_error: bool,
    /// The last status computed, for the access log and metrics.
    pub label: Option<&'static str>,
}

impl CacheCtx {
    /// Whether the request said `only-if-cached` and uses the cache: it must not reach the
    /// origin.
    pub(crate) fn only_if_cached(&self) -> bool {
        self.only_if_cached
    }

    pub(crate) fn new(policy: Arc<RoutePolicy>, url: String) -> Self {
        Self {
            policy,
            url,
            request_time: SystemTime::now(),
            bypass: None,
            key_query: String::new(),
            only_if_cached: false,
            only_if_cached_miss: false,
            forced: false,
            max_stale: false,
            found_stale: false,
            miss: None,
            upstream_status: None,
            not_modified: None,
            stored: false,
            not_stored: None,
            invalidate: false,
            stale_on_error: false,
            label: None,
        }
    }
}

/// Decides whether the request uses the cache and enables it. Unsafe methods are marked for
/// invalidation; requests with a body, upgrades, mirrored requests (their copy must see what
/// the service sees) and the route's `bypass` rules skip the cache. Query parameters the key
/// leaves out, and the override headers it does not key on, are removed from the request.
pub(crate) fn enable(session: &mut Session, cc: &mut CacheCtx, mirrored: bool) {
    let req = session.req_header();
    let method = req.method.clone();
    if method != Method::GET && method != Method::HEAD {
        cc.invalidate = invalidate::is_unsafe(&method);
        cc.bypass = Some((Fwd::Method, "method"));
        return;
    }
    let why = if mirrored {
        Some("mirrored")
    } else if req.headers.contains_key(http::header::UPGRADE) {
        Some("upgrade")
    } else {
        cc.policy.bypass(&req.headers)
    };
    if let Some(why) = why {
        cc.bypass = Some((Fwd::Bypass, why));
        return;
    }
    let filtered = query::apply(&cc.policy.query, req.uri.query());
    cc.key_query = filtered.key;
    cc.only_if_cached = request::only_if_cached(&req.headers);
    let req = session.req_header_mut();
    if let Some(forward) = filtered.forward {
        set_query(req, &forward);
    }
    for name in rdock_cache::OVERRIDE_HEADERS {
        if !cc.policy.keys_on(name) {
            req.remove_header(name);
        }
    }
    let policy = &cc.policy;
    let lock = policy.lock.filter(|_| !cc.only_if_cached);
    let mut overrides = CacheOptionOverrides::default();
    overrides.wait_timeout = lock.map(|l| l.timeout);
    session.cache.enable(
        policy.store,
        None,
        None,
        lock.map(|l| l.lock),
        Some(overrides),
    );
    session
        .cache
        .set_max_file_size_bytes(policy.max_object_size);
}

/// Replaces the query of `req`, keeping its path.
fn set_query(req: &mut RequestHeader, query: &str) {
    let path = req.uri.path();
    let target = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut parts = req.uri.clone().into_parts();
    if let Ok(pq) = target.parse() {
        parts.path_and_query = Some(pq);
        if let Ok(uri) = http::Uri::from_parts(parts) {
            req.set_uri(uri);
        }
    }
}

/// The request's identity for `key.consumer`.
pub(crate) fn identity(cx: Option<&rdock_middleware::Context>) -> rdock_cache::Identity {
    let Some(cx) = cx else {
        return rdock_cache::Identity::Anonymous;
    };
    if let Some(consumer) = &cx.consumer {
        return rdock_cache::Identity::Consumer(consumer.key().into_owned());
    }
    if let Some(user) = &cx.user {
        return rdock_cache::Identity::User(user.clone());
    }
    if let Some(claims) = &cx.claims {
        let text = |name: &str| {
            claims
                .get(name)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned()
        };
        return rdock_cache::Identity::Token {
            issuer: text("iss"),
            subject: text("sub"),
        };
    }
    if let Some(cert) = &cx.client_cert {
        return rdock_cache::Identity::Certificate(cert.subject.clone());
    }
    rdock_cache::Identity::Anonymous
}

/// The cache key (see `rdock_cache::policy::key`).
pub(crate) fn cache_key(
    session: &Session,
    cc: &CacheCtx,
    route: &str,
    tls: bool,
    host: &str,
    consumer: Option<&str>,
) -> CacheKey {
    let req = session.req_header();
    let headers = cc.policy.key_header_values(&req.headers);
    let header_refs: Vec<(&str, Option<&[u8]>)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_deref()))
        .collect();
    let parts = key::KeyParts {
        store: cc.policy.store.name(),
        route,
        scheme: if tls { "https" } else { "http" },
        host,
        path: req.uri.path(),
        query: &cc.key_query,
        method: key::method_class(&req.method),
        headers: &header_refs,
        consumer,
    };
    CacheKey::new(key::primary(&parts), route)
}

/// Marks a miss: no stored response, or none for this request's `Vary` fields.
pub(crate) fn note_miss(session: &Session, cc: &mut CacheCtx) {
    let vary = session
        .cache
        .maybe_cache_key()
        .is_some_and(|k| k.get_variance_key().is_some());
    cc.miss = Some(if vary { Fwd::VaryMiss } else { Fwd::UriMiss });
}

/// The client's directives against a stored response (RFC 9111 §5.2.1).
pub(crate) fn hit_filter(
    req: &RequestHeader,
    meta: &CacheMeta,
    is_fresh: bool,
    cc: &mut CacheCtx,
) -> Option<ForcedFreshness> {
    let now = SystemTime::now();
    let fresh_until = meta.fresh_until();
    let stored_cc =
        rdock_cache::policy::cache_control::Directives::of(&meta.response_header().headers);
    let stored = request::Stored {
        age: meta.age(),
        remaining: is_fresh.then(|| fresh_until.duration_since(now).unwrap_or(Duration::ZERO)),
        staleness: now.duration_since(fresh_until).unwrap_or(Duration::ZERO),
        cc: &stored_cc,
    };
    let honour = cc.policy.honour_request_directives || cc.only_if_cached;
    let advice = request::advise(&req.headers, &stored, honour);
    if cc.only_if_cached {
        return match (is_fresh, advice) {
            (true, _) => None,
            (false, request::Advice::ServeStale) => {
                cc.max_stale = true;
                Some(ForcedFreshness::ForceFresh)
            }
            _ => {
                cc.only_if_cached_miss = true;
                Some(ForcedFreshness::ForceMiss)
            }
        };
    }
    match advice {
        request::Advice::Revalidate => {
            cc.forced = true;
            cc.found_stale = true;
            Some(ForcedFreshness::ForceExpired)
        }
        request::Advice::ServeStale => {
            cc.max_stale = true;
            Some(ForcedFreshness::ForceFresh)
        }
        request::Advice::Default => {
            if !is_fresh {
                cc.found_stale = true;
            }
            None
        }
    }
}

/// Records the origin's answer; keeps a `304`'s headers for the full update, and
/// invalidates after a successful unsafe request.
pub(crate) async fn upstream_response(session: &Session, resp: &ResponseHeader, cc: &mut CacheCtx) {
    let status = resp.status.as_u16();
    cc.upstream_status = Some(status);
    if status == 304 && session.cache.phase() == CachePhase::Stale {
        cc.not_modified = Some(resp.headers.clone());
    }
    if cc.invalidate && invalidate::invalidates(status) {
        let targets = invalidate::targets(&cc.url, &resp.headers);
        cc.policy.store.invalidate(targets).await;
    }
}

/// Whether the response may be stored, and its metadata (RFC 9111 §3, §4.2).
pub(crate) fn response_cacheable(
    session: &Session,
    resp: &ResponseHeader,
    cc: &mut CacheCtx,
) -> RespCacheable {
    let mut header = resp.clone();
    if let Some(not_modified) = cc.not_modified.take() {
        for (name, values) in revalidate::updates(&not_modified) {
            header.remove_header(&name);
            for value in values {
                let _ = header.append_header(name.clone(), value);
            }
        }
    }
    let req = session.req_header();
    let facts = storable::RequestFacts {
        method: &req.method,
        headers: &req.headers,
        has_body: false,
    };
    let now = SystemTime::now();
    let decision = storable::storable(
        &facts,
        header.status.as_u16(),
        &header.headers,
        &cc.policy.store_options,
        cc.request_time,
        now,
    );
    let decision = match decision {
        Ok(decision) => decision,
        Err(why) => {
            cc.stored = false;
            cc.not_stored = Some(why.detail());
            return RespCacheable::Uncacheable(NoCacheReason::OriginNotCache);
        }
    };
    let object_tags = tags::parse_tags(&header.headers, &cc.policy.tag_headers);
    for name in &decision.strip {
        header.remove_header(name.as_str());
    }
    let epoch = now.checked_sub(decision.initial_age).unwrap_or(now);
    let fresh_until = epoch + decision.lifetime;
    let stale_if_error = u32::try_from(decision.stale_if_error.as_secs()).unwrap_or(u32::MAX);
    let mut meta = CacheMeta::new(fresh_until, now, 0, stale_if_error, header);
    if epoch != now {
        meta.set_epoch_override(epoch);
    }
    meta.extensions_mut()
        .insert(rdock_cache::ObjectInfo::new(&cc.url, &object_tags));
    cc.stored = true;
    RespCacheable::Cacheable(meta)
}

/// The variant a request selects for a stored response's `Vary` (RFC 9111 §4.1).
pub(crate) fn variance(meta: &CacheMeta, req: &RequestHeader) -> Option<HashBinary> {
    match vary::parse_vary(&meta.response_header().headers) {
        vary::Vary::Fields(fields) => vary::variance(&fields, &req.headers),
        vary::Vary::None | vary::Vary::Star => None,
    }
}

/// `stale-if-error` (RFC 5861 §4): only for origin errors and 500, 502, 503 and 504, never
/// for `stale-while-revalidate` (`error` is `None`), which is not served in this version.
pub(crate) fn serve_stale(error: Option<&Error>, cc: &mut CacheCtx) -> bool {
    let Some(e) = error else {
        return false;
    };
    let allowed = match e.etype() {
        pingora::ErrorType::HTTPStatus(code) => matches!(code, 500 | 502 | 503 | 504),
        _ => e.esource() == &pingora::ErrorSource::Upstream,
    };
    if allowed {
        cc.stale_on_error = true;
    }
    allowed
}

/// What the cache did, for `Cache-Status`, the access log and metrics.
pub(crate) fn status(session: &Session, cc: &mut CacheCtx) -> CacheStatus {
    let cache = &session.cache;
    let collapsed = cache.lock_duration().is_some();
    let now = SystemTime::now();
    let ttl = || {
        cache.maybe_cache_meta().map(|meta| {
            let until = meta.fresh_until();
            match until.duration_since(now) {
                Ok(left) => i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
                Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
            }
        })
    };
    let revalidating = if cc.forced { Fwd::Request } else { Fwd::Stale };
    let fetched = if cc.found_stale {
        revalidating
    } else {
        cc.miss.unwrap_or(Fwd::Miss)
    };
    let status = match cache.phase() {
        CachePhase::Hit => CacheStatus {
            hit: true,
            ttl: ttl(),
            collapsed,
            detail: cc.max_stale.then_some("max-stale"),
            ..CacheStatus::default()
        },
        CachePhase::Stale | CachePhase::StaleUpdating => CacheStatus {
            hit: true,
            ttl: ttl().map(|t| t.min(-1)),
            collapsed,
            detail: Some("stale-if-error"),
            fwd_status: cc.upstream_status.filter(|_| cc.stale_on_error),
            ..CacheStatus::default()
        },
        CachePhase::Revalidated | CachePhase::RevalidatedNoCache(_) => CacheStatus {
            fwd: Some(revalidating),
            fwd_status: Some(304),
            ttl: ttl(),
            stored: matches!(cache.phase(), CachePhase::Revalidated),
            collapsed,
            ..CacheStatus::default()
        },
        CachePhase::Miss | CachePhase::Expired => CacheStatus {
            fwd: Some(fetched),
            fwd_status: cc.upstream_status,
            stored: cc.stored,
            collapsed,
            detail: if cc.only_if_cached_miss {
                Some("only-if-cached")
            } else {
                cc.not_stored
            },
            ..CacheStatus::default()
        },
        CachePhase::Disabled(NoCacheReason::NeverEnabled)
        | CachePhase::Bypass
        | CachePhase::Uninit
        | CachePhase::CacheKey => {
            let (fwd, detail) = cc.bypass.unwrap_or((Fwd::Bypass, "middleware"));
            CacheStatus {
                fwd: Some(fwd),
                fwd_status: cc.upstream_status,
                detail: Some(detail),
                ..CacheStatus::default()
            }
        }
        CachePhase::Disabled(reason) => {
            let detail = match reason {
                NoCacheReason::ResponseTooLarge | NoCacheReason::PredictedResponseTooLarge => {
                    Some("too-large")
                }
                NoCacheReason::CacheLockTimeout => Some("lock-timeout"),
                NoCacheReason::CacheLockGiveUp => Some("lock-released"),
                NoCacheReason::CacheLockRetryLimit => Some("lock-retries"),
                NoCacheReason::UpstreamError => Some("origin-error"),
                NoCacheReason::StorageError | NoCacheReason::InternalError => Some("storage-error"),
                NoCacheReason::DeclinedToUpstream
                    if cc.only_if_cached_miss || cc.only_if_cached =>
                {
                    Some("only-if-cached")
                }
                NoCacheReason::Custom(why) => Some(why),
                _ => cc.not_stored,
            };
            CacheStatus {
                fwd: Some(if cc.only_if_cached {
                    Fwd::UriMiss
                } else {
                    fetched
                }),
                fwd_status: cc.upstream_status,
                collapsed,
                detail,
                ..CacheStatus::default()
            }
        }
    };
    cc.label = Some(status.label());
    status
}

/// Adds `Cache-Status` (when the route sends it) and removes the tag headers (unless kept).
pub(crate) fn decorate(session: &Session, resp: &mut ResponseHeader, cc: &mut CacheCtx) {
    let status = status(session, cc);
    if cc.policy.cache_status {
        let _ = resp.insert_header("cache-status", status.render());
    }
    if !cc.policy.keep_tags {
        for name in &cc.policy.tag_headers {
            resp.remove_header(name);
        }
    }
}

/// Whether the answer came from the store.
pub(crate) fn from_store(session: &Session) -> bool {
    matches!(
        session.cache.phase(),
        CachePhase::Hit
            | CachePhase::Stale
            | CachePhase::StaleUpdating
            | CachePhase::Revalidated
            | CachePhase::RevalidatedNoCache(_)
    )
}

/// Counts the request in `rdock_cache_requests_total` and lock waits.
pub(crate) fn observe(session: &Session, cc: &mut CacheCtx, route: &str) {
    let label = match cc.label {
        Some(label) => label,
        None => status(session, cc).label(),
    };
    let store = cc.policy.store;
    if let Some(metrics) = store.metrics() {
        metrics
            .requests
            .with_label_values(&[store.name(), route, label])
            .inc();
        if session.cache.lock_duration().is_some() {
            metrics.lock_waits.with_label_values(&[store.name()]).inc();
        }
    }
}

/// The public URL of a request: `scheme://host/path?query`, path normalised (before the
/// route's rewrites) and the query as the client sent it.
pub(crate) fn public_url(tls: bool, host: &str, path: &str, query: Option<&str>) -> String {
    invalidate::public_url(if tls { "https" } else { "http" }, host, path, query)
}
