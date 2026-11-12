//! Whether a response may be stored, and for how long (RFC 9111 §3, §3.5, §4.2, §4.2.4).

use std::time::{Duration, SystemTime};

use http::header::{AUTHORIZATION, ETAG, HeaderName, LAST_MODIFIED, SET_COOKIE};
use http::{HeaderMap, Method};

use super::cache_control::{Directives, Seconds};
use super::freshness::{FreshnessOptions, Lifetime, freshness_lifetime, initial_age};
use super::targeted::{CDN_CACHE_CONTROL, effective};
use super::vary::{Vary, parse_vary};

/// Statuses stored by default, each only with a lifetime (RFC 9110 §15.1's heuristically
/// cacheable codes minus 206, 405, 414 and 501). A 206 is never stored as such: Pingora asks
/// the origin for the whole object and answers ranges from it.
pub const DEFAULT_STATUSES: [u16; 8] = [200, 203, 204, 300, 301, 308, 404, 410];

/// What to do with a response that sets a cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SetCookiePolicy {
    /// Never store it (the default).
    #[default]
    Refuse,
    /// Store it without its `Set-Cookie` fields; the client that filled the cache still gets
    /// the cookie.
    Strip,
}

/// What to do with responses to requests that carry `Authorization` to the origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthorizationPolicy {
    /// Store only when the response says `public`, `s-maxage` or `must-revalidate` (RFC 9111
    /// §3.5; the default).
    #[default]
    Refuse,
    /// Store them like any other response.
    Store,
}

/// The route's storage options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOptions {
    /// Statuses that may be stored.
    pub statuses: Vec<u16>,
    /// Responses with `Set-Cookie`.
    pub set_cookie: SetCookiePolicy,
    /// Responses to requests with `Authorization`.
    pub authorization: AuthorizationPolicy,
    /// Default and heuristic lifetimes.
    pub freshness: FreshnessOptions,
    /// Upper bound on the origin's `stale-if-error` window.
    pub stale_if_error_cap: Duration,
    /// Targeted cache-control fields honoured, in order (RFC 9213); the first valid one
    /// replaces `Cache-Control` and `Expires`.
    pub targeted: Vec<HeaderName>,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            statuses: DEFAULT_STATUSES.to_vec(),
            set_cookie: SetCookiePolicy::Refuse,
            authorization: AuthorizationPolicy::Refuse,
            freshness: FreshnessOptions::default(),
            stale_if_error_cap: Duration::from_secs(24 * 3600),
            targeted: vec![HeaderName::from_static(CDN_CACHE_CONTROL)],
        }
    }
}

/// The request a response answers, as it was sent to the origin.
#[derive(Debug, Clone, Copy)]
pub struct RequestFacts<'a> {
    /// Method as received (the cache asks the origin with `GET` for `HEAD`).
    pub method: &'a Method,
    /// Headers as forwarded.
    pub headers: &'a HeaderMap,
    /// The request has a body (`Content-Length` above zero or `Transfer-Encoding`).
    pub has_body: bool,
}

/// Why a response is not stored. [`Self::detail`] is the `Cache-Status` detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotStorable {
    /// Not `GET` or `HEAD` (RFC 9111 §3).
    Method,
    /// The request has a body (a "fat GET").
    RequestBody,
    /// The request said `no-store` (RFC 9111 §5.2.1.5).
    RequestNoStore,
    /// The status is not in the route's list.
    Status(u16),
    /// `Cache-Control: no-store` (RFC 9111 §5.2.2.5).
    NoStore,
    /// `Cache-Control: private` (RFC 9111 §5.2.2.7).
    Private,
    /// The response sets a cookie.
    SetCookie,
    /// The request carried `Authorization` (RFC 9111 §3.5).
    Authorization,
    /// `Vary: *` never matches (RFC 9111 §4.1).
    VaryStar,
    /// Neither the origin nor the route gives it a usable lifetime.
    NoFreshness,
}

impl NotStorable {
    /// A short reason, used as the `Cache-Status` `detail`.
    #[must_use]
    pub fn detail(self) -> &'static str {
        match self {
            Self::Method => "method",
            Self::RequestBody => "request-body",
            Self::RequestNoStore => "request-no-store",
            Self::Status(_) => "status",
            Self::NoStore => "no-store",
            Self::Private => "private",
            Self::SetCookie => "set-cookie",
            Self::Authorization => "authorization",
            Self::VaryStar => "vary-star",
            Self::NoFreshness => "no-freshness",
        }
    }
}

/// A storable response: its lifetime, the age it arrived with, how long it may be served
/// stale on errors, and the header fields left out of the stored copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Storable {
    /// Freshness lifetime.
    pub lifetime: Duration,
    /// Where the lifetime came from.
    pub source: Lifetime,
    /// Age on arrival (RFC 9111 §4.2.3).
    pub initial_age: Duration,
    /// `stale-if-error` window (RFC 5861 §4), capped; zero when serving stale is forbidden.
    pub stale_if_error: Duration,
    /// Lower-case names of fields not stored.
    pub strip: Vec<String>,
}

/// Fields a cache must not store (RFC 9111 §3.1).
const NEVER_STORED: [&str; 2] = ["proxy-authenticate", "proxy-authentication-info"];

/// Decides whether the response (`status`, `headers`) to `request` may be stored. The
/// response's directives are those of the first valid targeted field of the route, else
/// `Cache-Control` (RFC 9213 §2.1).
pub fn storable(
    request: &RequestFacts<'_>,
    status: u16,
    headers: &HeaderMap,
    options: &StoreOptions,
    request_time: SystemTime,
    response_time: SystemTime,
) -> Result<Storable, NotStorable> {
    if request.method != Method::GET && request.method != Method::HEAD {
        return Err(NotStorable::Method);
    }
    if request.has_body {
        return Err(NotStorable::RequestBody);
    }
    if Directives::of(request.headers).has("no-store") {
        return Err(NotStorable::RequestNoStore);
    }
    if !options.statuses.contains(&status) {
        return Err(NotStorable::Status(status));
    }
    let effective = effective(headers, &options.targeted);
    let cc = effective.cc;
    if cc.has("no-store") {
        return Err(NotStorable::NoStore);
    }
    let private_fields = cc.field_names("private");
    if cc.has("private") && private_fields.is_empty() {
        return Err(NotStorable::Private);
    }
    if parse_vary(headers) == Vary::Star {
        return Err(NotStorable::VaryStar);
    }
    let mut strip: Vec<String> = NEVER_STORED.iter().map(|s| (*s).to_owned()).collect();
    strip.extend(private_fields);
    strip.extend(cc.field_names("no-cache"));
    if headers.contains_key(SET_COOKIE) || headers.contains_key("set-cookie2") {
        match options.set_cookie {
            SetCookiePolicy::Refuse => return Err(NotStorable::SetCookie),
            SetCookiePolicy::Strip => {
                strip.push("set-cookie".to_owned());
                strip.push("set-cookie2".to_owned());
            }
        }
    }
    let explicitly_shared = cc.has("public") || cc.has("s-maxage") || cc.has("must-revalidate");
    if request.headers.contains_key(AUTHORIZATION)
        && !explicitly_shared
        && options.authorization == AuthorizationPolicy::Refuse
    {
        return Err(NotStorable::Authorization);
    }
    let source = freshness_lifetime(
        status,
        headers,
        &cc,
        effective.targeted.is_none(),
        response_time,
        &options.freshness,
    );
    let Some(lifetime) = source.duration() else {
        return Err(NotStorable::NoFreshness);
    };
    let age = initial_age(headers, request_time, response_time);
    let validator = headers.contains_key(ETAG) || headers.contains_key(LAST_MODIFIED);
    if lifetime <= age && !validator {
        // Stale on arrival and impossible to revalidate: it could never be served.
        return Err(NotStorable::NoFreshness);
    }
    strip.sort();
    strip.dedup();
    Ok(Storable {
        lifetime,
        source,
        initial_age: age,
        stale_if_error: stale_if_error(&cc, options.stale_if_error_cap),
        strip,
    })
}

/// The `stale-if-error` window: the origin's, capped; none when `must-revalidate`,
/// `proxy-revalidate`, `s-maxage` or `no-cache` forbid serving stale (RFC 9111 §4.2.4,
/// §5.2.2.2, §5.2.2.8, §5.2.2.10).
#[must_use]
pub fn stale_if_error(cc: &Directives, cap: Duration) -> Duration {
    let forbidden = [
        "must-revalidate",
        "proxy-revalidate",
        "s-maxage",
        "no-cache",
    ]
    .iter()
    .any(|d| cc.has(d));
    if forbidden {
        return Duration::ZERO;
    }
    match cc.seconds("stale-if-error") {
        Some(Seconds::Valid(s)) => Duration::from_secs(s.into()).min(cap),
        _ => Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(*n, v.parse().unwrap());
        }
        h
    }

    fn decide(
        method: &Method,
        req: &HeaderMap,
        status: u16,
        resp: &HeaderMap,
    ) -> Result<Storable, NotStorable> {
        decide_with(method, req, status, resp, &StoreOptions::default())
    }

    fn decide_with(
        method: &Method,
        req: &HeaderMap,
        status: u16,
        resp: &HeaderMap,
        options: &StoreOptions,
    ) -> Result<Storable, NotStorable> {
        let now = SystemTime::now();
        storable(
            &RequestFacts {
                method,
                headers: req,
                has_body: false,
            },
            status,
            resp,
            options,
            now,
            now,
        )
    }

    const FRESH: (&str, &str) = ("cache-control", "max-age=60");

    #[test]
    fn rfc9111_3_only_get_and_head_and_no_fat_requests() {
        let resp = headers(&[FRESH]);
        let none = HeaderMap::new();
        assert!(decide(&Method::GET, &none, 200, &resp).is_ok());
        assert!(decide(&Method::HEAD, &none, 200, &resp).is_ok());
        assert_eq!(
            decide(&Method::POST, &none, 200, &resp),
            Err(NotStorable::Method)
        );
        let now = SystemTime::now();
        let fat = storable(
            &RequestFacts {
                method: &Method::GET,
                headers: &none,
                has_body: true,
            },
            200,
            &resp,
            &StoreOptions::default(),
            now,
            now,
        );
        assert_eq!(fat, Err(NotStorable::RequestBody));
    }

    #[test]
    fn rfc9111_3_status_allow_list_and_its_override() {
        let resp = headers(&[FRESH]);
        let none = HeaderMap::new();
        for status in DEFAULT_STATUSES {
            assert!(
                decide(&Method::GET, &none, status, &resp).is_ok(),
                "{status}"
            );
        }
        for status in [201, 206, 302, 304, 403, 500, 503] {
            assert_eq!(
                decide(&Method::GET, &none, status, &resp),
                Err(NotStorable::Status(status))
            );
        }
        let options = StoreOptions {
            statuses: vec![302],
            ..StoreOptions::default()
        };
        assert!(decide_with(&Method::GET, &none, 302, &resp, &options).is_ok());
        assert!(decide_with(&Method::GET, &none, 200, &resp, &options).is_err());
    }

    #[test]
    fn rfc9111_5_2_2_5_and_5_2_2_7_no_store_and_private_are_never_stored() {
        let none = HeaderMap::new();
        for (cc, why) in [
            ("max-age=60, no-store", NotStorable::NoStore),
            ("max-age=60, private", NotStorable::Private),
            ("PRIVATE, s-maxage=60", NotStorable::Private),
        ] {
            let resp = headers(&[("cache-control", cc)]);
            assert_eq!(decide(&Method::GET, &none, 200, &resp), Err(why), "{cc}");
        }
        let qualified = headers(&[("cache-control", "max-age=60, private=\"x-user\"")]);
        let ok = decide(&Method::GET, &none, 200, &qualified).unwrap();
        assert!(ok.strip.contains(&"x-user".to_owned()));
    }

    #[test]
    fn rfc9111_5_2_1_5_request_no_store_is_not_stored() {
        let req = headers(&[("cache-control", "no-store")]);
        assert_eq!(
            decide(&Method::GET, &req, 200, &headers(&[FRESH])),
            Err(NotStorable::RequestNoStore)
        );
    }

    #[test]
    fn rfc9111_4_1_vary_star_is_never_stored() {
        let resp = headers(&[FRESH, ("vary", "accept, *")]);
        assert_eq!(
            decide(&Method::GET, &HeaderMap::new(), 200, &resp),
            Err(NotStorable::VaryStar)
        );
    }

    #[test]
    fn rfc9111_7_3_set_cookie_refused_by_default_and_stripped_on_request() {
        let resp = headers(&[FRESH, ("set-cookie", "sid=1")]);
        let none = HeaderMap::new();
        assert_eq!(
            decide(&Method::GET, &none, 200, &resp),
            Err(NotStorable::SetCookie)
        );
        let strip = StoreOptions {
            set_cookie: SetCookiePolicy::Strip,
            ..StoreOptions::default()
        };
        let ok = decide_with(&Method::GET, &none, 200, &resp, &strip).unwrap();
        assert!(ok.strip.contains(&"set-cookie".to_owned()));
    }

    #[test]
    fn rfc9111_3_5_authorization_needs_an_explicit_shared_directive() {
        let req = headers(&[("authorization", "Bearer x")]);
        assert_eq!(
            decide(&Method::GET, &req, 200, &headers(&[FRESH])),
            Err(NotStorable::Authorization)
        );
        for cc in [
            "public, max-age=60",
            "s-maxage=60",
            "max-age=60, must-revalidate",
        ] {
            let resp = headers(&[("cache-control", cc)]);
            assert!(decide(&Method::GET, &req, 200, &resp).is_ok(), "{cc}");
        }
        let store = StoreOptions {
            authorization: AuthorizationPolicy::Store,
            ..StoreOptions::default()
        };
        assert!(decide_with(&Method::GET, &req, 200, &headers(&[FRESH]), &store).is_ok());
    }

    #[test]
    fn rfc9111_3_1_proxy_authentication_fields_are_not_stored() {
        let ok = decide(&Method::GET, &HeaderMap::new(), 200, &headers(&[FRESH])).unwrap();
        assert!(ok.strip.contains(&"proxy-authenticate".to_owned()));
        assert!(ok.strip.contains(&"proxy-authentication-info".to_owned()));
    }

    #[test]
    fn rfc9111_4_2_2_no_default_ttl_means_no_storing_without_freshness() {
        let none = HeaderMap::new();
        let plain = headers(&[("etag", "\"a\"")]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &plain),
            Err(NotStorable::NoFreshness)
        );
        let public_only = headers(&[("cache-control", "public")]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &public_only),
            Err(NotStorable::NoFreshness)
        );
        // Zero lifetime with a validator is stored (it revalidates every time)...
        let revalidate = headers(&[("cache-control", "no-cache"), ("etag", "\"a\"")]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &revalidate)
                .unwrap()
                .lifetime,
            Duration::ZERO
        );
        // ...without one it could never be used.
        let useless = headers(&[("cache-control", "max-age=0")]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &useless),
            Err(NotStorable::NoFreshness)
        );
    }

    #[test]
    fn rfc9111_5_2_2_4_no_cache_with_max_age_is_revalidated_or_not_stored() {
        let none = HeaderMap::new();
        let fresh_no_cache = headers(&[("cache-control", "max-age=10000, no-cache")]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &fresh_no_cache),
            Err(NotStorable::NoFreshness),
            "zero lifetime and no validator: never usable"
        );
        let with_etag = headers(&[
            ("cache-control", "max-age=10000, no-cache"),
            ("etag", "\"a\""),
        ]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &with_etag)
                .unwrap()
                .lifetime,
            Duration::ZERO
        );
    }

    #[test]
    fn rfc9213_cdn_cache_control_replaces_cache_control_by_default_and_can_be_turned_off() {
        let none = HeaderMap::new();
        for (cdn, why) in [
            ("private", NotStorable::Private),
            ("no-store", NotStorable::NoStore),
            ("no-cache", NotStorable::NoFreshness),
        ] {
            let resp = headers(&[
                ("cache-control", "max-age=10000"),
                ("cdn-cache-control", cdn),
            ]);
            assert_eq!(decide(&Method::GET, &none, 200, &resp), Err(why), "{cdn}");
        }
        let resp = headers(&[
            ("cache-control", "no-store"),
            ("cdn-cache-control", "max-age=10000"),
        ]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &resp).unwrap().lifetime,
            Duration::from_secs(10_000)
        );
        // Expires is ignored with the targeted field, Cache-Control too.
        let resp = headers(&[
            ("cdn-cache-control", "max-age=0"),
            ("expires", "Thu, 01 Jan 2099 00:00:00 GMT"),
        ]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &resp),
            Err(NotStorable::NoFreshness)
        );
        // An invalid field is ignored.
        let resp = headers(&[
            ("cache-control", "no-store"),
            ("cdn-cache-control", "max-age=\"1\""),
        ]);
        assert_eq!(
            decide(&Method::GET, &none, 200, &resp),
            Err(NotStorable::NoStore)
        );
        // `targeted: []` reads Cache-Control only.
        let off = StoreOptions {
            targeted: Vec::new(),
            ..StoreOptions::default()
        };
        let resp = headers(&[
            ("cache-control", "no-store"),
            ("cdn-cache-control", "max-age=10000"),
        ]);
        assert_eq!(
            decide_with(&Method::GET, &none, 200, &resp, &off),
            Err(NotStorable::NoStore)
        );
        let resp = headers(&[
            ("cache-control", "max-age=60"),
            ("cdn-cache-control", "no-store"),
        ]);
        assert!(decide_with(&Method::GET, &none, 200, &resp, &off).is_ok());
        // The Authorization rule reads the directives in effect.
        let auth = headers(&[("authorization", "Bearer x")]);
        let resp = headers(&[
            ("cache-control", "public, max-age=60"),
            ("cdn-cache-control", "max-age=60"),
        ]);
        assert_eq!(
            decide(&Method::GET, &auth, 200, &resp),
            Err(NotStorable::Authorization)
        );
    }

    #[test]
    fn rfc5861_4_stale_if_error_is_capped_and_forbidden_by_revalidation_directives() {
        let cap = Duration::from_secs(100);
        let cc = |v: &str| Directives::parse([v.as_bytes()]);
        assert_eq!(
            stale_if_error(&cc("max-age=1, stale-if-error=50"), cap),
            Duration::from_secs(50)
        );
        assert_eq!(
            stale_if_error(&cc("max-age=1, stale-if-error=500"), cap),
            cap
        );
        assert_eq!(stale_if_error(&cc("max-age=1"), cap), Duration::ZERO);
        for forbidding in [
            "must-revalidate",
            "proxy-revalidate",
            "s-maxage=5",
            "no-cache",
        ] {
            let value = format!("max-age=1, stale-if-error=50, {forbidding}");
            assert_eq!(
                stale_if_error(&cc(&value), cap),
                Duration::ZERO,
                "{forbidding}"
            );
        }
    }
}
