//! A route's cache policy, compiled from its `cache` middleware.

use std::collections::BTreeMap;
use std::time::Duration;

use http::HeaderMap;
use http::header::{CONTENT_LENGTH, COOKIE, HeaderName, TRANSFER_ENCODING};
use rdock_model::cache::{AuthorizationRule, CacheConfig, QueryKey, RequestDirectives, SetCookie};

use crate::pingora_types::CacheKeyLockImpl;
use crate::policy::freshness::FreshnessOptions;
use crate::policy::query::{Pattern, QueryRule};
use crate::policy::storable::{
    AuthorizationPolicy, DEFAULT_STATUSES, SetCookiePolicy, StoreOptions,
};
use crate::policy::vary::normalized_value;
use crate::store::Store;

/// Request headers that make some origins answer for another URL, method or host
/// (`X-Original-URL`, `X-HTTP-Method-Override`…). They are removed from requests on caching
/// routes unless the route keys on them, so a response can never be stored under a key that
/// does not describe it (unkeyed-input cache poisoning).
pub const OVERRIDE_HEADERS: [&str; 7] = [
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-host",
    "x-forwarded-server",
];

/// Who the request is, for `key.consumer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The consumer set by an authenticating middleware.
    Consumer(String),
    /// The `basic_auth` user.
    User(String),
    /// The `jwt` issuer and subject.
    Token {
        /// `iss`.
        issuer: String,
        /// `sub`.
        subject: String,
    },
    /// The client certificate's subject.
    Certificate(String),
    /// Nobody authenticated.
    Anonymous,
}

impl Identity {
    /// The key component: the kind and the value, so a user and a consumer of the same name
    /// never share a copy.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Consumer(c) => format!("consumer:{c}"),
            Self::User(u) => format!("user:{u}"),
            Self::Token { issuer, subject } => format!("token:{}:{issuer}{subject}", issuer.len()),
            Self::Certificate(s) => format!("cert:{s}"),
            Self::Anonymous => "anonymous".to_owned(),
        }
    }
}

/// Coalescing settings.
#[derive(Clone, Copy)]
pub struct LockPolicy {
    /// The lock.
    pub lock: &'static CacheKeyLockImpl,
    /// Longest wait, and longest a writer holds the lock.
    pub timeout: Duration,
}

impl std::fmt::Debug for LockPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockPolicy")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// A route's compiled cache policy.
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent settings, compiled one to one from the middleware"
)]
pub struct RoutePolicy {
    /// The store.
    pub store: &'static Store,
    /// Largest body stored.
    pub max_object_size: usize,
    /// `key.query`.
    pub query: QueryRule,
    /// `key.headers`, lower case.
    pub key_headers: Vec<HeaderName>,
    /// `key.consumer`.
    pub key_consumer: bool,
    /// `bypass.cookies`.
    pub bypass_cookies: Vec<String>,
    /// `bypass.headers`.
    pub bypass_headers: Vec<HeaderName>,
    /// What may be stored and for how long.
    pub store_options: StoreOptions,
    /// `request_directives: honour`.
    pub honour_request_directives: bool,
    /// Coalescing, unless `lock.enabled` is false.
    pub lock: Option<LockPolicy>,
    /// `tags.headers`, lower case.
    pub tag_headers: Vec<HeaderName>,
    /// `tags.keep`.
    pub keep_tags: bool,
    /// `cache_status`.
    pub cache_status: bool,
    /// `remove_targeted`: the targeted fields are removed from responses.
    pub remove_targeted: bool,
}

fn header_names(names: &[String]) -> Result<Vec<HeaderName>, String> {
    names
        .iter()
        .map(|n| {
            HeaderName::from_bytes(n.to_ascii_lowercase().as_bytes())
                .map_err(|_| format!("`{n}` is not a header name"))
        })
        .collect()
}

impl RoutePolicy {
    /// Compiles `config` for `store`.
    ///
    /// # Errors
    ///
    /// A setting validation should have refused (a bad header name or status).
    pub fn compile(config: &CacheConfig, store: &'static Store) -> Result<Self, String> {
        let mut default_ttl = BTreeMap::new();
        for (code, ttl) in &config.default_ttl {
            let status = code
                .parse::<u16>()
                .map_err(|_| format!("`{code}` is not a status code"))?;
            default_ttl.insert(status, ttl.as_std());
        }
        let query = match &config.key.query {
            QueryKey::AsSent => QueryRule::AsSent,
            QueryKey::Sorted => QueryRule::Sorted,
            QueryKey::Only(p) => QueryRule::Only(p.iter().map(|s| Pattern::new(s)).collect()),
            QueryKey::Ignore(p) => QueryRule::Ignore(p.iter().map(|s| Pattern::new(s)).collect()),
        };
        let timeout = config.lock.timeout.as_std();
        Ok(Self {
            store,
            max_object_size: usize::try_from(config.max_object_size.as_u64()).unwrap_or(usize::MAX),
            query,
            key_headers: header_names(&config.key.headers)?,
            key_consumer: config.key.consumer,
            bypass_cookies: config.bypass.cookies.clone(),
            bypass_headers: header_names(&config.bypass.headers)?,
            store_options: StoreOptions {
                statuses: config
                    .statuses
                    .clone()
                    .unwrap_or_else(|| DEFAULT_STATUSES.to_vec()),
                set_cookie: match config.set_cookie {
                    SetCookie::Refuse => SetCookiePolicy::Refuse,
                    SetCookie::Strip => SetCookiePolicy::Strip,
                },
                authorization: match config.authorization {
                    AuthorizationRule::Refuse => AuthorizationPolicy::Refuse,
                    AuthorizationRule::Store => AuthorizationPolicy::Store,
                },
                freshness: FreshnessOptions {
                    default_ttl,
                    heuristic: config.heuristic_freshness,
                },
                stale_if_error_cap: config.stale_if_error.as_std(),
                targeted: header_names(&config.targeted)?,
            },
            honour_request_directives: config.request_directives == RequestDirectives::Honour,
            lock: (config.lock.enabled && !timeout.is_zero()).then(|| LockPolicy {
                lock: crate::lock::lock_for(timeout),
                timeout,
            }),
            tag_headers: header_names(&config.tags.headers)?,
            keep_tags: config.tags.keep,
            cache_status: config.cache_status,
            remove_targeted: config.remove_targeted,
        })
    }

    /// Why this request skips the cache, if it does: a body, or a `bypass` cookie or header.
    #[must_use]
    pub fn bypass(&self, request: &HeaderMap) -> Option<&'static str> {
        if has_body(request) {
            return Some("request-body");
        }
        if self.bypass_headers.iter().any(|h| request.contains_key(h)) {
            return Some("bypass-header");
        }
        if !self.bypass_cookies.is_empty() {
            let has_cookie = request
                .get_all(COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(';'))
                .filter_map(|pair| pair.split_once('=').map(|(n, _)| n.trim()))
                .any(|name| self.bypass_cookies.iter().any(|c| c == name));
            if has_cookie {
                return Some("bypass-cookie");
            }
        }
        None
    }

    /// The `key.headers` components: each name with the request's normalised value.
    #[must_use]
    pub fn key_header_values(&self, request: &HeaderMap) -> Vec<(String, Option<Vec<u8>>)> {
        self.key_headers
            .iter()
            .map(|name| {
                (
                    name.as_str().to_owned(),
                    normalized_value(request, name.as_str()),
                )
            })
            .collect()
    }

    /// The directives a stored or received response is judged by: its first valid targeted
    /// field, else `Cache-Control` (RFC 9213 §2.1).
    #[must_use]
    pub fn directives(&self, response: &HeaderMap) -> crate::policy::cache_control::Directives {
        crate::policy::targeted::effective(response, &self.store_options.targeted).cc
    }

    /// Whether the route keys on request header `name`.
    #[must_use]
    pub fn keys_on(&self, name: &str) -> bool {
        self.key_headers
            .iter()
            .any(|h| h.as_str().eq_ignore_ascii_case(name))
    }
}

/// Whether a request has a body: `Content-Length` above zero or any `Transfer-Encoding`.
#[must_use]
pub fn has_body(request: &HeaderMap) -> bool {
    request.contains_key(TRANSFER_ENCODING)
        || request
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() != "0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdock_model::cache::CacheConfig;

    fn config(yaml: serde_json::Value) -> CacheConfig {
        serde_json::from_value(yaml).unwrap()
    }

    fn store() -> &'static Store {
        Box::leak(Box::new(Store::memory("m", 1 << 20, None)))
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(*n, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn defaults_compile_to_the_safe_policy() {
        let policy =
            RoutePolicy::compile(&config(serde_json::json!({ "store": "m" })), store()).unwrap();
        assert_eq!(policy.max_object_size, 64 << 20);
        assert_eq!(policy.store_options.statuses, DEFAULT_STATUSES);
        assert_eq!(policy.store_options.set_cookie, SetCookiePolicy::Refuse);
        assert_eq!(policy.store_options.freshness.default_ttl.len(), 0);
        assert!(!policy.store_options.freshness.heuristic);
        assert!(policy.honour_request_directives);
        assert_eq!(policy.lock.map(|l| l.timeout), Some(Duration::from_secs(5)));
        assert!(policy.cache_status && !policy.keep_tags);
        assert_eq!(policy.tag_headers, ["cache-tag", "surrogate-key"]);
        assert_eq!(policy.store_options.targeted, ["cdn-cache-control"]);
        assert!(!policy.remove_targeted);
    }

    #[test]
    fn opposites_compile() {
        let policy = RoutePolicy::compile(
            &config(serde_json::json!({
                "store": "m", "default_ttl": { "200": "5m" }, "heuristic_freshness": true,
                "set_cookie": "strip", "authorization": "store", "request_directives": "ignore",
                "lock": { "enabled": false }, "tags": { "keep": true }, "cache_status": false,
                "key": { "query": { "ignore": ["utm_*"] }, "headers": ["Accept-Language"] },
                "targeted": [], "remove_targeted": true
            })),
            store(),
        )
        .unwrap();
        assert_eq!(
            policy.store_options.freshness.default_ttl[&200],
            Duration::from_secs(300)
        );
        assert_eq!(policy.store_options.set_cookie, SetCookiePolicy::Strip);
        assert_eq!(
            policy.store_options.authorization,
            AuthorizationPolicy::Store
        );
        assert!(!policy.honour_request_directives && policy.lock.is_none());
        assert!(policy.keep_tags && !policy.cache_status);
        assert!(policy.keys_on("ACCEPT-language"));
        assert_eq!(policy.query, QueryRule::Ignore(vec![Pattern::new("utm_*")]));
        assert!(policy.store_options.targeted.is_empty() && policy.remove_targeted);
    }

    #[test]
    fn bodies_cookies_and_headers_bypass() {
        let policy = RoutePolicy::compile(
            &config(serde_json::json!({ "store": "m", "bypass": { "cookies": ["session"], "headers": ["x-preview"] } })),
            store(),
        )
        .unwrap();
        assert_eq!(policy.bypass(&headers(&[])), None);
        assert_eq!(policy.bypass(&headers(&[("content-length", "0")])), None);
        assert_eq!(
            policy.bypass(&headers(&[("content-length", "3")])),
            Some("request-body")
        );
        assert_eq!(
            policy.bypass(&headers(&[("transfer-encoding", "chunked")])),
            Some("request-body")
        );
        assert_eq!(
            policy.bypass(&headers(&[("x-preview", "1")])),
            Some("bypass-header")
        );
        assert_eq!(
            policy.bypass(&headers(&[("cookie", "a=1; session=x")])),
            Some("bypass-cookie")
        );
        assert_eq!(policy.bypass(&headers(&[("cookie", "sessionid=x")])), None);
    }

    #[test]
    fn identities_of_different_kinds_never_collide() {
        let keys = [
            Identity::Consumer("a".into()).key(),
            Identity::User("a".into()).key(),
            Identity::Certificate("a".into()).key(),
            Identity::Anonymous.key(),
            Identity::Token {
                issuer: "ab".into(),
                subject: "c".into(),
            }
            .key(),
            Identity::Token {
                issuer: "a".into(),
                subject: "bc".into(),
            }
            .key(),
        ];
        let mut unique = keys.to_vec();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), keys.len());
    }
}
