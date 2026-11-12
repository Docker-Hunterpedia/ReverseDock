//! The HTTP cache (F-WEB-03, ADR-0030): named stores under `caches`, and the `cache`
//! middleware that puts a route's responses in one of them.

use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::{ByteSize, Duration};

/// A cache store: where cached responses live. Stores are created once per process; adding
/// one applies on reload, changing or removing one takes effect after a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CacheStore {
    /// Responses in memory, evicted least recently used first beyond `max_size`.
    Memory(MemoryStore),
    /// Responses on disk, one file per object, evicted least recently used first beyond
    /// `max_size` or `max_objects`. Objects survive restarts.
    Disk(DiskStore),
}

impl CacheStore {
    /// The store's size limit.
    #[must_use]
    pub fn max_size(&self) -> ByteSize {
        match self {
            Self::Memory(m) => m.max_size,
            Self::Disk(d) => d.max_size,
        }
    }
}

/// A memory store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct MemoryStore {
    /// Bytes kept, bodies and headers together.
    pub max_size: ByteSize,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            max_size: ByteSize::mib(256),
        }
    }
}

/// A disk store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct DiskStore {
    /// Directory of the store, absolute; `<data dir>/cache/<name>` when omitted. Created with
    /// mode 0700. Anyone who can write it can serve arbitrary content through the cache.
    pub path: Option<PathBuf>,
    /// Bytes kept on disk (file sizes).
    pub max_size: ByteSize,
    /// Objects kept on disk (one file each).
    pub max_objects: u64,
}

impl Default for DiskStore {
    fn default() -> Self {
        Self {
            path: None,
            max_size: ByteSize::mib(1024),
            max_objects: 1_000_000,
        }
    }
}

/// Cache the route's responses in a store (RFC 9111). Off unless a route lists it; only
/// what the origin's headers allow is stored, for as long as they allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent switches, each the opposite of one safe default"
)]
pub struct CacheConfig {
    /// The store, a name under `caches`.
    pub store: String,
    /// Largest response body stored; larger ones pass through uncached.
    #[serde(default = "default_max_object_size")]
    pub max_object_size: ByteSize,
    /// What, besides store, route, scheme, host, path and method, selects a stored response.
    #[serde(default)]
    pub key: CacheKey,
    /// The route authenticates requests but its responses are the same for every user, so
    /// one stored copy may be served to all of them. Required (or `key.consumer`) when the
    /// route has an authenticating middleware; the risk is serving one user's page to
    /// another.
    #[serde(default)]
    pub shared_across_users: bool,
    /// Requests that skip the cache entirely.
    #[serde(default)]
    pub bypass: CacheBypass,
    /// Statuses that may be stored, each only with a lifetime; default 200, 203, 204, 300,
    /// 301, 308, 404, 410. 206 and 304 are never stored as such.
    #[serde(default)]
    pub statuses: Option<Vec<u16>>,
    /// Lifetime by status (`"200": 5m`) for responses whose origin gives none (no
    /// `max-age`, `s-maxage` or `Expires`). Never applies over `no-store`, `private` or
    /// `no-cache`. Empty by default: the risk is caching personalised pages the origin did
    /// not mark.
    #[serde(default)]
    pub default_ttl: BTreeMap<String, Duration>,
    /// Give responses with `Last-Modified` and no explicit lifetime 10 % of their age, at
    /// most a day (RFC 9111 §4.2.2). Off by default: the origin did not ask for caching.
    #[serde(default)]
    pub heuristic_freshness: bool,
    /// Responses that set a cookie: `refuse` (default) never stores them; `strip` stores
    /// them without `Set-Cookie`. The risk of `strip` is a page that depends on the cookie.
    #[serde(default)]
    pub set_cookie: SetCookie,
    /// Responses to requests that carry `Authorization` to the origin: `refuse` (default)
    /// stores them only when they are marked `public`, `s-maxage` or `must-revalidate` (RFC
    /// 9111 §3.5); `store` stores them anyway. The risk of `store` is serving one
    /// credential's answer to another.
    #[serde(default)]
    pub authorization: AuthorizationRule,
    /// The client's `no-cache`, `max-age`, `min-fresh` and `max-stale`: `honour` (default,
    /// RFC 9111 §5.2.1) or `ignore`, so clients cannot force origin fetches.
    /// `only-if-cached` is always honoured.
    #[serde(default)]
    pub request_directives: RequestDirectives,
    /// Longest time a stale response is served when the origin fails, if the origin allowed
    /// it with `stale-if-error` (RFC 5861). `0s` turns it off.
    #[serde(default = "default_stale_if_error")]
    pub stale_if_error: Duration,
    /// Refresh stale responses in the background (`stale-while-revalidate`). Not supported
    /// in this version: `stale-while-revalidate` is treated as plain staleness.
    #[serde(default)]
    pub background_refresh: bool,
    /// Request coalescing: one origin fetch per key at a time.
    #[serde(default)]
    pub lock: CacheLock,
    /// Cache tags for purging groups of responses.
    #[serde(default)]
    pub tags: CacheTags,
    /// Add `Cache-Status` (RFC 9211) to responses.
    #[serde(default = "crate::defaults::yes")]
    pub cache_status: bool,
}

const fn default_max_object_size() -> ByteSize {
    ByteSize::mib(64)
}

const fn default_stale_if_error() -> Duration {
    Duration::from_secs(24 * 3600)
}

/// Key options.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct CacheKey {
    /// How the query string enters the key.
    pub query: QueryKey,
    /// Request headers whose values select a response (beyond the origin's `Vary`).
    pub headers: Vec<String>,
    /// Keep one copy per authenticated identity: the consumer, else the `basic_auth` user,
    /// else the `jwt` issuer and subject, else the client certificate's subject.
    pub consumer: bool,
}

/// How the query string enters the key. Parameters left out of the key are also removed
/// from the request sent to the origin.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryKey {
    /// The query exactly as forwarded.
    #[default]
    AsSent,
    /// Parameters sorted by name.
    Sorted,
    /// Only these parameters (`name` or `prefix*`).
    Only(Vec<String>),
    /// All but these parameters (`name` or `prefix*`).
    Ignore(Vec<String>),
}

/// Requests that skip the cache.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct CacheBypass {
    /// Skip when the request has one of these cookies.
    pub cookies: Vec<String>,
    /// Skip when the request has one of these headers.
    pub headers: Vec<String>,
}

/// What to do with responses that set a cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetCookie {
    /// Never store them.
    #[default]
    Refuse,
    /// Store them without `Set-Cookie`.
    Strip,
}

/// What to do with responses to requests that carry `Authorization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationRule {
    /// Store only `public`, `s-maxage` or `must-revalidate` responses (RFC 9111 §3.5).
    #[default]
    Refuse,
    /// Store them like other responses.
    Store,
}

/// The client's request directives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestDirectives {
    /// Apply them (RFC 9111 §5.2.1).
    #[default]
    Honour,
    /// Ignore them, except `only-if-cached`.
    Ignore,
}

/// Request coalescing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct CacheLock {
    /// While one request fetches a key, others wait for its response instead of asking the
    /// origin too. Off, every miss goes to the origin.
    pub enabled: bool,
    /// Longest wait. After it the waiting request goes to the origin without storing, and
    /// a fetch running that long no longer holds others back.
    pub timeout: Duration,
}

impl Default for CacheLock {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_secs(5),
        }
    }
}

/// Cache tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(inline)]
pub struct CacheTags {
    /// Response headers that carry tags (comma or space separated).
    pub headers: Vec<String>,
    /// Pass the tag headers on to clients; by default they are removed.
    pub keep: bool,
}

impl Default for CacheTags {
    fn default() -> Self {
        Self {
            headers: vec!["cache-tag".to_owned(), "surrogate-key".to_owned()],
            keep: false,
        }
    }
}
