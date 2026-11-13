//! The `Cache-Status` response field (RFC 9211).

use std::fmt::Write as _;

/// The cache's name in `Cache-Status`.
pub const CACHE_NAME: &str = "rdock";

/// Why the request went to the origin (RFC 9211 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fwd {
    /// The cache was configured not to handle this request.
    Bypass,
    /// The request method is not cacheable.
    Method,
    /// Nothing was stored for the URL.
    UriMiss,
    /// Something was stored for the URL, but not for this request's `Vary` fields.
    VaryMiss,
    /// Not in the cache, for a reason not told apart.
    Miss,
    /// The request's own directives asked for the origin.
    Request,
    /// A stored response was stale and had to be validated or replaced.
    Stale,
}

impl Fwd {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bypass => "bypass",
            Self::Method => "method",
            Self::UriMiss => "uri-miss",
            Self::VaryMiss => "vary-miss",
            Self::Miss => "miss",
            Self::Request => "request",
            Self::Stale => "stale",
        }
    }
}

/// What the cache did with one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStatus {
    /// Answered from the store without contacting the origin.
    pub hit: bool,
    /// Why the origin was asked, when it was.
    pub fwd: Option<Fwd>,
    /// The origin's status, when it answered.
    pub fwd_status: Option<u16>,
    /// Freshness left in seconds; negative when stale.
    pub ttl: Option<i64>,
    /// The origin's response was stored.
    pub stored: bool,
    /// The request waited for another request to fill the cache.
    pub collapsed: bool,
    /// An implementation-specific reason (`stale-if-error`, `no-store`, `lock-timeout`…).
    pub detail: Option<&'static str>,
}

impl CacheStatus {
    /// The field value, `rdock; hit; ttl=12` or `rdock; fwd=miss; fwd-status=200; stored`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from(CACHE_NAME);
        if self.hit {
            out.push_str("; hit");
        }
        if let Some(fwd) = self.fwd {
            let _ = write!(out, "; fwd={}", fwd.as_str());
        }
        if let Some(status) = self.fwd_status {
            let _ = write!(out, "; fwd-status={status}");
        }
        if let Some(ttl) = self.ttl {
            let _ = write!(out, "; ttl={ttl}");
        }
        if self.stored {
            out.push_str("; stored");
        }
        if self.collapsed {
            out.push_str("; collapsed");
        }
        if let Some(detail) = self.detail {
            // A token: the details used here are all token characters.
            let _ = write!(out, "; detail={detail}");
        }
        out
    }

    /// A bounded label for logs and metrics: `hit`, `stale` (served stale after an origin
    /// error), `revalidated`, `expired` (stale and replaced), `miss` or `bypass`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match (self.hit, self.fwd) {
            (true, _) if self.ttl.is_some_and(|t| t < 0) => "stale",
            (true, _) => "hit",
            (false, Some(Fwd::Stale)) if self.fwd_status == Some(304) => "revalidated",
            (false, Some(Fwd::Stale | Fwd::Request)) => "expired",
            (false, Some(Fwd::Miss | Fwd::UriMiss | Fwd::VaryMiss)) => "miss",
            (false, _) => "bypass",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9211_2_hit_and_forward_forms() {
        let hit = CacheStatus {
            hit: true,
            ttl: Some(30),
            collapsed: true,
            ..CacheStatus::default()
        };
        assert_eq!(hit.render(), "rdock; hit; ttl=30; collapsed");
        assert_eq!(hit.label(), "hit");
        let miss = CacheStatus {
            fwd: Some(Fwd::UriMiss),
            fwd_status: Some(200),
            stored: true,
            ..CacheStatus::default()
        };
        assert_eq!(miss.render(), "rdock; fwd=uri-miss; fwd-status=200; stored");
        assert_eq!(miss.label(), "miss");
        let stale = CacheStatus {
            hit: true,
            ttl: Some(-5),
            detail: Some("stale-if-error"),
            ..CacheStatus::default()
        };
        assert_eq!(stale.render(), "rdock; hit; ttl=-5; detail=stale-if-error");
        assert_eq!(stale.label(), "stale");
    }

    #[test]
    fn rfc9211_2_labels_cover_revalidation_and_bypass() {
        let revalidated = CacheStatus {
            fwd: Some(Fwd::Stale),
            fwd_status: Some(304),
            ..CacheStatus::default()
        };
        assert_eq!(revalidated.label(), "revalidated");
        let expired = CacheStatus {
            fwd: Some(Fwd::Stale),
            fwd_status: Some(200),
            ..CacheStatus::default()
        };
        assert_eq!(expired.label(), "expired");
        let bypass = CacheStatus {
            fwd: Some(Fwd::Method),
            ..CacheStatus::default()
        };
        assert_eq!(bypass.render(), "rdock; fwd=method");
        assert_eq!(bypass.label(), "bypass");
        assert_eq!(CacheStatus::default().label(), "bypass");
    }
}
