//! Request directives against a stored response (RFC 9111 §5.2.1, §4.2.4).

use std::time::Duration;

use http::HeaderMap;

use super::cache_control::{Directives, Seconds, pragma_no_cache};

/// What to do with a stored response for this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advice {
    /// Serve it as it is (fresh), or treat it as stale when it is.
    Default,
    /// Revalidate it with the origin before serving (`no-cache`, `max-age`, `min-fresh`).
    Revalidate,
    /// Serve it although it is stale: the client accepts it (`max-stale`).
    ServeStale,
}

/// The stored response as the request sees it.
#[derive(Debug, Clone, Copy)]
pub struct Stored<'a> {
    /// Its current age.
    pub age: Duration,
    /// Time left until it is stale; `None` when it already is.
    pub remaining: Option<Duration>,
    /// How long it has been stale.
    pub staleness: Duration,
    /// Its `Cache-Control`.
    pub cc: &'a Directives,
}

/// Applies the request's directives (`no-cache`, `Pragma: no-cache`, `max-age`, `min-fresh`,
/// `max-stale`) to a stored response. With `honour` false only the defaults apply: clients
/// cannot force origin fetches. `max-stale` never overrides `must-revalidate`,
/// `proxy-revalidate`, `s-maxage` or `no-cache` on the stored response (§4.2.4).
#[must_use]
pub fn advise(request: &HeaderMap, stored: &Stored<'_>, honour: bool) -> Advice {
    if !honour {
        return Advice::Default;
    }
    let cc = Directives::of(request);
    if cc.has("no-cache") || pragma_no_cache(request) {
        return Advice::Revalidate;
    }
    match cc.seconds("max-age") {
        Some(Seconds::Valid(0) | Seconds::Invalid) => return Advice::Revalidate,
        Some(Seconds::Valid(n)) if stored.age > Duration::from_secs(n.into()) => {
            return Advice::Revalidate;
        }
        _ => {}
    }
    if let Some(Seconds::Valid(n)) = cc.seconds("min-fresh")
        && stored
            .remaining
            .is_none_or(|left| left < Duration::from_secs(n.into()))
    {
        return Advice::Revalidate;
    }
    if stored.remaining.is_none() && cc.has("max-stale") {
        let forbidden = [
            "must-revalidate",
            "proxy-revalidate",
            "s-maxage",
            "no-cache",
        ]
        .iter()
        .any(|d| stored.cc.has(d));
        let within = match cc.seconds("max-stale") {
            None | Some(Seconds::Invalid) => cc.value("max-stale") == Some(None),
            Some(Seconds::Valid(n)) => stored.staleness <= Duration::from_secs(n.into()),
        };
        if within && !forbidden {
            return Advice::ServeStale;
        }
    }
    Advice::Default
}

/// `only-if-cached`: answer from the store or with `504` (RFC 9111 §5.2.1.7). Honoured even
/// when request directives are otherwise ignored: it can only avoid origin traffic.
#[must_use]
pub fn only_if_cached(request: &HeaderMap) -> bool {
    Directives::of(request).has("only-if-cached")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(cc: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("cache-control", cc.parse().unwrap());
        h
    }

    fn stored(age: u64, remaining: Option<u64>, staleness: u64, cc: &Directives) -> Stored<'_> {
        Stored {
            age: Duration::from_secs(age),
            remaining: remaining.map(Duration::from_secs),
            staleness: Duration::from_secs(staleness),
            cc,
        }
    }

    #[test]
    fn rfc9111_5_2_1_4_no_cache_and_pragma_force_revalidation() {
        let cc = Directives::default();
        let fresh = stored(1, Some(50), 0, &cc);
        assert_eq!(advise(&req("no-cache"), &fresh, true), Advice::Revalidate);
        let mut pragma = HeaderMap::new();
        pragma.insert("pragma", "no-cache".parse().unwrap());
        assert_eq!(advise(&pragma, &fresh, true), Advice::Revalidate);
        assert_eq!(advise(&req("no-cache"), &fresh, false), Advice::Default);
    }

    #[test]
    fn rfc9111_5_2_1_1_max_age_limits_the_acceptable_age() {
        let cc = Directives::default();
        assert_eq!(
            advise(&req("max-age=0"), &stored(0, Some(50), 0, &cc), true),
            Advice::Revalidate
        );
        assert_eq!(
            advise(&req("max-age=10"), &stored(11, Some(50), 0, &cc), true),
            Advice::Revalidate
        );
        assert_eq!(
            advise(&req("max-age=10"), &stored(10, Some(50), 0, &cc), true),
            Advice::Default
        );
    }

    #[test]
    fn rfc9111_5_2_1_3_min_fresh_needs_time_left() {
        let cc = Directives::default();
        assert_eq!(
            advise(&req("min-fresh=30"), &stored(1, Some(20), 0, &cc), true),
            Advice::Revalidate
        );
        assert_eq!(
            advise(&req("min-fresh=30"), &stored(1, Some(40), 0, &cc), true),
            Advice::Default
        );
    }

    #[test]
    fn rfc9111_5_2_1_2_max_stale_accepts_stale_unless_the_origin_forbids_it() {
        let cc = Directives::default();
        assert_eq!(
            advise(&req("max-stale"), &stored(100, None, 50, &cc), true),
            Advice::ServeStale
        );
        assert_eq!(
            advise(&req("max-stale=60"), &stored(100, None, 50, &cc), true),
            Advice::ServeStale
        );
        assert_eq!(
            advise(&req("max-stale=10"), &stored(100, None, 50, &cc), true),
            Advice::Default
        );
        let strict = Directives::parse([b"max-age=1, must-revalidate".as_slice()]);
        assert_eq!(
            advise(&req("max-stale"), &stored(100, None, 50, &strict), true),
            Advice::Default
        );
        // A fresh response is served as it is.
        assert_eq!(
            advise(&req("max-stale"), &stored(1, Some(9), 0, &cc), true),
            Advice::Default
        );
    }

    #[test]
    fn rfc9111_5_2_1_7_only_if_cached_is_recognised() {
        assert!(only_if_cached(&req("only-if-cached")));
        assert!(!only_if_cached(&req("max-age=5")));
    }
}
