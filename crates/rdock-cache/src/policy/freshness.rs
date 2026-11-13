//! Freshness lifetime and age (RFC 9111 §4.2).

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use http::HeaderMap;
use http::header::{AGE, DATE, EXPIRES, LAST_MODIFIED};

use super::cache_control::{Directives, Seconds, parse_delta_seconds};

/// Longest lifetime heuristic freshness may give (RFC 9111 §4.2.2 leaves it to the cache).
pub const HEURISTIC_MAX: Duration = Duration::from_secs(24 * 3600);

/// Status codes that are heuristically cacheable (RFC 9110 §15.1).
pub const HEURISTIC_STATUSES: [u16; 12] =
    [200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501];

/// Where a response's freshness lifetime came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// `s-maxage`, `max-age`, `Expires`, or `no-cache` (zero): the origin said so.
    Explicit(Duration),
    /// The route's `default_ttl` for the status.
    Default(Duration),
    /// 10 % of the time since `Last-Modified` (opt-in).
    Heuristic(Duration),
    /// Nothing gives the response a lifetime.
    None,
}

impl Lifetime {
    /// The lifetime, if any.
    #[must_use]
    pub fn duration(self) -> Option<Duration> {
        match self {
            Self::Explicit(d) | Self::Default(d) | Self::Heuristic(d) => Some(d),
            Self::None => None,
        }
    }
}

/// The options that add lifetimes the origin did not give.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FreshnessOptions {
    /// Lifetime per status for responses without explicit freshness.
    pub default_ttl: BTreeMap<u16, Duration>,
    /// Heuristic freshness from `Last-Modified`.
    pub heuristic: bool,
}

/// An HTTP date header (RFC 9110 §5.6.7); `None` when absent, repeated or invalid.
#[must_use]
pub fn http_date(headers: &HeaderMap, name: &http::HeaderName) -> Option<SystemTime> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    httpdate::parse_http_date(value.to_str().ok()?.trim()).ok()
}

/// The freshness lifetime of a response in a shared cache (RFC 9111 §4.2.1): `s-maxage`, then
/// `max-age`, then `Expires` minus `Date`; then the configured default for the status, then
/// heuristic freshness when enabled. An invalid `max-age`, `s-maxage` or `Expires` makes the
/// response stale (§4.2.1, §5.3). An unqualified `no-cache` gives a zero lifetime whatever
/// `max-age`, `s-maxage` or `Expires` say, so a stored copy is revalidated before every use
/// (§5.2.2.4); a qualified one (`no-cache="x-a"`, whose fields are not stored) still keeps
/// the default and heuristic lifetimes away.
///
/// `cc` are the directives in effect: `Cache-Control`, or the targeted field that replaces
/// it (RFC 9213 §2.1), in which case `expires` is false and `Expires` is ignored too.
#[must_use]
pub fn freshness_lifetime(
    status: u16,
    headers: &HeaderMap,
    cc: &Directives,
    expires: bool,
    response_time: SystemTime,
    options: &FreshnessOptions,
) -> Lifetime {
    if cc.unqualified_no_cache() {
        return Lifetime::Explicit(Duration::ZERO);
    }
    for name in ["s-maxage", "max-age"] {
        match cc.seconds(name) {
            Some(Seconds::Valid(s)) => return Lifetime::Explicit(Duration::from_secs(s.into())),
            Some(Seconds::Invalid) => return Lifetime::Explicit(Duration::ZERO),
            None => {}
        }
    }
    if expires && headers.contains_key(EXPIRES) {
        let Some(expires) = http_date(headers, &EXPIRES) else {
            return Lifetime::Explicit(Duration::ZERO);
        };
        let date = http_date(headers, &DATE).unwrap_or(response_time);
        return Lifetime::Explicit(expires.duration_since(date).unwrap_or(Duration::ZERO));
    }
    if cc.has("no-cache") {
        return Lifetime::Explicit(Duration::ZERO);
    }
    if let Some(ttl) = options.default_ttl.get(&status) {
        return Lifetime::Default(*ttl);
    }
    if options.heuristic
        && HEURISTIC_STATUSES.contains(&status)
        && let Some(modified) = http_date(headers, &LAST_MODIFIED)
        && let Ok(since) = http_date(headers, &DATE)
            .unwrap_or(response_time)
            .duration_since(modified)
    {
        return Lifetime::Heuristic((since / 10).min(HEURISTIC_MAX));
    }
    Lifetime::None
}

/// The origin's `Age` (RFC 9111 §5.1): the first member of the field, across its lines, so
/// `Age: 7200, 0` and the lines `Age: 7200` and `Age: 0` both read 7200 (a cache that chose
/// the smaller value would serve a stale response as fresh). A parameter (`7200;foo=bar`) is
/// cut off, which can only make the response older. Anything else that is not a
/// delta-seconds value (`abc`, `-7200`, `7200.0`) is ignored, as §5.1 asks.
#[must_use]
pub fn age_header(headers: &HeaderMap) -> Option<Duration> {
    let first = headers.get(AGE)?.to_str().ok()?;
    let member = first.split(',').next().unwrap_or_default();
    let value = member.split(';').next().unwrap_or_default();
    match parse_delta_seconds(value.trim_matches([' ', '\t'])) {
        Seconds::Valid(s) => Some(Duration::from_secs(s.into())),
        Seconds::Invalid => None,
    }
}

/// The age a response already has when it arrives (RFC 9111 §4.2.3, `corrected_initial_age`):
/// the larger of its apparent age (`response_time` − `Date`) and the origin's `Age` plus the
/// time the request took.
#[must_use]
pub fn initial_age(
    headers: &HeaderMap,
    request_time: SystemTime,
    response_time: SystemTime,
) -> Duration {
    let apparent = http_date(headers, &DATE)
        .and_then(|date| response_time.duration_since(date).ok())
        .unwrap_or(Duration::ZERO);
    let age_value = age_header(headers).unwrap_or(Duration::ZERO);
    let delay = response_time
        .duration_since(request_time)
        .unwrap_or(Duration::ZERO);
    apparent.max(age_value + delay)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::cache_control::DELTA_SECONDS_MAX;

    fn headers(pairs: &[(&'static str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(*n, v.parse().unwrap());
        }
        h
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + secs)
    }

    fn date(t: SystemTime) -> String {
        httpdate::fmt_http_date(t)
    }

    fn lifetime(h: &HeaderMap, options: &FreshnessOptions) -> Lifetime {
        freshness_lifetime(200, h, &Directives::of(h), true, at(0), options)
    }

    #[test]
    fn rfc9111_4_2_1_s_maxage_beats_max_age_beats_expires() {
        let none = FreshnessOptions::default();
        let h = headers(&[
            ("cache-control", "max-age=60, s-maxage=30".into()),
            ("expires", date(at(1000))),
        ]);
        assert_eq!(
            lifetime(&h, &none),
            Lifetime::Explicit(Duration::from_secs(30))
        );
        let h = headers(&[
            ("cache-control", "max-age=60".into()),
            ("expires", date(at(1000))),
        ]);
        assert_eq!(
            lifetime(&h, &none),
            Lifetime::Explicit(Duration::from_secs(60))
        );
        let h = headers(&[("date", date(at(0))), ("expires", date(at(90)))]);
        assert_eq!(
            lifetime(&h, &none),
            Lifetime::Explicit(Duration::from_secs(90))
        );
    }

    #[test]
    fn rfc9111_5_3_invalid_or_repeated_expires_means_already_expired() {
        let none = FreshnessOptions::default();
        let h = headers(&[("expires", "0".into())]);
        assert_eq!(lifetime(&h, &none), Lifetime::Explicit(Duration::ZERO));
        let h = headers(&[("expires", date(at(50))), ("expires", date(at(60)))]);
        assert_eq!(lifetime(&h, &none), Lifetime::Explicit(Duration::ZERO));
        let h = headers(&[("date", date(at(100))), ("expires", date(at(50)))]);
        assert_eq!(lifetime(&h, &none), Lifetime::Explicit(Duration::ZERO));
    }

    #[test]
    fn rfc9111_4_2_1_invalid_max_age_is_stale() {
        let h = headers(&[("cache-control", "max-age=abc".into())]);
        assert_eq!(
            lifetime(&h, &FreshnessOptions::default()),
            Lifetime::Explicit(Duration::ZERO)
        );
    }

    #[test]
    fn rfc9111_4_2_2_no_heuristic_or_default_unless_configured() {
        let h = headers(&[("last-modified", date(at(0) - Duration::from_secs(10_000)))]);
        assert_eq!(lifetime(&h, &FreshnessOptions::default()), Lifetime::None);
        let heuristic = FreshnessOptions {
            heuristic: true,
            ..FreshnessOptions::default()
        };
        assert_eq!(
            lifetime(&h, &heuristic),
            Lifetime::Heuristic(Duration::from_secs(1000))
        );
        let old = headers(&[(
            "last-modified",
            date(at(0) - Duration::from_secs(100 * 24 * 3600)),
        )]);
        assert_eq!(
            lifetime(&old, &heuristic),
            Lifetime::Heuristic(HEURISTIC_MAX)
        );
        let default = FreshnessOptions {
            default_ttl: BTreeMap::from([(200, Duration::from_secs(5))]),
            heuristic: true,
        };
        assert_eq!(
            lifetime(&h, &default),
            Lifetime::Default(Duration::from_secs(5))
        );
        // An explicit lifetime always wins over the configured ones.
        let explicit = headers(&[("cache-control", "max-age=1".into())]);
        assert_eq!(
            lifetime(&explicit, &default),
            Lifetime::Explicit(Duration::from_secs(1))
        );
    }

    #[test]
    fn rfc9111_5_2_2_4_response_no_cache_stores_with_zero_lifetime() {
        let h = headers(&[("cache-control", "no-cache".into())]);
        let default = FreshnessOptions {
            default_ttl: BTreeMap::from([(200, Duration::from_secs(5))]),
            heuristic: false,
        };
        assert_eq!(lifetime(&h, &default), Lifetime::Explicit(Duration::ZERO));
    }

    #[test]
    fn rfc9111_5_2_2_4_no_cache_beats_max_age_and_expires_but_a_qualified_one_does_not() {
        let none = FreshnessOptions::default();
        for cc in [
            "max-age=10000, no-cache",
            "No-CaChE, s-maxage=50",
            "no-cache=\"\"",
        ] {
            let h = headers(&[
                ("cache-control", cc.into()),
                ("date", date(at(0))),
                ("expires", date(at(10_000))),
            ]);
            assert_eq!(
                lifetime(&h, &none),
                Lifetime::Explicit(Duration::ZERO),
                "{cc}"
            );
        }
        let h = headers(&[("cache-control", "max-age=60, no-cache=\"x-a\"".into())]);
        assert_eq!(
            lifetime(&h, &none),
            Lifetime::Explicit(Duration::from_secs(60))
        );
        // Without a lifetime, a qualified no-cache still keeps the defaults away.
        let default = FreshnessOptions {
            default_ttl: BTreeMap::from([(200, Duration::from_secs(5))]),
            heuristic: false,
        };
        let h = headers(&[("cache-control", "no-cache=\"x-a\"".into())]);
        assert_eq!(lifetime(&h, &default), Lifetime::Explicit(Duration::ZERO));
    }

    #[test]
    fn rfc9213_2_1_a_targeted_field_ignores_expires() {
        let h = headers(&[("date", date(at(0))), ("expires", date(at(90)))]);
        let none = FreshnessOptions::default();
        assert_eq!(
            freshness_lifetime(200, &h, &Directives::default(), false, at(0), &none),
            Lifetime::None
        );
    }

    #[test]
    fn rfc9111_5_1_age_reads_the_first_member_and_ignores_invalid_values() {
        let read = |lines: &[&str]| {
            let mut h = HeaderMap::new();
            for l in lines {
                h.append(AGE, l.parse().unwrap());
            }
            age_header(&h).map(|d| d.as_secs())
        };
        assert_eq!(read(&["7200, 0"]), Some(7200));
        assert_eq!(read(&["0, 7200"]), Some(0));
        assert_eq!(read(&["7200", "0"]), Some(7200));
        assert_eq!(read(&["0", "7200"]), Some(0));
        assert_eq!(read(&["0, 0"]), Some(0));
        assert_eq!(read(&["7200;foo=bar"]), Some(7200));
        assert_eq!(read(&[" 30 "]), Some(30));
        assert_eq!(read(&["2147483649"]), Some(u64::from(DELTA_SECONDS_MAX)));
        for bad in ["abc", "-7200", "7200.0", "", ", 5"] {
            assert_eq!(read(&[bad]), None, "{bad:?}");
        }
        assert_eq!(read(&[]), None);
    }

    #[test]
    fn rfc9111_4_2_3_initial_age_uses_origin_age_and_date() {
        let h = headers(&[("age", "100".into()), ("date", date(at(0)))]);
        assert_eq!(initial_age(&h, at(0), at(2)), Duration::from_secs(102));
        let h = headers(&[("date", date(at(0)))]);
        assert_eq!(initial_age(&h, at(9), at(10)), Duration::from_secs(10));
        let h = headers(&[("age", "bogus".into())]);
        assert_eq!(initial_age(&h, at(0), at(0)), Duration::ZERO);
        // A Date in the future is not a negative age.
        let h = headers(&[("date", date(at(50)))]);
        assert_eq!(initial_age(&h, at(0), at(0)), Duration::ZERO);
    }
}
