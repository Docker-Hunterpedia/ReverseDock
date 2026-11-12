//! API-gateway configuration (ADR-0030, F-GW-01, F-GW-02, F-GW-05): consumers and their API
//! keys, the `api_key` and `quota` middlewares, per-group limit overrides and usage metering.

use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::{Duration, HttpUrl};

/// A consumer: an API client or user that requests are attributed to (`consumers.<name>`).
///
/// An authenticating middleware (`api_key`, `cloudflare_access`) sets the request's consumer;
/// rate limits and quotas can count per consumer, and the access log, metrics, metering and the
/// cache key see its name.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Consumer {
    /// Groups, in order of precedence: per-group limit overrides use the first listed group
    /// that has one, and `api_key.groups` admits a consumer in any of them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// API keys, stored as their ID and the SHA-256 of their secret; never the key itself.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<ApiKeyEntry>,
    /// A file of `id:sha256[:expires]` lines (blank lines and `#` comments ignored), read on
    /// every reload and watched like the configuration file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_file: Option<PathBuf>,
}

/// One API key of a consumer: `rdk_<id>_<secret><checksum>` is the key, and only `id` and the
/// SHA-256 of the secret are stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyEntry {
    /// The key's public ID: the 12 characters after `rdk_`.
    pub id: String,
    /// SHA-256 of the key's secret (the 32 characters after the ID's `_`, without the
    /// 6-character checksum), as 64 lower-case hex digits. `rdock keys hash` prints it.
    pub hash: String,
    /// When the key stops working: an RFC 3339 time, e.g. `2027-01-01T00:00:00Z`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// What the key is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// API key authentication (`type: api_key`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(inline)]
pub struct ApiKeyConfig {
    /// Request headers the key is read from, in order; the first present wins. A key in
    /// `Authorization` must follow `Bearer `.
    pub headers: Vec<String>,
    /// A query parameter the key is also read from, after the headers. Off unless named: keys
    /// in URLs end up in other systems' logs.
    pub query: Option<String>,
    /// Keep the key in the request to the backend. Off by default: the backend gets the
    /// consumer in `X-Consumer-Name`, `X-Consumer-Groups` and `X-Credential-Id` instead.
    pub forward_credential: bool,
    /// Requests without a key: `deny` answers `401`; `allow` lets them through without a
    /// consumer (an invalid key is still refused).
    pub anonymous: Anonymous,
    /// Only consumers in one of these groups are let in; others get `403`. Any consumer when
    /// empty.
    pub groups: Vec<String>,
    /// The realm of the `WWW-Authenticate` challenge.
    pub realm: Option<String>,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            headers: vec!["Authorization".to_owned(), "X-API-Key".to_owned()],
            query: None,
            forward_credential: false,
            anonymous: Anonymous::Deny,
            groups: Vec::new(),
            realm: None,
        }
    }
}

/// What an authenticating middleware does with a request that carries no credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Anonymous {
    /// Answer `401`.
    #[default]
    Deny,
    /// Continue without a consumer.
    Allow,
}

/// A limit for the consumers of one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateOverride {
    /// Requests allowed per `period` on average.
    pub average: u32,
    /// Largest burst; defaults to `average`.
    #[serde(default)]
    pub burst: Option<u32>,
    /// Period of `average`; defaults to the middleware's.
    #[serde(default)]
    pub period: Option<Duration>,
}

/// Requests per consumer per calendar window (`type: quota`).
///
/// Counters are kept per instance and written to `<data dir>/quota/` every `flush_interval`
/// and at shutdown, so a restart keeps them and a crash loses at most that interval: an
/// approximate allowance, not a billing record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(inline)]
pub struct QuotaConfig {
    /// Requests allowed per window.
    pub limit: u64,
    /// The calendar window, in UTC: `hour`, `day` (from 00:00) or `month` (from the 1st).
    pub window: QuotaWindow,
    /// What to count by; only `consumer` (the default) is accepted. Requests without a
    /// consumer are counted per client IP.
    #[serde(default = "consumer_key")]
    pub key: crate::values::RateLimitKey,
    /// Group → limit, for consumers in that group (the first of the consumer's groups that has
    /// one wins).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, u64>,
    /// `draft` adds `RateLimit-Policy` and `RateLimit` to responses, in the syntax of
    /// `draft-ietf-httpapi-ratelimit-headers-11`. Off by default while the draft changes.
    #[serde(default)]
    pub headers: LimitHeaders,
    /// How often counters are written to disk.
    #[serde(default = "ten_seconds")]
    pub flush_interval: Duration,
}

fn consumer_key() -> crate::values::RateLimitKey {
    crate::values::RateLimitKey::Consumer
}

const fn ten_seconds() -> Duration {
    Duration::from_secs(10)
}

/// A quota's calendar window, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuotaWindow {
    /// From the start of each hour.
    Hour,
    /// From 00:00 UTC.
    Day,
    /// From 00:00 UTC on the 1st.
    Month,
}

impl QuotaWindow {
    /// The name used in configuration.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Month => "month",
        }
    }
}

/// Rate-limit response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LimitHeaders {
    /// None (`Retry-After` is always sent with `429`).
    #[default]
    Off,
    /// `RateLimit-Policy` and `RateLimit` as in `draft-ietf-httpapi-ratelimit-headers-11`.
    Draft,
}

/// Usage metering (`observability.metering`, F-GW-05): one event per request that has a
/// consumer, sent in batches to a webhook (`CloudEvents` 1.0) and/or an OTLP logs endpoint.
///
/// Events wait in a bounded in-memory queue; when it is full the newest are dropped and
/// counted. Delivery is at least once (a retried batch carries the same event IDs). There is
/// no disk spool: events still queued are lost on a crash. Per instance; not billing-grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metering {
    /// Also meter requests without a consumer.
    #[serde(default)]
    pub all_requests: bool,
    /// `CloudEvents` over HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook: Option<MeteringWebhook>,
    /// OTLP/HTTP logs (JSON encoding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otlp: Option<MeteringOtlp>,
    /// Events per request to a sink, at most.
    #[serde(default = "default_batch")]
    pub max_batch: u32,
    /// Longest an event waits before its batch is sent.
    #[serde(default = "five_seconds")]
    pub flush_interval: Duration,
    /// Events waiting per sink, at most; more are dropped and counted.
    #[serde(default = "default_queue")]
    pub queue: u32,
}

const fn default_batch() -> u32 {
    500
}

const fn default_queue() -> u32 {
    10_000
}

const fn five_seconds() -> Duration {
    Duration::from_secs(5)
}

/// The `CloudEvents` webhook sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeteringWebhook {
    /// Where batches are posted (`application/cloudevents-batch+json`).
    pub url: HttpUrl,
    /// The events' `type`.
    #[serde(default = "default_event_type")]
    pub r#type: String,
    /// The events' `source`; `rdock/<host name>` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// A Standard Webhooks signing secret (`whsec_…`) as a `${file:…}` or `${env:…}`
    /// reference: requests carry `webhook-id`, `webhook-timestamp` and `webhook-signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// A bearer token as a `${file:…}` or `${env:…}` reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Allow a receiver on a private, loopback or link-local address.
    #[serde(default)]
    pub allow_private_targets: bool,
}

fn default_event_type() -> String {
    "dev.reversedock.request.v1".to_owned()
}

/// The OTLP logs sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeteringOtlp {
    /// The collector's base URL (`/v1/logs` is added) or the full logs URL.
    pub endpoint: HttpUrl,
    /// A bearer token as a `${file:…}` or `${env:…}` reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Allow a collector on a private, loopback or link-local address (the usual case).
    #[serde(default = "crate::defaults::yes")]
    pub allow_private_targets: bool,
}

/// Seconds since the Unix epoch of an RFC 3339 time (`2027-01-01T00:00:00Z`,
/// `2027-01-01T02:00:00+02:00`, fractions of a second ignored), or `None` when it is not one.
#[must_use]
pub fn parse_rfc3339(value: &str) -> Option<i64> {
    let v = value.trim().as_bytes();
    if v.len() < 20 || v[4] != b'-' || v[7] != b'-' || !matches!(v[10], b'T' | b't' | b' ') {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let text = std::str::from_utf8(v.get(range)?).ok()?;
        text.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| text.parse().ok())?
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if v[13] != b':' || v[16] != b':' {
        return None;
    }
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = &v[19..];
    if rest.first() == Some(&b'.') {
        let digits = rest[1..].iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        rest = &rest[1 + digits..];
    }
    let offset = match rest {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let digits = [*h1, *h2, *m1, *m2];
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let h = i64::from(h1 - b'0') * 10 + i64::from(h2 - b'0');
            let m = i64::from(m1 - b'0') * 10 + i64::from(m2 - b'0');
            let total = h * 3600 + m * 60;
            if *sign == b'+' { total } else { -total }
        }
        _ => return None,
    };
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// Days in `month` of `year` (proleptic Gregorian).
#[must_use]
pub fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to the date (Howard Hinnant's algorithm).
#[must_use]
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day number from 1970-01-01: (year, month, day).
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_times_parse() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2027-01-01T00:00:00Z"), Some(1_798_761_600));
        assert_eq!(
            parse_rfc3339("2027-01-01T02:00:00+02:00"),
            Some(1_798_761_600)
        );
        assert_eq!(
            parse_rfc3339("2024-02-29T12:00:00.250Z"),
            Some(1_709_208_000)
        );
        for bad in [
            "2027-01-01",
            "2027-13-01T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2027-01-01T00:00:00",
            "2027-01-01T00:00:00+2:00",
            "2027-01-01T24:00:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
        for days in [-1, 0, 59, 10_957, 20_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
