//! `rate_limit`: token buckets per client IP, route, consumer, header or cookie value, with
//! per-group limits for consumers (F-GW-02) and the draft `RateLimit` headers on request.

use std::time::Instant;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_limits::{Decision, RateLimiter};
use rdock_model::gateway::LimitHeaders;
use rdock_model::middleware::RateLimitConfig;
use rdock_model::values::RateLimitKey;

use crate::phase::{Capabilities, Phases};
use crate::{Context, Flow, Middleware, ProblemKind, Reply};

use crate::limits::MAX_KEYS;

/// One limit: its bucket set and what `RateLimit-Policy` says about it.
#[derive(Debug)]
struct Limit {
    limiter: RateLimiter,
    average: u32,
    period_secs: u64,
}

impl Limit {
    fn new(average: u32, period: std::time::Duration, burst: u32) -> Self {
        Self {
            limiter: RateLimiter::new(average, period, burst, MAX_KEYS),
            average,
            period_secs: period.as_secs().max(1),
        }
    }
}

/// The `rate_limit` middleware.
#[derive(Debug)]
pub(crate) struct RateLimit {
    name: String,
    key: RateLimitKey,
    default: Limit,
    /// Group overrides, in name order; the consumer's group order decides which applies.
    overrides: Vec<(String, Limit)>,
    headers: LimitHeaders,
}

/// What the response phase adds when `headers: draft`.
struct Remaining {
    average: u32,
    period_secs: u64,
    left: u64,
    reset: u64,
}

impl RateLimit {
    pub(crate) fn new(name: &str, config: &RateLimitConfig) -> Self {
        let period = config.period.as_std();
        Self {
            name: name.to_owned(),
            key: config.key.clone(),
            default: Limit::new(
                config.average,
                period,
                config.burst.unwrap_or(config.average),
            ),
            overrides: config
                .overrides
                .iter()
                .map(|(group, o)| {
                    (
                        group.clone(),
                        Limit::new(
                            o.average,
                            o.period
                                .map_or(period, rdock_model::values::Duration::as_std),
                            o.burst.unwrap_or(o.average),
                        ),
                    )
                })
                .collect(),
            headers: config.headers,
        }
    }

    /// The limit for this request: the first of the consumer's groups with an override.
    fn limit(&self, cx: &Context) -> &Limit {
        if self.key == RateLimitKey::Consumer
            && let Some(consumer) = &cx.consumer
        {
            for group in consumer.groups.iter() {
                if let Some((_, limit)) = self.overrides.iter().find(|(g, _)| **g == **group) {
                    return limit;
                }
            }
        }
        &self.default
    }
}

fn ceil_secs(d: std::time::Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

#[async_trait]
impl Middleware for RateLimit {
    fn capabilities(&self) -> Capabilities {
        match self.headers {
            LimitHeaders::Off => Capabilities::new(Phases::REQUEST),
            LimitHeaders::Draft => {
                Capabilities::new(Phases::REQUEST | Phases::RESPONSE).with_state()
            }
        }
    }

    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let now = Instant::now();
        let limit = self.limit(cx);
        let key = crate::limits::key_of(&self.key, req, cx);
        let (decision, remaining, full) = limit.limiter.check_remaining(&key, now);
        match decision {
            Decision::Allow => {
                if self.headers == LimitHeaders::Draft {
                    cx.set_state(Remaining {
                        average: limit.average,
                        period_secs: limit.period_secs,
                        left: remaining,
                        reset: ceil_secs(full),
                    });
                }
                Flow::Next
            }
            Decision::Deny { retry_after } => {
                tracing::debug!(middleware = %self.name, "rate limit exceeded");
                let seconds = ceil_secs(retry_after).max(1);
                let mut reply = Reply::problem(ProblemKind::RateLimited)
                    .header(http::header::RETRY_AFTER, HeaderValue::from(seconds));
                if self.headers == LimitHeaders::Draft {
                    let window = i64::try_from(limit.period_secs).unwrap_or(i64::MAX);
                    for (name, value) in crate::quota::draft_headers(
                        &self.name,
                        u64::from(limit.average),
                        window,
                        0,
                        seconds,
                    ) {
                        reply = reply.header(name, value);
                    }
                }
                Flow::Reply(reply)
            }
        }
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        if let Some(r) = cx.take_state::<Remaining>() {
            let window = i64::try_from(r.period_secs).unwrap_or(i64::MAX);
            for (name, value) in crate::quota::draft_headers(
                &self.name,
                u64::from(r.average),
                window,
                r.left,
                r.reset,
            ) {
                let _ = resp.insert_header(name, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rdock_model::values::Duration;

    use super::*;
    use crate::test_support::{block_on, cx, reply_header, request};

    #[test]
    fn rejects_over_the_burst_with_retry_after() {
        let mw = RateLimit::new(
            "rl",
            &RateLimitConfig {
                key: RateLimitKey::ClientIp,
                average: 1,
                burst: Some(2),
                period: Duration::from_secs(10),
                overrides: std::collections::BTreeMap::new(),
                headers: LimitHeaders::Off,
            },
        );
        let mut req = request("GET", "/", &[]);
        assert_eq!(block_on(mw.request(&mut req, &mut cx())), Flow::Next);
        assert_eq!(block_on(mw.request(&mut req, &mut cx())), Flow::Next);
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx())) else {
            panic!("third request must be limited")
        };
        assert_eq!(reply.status, 429);
        let seconds: u64 = reply_header(&reply, "retry-after")
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=10).contains(&seconds), "{seconds}");
    }

    #[test]
    fn header_keys_get_their_own_buckets() {
        let mw = RateLimit::new(
            "rl",
            &RateLimitConfig {
                key: RateLimitKey::Header("X-Api-Key".into()),
                average: 1,
                burst: Some(1),
                period: Duration::from_secs(60),
                overrides: std::collections::BTreeMap::new(),
                headers: LimitHeaders::Off,
            },
        );
        let mut a = request("GET", "/", &[("x-api-key", "a")]);
        let mut b = request("GET", "/", &[("x-api-key", "b")]);
        assert_eq!(block_on(mw.request(&mut a, &mut cx())), Flow::Next);
        assert_eq!(block_on(mw.request(&mut b, &mut cx())), Flow::Next);
        assert!(matches!(
            block_on(mw.request(&mut a, &mut cx())),
            Flow::Reply(_)
        ));
    }
}
