//! `rate_limit`: token buckets per client IP, per route or per header value.

use std::time::Instant;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::RequestHeader;
use rdock_limits::{Decision, RateLimiter};
use rdock_model::middleware::RateLimitConfig;
use rdock_model::values::RateLimitKey;

use crate::{Context, Flow, Middleware, Reply};

/// Keys tracked per rate-limit middleware.
const MAX_KEYS: usize = 65_536;

/// The `rate_limit` middleware.
#[derive(Debug)]
pub(crate) struct RateLimit {
    name: String,
    key: RateLimitKey,
    limiter: RateLimiter,
}

impl RateLimit {
    pub(crate) fn new(name: &str, config: &RateLimitConfig) -> Self {
        Self {
            name: name.to_owned(),
            key: config.key.clone(),
            limiter: RateLimiter::new(
                config.average,
                config.period.as_std(),
                config.burst.unwrap_or(config.average),
                MAX_KEYS,
            ),
        }
    }
}

#[async_trait]
impl Middleware for RateLimit {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let now = Instant::now();
        let decision = match &self.key {
            RateLimitKey::ClientIp => self.limiter.check(&cx.client_ip, now),
            RateLimitKey::Route => self.limiter.check(&*cx.route, now),
            RateLimitKey::Header(name) => {
                // A missing header shares one bucket, like Traefik's `requestHeaderName`.
                let value = req.headers.get(name.as_str()).map(HeaderValue::as_bytes);
                self.limiter.check(&value, now)
            }
        };
        match decision {
            Decision::Allow => Flow::Next,
            Decision::Deny { retry_after } => {
                tracing::debug!(middleware = %self.name, "rate limit exceeded");
                let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
                Flow::Reply(
                    Reply::status(429)
                        .header(http::header::RETRY_AFTER, HeaderValue::from(seconds.max(1))),
                )
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
