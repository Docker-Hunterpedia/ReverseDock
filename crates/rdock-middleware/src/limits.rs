//! `in_flight` (requests in flight per key, with a queue) and `bandwidth` (response bytes per
//! second per key), and the request key that all limits share.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::RequestHeader;
use rdock_limits::{ByteLimiter, ConcurrencyLimiter, Refused};
use rdock_model::middleware::{BandwidthConfig, InFlightConfig};
use rdock_model::values::{ByteSize, RateLimitKey};

use crate::{Context, Flow, Middleware, Reply};

/// Keys tracked per limit middleware.
pub(crate) const MAX_KEYS: usize = 65_536;

/// The bytes a limit counts by. A missing header or cookie gives an empty key, so such
/// requests share one bucket (Traefik does the same for `requestHeaderName`).
pub(crate) fn key_of(key: &RateLimitKey, req: &RequestHeader, cx: &Context) -> Vec<u8> {
    match key {
        RateLimitKey::ClientIp => cx.client_ip.to_string().into_bytes(),
        RateLimitKey::Route => cx.route.as_bytes().to_vec(),
        RateLimitKey::Header(name) => req
            .headers
            .get(name.as_str())
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default(),
        RateLimitKey::Cookie(name) => cookie(req, name)
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default(),
    }
}

/// The value of cookie `name`.
pub(crate) fn cookie<'a>(req: &'a RequestHeader, name: &str) -> Option<&'a str> {
    req.headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.trim_matches('"'))
}

fn too_many(retry_after: u64) -> Flow {
    Flow::Reply(
        Reply::status(429).header(http::header::RETRY_AFTER, HeaderValue::from(retry_after)),
    )
}

/// The `in_flight` middleware.
#[derive(Debug)]
pub(crate) struct InFlight {
    key: RateLimitKey,
    limiter: ConcurrencyLimiter,
}

impl InFlight {
    pub(crate) fn new(config: &InFlightConfig) -> Self {
        Self {
            key: config.key.clone(),
            limiter: ConcurrencyLimiter::new(
                config.amount,
                config.queue,
                config.queue_timeout.as_std(),
                MAX_KEYS,
            ),
        }
    }
}

#[async_trait]
impl Middleware for InFlight {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let key = key_of(&self.key, req, cx);
        match self.limiter.admit(&key).await {
            Ok(admitted) => {
                // Held until the request ends, when the context is dropped.
                cx.admitted.push(admitted);
                Flow::Next
            }
            Err(Refused::Full | Refused::Timeout) => too_many(1),
        }
    }
}

/// The `bandwidth` middleware.
#[derive(Debug)]
pub(crate) struct Bandwidth {
    key: RateLimitKey,
    limiter: Arc<ByteLimiter>,
}

impl Bandwidth {
    pub(crate) fn new(config: &BandwidthConfig) -> Self {
        let rate = config.rate.as_u64();
        Self {
            key: config.key.clone(),
            limiter: Arc::new(ByteLimiter::new(
                rate,
                config.burst.map_or(rate, ByteSize::as_u64),
                MAX_KEYS,
            )),
        }
    }
}

#[async_trait]
impl Middleware for Bandwidth {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        // The proxy feeds every response chunk through the limiter and waits as told.
        cx.throttle = Some(Throttle {
            limiter: self.limiter.clone(),
            key: key_of(&self.key, req, cx),
        });
        Flow::Next
    }
}

/// The byte limiter and key of a request with `bandwidth`.
#[derive(Debug)]
pub struct Throttle {
    limiter: Arc<ByteLimiter>,
    key: Vec<u8>,
}

impl Throttle {
    /// Records `bytes` sent; returns how long to wait before the next chunk.
    #[must_use]
    pub fn take(&self, bytes: usize) -> Duration {
        self.limiter
            .take(&self.key, bytes, std::time::Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, request};

    #[test]
    fn keys_cover_every_kind() {
        let req = request(
            "GET",
            "/",
            &[("x-api-key", "k1"), ("cookie", "a=1; sid=\"s9\"")],
        );
        let c = cx();
        assert_eq!(key_of(&RateLimitKey::ClientIp, &req, &c), b"192.0.2.10");
        assert_eq!(key_of(&RateLimitKey::Route, &req, &c), b"route");
        assert_eq!(
            key_of(&RateLimitKey::Header("x-api-key".into()), &req, &c),
            b"k1"
        );
        assert_eq!(key_of(&RateLimitKey::Cookie("sid".into()), &req, &c), b"s9");
        assert_eq!(
            key_of(&RateLimitKey::Cookie("none".into()), &req, &c),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn in_flight_refuses_over_the_limit_and_frees_on_drop() {
        let mw = InFlight::new(&InFlightConfig {
            amount: 1,
            key: RateLimitKey::ClientIp,
            queue: 0,
            queue_timeout: rdock_model::values::Duration::from_secs(1),
        });
        let mut first = cx();
        let mut req = request("GET", "/", &[]);
        assert!(matches!(
            block_on(mw.request(&mut req, &mut first)),
            Flow::Next
        ));
        let mut second = cx();
        assert!(matches!(
            block_on(mw.request(&mut req, &mut second)),
            Flow::Reply(_)
        ));
        drop(first);
        let mut third = cx();
        assert!(matches!(
            block_on(mw.request(&mut req, &mut third)),
            Flow::Next
        ));
    }

    #[test]
    fn bandwidth_sets_a_throttle() {
        let mw = Bandwidth::new(&BandwidthConfig {
            rate: ByteSize::kib(1),
            burst: None,
            key: RateLimitKey::ClientIp,
        });
        let mut c = cx();
        let mut req = request("GET", "/", &[]);
        block_on(mw.request(&mut req, &mut c));
        let throttle = c.throttle.as_ref().unwrap();
        assert_eq!(throttle.take(1024), Duration::ZERO);
        // Real time passes between the two calls, so the wait is just under 500 ms.
        let wait = throttle.take(512);
        assert!(
            wait > Duration::from_millis(450) && wait <= Duration::from_millis(500),
            "{wait:?}"
        );
    }
}
