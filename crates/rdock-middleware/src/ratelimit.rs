//! `rate_limit`: token buckets per client IP, route, consumer, header or cookie value, with
//! per-group limits for consumers (F-GW-02) and the draft `RateLimit` headers on request.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_limits::shared::{Budget, SharedLimits, Take, WindowKind};
use rdock_limits::{Decision, RateLimiter};
use rdock_model::gateway::LimitHeaders;
use rdock_model::middleware::{LimitScope, RateLimitConfig};
use rdock_model::values::RateLimitKey;

use crate::phase::{Capabilities, Phases};
use crate::{Context, Flow, Middleware, ProblemKind, Reply};

use crate::limits::MAX_KEYS;

/// One limit: its bucket set, its share of a cluster-wide budget with `scope: cluster`, and
/// what `RateLimit-Policy` says about it.
#[derive(Debug)]
struct Limit {
    limiter: RateLimiter,
    average: u32,
    period_secs: u64,
    cluster: Option<Arc<Budget>>,
}

impl Limit {
    fn new(
        average: u32,
        period: std::time::Duration,
        burst: u32,
        cluster: Option<(&SharedLimits, String)>,
    ) -> Self {
        Self {
            limiter: RateLimiter::new(average, period, burst, MAX_KEYS),
            average,
            period_secs: period.as_secs().max(1),
            cluster: cluster.map(|(shared, id)| shared.budget(&id, WindowKind::Fixed(period))),
        }
    }
}

/// A store-safe, collision-free budget id for middleware `name` (and `group`).
pub(crate) fn budget_id(kind: &str, name: &str, group: Option<&str>) -> String {
    use std::fmt::Write as _;
    let full = match group {
        Some(g) => format!("{name}\u{0}{g}"),
        None => name.to_owned(),
    };
    let readable: String = full
        .chars()
        .take(40)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let digest = ring::digest::digest(&ring::digest::SHA256, full.as_bytes());
    let mut id = format!("{kind}-{readable}-");
    for b in &digest.as_ref()[..4] {
        let _ = write!(id, "{b:02x}");
    }
    id
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
    pub(crate) fn new(name: &str, config: &RateLimitConfig, shared: Option<&SharedLimits>) -> Self {
        let period = config.period.as_std();
        let shared = shared.filter(|_| config.scope == LimitScope::Cluster);
        Self {
            name: name.to_owned(),
            key: config.key.clone(),
            default: Limit::new(
                config.average,
                period,
                config.burst.unwrap_or(config.average),
                shared.map(|s| (s, budget_id("rl", name, None))),
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
                            shared.map(|s| (s, budget_id("rl", name, Some(group)))),
                        ),
                    )
                })
                .collect(),
            headers: config.headers,
        }
    }

    /// The limit for this request: with `key: consumer`, the first of the consumer's groups
    /// with an override; with `key: group`, the primary group's override.
    fn limit(&self, cx: &Context) -> &Limit {
        if self.key == RateLimitKey::Group
            && let Some(primary) = cx
                .consumer
                .as_ref()
                .and_then(crate::Consumer::primary_group)
        {
            if let Some((_, limit)) = self.overrides.iter().find(|(g, _)| **g == **primary) {
                return limit;
            }
            return &self.default;
        }
        if self.key == RateLimitKey::Consumer
            && let Some(consumer) = &cx.consumer
        {
            for group in consumer.counted_groups() {
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
        let (mut decision, remaining, full) = limit.limiter.check_remaining(&key, now);
        if decision == Decision::Allow
            && let Some(budget) = limit.cluster.as_ref().filter(|b| b.attached())
            && let Take::Exceeded { reset } =
                budget.take(&String::from_utf8_lossy(&key), u64::from(limit.average))
        {
            decision = Decision::Deny {
                retry_after: std::time::Duration::from_secs(reset),
            };
        }
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
                scope: rdock_model::middleware::LimitScope::Instance,
            },
            None,
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
    fn cluster_scope_uses_the_shared_budget_once_a_driver_is_attached() {
        let config = RateLimitConfig {
            key: RateLimitKey::ClientIp,
            average: 10,
            burst: Some(100),
            period: Duration::from_secs(3600),
            overrides: std::collections::BTreeMap::new(),
            headers: LimitHeaders::Off,
            scope: LimitScope::Cluster,
        };
        let shared = SharedLimits::default();
        let mw = RateLimit::new("rl", &config, Some(&shared));
        let admitted = |mw: &RateLimit| {
            (0..50)
                .filter(|_| {
                    let mut req = request("GET", "/", &[]);
                    block_on(mw.request(&mut req, &mut cx())) == Flow::Next
                })
                .count()
        };
        // No driver: counted per instance (the token bucket's burst of 100).
        assert_eq!(admitted(&mw), 50);
        // A driver whose store is away, two members: the share ⌈10 / 2⌉, then 429 with the
        // window's reset as Retry-After.
        shared.attach();
        shared.set_members(2);
        let mw = RateLimit::new("rl2", &config, Some(&shared));
        assert_eq!(admitted(&mw), 5);
        let mut req = request("GET", "/", &[]);
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx())) else {
            panic!("over the share must be limited")
        };
        assert_eq!(reply.status, 429);
        let seconds: u64 = reply_header(&reply, "retry-after")
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=3600).contains(&seconds), "{seconds}");
        // `scope: instance` ignores the shared budgets.
        let local = RateLimit::new(
            "rl3",
            &RateLimitConfig {
                scope: LimitScope::Instance,
                ..config
            },
            Some(&shared),
        );
        assert_eq!(admitted(&local), 50);
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
                scope: rdock_model::middleware::LimitScope::Instance,
            },
            None,
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

    fn member(name: &str, groups: &[&str]) -> Context {
        let mut c = cx();
        c.consumer = Some(crate::Consumer::configured(name, groups));
        c
    }

    #[test]
    fn group_keys_share_one_bucket_per_primary_group_with_its_override() {
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert(
            "gold".to_owned(),
            rdock_model::gateway::RateOverride {
                average: 3,
                burst: Some(3),
                period: None,
            },
        );
        let config = RateLimitConfig {
            key: RateLimitKey::Group,
            average: 2,
            burst: Some(2),
            period: Duration::from_secs(3600),
            overrides,
            headers: LimitHeaders::Off,
            scope: LimitScope::Instance,
        };
        let mw = RateLimit::new("rl", &config, None);
        let pass = |c: &mut Context| {
            let mut req = request("GET", "/", &[]);
            block_on(mw.request(&mut req, c)) == Flow::Next
        };
        // Ann and Bob are both in `acme` first: two requests between them.
        assert!(pass(&mut member("ann", &["acme", "gold"])));
        assert!(pass(&mut member("bob", &["acme"])));
        assert!(
            !pass(&mut member("ann", &["acme", "gold"])),
            "acme's 2 are used"
        );
        // `gold` first: its override (3), its own bucket.
        for _ in 0..3 {
            assert!(pass(&mut member("cy", &["gold", "acme"])));
        }
        assert!(!pass(&mut member("dee", &["gold"])));
        // No group: counted per consumer; no consumer: per address.
        assert!(pass(&mut member("solo", &[])));
        assert!(pass(&mut member("solo", &[])));
        assert!(!pass(&mut member("solo", &[])));
        assert!(pass(&mut cx()));
    }

    #[test]
    fn group_keys_work_with_cluster_scope() {
        let config = RateLimitConfig {
            key: RateLimitKey::Group,
            average: 4,
            burst: Some(100),
            period: Duration::from_secs(3600),
            overrides: std::collections::BTreeMap::new(),
            headers: LimitHeaders::Off,
            scope: LimitScope::Cluster,
        };
        let shared = SharedLimits::default();
        shared.attach();
        shared.set_members(2);
        let mw = RateLimit::new("rlg", &config, Some(&shared));
        let admitted = |name: &str, group: &str| {
            (0..10)
                .filter(|_| {
                    let mut req = request("GET", "/", &[]);
                    block_on(mw.request(&mut req, &mut member(name, &[group]))) == Flow::Next
                })
                .count()
        };
        // Store away, two members: each group gets the share ⌈4 / 2⌉ on this instance.
        assert_eq!(admitted("ann", "acme") + admitted("bob", "acme"), 2);
        assert_eq!(admitted("cy", "globex"), 2);
    }
}
