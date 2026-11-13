//! `abuse`: counts abuse signals per key and bans keys past a threshold (H-SEC-01, ADR-0031).
//! Counters and bans live in the process-wide [`AbuseRegistry`], so a reload keeps them, and
//! bans are written to the data directory, so a restart or a binary upgrade keeps them.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_limits::abuse::{Abuse, AbuseRegistry, Policy, Recorded};
use rdock_model::middleware::{AbuseAction, AbuseConfig, AbuseEvent, AbuseKey};
use rdock_model::values::IpNetwork;

use crate::phase::{Capabilities, Phases};
use crate::{BuildEnv, Context, Flow, Middleware, ProblemKind, Reply};

/// The key computed in the request phase, for the response phase.
struct RequestKey(String);

/// Longest header value used as a key; longer values are cut.
const MAX_HEADER_KEY: usize = 256;

/// The `abuse` middleware.
#[derive(Debug)]
pub(crate) struct AbuseGuard {
    name: String,
    key: AbuseKey,
    events: Vec<AbuseEvent>,
    action: AbuseAction,
    delay: std::time::Duration,
    held: Arc<tokio::sync::Semaphore>,
    exempt: Vec<IpNetwork>,
    state: Arc<Abuse>,
    metrics: Option<rdock_observability::Metrics>,
}

impl AbuseGuard {
    pub(crate) fn new(name: &str, config: &AbuseConfig, env: &BuildEnv<'_>) -> Self {
        let policy = Policy {
            threshold: config.threshold.max(1),
            window: i64::try_from(config.window.as_std().as_secs().max(1)).unwrap_or(i64::MAX),
            ban: i64::try_from(config.ban.as_std().as_secs().max(1)).unwrap_or(i64::MAX),
            max_keys: usize::try_from(config.max_keys).unwrap_or(usize::MAX),
            max_bans: usize::try_from(config.max_bans).unwrap_or(usize::MAX),
        };
        let state = match env.abuse {
            Some(registry) => registry.get(name, policy),
            None => AbuseRegistry::default().get(name, policy),
        };
        let mut exempt = config.exempt.clone();
        exempt.extend(env.trusted_proxies.iter().copied());
        Self {
            name: name.to_owned(),
            key: config.key.clone(),
            events: config.events.clone(),
            action: config.action,
            delay: config.tarpit.delay.as_std(),
            held: Arc::new(tokio::sync::Semaphore::new(
                usize::try_from(config.tarpit.max_held).unwrap_or(usize::MAX),
            )),
            exempt,
            state,
            metrics: env.metrics.cloned(),
        }
    }

    fn exempt(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.exempt.iter().any(|n| n.contains(&ip))
    }

    /// The key this request counts under.
    fn key(&self, req: &RequestHeader, cx: &Context) -> String {
        match &self.key {
            AbuseKey::ClientIp => client_key(cx.client_ip),
            AbuseKey::Consumer => cx.consumer.as_ref().map_or_else(
                || client_key(cx.client_ip),
                |c| format!("consumer:{}", c.key()),
            ),
            AbuseKey::Ja4 => cx
                .fingerprint
                .as_ref()
                .and_then(|f| f.ja4.as_deref())
                .map_or_else(|| client_key(cx.client_ip), |j| format!("ja4:{j}")),
            AbuseKey::Header(name) => req.headers.get(name.as_str()).map_or_else(
                || client_key(cx.client_ip),
                |v| {
                    let bytes = v.as_bytes();
                    let cut = bytes.get(..MAX_HEADER_KEY).unwrap_or(bytes);
                    format!("header:{}", String::from_utf8_lossy(cut))
                },
            ),
        }
    }

    fn count(&self, action: &str) {
        if let Some(m) = &self.metrics {
            m.abuse_actions
                .with_label_values(&[self.name.as_str(), action])
                .inc();
        }
    }
}

/// The address as rdock compares it: IPv4-mapped IPv6 as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// `ip:192.0.2.1`, or `ip:2001:db8:1:2::/64`: one subscriber usually controls a whole /64
/// (RFC 6177), so a ban by single IPv6 address is trivially evaded.
pub(crate) fn client_key(ip: IpAddr) -> String {
    match canonical(ip) {
        IpAddr::V4(v4) => format!("ip:{v4}"),
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            format!("ip:{}/64", std::net::Ipv6Addr::from(prefix))
        }
    }
}

#[async_trait]
impl Middleware for AbuseGuard {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::REQUEST | Phases::RESPONSE).with_state()
    }

    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        if self.exempt(cx.client_ip) {
            return Flow::Next;
        }
        let key = self.key(req, cx);
        let banned = self.state.banned(&key).is_some();
        cx.set_state(RequestKey(key));
        if !banned {
            return Flow::Next;
        }
        match self.action {
            AbuseAction::Tag => {
                cx.abuse = Some("tagged");
                self.count("tag");
                Flow::Next
            }
            AbuseAction::Deny => {
                cx.abuse = Some("banned");
                self.count("deny");
                Flow::Reply(Reply::problem(ProblemKind::Banned))
            }
            AbuseAction::Tarpit => {
                cx.abuse = Some("tarpit");
                if let Ok(_permit) = self.held.clone().try_acquire_owned() {
                    self.count("tarpit");
                    tokio::time::sleep(self.delay).await;
                } else {
                    // At the cap, denied at once: holding more would cost the proxy more.
                    self.count("deny");
                }
                Flow::Reply(Reply::problem(ProblemKind::Banned))
            }
        }
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        // A request refused or tagged as banned is not counted again.
        if cx.abuse.is_some() || self.exempt(cx.client_ip) {
            return;
        }
        let status = resp.status.as_u16();
        if !self.events.iter().any(|e| e.counts(status, cx.auth_failed)) {
            return;
        }
        let Some(RequestKey(seen)) = cx.take_state::<RequestKey>() else {
            return;
        };
        // An authenticating middleware after this one may have set the consumer since.
        let key = match (&self.key, &cx.consumer) {
            (AbuseKey::Consumer, Some(c)) => format!("consumer:{}", c.key()),
            _ => seen,
        };
        match self.state.record(&key) {
            Recorded::Counted => {}
            Recorded::Banned => {
                self.count("ban");
                tracing::info!(middleware = %self.name, key = %key, "abuse threshold reached; key banned");
            }
            Recorded::Refused => {
                if let Some(m) = &self.metrics {
                    m.abuse_bans_refused.with_label_values(&[&self.name]).inc();
                }
                tracing::warn!(middleware = %self.name, "the ban list is full; a ban was not started");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_keys_group_ipv6_by_64() {
        assert_eq!(client_key("192.0.2.1".parse().unwrap()), "ip:192.0.2.1");
        assert_eq!(
            client_key("2001:db8:1:2:aaaa::1".parse().unwrap()),
            "ip:2001:db8:1:2::/64"
        );
        assert_eq!(
            client_key("2001:db8:1:2:ffff::9".parse().unwrap()),
            client_key("2001:db8:1:2::1".parse().unwrap())
        );
        assert_eq!(
            client_key("::ffff:192.0.2.1".parse().unwrap()),
            "ip:192.0.2.1"
        );
    }
}
