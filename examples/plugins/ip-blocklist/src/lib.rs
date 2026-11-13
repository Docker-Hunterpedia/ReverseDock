//! `ip-blocklist`: refuses requests from client addresses in a list of networks with `403`.
//! It shows configuration errors with paths (`deny[2]`), per-request state carried from the
//! `request` phase to `log`, and a counter the binary can read.
//!
//! ```yaml
//! middlewares:
//!   blocklist:
//!     type: plugin
//!     name: ip_blocklist
//!     config:
//!       deny: [203.0.113.0/24, "2001:db8:bad::/48", 198.51.100.7]
//!       message: "Your network is blocked.\n"   # optional
//!       status: 403                             # optional, a 4xx
//! ```
//!
//! The address checked is the client address rdock resolved (after `trusted_proxies`), not a
//! header the client controls. The built-in `ip_deny` middleware does the same job; this
//! plugin exists to show how one is written.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rdock_plugin_api::http::StatusCode;
use rdock_plugin_api::{
    Capabilities, ConfigError, Ctx, Decision, Factory, LogSummary, Phases, Plugin, RequestHead,
    Response, async_trait, typed,
};
use serde::Deserialize;

/// The plugin's configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Networks (`203.0.113.0/24`, `2001:db8::/32`) or single addresses.
    pub deny: Vec<String>,
    /// Status of the refusal, a 4xx; `403` by default.
    #[serde(default = "forbidden")]
    pub status: u16,
    /// Body of the refusal; the proxy's standard page when absent.
    #[serde(default)]
    pub message: Option<String>,
}

fn forbidden() -> u16 {
    403
}

/// An IPv4 or IPv6 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    /// Parses `a.b.c.d/len`, `x::y/len` or a single address.
    ///
    /// # Errors
    ///
    /// Not an address, a prefix longer than the address, or host bits set.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("`{text}` is not an IP address or network"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("`{text}`: the prefix length must be 0 to {max}"))?,
        };
        let network = Self { addr, prefix };
        if network.mask(addr) != bits(addr) {
            return Err(format!("`{text}` has host bits set"));
        }
        Ok(network)
    }

    fn mask(&self, ip: IpAddr) -> u128 {
        let max: u32 = if self.addr.is_ipv4() { 32 } else { 128 };
        let host_bits = max - u32::from(self.prefix);
        let mask = if host_bits >= 128 {
            0
        } else {
            u128::MAX << host_bits
        };
        bits(ip) & mask
    }

    /// Whether `ip` is in this network (IPv4-mapped IPv6 addresses count as IPv4).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        ip.is_ipv4() == self.addr.is_ipv4() && self.mask(ip) == bits(self.addr)
    }
}

fn bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// What the `request` phase leaves in the state for `log`: the network that matched.
#[derive(Debug, Clone, Copy)]
struct Blocked(Network);

/// The plugin.
#[derive(Debug)]
pub struct IpBlocklist {
    deny: Vec<Network>,
    status: StatusCode,
    message: Option<String>,
    blocked: Arc<AtomicU64>,
    last: Mutex<Option<Network>>,
}

/// The factory to register: `Registry::new().plugin("ip_blocklist", ip_blocklist::factory())`.
pub fn factory() -> impl Factory {
    typed(IpBlocklist::new)
}

impl IpBlocklist {
    /// Checks `config` and builds the plugin.
    ///
    /// # Errors
    ///
    /// An empty list, an invalid network (reported at `deny[i]`), or a status that is not a
    /// 4xx.
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        let mut errors = ConfigError::empty();
        let mut deny = Vec::new();
        for (i, text) in config.deny.iter().enumerate() {
            match Network::parse(text) {
                Ok(network) => deny.push(network),
                Err(message) => errors.push(ConfigError::at(format!("deny[{i}]"), message)),
            }
        }
        if config.deny.is_empty() {
            errors.push(ConfigError::at(
                "deny",
                "list at least one network or address",
            ));
        }
        let status = StatusCode::from_u16(config.status)
            .ok()
            .filter(StatusCode::is_client_error);
        if status.is_none() {
            errors.push(
                ConfigError::at("status", format!("{} is not a 4xx status", config.status))
                    .with_hint("403 is usual"),
            );
        }
        errors.into_result(Self {
            deny,
            status: status.unwrap_or(StatusCode::FORBIDDEN),
            message: config.message,
            blocked: Arc::default(),
            last: Mutex::new(None),
        })
    }

    /// Requests refused so far, across every route that uses this instance.
    #[must_use]
    pub fn blocked(&self) -> u64 {
        self.blocked.load(Ordering::Relaxed)
    }

    /// The network that matched the last refused request.
    #[must_use]
    pub fn last_blocked(&self) -> Option<Network> {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl Plugin for IpBlocklist {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::REQUEST | Phases::LOG).with_state()
    }

    async fn request(&self, _req: &mut RequestHead, cx: &mut Ctx<'_>) -> Decision {
        let client = cx.client_ip();
        let Some(network) = self.deny.iter().find(|n| n.contains(client)) else {
            return Decision::Continue;
        };
        cx.set_state(Blocked(*network));
        let response = match &self.message {
            Some(message) => Response::text(self.status, message.clone()),
            None => Response::new(self.status),
        };
        Decision::Respond(response)
    }

    fn log(&self, _summary: &LogSummary, cx: &Ctx<'_>) {
        if let Some(Blocked(network)) = cx.state::<Blocked>() {
            self.blocked.fetch_add(1, Ordering::Relaxed);
            *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(*network);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use rdock_plugin_api::serde_json::json;
    use rdock_plugin_api::testing::{Harness, block_on, request, response};

    use super::*;

    #[test]
    fn networks_parse_and_match() {
        let net = Network::parse("203.0.113.0/24").unwrap();
        assert!(net.contains("203.0.113.9".parse().unwrap()));
        assert!(
            net.contains("::ffff:203.0.113.9".parse().unwrap()),
            "mapped IPv4"
        );
        assert!(!net.contains("203.0.114.1".parse().unwrap()));
        assert!(!net.contains("2001:db8::1".parse().unwrap()));
        let v6 = Network::parse("2001:db8:bad::/48").unwrap();
        assert!(v6.contains("2001:db8:bad:1::5".parse().unwrap()));
        assert!(!v6.contains("2001:db8:bae::1".parse().unwrap()));
        assert!(
            Network::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        let single = Network::parse("198.51.100.7").unwrap();
        assert!(single.contains("198.51.100.7".parse().unwrap()));
        assert!(!single.contains("198.51.100.8".parse().unwrap()));
        assert!(Network::parse("10.0.0.1/8").is_err(), "host bits");
        assert!(Network::parse("10.0.0.0/33").is_err());
        assert!(Network::parse("ten").is_err());
    }

    #[test]
    fn refuses_listed_clients_and_counts_them_in_log() {
        let plugin = IpBlocklist::new(Config {
            deny: vec!["203.0.113.0/24".into()],
            status: 403,
            message: Some("blocked\n".into()),
        })
        .unwrap();
        let plugin = Arc::new(plugin);
        let mut blocked =
            Harness::from_arc(plugin.clone()).client_ip("203.0.113.50".parse().unwrap());
        let outcome = block_on(blocked.run(request("GET", "/"), None, response(StatusCode::OK)));
        let answer = outcome.answered.expect("refused");
        assert_eq!(answer.status(), StatusCode::FORBIDDEN);
        assert_eq!(answer.body().map(|b| &b[..]), Some(&b"blocked\n"[..]));
        assert_eq!(plugin.blocked(), 1, "state reached the log phase");
        assert_eq!(plugin.last_blocked(), Network::parse("203.0.113.0/24").ok());

        let mut allowed = Harness::from_factory(&factory(), &json!({ "deny": ["203.0.113.0/24"] }))
            .unwrap()
            .client_ip("192.0.2.1".parse().unwrap());
        let outcome = block_on(allowed.run(request("GET", "/"), None, response(StatusCode::OK)));
        assert!(outcome.answered.is_none());
        assert_eq!(outcome.response.status(), StatusCode::OK);
    }

    #[test]
    fn configuration_errors_point_at_the_entry() {
        let err = Harness::from_factory(
            &factory(),
            &json!({ "deny": ["10.0.0.0/8", "10.1.2.3/8", "nope"], "status": 500 }),
        )
        .unwrap_err();
        let issues: Vec<(&str, &str)> = err
            .issues()
            .iter()
            .map(|i| (i.path.as_str(), i.message.as_str()))
            .collect();
        assert_eq!(
            issues,
            [
                ("deny[1]", "`10.1.2.3/8` has host bits set"),
                ("deny[2]", "`nope` is not an IP address or network"),
                ("status", "500 is not a 4xx status"),
            ]
        );
        let err = Harness::from_factory(&factory(), &json!({ "deny": [] })).unwrap_err();
        assert_eq!(err.issues()[0].path, "deny");
        let err = Harness::from_factory(&factory(), &json!({})).unwrap_err();
        assert!(err.to_string().contains("missing field `deny`"), "{err}");
        let err =
            Harness::from_factory(&factory(), &json!({ "deny": ["10.0.0.0/8", 7] })).unwrap_err();
        assert_eq!(
            err.issues()[0].path,
            "deny[1]",
            "type errors carry the path"
        );
    }
}
