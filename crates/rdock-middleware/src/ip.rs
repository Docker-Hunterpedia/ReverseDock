//! `ip_allow` and `ip_deny`: client networks, using the client IP after trusted-proxy handling.

use async_trait::async_trait;
use pingora::http::RequestHeader;
use rdock_model::middleware::IpListConfig;
use rdock_model::values::IpNetwork;

use crate::{Context, Flow, Middleware, Reply};

/// Allow-list or deny-list of client networks.
#[derive(Debug)]
pub(crate) struct IpFilter {
    networks: Vec<IpNetwork>,
    allow: bool,
}

impl IpFilter {
    pub(crate) fn allow(config: &IpListConfig) -> Self {
        Self {
            networks: config.cidrs.clone(),
            allow: true,
        }
    }

    pub(crate) fn deny(config: &IpListConfig) -> Self {
        Self {
            networks: config.cidrs.clone(),
            allow: false,
        }
    }
}

#[async_trait]
impl Middleware for IpFilter {
    async fn request(&self, _req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let listed = self.networks.iter().any(|n| n.contains(&cx.client_ip));
        if listed == self.allow {
            Flow::Next
        } else {
            Flow::Reply(Reply::status(403))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, request};

    fn config(cidrs: &[&str]) -> IpListConfig {
        IpListConfig {
            cidrs: cidrs.iter().map(|c| c.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn allow_and_deny_lists() {
        let mut req = request("GET", "/", &[]);
        let allow = IpFilter::allow(&config(&["192.0.2.0/24"]));
        assert_eq!(block_on(allow.request(&mut req, &mut cx())), Flow::Next);
        let other = IpFilter::allow(&config(&["10.0.0.0/8", "2001:db8::/32"]));
        assert_eq!(
            block_on(other.request(&mut req, &mut cx())),
            Flow::Reply(Reply::status(403))
        );
        let deny = IpFilter::deny(&config(&["192.0.2.10"]));
        assert_eq!(
            block_on(deny.request(&mut req, &mut cx())),
            Flow::Reply(Reply::status(403))
        );
    }
}
