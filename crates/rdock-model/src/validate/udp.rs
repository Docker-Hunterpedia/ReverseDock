//! UDP listeners, routes and services (M-L4-04, ADR-0030).

use std::collections::BTreeMap;

use rdock_rules::Context;

use super::{Validator, protocol_name, reference_key};
use crate::config::ListenerProtocol;
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::middleware::Middleware;
use crate::route::UdpRoute;
use crate::values::BackendAddress;

impl Validator<'_> {
    pub(super) fn check_udp(&mut self) {
        self.check_udp_listeners();
        // Listener → the enabled routes without `match` on it, in name order.
        let mut catch_all: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, route) in &self.config.udp_routes {
            let path = path_key("udp_routes", name);
            self.check_name("udp_routes", name);
            if let Some(rule) = &route.matcher {
                self.parse_udp_match(&path, rule);
            }
            self.check_udp_route_listeners(&path, route);
            self.check_reference(
                &format!("{path}.service"),
                "UDP service",
                &route.service,
                &self.config.udp_services,
            );
            self.check_udp_middlewares(&path, route);
            if route.matcher.is_none() && route.enabled {
                for listener in route.listeners.iter().flatten() {
                    catch_all
                        .entry(listener.clone())
                        .or_default()
                        .push(name.clone());
                }
            }
        }
        for (listener, routes) in catch_all {
            if let [first, rest @ ..] = routes.as_slice() {
                for other in rest {
                    self.push(
                        Diagnostic::error(
                            format!("{}.match", path_key("udp_routes", other)),
                            format!(
                                "listener `{listener}` already sends every datagram to UDP route `{first}`; a listener has at most one route without `match`"
                            ),
                        )
                        .with_hint("give one of the routes a ``ClientIP(`…`)`` rule, or attach it to another listener"),
                    );
                }
            }
        }
        self.check_udp_services();
    }

    /// Settings that only `udp` listeners have, or that they do not.
    fn check_udp_listeners(&mut self) {
        let listeners: Vec<(String, ListenerProtocol, bool, bool)> = self
            .listeners
            .iter()
            .map(|(name, l)| {
                (
                    name.clone(),
                    l.effective_protocol(),
                    l.sessions.is_some(),
                    l.ping.is_some(),
                )
            })
            .collect();
        for (name, protocol, sessions, ping) in listeners {
            let path = path_key("listeners", &name);
            let udp = protocol == ListenerProtocol::Udp;
            if sessions && !udp {
                self.error(
                    format!("{path}.sessions"),
                    format!(
                        "only `udp` listeners have sessions; this one is `{}`",
                        protocol_name(protocol)
                    ),
                );
            }
            if ping && udp {
                self.error(
                    format!("{path}.ping"),
                    "a `udp` listener answers no HTTP requests",
                );
            }
        }
    }

    fn parse_udp_match(&mut self, path: &str, rule: &str) {
        match rdock_rules::parse(rule) {
            Ok(expr) => {
                for err in expr.validate(Context::Udp) {
                    self.error(format!("{path}.match"), err.to_string());
                }
            }
            Err(err) => {
                self.push(
                    Diagnostic::error(
                        format!("{path}.match"),
                        format!("invalid rule: {}", err.kind),
                    )
                    .with_hint(err.render(rule)),
                );
            }
        }
    }

    fn check_udp_route_listeners(&mut self, path: &str, route: &UdpRoute) {
        let Some(listeners) = &route.listeners else {
            self.push(
                Diagnostic::error(format!("{path}.listeners"), "UDP routes need `listeners`")
                    .with_hint("name a listener with `protocol: udp`"),
            );
            return;
        };
        if listeners.is_empty() {
            self.error(format!("{path}.listeners"), "name at least one listener");
        }
        for (i, name) in listeners.iter().enumerate() {
            let p = path_index(&format!("{path}.listeners"), i);
            match self
                .listeners
                .get(name)
                .map(crate::config::Listener::effective_protocol)
            {
                None => self.error(p, format!("listener `{name}` does not exist")),
                Some(ListenerProtocol::Udp) => {}
                Some(other) => self.error(
                    p,
                    format!(
                        "listener `{name}` is `{}`; UDP routes need a udp listener",
                        protocol_name(other)
                    ),
                ),
            }
        }
    }

    fn check_udp_middlewares(&mut self, path: &str, route: &UdpRoute) {
        for (i, reference) in route.middlewares.iter().enumerate() {
            let p = path_index(&format!("{path}.middlewares"), i);
            self.check_reference(&p, "middleware", reference, &self.config.middlewares);
            match self.config.middlewares.get(reference_key(reference)) {
                None | Some(Middleware::IpAllow(_) | Middleware::IpDeny(_)) => {}
                Some(Middleware::InFlight(_)) => self.push(
                    Diagnostic::error(
                        p,
                        "`in_flight` does not apply to UDP routes",
                    )
                    .with_hint("sessions per client are capped by the listener's `sessions.max_per_client`"),
                ),
                Some(_) => self.push(
                    Diagnostic::error(
                        p,
                        format!("middleware `{reference}` does not apply to UDP routes"),
                    )
                    .with_hint("UDP routes accept `ip_allow` and `ip_deny`"),
                ),
            }
        }
    }

    fn check_udp_services(&mut self) {
        for (name, service) in &self.config.udp_services {
            let path = path_key("udp_services", name);
            self.check_name("udp_services", name);
            let backends = format!("{path}.backends");
            if service.backends.is_empty() {
                self.error(&backends, "the service has no backends");
            }
            self.check_backend_tiers(&path, &service.backends, true);
            for (i, backend) in service.backends.iter().enumerate() {
                let p = path_index(&backends, i);
                if backend.weight == 0 {
                    self.error(format!("{p}.weight"), "weight must be at least 1");
                }
                if let BackendAddress::Unix(_) = backend.address {
                    self.error(
                        format!("{p}.address"),
                        "UDP backends are `host:port` addresses; Unix sockets are not supported",
                    );
                }
            }
            self.check_not_zero(
                &format!("{path}.timeouts.idle"),
                service.timeouts.idle.is_zero(),
            );
            for (field, value) in [
                ("responses", service.responses),
                ("requests", service.requests),
            ] {
                if value == Some(0) {
                    self.push(
                        Diagnostic::error(format!("{path}.{field}"), "must be at least 1")
                            .with_hint("omit it to end sessions only when they are idle"),
                    );
                }
            }
            let passive = &service.health.passive;
            if passive.enabled {
                if passive.failures == 0 {
                    self.error(
                        format!("{path}.health.passive.failures"),
                        "must be at least 1",
                    );
                }
                if passive.max_ejection_percent > 100 {
                    self.error(
                        format!("{path}.health.passive.max_ejection_percent"),
                        "a percentage is at most 100",
                    );
                }
                self.check_not_zero(
                    &format!("{path}.health.passive.window"),
                    passive.window.is_zero(),
                );
                self.check_not_zero(
                    &format!("{path}.health.passive.ejection"),
                    passive.ejection.is_zero(),
                );
            }
            if let Some(check) = &service.health.tcp_check {
                let p = format!("{path}.health.tcp_check");
                self.check_not_zero(&format!("{p}.interval"), check.interval.is_zero());
                self.check_not_zero(&format!("{p}.timeout"), check.timeout.is_zero());
                if check.port == Some(0) {
                    self.error(format!("{p}.port"), "port 0 cannot be probed");
                }
                for (field, value) in [("healthy", check.healthy), ("unhealthy", check.unhealthy)] {
                    if value == 0 {
                        self.error(format!("{p}.{field}"), "must be at least 1");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::{Value, json};

    use crate::{Config, Diagnostic};

    fn errors(value: Value) -> Vec<(String, String)> {
        let config: Config = serde_json::from_value(value).unwrap();
        config
            .validate()
            .into_iter()
            .filter(Diagnostic::is_error)
            .map(|d| (d.path, d.message))
            .collect()
    }

    fn has(found: &[(String, String)], path: &str, fragment: &str) -> bool {
        found.iter().any(|(p, m)| p == path && m.contains(fragment))
    }

    fn base() -> Value {
        json!({
            "listeners": {
                "dns": { "address": ":53", "protocol": "udp" },
                "dns-tcp": { "address": ":53", "protocol": "tcp" },
                "web": { "address": ":80" }
            },
            "udp_routes": { "dns": { "listeners": ["dns"], "service": "dns" } },
            "udp_services": { "dns": { "backends": [{ "address": "10.0.0.53:53" }] } }
        })
    }

    #[test]
    fn a_plain_udp_configuration_is_valid_and_shares_a_port_with_tcp() {
        assert_eq!(errors(base()), Vec::new());
        let config: Config = serde_json::from_value(base()).unwrap();
        let service = &config.udp_services["dns"];
        assert_eq!(service.timeouts.idle.as_std().as_secs(), 60);
        assert_eq!(service.responses, None);
        assert!(service.health.passive.enabled);
        let sessions = config.listeners["dns"].sessions.unwrap_or_default();
        assert_eq!(sessions.max.get(), Some(4096));
        assert_eq!(sessions.max_per_client.get(), Some(64));
    }

    #[test]
    fn routes_need_udp_listeners_client_ip_rules_and_ip_middlewares() {
        let mut value = base();
        value["udp_routes"]["bad"] = json!({
            "match": "HostSNI(`*`)",
            "listeners": ["web", "nope"],
            "service": "missing",
            "middlewares": ["limit", "auth"]
        });
        value["udp_routes"]["unattached"] = json!({ "service": "dns" });
        value["middlewares"] = json!({
            "limit": { "type": "in_flight", "amount": 1 },
            "auth": { "type": "basic_auth", "users": ["u:$2y$05$abcdefghijklmnopqrstuu"] }
        });
        let found = errors(value);
        assert!(
            has(&found, "udp_routes.bad.match", "ClientIP only"),
            "{found:?}"
        );
        assert!(has(&found, "udp_routes.bad.listeners[0]", "is `http`"));
        assert!(has(&found, "udp_routes.bad.listeners[1]", "does not exist"));
        assert!(has(&found, "udp_routes.bad.service", "missing"));
        assert!(has(
            &found,
            "udp_routes.bad.middlewares[0]",
            "`in_flight` does not apply"
        ));
        assert!(has(
            &found,
            "udp_routes.bad.middlewares[1]",
            "does not apply to UDP"
        ));
        assert!(has(
            &found,
            "udp_routes.unattached.listeners",
            "need `listeners`"
        ));
    }

    #[test]
    fn a_listener_has_at_most_one_route_without_match() {
        let mut value = base();
        value["udp_routes"]["second"] = json!({ "listeners": ["dns"], "service": "dns" });
        value["udp_routes"]["lan"] =
            json!({ "match": "ClientIP(`10.0.0.0/8`)", "listeners": ["dns"], "service": "dns" });
        value["udp_routes"]["off"] =
            json!({ "listeners": ["dns"], "service": "dns", "enabled": false });
        let found = errors(value);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(has(
            &found,
            "udp_routes.second.match",
            "already sends every datagram to UDP route `dns`"
        ));
    }

    #[test]
    fn services_and_listener_settings_are_checked() {
        let mut value = base();
        value["udp_services"]["bad"] = json!({
            "backends": [{ "address": "unix:///run/x.sock", "weight": 0 }],
            "timeouts": { "idle": "0s" },
            "responses": 0,
            "requests": 0,
            "health": {
                "passive": { "failures": 0, "max_ejection_percent": 101 },
                "tcp_check": { "port": 0, "healthy": 0 }
            }
        });
        value["udp_services"]["backups"] =
            json!({ "backends": [{ "address": "a:53", "backup": true }] });
        value["listeners"]["web"]["sessions"] = json!({ "max": 10 });
        value["listeners"]["dns"]["ping"] = json!("/ping");
        let found = errors(value);
        for (path, fragment) in [
            ("udp_services.bad.backends[0].weight", "at least 1"),
            ("udp_services.bad.backends[0].address", "Unix sockets"),
            ("udp_services.bad.timeouts.idle", ""),
            ("udp_services.bad.responses", "at least 1"),
            ("udp_services.bad.requests", "at least 1"),
            ("udp_services.bad.health.passive.failures", "at least 1"),
            (
                "udp_services.bad.health.passive.max_ejection_percent",
                "at most 100",
            ),
            ("udp_services.bad.health.tcp_check.port", "port 0"),
            ("udp_services.bad.health.tcp_check.healthy", "at least 1"),
            ("udp_services.backups.backends", "every backend is a backup"),
            ("listeners.web.sessions", "only `udp` listeners"),
            ("listeners.dns.ping", "answers no HTTP"),
        ] {
            assert!(has(&found, path, fragment), "{path}: {found:?}");
        }
        let mut tls = base();
        tls["listeners"]["dns"]["tls"] = json!({});
        assert!(has(
            &errors(tls),
            "listeners.dns.tls",
            "cannot terminate TLS"
        ));
    }

    #[test]
    fn session_caps_take_a_number_or_unlimited() {
        let caps = |v: Value| serde_json::from_value::<crate::config::UdpSessions>(v);
        let parsed = caps(json!({ "max": "unlimited", "max_per_client": 5 })).unwrap();
        assert_eq!(parsed.max.get(), None);
        assert_eq!(parsed.max_per_client.get(), Some(5));
        assert_eq!(
            serde_json::to_value(parsed).unwrap(),
            json!({ "max": "unlimited", "max_per_client": 5 })
        );
        for bad in [
            json!({ "max": 0 }),
            json!({ "max": "none" }),
            json!({ "max": -1 }),
        ] {
            assert!(caps(bad.clone()).is_err(), "{bad}");
        }
    }
}
