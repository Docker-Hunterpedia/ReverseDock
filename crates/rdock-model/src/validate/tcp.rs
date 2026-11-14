//! TCP routes and services (M-L4-01, M-L4-02, ADR-0026).

use rdock_rules::{Context, Expr};

use super::{Validator, protocol_name, reference_key};
use crate::config::ListenerProtocol;
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::middleware::Middleware;
use crate::route::TcpRoute;
use crate::values::{BackendAddress, RateLimitKey};

/// Well-known ports of protocols that negotiate TLS inside the protocol (the server speaks
/// first, or the client asks with STARTTLS): no ClientHello arrives first, so neither SNI
/// routing nor termination can work for them.
const NEGOTIATED_TLS_PORTS: [(u16, &str); 5] = [
    (25, "SMTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (587, "SMTP submission"),
    (3306, "MySQL"),
];

impl Validator<'_> {
    pub(super) fn check_tcp(&mut self) {
        for (name, route) in &self.config.tcp_routes {
            let path = path_key("tcp_routes", name);
            self.check_name("tcp_routes", name);
            let expr = self.parse_tcp_match(&path, &route.matcher);
            self.check_tcp_listeners(&path, route, expr.as_ref());
            self.check_reference(
                &format!("{path}.service"),
                "TCP service",
                &route.service,
                &self.config.tcp_services,
            );
            self.check_tcp_middlewares(&path, route);
            let needs_hello =
                route.tls.is_some() || expr.as_ref().is_some_and(Expr::reads_client_hello);
            if needs_hello {
                self.check_negotiated_tls(&path, route);
            }
        }
        for (name, service) in &self.config.tcp_services {
            let path = path_key("tcp_services", name);
            self.check_name("tcp_services", name);
            if service.backends.is_empty() {
                self.error(format!("{path}.backends"), "the service has no backends");
            }
            self.check_backend_tiers(&path, &service.backends, false);
            for (i, backend) in service.backends.iter().enumerate() {
                if backend.weight == 0 {
                    self.error(
                        format!("{}.weight", path_index(&format!("{path}.backends"), i)),
                        "weight must be at least 1",
                    );
                }
            }
            let timeouts = &service.timeouts;
            self.check_not_zero(
                &format!("{path}.timeouts.connect"),
                timeouts.connect.is_zero(),
            );
            self.check_not_zero(&format!("{path}.timeouts.idle"), timeouts.idle.is_zero());
        }
    }

    fn parse_tcp_match(&mut self, path: &str, rule: &str) -> Option<Expr> {
        match rdock_rules::parse(rule) {
            Ok(expr) => {
                let errors = expr.validate(Context::Tcp);
                for err in &errors {
                    self.error(format!("{path}.match"), err.to_string());
                }
                errors.is_empty().then_some(expr)
            }
            Err(err) => {
                self.push(
                    Diagnostic::error(
                        format!("{path}.match"),
                        format!("invalid rule: {}", err.kind),
                    )
                    .with_hint(err.render(rule)),
                );
                None
            }
        }
    }

    fn check_tcp_listeners(&mut self, path: &str, route: &TcpRoute, expr: Option<&Expr>) {
        let Some(listeners) = &route.listeners else {
            self.push(
                Diagnostic::error(format!("{path}.listeners"), "TCP routes need `listeners`")
                    .with_hint("name a `tcp` listener, or an `https` listener for SNI routing"),
            );
            return;
        };
        let terminates = route.tls.is_some_and(|t| !t.passthrough);
        let any_sni = expr.is_some_and(Expr::has_any_sni);
        for (i, name) in listeners.iter().enumerate() {
            let p = path_index(&format!("{path}.listeners"), i);
            let Some((protocol, listener_tls)) = self
                .listeners
                .get(name)
                .map(|l| (l.effective_protocol(), l.tls.is_some()))
            else {
                self.error(p, format!("listener `{name}` does not exist"));
                continue;
            };
            match protocol {
                ListenerProtocol::Tcp | ListenerProtocol::Https => {}
                other => {
                    self.error(
                        p,
                        format!(
                            "listener `{name}` is `{}`; TCP routes need a tcp or https listener",
                            protocol_name(other)
                        ),
                    );
                    continue;
                }
            }
            if protocol == ListenerProtocol::Https && any_sni {
                self.push(
                    Diagnostic::error(
                        &p,
                        format!("``HostSNI(`*`)`` cannot share the https listener `{name}` with HTTP routes"),
                    )
                    .with_hint("attach the route to a `tcp` listener, or match server names"),
                );
            }
            if terminates && !listener_tls {
                self.push(
                    Diagnostic::error(
                        &p,
                        format!("terminating TLS needs `tls` on listener `{name}`"),
                    )
                    .with_hint("add `tls: {}` to the listener, or set `tls.passthrough: true` on the route"),
                );
            }
        }
    }

    fn check_tcp_middlewares(&mut self, path: &str, route: &TcpRoute) {
        for (i, reference) in route.middlewares.iter().enumerate() {
            let p = path_index(&format!("{path}.middlewares"), i);
            self.check_reference(&p, "middleware", reference, &self.config.middlewares);
            match self.config.middlewares.get(reference_key(reference)) {
                None | Some(Middleware::IpAllow(_) | Middleware::IpDeny(_)) => {}
                Some(Middleware::InFlight(c)) if c.key == RateLimitKey::ClientIp => {}
                Some(Middleware::InFlight(_)) => self.error(
                    p,
                    "on a TCP route `in_flight` counts connections per client IP; remove `key`",
                ),
                Some(_) => self.push(
                    Diagnostic::error(
                        p,
                        format!("middleware `{reference}` does not apply to TCP routes"),
                    )
                    .with_hint("TCP routes accept `ip_allow`, `ip_deny` and `in_flight`"),
                ),
            }
        }
    }

    /// A route that reads the ClientHello, in front of a protocol that never sends one first.
    fn check_negotiated_tls(&mut self, path: &str, route: &TcpRoute) {
        let Some(service) = self.config.tcp_services.get(reference_key(&route.service)) else {
            return;
        };
        let found = service.backends.iter().find_map(|b| match &b.address {
            BackendAddress::Tcp { port, .. } => {
                NEGOTIATED_TLS_PORTS.iter().find(|(known, _)| known == port)
            }
            _ => None,
        });
        if let Some((port, protocol)) = found {
            self.push(
                Diagnostic::warning(
                    format!("{path}.match"),
                    format!(
                        "{protocol} (port {port}) negotiates TLS inside its own protocol, so no TLS ClientHello comes first: this route cannot route by server name or terminate TLS for it"
                    ),
                )
                .with_hint("relay it with ``HostSNI(`*`)`` and no `tls` on a `tcp` listener of its own"),
            );
        }
    }
}
