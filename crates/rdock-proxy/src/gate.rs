//! Settings the model accepts but this version does not implement yet (ADR-0014). They are
//! reported instead of ignored: `rdock validate` warns, `rdock run` refuses to start, so nothing
//! silently behaves differently from what the configuration says.

use rdock_model::acme::AcmeSetting;
use rdock_model::config::{Config, ListenerProtocol};
use rdock_model::diagnostics::{Diagnostic, path_key};
use rdock_model::middleware::{CompressAlgorithm, Middleware};
use rdock_model::route::RouteTls;
use rdock_model::service::LbPolicy;
use rdock_model::settings::ClientIpHeader;
use rdock_model::values::TrustedProxy;

/// Why compilation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `rdock validate`: report missing features as warnings.
    Validate,
    /// `rdock run` and reloads: missing features are errors.
    Run,
}

struct Gate<'a> {
    mode: Mode,
    out: &'a mut Vec<Diagnostic>,
}

impl Gate<'_> {
    fn unsupported(&mut self, path: impl Into<String>, what: &str, milestone: &str) {
        let message = format!("{what}: not supported in this version (planned for {milestone})");
        let diagnostic = match self.mode {
            Mode::Validate => Diagnostic::warning(path, message)
                .with_hint("`rdock run` refuses this configuration until then"),
            Mode::Run => Diagnostic::error(path, message),
        };
        self.out.push(diagnostic);
    }
}

/// Reports every setting this version cannot honour.
pub fn check(config: &Config, mode: Mode, out: &mut Vec<Diagnostic>) {
    let mut gate = Gate { mode, out };
    // `acme: false` only states what this version already does.
    if !matches!(config.acme, None | Some(AcmeSetting::Enabled(false))) {
        gate.unsupported("acme", "automatic certificates (ACME)", "v0.3");
    }
    if config.observability.alerts.webhook.is_some() {
        gate.unsupported("observability.alerts.webhook", "alert webhooks", "v0.3");
    }
    for (name, listener) in config.effective_listeners().iter() {
        let path = path_key("listeners", name);
        if matches!(
            listener.effective_protocol(),
            ListenerProtocol::Tcp | ListenerProtocol::Udp
        ) {
            gate.unsupported(format!("{path}.protocol"), "TCP and UDP listeners", "v0.6");
        }
        if listener.proxy_protocol.is_some() {
            gate.unsupported(
                format!("{path}.proxy_protocol"),
                "the PROXY protocol",
                "v0.6",
            );
        }
    }
    if !config.tcp_routes.is_empty() {
        gate.unsupported("tcp_routes", "TCP routes", "v0.6");
    }
    if !config.tcp_services.is_empty() {
        gate.unsupported("tcp_services", "TCP services", "v0.6");
    }
    for (name, route) in &config.routes {
        if let Some(RouteTls::Options(options)) = &route.tls {
            let path = format!("{}.tls", path_key("routes", name));
            if options.dns_provider.is_some() {
                gate.unsupported(
                    format!("{path}.dns_provider"),
                    "DNS-01 certificates",
                    "v0.3",
                );
            }
            if !options.domains.is_empty() {
                gate.unsupported(
                    format!("{path}.domains"),
                    "automatic certificate names",
                    "v0.3",
                );
            }
        }
    }
    for (name, service) in &config.services {
        check_service(&mut gate, &path_key("services", name), service);
    }
    for (name, middleware) in &config.middlewares {
        let path = path_key("middlewares", name);
        match middleware {
            Middleware::Compress(c)
                if c.algorithms.iter().any(|a| *a != CompressAlgorithm::Gzip) =>
            {
                gate.unsupported(
                    format!("{path}.algorithms"),
                    "brotli and zstd compression",
                    "v0.4",
                );
            }
            _ => {}
        }
    }
    let providers = &config.providers;
    if providers.swarm.is_some() {
        gate.unsupported("providers.swarm", "the Swarm provider", "v0.6");
    }
    if providers.kubernetes.is_some() {
        gate.unsupported("providers.kubernetes", "the Kubernetes provider", "v0.7");
    }
    let security = &config.security;
    if security.trusted_proxies.contains(&TrustedProxy::Cloudflare) {
        gate.unsupported(
            "security.trusted_proxies",
            "`cloudflare` (synced edge ranges)",
            "v0.3",
        );
    }
    if security.client_ip_header == ClientIpHeader::CfConnectingIp {
        gate.unsupported("security.client_ip_header", "`cf-connecting-ip`", "v0.3");
    }
    if config.observability.tracing.is_some() {
        gate.unsupported("observability.tracing", "OpenTelemetry tracing", "v0.4");
    }
}

fn check_service(gate: &mut Gate<'_>, path: &str, service: &rdock_model::service::Service) {
    if !service.split.is_empty() {
        gate.unsupported(format!("{path}.split"), "weighted traffic splits", "v0.4");
    }
    if !matches!(
        service.load_balancer.policy,
        LbPolicy::RoundRobin | LbPolicy::Random
    ) {
        gate.unsupported(
            format!("{path}.load_balancer.policy"),
            "load-balancing policies other than round_robin and random",
            "v0.4",
        );
    }
    if service.health.is_some() {
        gate.unsupported(format!("{path}.health"), "health checks", "v0.4");
    }
    if service.retries.is_some() {
        gate.unsupported(format!("{path}.retries"), "retries", "v0.4");
    }
    if service.sticky.is_some() {
        gate.unsupported(format!("{path}.sticky"), "sticky sessions", "v0.4");
    }
    if service
        .tls
        .as_ref()
        .is_some_and(|t| t.cert_file.is_some() || t.key_file.is_some())
    {
        gate.unsupported(
            format!("{path}.tls"),
            "client certificates to backends",
            "v0.4",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostics(yaml: &str, mode: Mode) -> Vec<Diagnostic> {
        let config = rdock_config::load_str(yaml, rdock_config::Format::Yaml)
            .unwrap()
            .config;
        let mut out = Vec::new();
        check(&config, mode, &mut out);
        out
    }

    #[test]
    fn reports_unsupported_settings_by_mode() {
        let yaml = "acme: { email: a@example.com }\nservices:\n  s:\n    backends: [{ address: \"s:1\" }]\n    health: { active: { path: / } }\n";
        let validate = diagnostics(yaml, Mode::Validate);
        assert_eq!(validate.len(), 2, "{validate:?}");
        assert!(validate.iter().all(|d| !d.is_error()));
        assert_eq!(
            validate[0].message,
            "automatic certificates (ACME): not supported in this version (planned for v0.3)"
        );
        let run = diagnostics(yaml, Mode::Run);
        assert!(run.iter().all(Diagnostic::is_error));
        assert_eq!(run[1].path, "services.s.health");
    }

    #[test]
    fn plain_configurations_pass() {
        let yaml = "listeners:\n  web: { address: \":8080\" }\nroutes:\n  r: { match: \"PathPrefix(`/`)\", service: s, listeners: [web], tls: off }\nservices:\n  s: { backends: [{ address: \"s:1\" }] }\n";
        assert_eq!(diagnostics(yaml, Mode::Run), Vec::new());
        let acme_off = format!("acme: false\n{yaml}");
        assert_eq!(diagnostics(&acme_off, Mode::Run), Vec::new());
    }
}
