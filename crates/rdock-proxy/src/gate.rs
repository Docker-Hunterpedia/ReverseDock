//! Settings the model accepts but this version does not implement yet (ADR-0014). They are
//! reported instead of ignored: `rdock validate` warns, `rdock run` refuses to start, so nothing
//! silently behaves differently from what the configuration says.

use rdock_model::config::{Config, ListenerProtocol};
use rdock_model::diagnostics::{Diagnostic, path_key};

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
    for (name, middleware) in &config.middlewares {
        // Background refresh re-runs the whole pipeline for a request no client waits on
        // (ADR-0030); `stale-while-revalidate` is honoured as plain staleness instead.
        if let rdock_model::middleware::Middleware::Cache(cache) = middleware
            && cache.background_refresh
        {
            gate.unsupported(
                format!("{}.background_refresh", path_key("middlewares", name)),
                "background refresh of stale responses (`stale-while-revalidate`)",
                "a later version",
            );
        }
    }
    for (name, listener) in config.effective_listeners().iter() {
        let path = path_key("listeners", name);
        // The PROXY protocol specification defines no framing for datagrams (ADR-0030).
        if listener.effective_protocol() == ListenerProtocol::Udp
            && listener.proxy_protocol.is_some()
        {
            gate.unsupported(
                format!("{path}.proxy_protocol"),
                "PROXY protocol on UDP listeners",
                "a later version",
            );
        }
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
        let yaml = "listeners:\n  dns: { address: \":53\", protocol: udp, proxy_protocol: { trusted: [10.0.0.0/8] } }\nservices:\n  s:\n    backends: [{ address: \"s:1\" }]\n";
        let validate = diagnostics(yaml, Mode::Validate);
        assert_eq!(validate.len(), 1, "{validate:?}");
        assert!(validate.iter().all(|d| !d.is_error()));
        assert!(validate.iter().any(|d| d.path == "listeners.dns.proxy_protocol"
            && d.message
                == "PROXY protocol on UDP listeners: not supported in this version (planned for a later version)"));
        let run = diagnostics(yaml, Mode::Run);
        assert!(run.iter().all(Diagnostic::is_error));
        assert!(run.iter().any(|d| d.path == "listeners.dns.proxy_protocol"));
    }

    #[test]
    fn background_refresh_is_planned() {
        let yaml = "caches:\n  mem: { type: memory }\nmiddlewares:\n  c: { type: cache, store: mem, background_refresh: true }\nservices:\n  s:\n    backends: [{ address: \"s:1\" }]\n";
        let run = diagnostics(yaml, Mode::Run);
        assert_eq!(run.len(), 1, "{run:?}");
        assert_eq!(run[0].path, "middlewares.c.background_refresh");
        assert_eq!(
            run[0].message,
            "background refresh of stale responses (`stale-while-revalidate`): not supported in this version (planned for a later version)"
        );
        assert!(run[0].is_error());
        assert!(
            diagnostics(yaml, Mode::Validate)
                .iter()
                .all(|d| !d.is_error())
        );
    }

    #[test]
    fn plain_configurations_pass() {
        let yaml = "listeners:\n  web: { address: \":8080\" }\nroutes:\n  r: { match: \"PathPrefix(`/`)\", service: s, listeners: [web], tls: off }\nservices:\n  s: { backends: [{ address: \"s:1\" }] }\n";
        assert_eq!(diagnostics(yaml, Mode::Run), Vec::new());
        let acme_off = format!("acme: false\n{yaml}");
        assert_eq!(diagnostics(&acme_off, Mode::Run), Vec::new());
        let proxy_protocol = yaml.replace(
            "address: \":8080\"",
            "address: \":8080\", proxy_protocol: { trusted: [10.0.0.0/8] }",
        );
        assert!(proxy_protocol.contains("trusted"));
        assert_eq!(diagnostics(&proxy_protocol, Mode::Run), Vec::new());
        // The Kubernetes provider is implemented (v0.7, ADR-0029).
        let kubernetes = format!("{acme_off}providers:\n  kubernetes: {{}}\n");
        assert_eq!(diagnostics(&kubernetes, Mode::Run), Vec::new());
        let tcp = "listeners:\n  db: { address: \":5432\", protocol: tcp }\ntcp_routes:\n  db: { match: \"HostSNI(`*`)\", listeners: [db], service: db }\ntcp_services:\n  db: { backends: [{ address: \"db:5432\" }] }\n";
        assert_eq!(diagnostics(tcp, Mode::Run), Vec::new());
        // UDP is implemented (v0.8, ADR-0030).
        let udp = "listeners:\n  dns: { address: \":53\", protocol: udp }\nudp_routes:\n  dns: { listeners: [dns], service: dns }\nudp_services:\n  dns: { backends: [{ address: \"dns:53\" }] }\n";
        assert_eq!(diagnostics(udp, Mode::Run), Vec::new());
    }
}
