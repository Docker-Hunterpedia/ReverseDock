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

    /// A setting that needs a cargo feature this build was compiled without.
    fn not_built(&mut self, path: impl Into<String>, what: &str, message: &str) {
        let message = format!("{what}: {message}");
        let diagnostic = match self.mode {
            Mode::Validate => Diagnostic::warning(path, message)
                .with_hint("`rdock run` refuses this configuration in this build"),
            Mode::Run => Diagnostic::error(path, message),
        };
        self.out.push(diagnostic);
    }
}

/// Reports every setting this version cannot honour.
#[allow(clippy::too_many_lines, reason = "a flat list of independent checks")]
pub fn check(config: &Config, mode: Mode, out: &mut Vec<Diagnostic>) {
    let mut gate = Gate { mode, out };
    for (name, middleware) in &config.middlewares {
        // WASM plugins are behind the `wasm` cargo feature (experimental, ADR-0030).
        if matches!(middleware, rdock_model::middleware::Middleware::Wasm(_))
            && !rdock_middleware::wasm::ENABLED
        {
            gate.not_built(
                path_key("middlewares", name),
                "WASM plugins (`type: wasm`)",
                rdock_middleware::wasm::DISABLED_MESSAGE,
            );
        }
        // gRPC and SPOP agent transports are planned (ADR-0030); `rdock` and `forward` exist.
        if let rdock_model::middleware::Middleware::Agent(agent) = middleware {
            use rdock_model::middleware::AgentProtocol;
            let what = match agent.protocol {
                AgentProtocol::Rdock | AgentProtocol::Forward => None,
                AgentProtocol::ExtProc => {
                    Some("agents over Envoy's gRPC external processing (`ext_proc`)")
                }
                AgentProtocol::ExtAuthz => {
                    Some("agents over Envoy's gRPC external authorization (`ext_authz`)")
                }
                AgentProtocol::Spop => Some("agents over HAProxy's SPOP (`spop`)"),
            };
            if let Some(what) = what {
                gate.unsupported(
                    format!("{}.protocol", path_key("middlewares", name)),
                    what,
                    "a later version",
                );
            }
        }
        // A cluster-wide count of requests in flight needs decrements and the cleanup of a
        // crashed member's count (ADR-0031); `rate_limit` and `quota` share leased budgets.
        if let rdock_model::middleware::Middleware::InFlight(f) = middleware
            && f.scope == rdock_model::middleware::LimitScope::Cluster
        {
            gate.unsupported(
                format!("{}.scope", path_key("middlewares", name)),
                "a cluster-wide count of requests in flight (`in_flight` with `scope: cluster`)",
                "a later version",
            );
        }
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
    for (name, service) in &config.services {
        // Pingora 0.9's `ProxyHttp` runs one upstream attempt at a time: no hook starts a
        // second exchange while the first is open (ADR-0031). `retries.per_try_timeout`
        // abandons a stalled attempt instead.
        if service.hedge.is_some() {
            gate.unsupported(
                format!("{}.hedge", path_key("services", name)),
                "hedged requests (`hedge`): Pingora 0.9 cannot race two upstream attempts of one request; `retries.per_try_timeout` retries a stalled attempt on another backend instead",
                "a later version",
            );
        }
    }
    // Rolling back on the canary's health needs a health signal from data planes, which they
    // do not send yet (ADR-0031); a refusal or a silent canary halts the rollout.
    if config
        .control
        .as_ref()
        .is_some_and(|c| c.rollout.auto_rollback)
    {
        gate.unsupported(
            "control.rollout.auto_rollback",
            "automatic rollback on the canary's health (`auto_rollback`)",
            "a later version",
        );
    }
    check_tenants(config, &mut gate);
    // `control` belongs to `rdock control run`; a data plane never reads it.
    if config.control.is_some() && mode == Mode::Run {
        gate.out.push(
            Diagnostic::error("control", "`rdock run` does not read `control`: the control plane runs with `rdock control run`")
                .with_hint("remove `control` from a data plane's file"),
        );
    }
    for (name, listener) in config.effective_listeners().iter() {
        let path = path_key("listeners", name);
        // The handshake bound covers `https` listeners; a `tcp` listener that terminates TLS
        // does its handshake inside the relay (ADR-0031).
        if listener.effective_protocol() == ListenerProtocol::Tcp
            && listener
                .tls
                .as_ref()
                .is_some_and(|t| t.max_handshakes.is_some())
        {
            gate.unsupported(
                format!("{path}.tls.max_handshakes"),
                "`tls.max_handshakes` on `tcp` listeners",
                "a later version",
            );
        }
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

/// Tenants scope the admin API only (ADR-0031); what a tenant would own on the data plane or
/// in the dashboard is planned.
fn check_tenants(config: &Config, gate: &mut Gate<'_>) {
    for (name, tenant) in &config.tenants {
        let path = path_key("tenants", name);
        let planned = [
            (
                !tenant.listeners.is_empty(),
                "listeners",
                "tenant-owned listeners",
            ),
            (
                !tenant.certificates.is_empty(),
                "certificates",
                "tenant-owned certificates",
            ),
            (
                tenant.metrics_label,
                "metrics_label",
                "a tenant label on the core metrics",
            ),
            (
                tenant.dashboard,
                "dashboard",
                "a dashboard view limited to a tenant",
            ),
        ];
        for (set, field, what) in planned {
            if set {
                gate.unsupported(format!("{path}.{field}"), what, "a later version");
            }
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
    fn hedging_is_planned_and_says_why() {
        let yaml = r"
routes:
  app: { match: 'Host(`a`)', service: app }
services:
  app:
    backends: [{ address: '127.0.0.1:1' }]
    hedge: { delay: 50ms }
";
        let run = diagnostics(yaml, Mode::Run);
        assert_eq!(run.len(), 1, "{run:?}");
        assert!(run[0].is_error());
        assert_eq!(run[0].path, "services.app.hedge");
        assert!(run[0].message.contains("cannot race two upstream attempts"));
        assert!(run[0].message.ends_with("(planned for a later version)"));
        let validate = diagnostics(yaml, Mode::Validate);
        assert!(!validate[0].is_error());
    }

    #[test]
    fn cluster_scoped_in_flight_and_automatic_rollback_are_planned() {
        let yaml = r"
middlewares:
  slots: { type: in_flight, amount: 4, scope: cluster }
  shared: { type: rate_limit, average: 10, scope: cluster }
";
        let run = diagnostics(yaml, Mode::Run);
        assert_eq!(run.len(), 1, "{run:?}");
        assert_eq!(run[0].path, "middlewares.slots.scope");
        assert!(run[0].is_error());
        let run = diagnostics("control:\n  rollout: { auto_rollback: true }\n", Mode::Run);
        assert!(
            run.iter()
                .any(|d| d.path == "control.rollout.auto_rollback" && d.is_error()),
            "{run:?}"
        );
        let validate = diagnostics(
            "control:\n  rollout: { auto_rollback: true }\n",
            Mode::Validate,
        );
        assert!(validate.iter().all(|d| !d.is_error()), "{validate:?}");
    }

    #[test]
    fn tenant_owned_listeners_certificates_metrics_and_dashboards_are_planned() {
        let yaml = r#"
tenants:
  acme:
    hosts: ["acme.example.com"]
    listeners: [web]
    certificates: [acme]
    metrics_label: true
    dashboard: true
  globex: { hosts: ["globex.example.com"] }
"#;
        let run = diagnostics(yaml, Mode::Run);
        let paths: Vec<&str> = run.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "tenants.acme.listeners",
                "tenants.acme.certificates",
                "tenants.acme.metrics_label",
                "tenants.acme.dashboard"
            ]
        );
        assert!(run.iter().all(Diagnostic::is_error));
        assert!(
            diagnostics(yaml, Mode::Validate)
                .iter()
                .all(|d| !d.is_error())
        );
    }

    #[test]
    fn the_handshake_bound_on_tcp_listeners_is_planned() {
        let yaml = "listeners:\n  raw: { address: \":5432\", protocol: tcp, tls: { max_handshakes: 8 } }\n  web: { address: \":443\", tls: { max_handshakes: 8 } }\n";
        let run = diagnostics(yaml, Mode::Run);
        assert_eq!(run.len(), 1, "{run:?}");
        assert_eq!(run[0].path, "listeners.raw.tls.max_handshakes");
        assert!(run[0].is_error() && run[0].message.ends_with("(planned for a later version)"));
    }

    #[test]
    fn a_data_plane_refuses_the_control_section_and_validate_accepts_it() {
        let yaml = "control: { listener: \"127.0.0.1:7443\" }\n";
        let run = diagnostics(yaml, Mode::Run);
        assert_eq!(run.len(), 1, "{run:?}");
        assert!(run[0].is_error() && run[0].path == "control");
        assert!(run[0].message.contains("rdock control run"));
        assert_eq!(diagnostics(yaml, Mode::Validate).len(), 0);
        let member = "cluster: { store: { type: directory, path: /shared } }\n";
        assert!(
            diagnostics(member, Mode::Run).is_empty(),
            "the cluster is built"
        );
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
    fn wasm_needs_the_feature() {
        let yaml = "middlewares:\n  w: { type: wasm, path: /p.wasm, sha256: \"0000000000000000000000000000000000000000000000000000000000000000\", allow_unsigned: true }\n";
        let run = diagnostics(yaml, Mode::Run);
        if rdock_middleware::wasm::ENABLED {
            assert!(run.is_empty(), "{run:?}");
            return;
        }
        assert_eq!(run.len(), 1, "{run:?}");
        assert_eq!(run[0].path, "middlewares.w");
        assert!(run[0].is_error());
        assert_eq!(
            run[0].message,
            "WASM plugins (`type: wasm`): this build does not include WASM plugins; build with --features wasm"
        );
        assert!(
            diagnostics(yaml, Mode::Validate)
                .iter()
                .all(|d| !d.is_error())
        );
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
    fn grpc_and_spop_agents_are_planned() {
        for protocol in ["ext_proc", "ext_authz", "spop"] {
            let yaml = format!(
                "middlewares:\n  waf: {{ type: agent, address: \"http://127.0.0.1:9000\", protocol: {protocol} }}\n"
            );
            let run = diagnostics(&yaml, Mode::Run);
            assert_eq!(run.len(), 1, "{run:?}");
            assert_eq!(run[0].path, "middlewares.waf.protocol");
            assert!(run[0].is_error());
            assert!(
                run[0].message.contains(&format!("`{protocol}`")),
                "{}",
                run[0].message
            );
            assert!(run[0].message.ends_with("(planned for a later version)"));
        }
        for protocol in ["rdock", "forward"] {
            let yaml = format!(
                "middlewares:\n  waf: {{ type: agent, address: \"http://127.0.0.1:9000\", protocol: {protocol} }}\n"
            );
            assert_eq!(diagnostics(&yaml, Mode::Run), Vec::new());
        }
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
