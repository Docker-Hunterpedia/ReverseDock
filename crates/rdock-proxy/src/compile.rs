//! Compilation: a validated `Config` becomes a [`Runtime`]. Compilation reads the files the
//! configuration refers to (certificates, user lists, pages) but does no network I/O, so
//! `rdock validate` runs it too.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rdock_balancer::{Balancer, RoundRobin};
use rdock_middleware::{BuildEnv, HttpClient, Middleware, ServiceClient};
use rdock_model::config::{Config, Listener, ListenerProtocol};
use rdock_model::diagnostics::{Diagnostic, path_key};
use rdock_model::route::{MatchSpec, Route, RouteTls, TlsMode};
use rdock_model::service::{LbPolicy, Service};
use rdock_model::values::{BackendAddress, TrustedProxy};
use rdock_observability::AccessLog;
use rdock_rules::Expr;
use rdock_tls::{CertIndex, LoadedCert};

use crate::forwarded::ClientIpPolicy;
use crate::gate::{self, Mode};
use crate::router::{HostSet, Rule};
use crate::runtime::{
    BackendRuntime, Endpoint, HttpsRedirect, ListenerRuntime, RouteRuntime, Runtime,
    ServiceRuntime, UpstreamTls,
};
use crate::upstream::{Dns, ServiceFetcher};

/// What compilation needs besides the configuration.
pub struct CompileEnv<'a> {
    /// Validation or a real start.
    pub mode: Mode,
    /// Generation number of the result.
    pub generation: u64,
    /// Name resolution shared across generations.
    pub dns: &'a Dns,
    /// Client for subrequests.
    pub client: Arc<HttpClient>,
    /// The running generation, whose access-log writer is reused when unchanged.
    pub previous: Option<&'a Runtime>,
}

/// The result of compilation.
#[derive(Debug)]
pub struct Compiled {
    /// The runtime, unless an error was found.
    pub runtime: Option<Runtime>,
    /// Findings, including unsupported settings.
    pub diagnostics: Vec<Diagnostic>,
}

/// Compiles `config`, which should already have passed validation.
pub fn compile(config: &Config, env: &CompileEnv<'_>) -> Compiled {
    let mut out = Vec::new();
    gate::check(config, env.mode, &mut out);
    let certs = load_certificates(config, &mut out);
    let index = Arc::new(CertIndex::build(
        &certs,
        config.defaults.certificate.as_deref(),
    ));
    let services = compile_services(config, env.dns, &mut out);
    let middlewares = build_middlewares(config, &services, env, &mut out);
    let listeners = compile_listeners(config, &services, &middlewares, &index, env.mode, &mut out);
    let runtime = (!out.iter().any(Diagnostic::is_error)).then(|| Runtime {
        generation: env.generation,
        listeners,
        client_ip: client_ip_policy(config),
        limits: config.security.limits,
        access_log: access_log(config, env.previous),
        certificates: index,
        cert_expiry: certs
            .iter()
            .map(|c| (c.name.clone(), c.not_after))
            .collect(),
    });
    Compiled {
        runtime,
        diagnostics: out,
    }
}

fn access_log(config: &Config, previous: Option<&Runtime>) -> Arc<AccessLog> {
    let wanted = &config.observability.access_log;
    previous
        .map(|p| p.access_log.clone())
        .filter(|log| log.config() == wanted)
        .unwrap_or_else(|| Arc::new(AccessLog::new(wanted)))
}

fn client_ip_policy(config: &Config) -> ClientIpPolicy {
    let trusted = config
        .security
        .trusted_proxies
        .iter()
        .filter_map(|p| match p {
            TrustedProxy::Network(net) => net.to_string().parse().ok(),
            TrustedProxy::Cloudflare => None,
        })
        .collect();
    ClientIpPolicy::new(trusted, config.security.client_ip_header)
}

/// Resolves `name` or `name@file`; other providers do not exist yet.
fn local(reference: &str) -> Option<&str> {
    match reference.split_once('@') {
        None => Some(reference),
        Some((name, "file")) => Some(name),
        Some(_) => None,
    }
}

fn load_certificates(config: &Config, out: &mut Vec<Diagnostic>) -> Vec<LoadedCert> {
    let mut certs = Vec::new();
    for (name, cert) in &config.certificates {
        let path = path_key("certificates", name);
        let password = match cert.key_password.as_deref().map(|p| {
            rdock_config::interpolate::expand(p, &rdock_config::System)
                .map(std::borrow::Cow::into_owned)
        }) {
            Some(Err(e)) => {
                out.push(Diagnostic::error(
                    format!("{path}.key_password"),
                    e.to_string(),
                ));
                continue;
            }
            Some(Ok(p)) => Some(p),
            None => None,
        };
        match rdock_tls::load_certificate(
            name,
            &cert.cert_file,
            &cert.key_file,
            password.as_deref(),
        ) {
            Ok(loaded) => {
                if loaded.names.is_empty() {
                    out.push(Diagnostic::warning(
                        &path,
                        "the certificate has no subject alternative names, so it is only served as the default",
                    ));
                }
                certs.push(loaded);
            }
            Err(e) => out.push(Diagnostic::error(path, e.to_string())),
        }
    }
    certs
}

fn compile_services(
    config: &Config,
    dns: &Dns,
    out: &mut Vec<Diagnostic>,
) -> HashMap<String, Arc<ServiceRuntime>> {
    let mut services = HashMap::new();
    for (name, service) in &config.services {
        let path = path_key("services", name);
        match compile_service(name, service, dns) {
            Ok(runtime) => {
                services.insert(name.clone(), Arc::new(runtime));
            }
            Err(message) => out.push(Diagnostic::error(path, message)),
        }
    }
    services
}

fn compile_service(name: &str, service: &Service, dns: &Dns) -> Result<ServiceRuntime, String> {
    let backends = service
        .backends
        .iter()
        .map(|b| BackendRuntime {
            endpoint: match &b.address {
                BackendAddress::Tcp { host, port } => {
                    let literal = host
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<IpAddr>()
                        .ok();
                    Endpoint::Tcp {
                        host: host.clone(),
                        port: *port,
                        addrs: match literal {
                            Some(ip) => {
                                Arc::new(ArcSwap::from_pointee(vec![SocketAddr::new(ip, *port)]))
                            }
                            None => dns.cell(host, *port),
                        },
                    }
                }
                BackendAddress::Unix(path) => Endpoint::Unix(path.clone()),
            },
            weight: b.weight,
        })
        .collect();
    let tls = service.tls.as_ref();
    let ca = match tls.and_then(|t| t.ca_file.as_deref()) {
        Some(file) => Some(load_ca(file)?),
        None => None,
    };
    let verify = tls.is_none_or(|t| t.verify);
    let server_name = tls.and_then(|t| t.server_name.clone());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (verify, &server_name, tls.and_then(|t| t.ca_file.as_ref())).hash(&mut hasher);
    Ok(ServiceRuntime {
        name: Arc::from(name),
        scheme: service.scheme,
        backends,
        balancer: match service.load_balancer.policy {
            LbPolicy::Random => Balancer::Random,
            _ => Balancer::RoundRobin(RoundRobin::default()),
        },
        timeouts: service.timeouts,
        tls: UpstreamTls {
            verify,
            server_name,
            ca,
            group_key: hasher.finish(),
        },
        pass_host_header: service.pass_host_header,
    })
}

/// Reads a PEM bundle of CA certificates for backend verification.
fn load_ca(file: &std::path::Path) -> Result<Arc<[pingora::utils::tls::WrappedX509]>, String> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    use x509_parser::prelude::FromDer;

    let bytes =
        std::fs::read(file).map_err(|e| format!("cannot read `{}`: {e}", file.display()))?;
    let mut certs = Vec::new();
    for der in CertificateDer::pem_slice_iter(&bytes) {
        let der = der.map_err(|e| format!("invalid PEM in `{}`: {e}", file.display()))?;
        // Pingora's parser panics on invalid DER, so check it first.
        x509_parser::certificate::X509Certificate::from_der(der.as_ref())
            .map_err(|e| format!("invalid certificate in `{}`: {e}", file.display()))?;
        certs.push(pingora::utils::tls::WrappedX509::new(
            der.as_ref().to_vec(),
            pingora::utils::tls::parse_x509,
        ));
    }
    if certs.is_empty() {
        return Err(format!("`{}` contains no certificate", file.display()));
    }
    Ok(certs.into())
}

fn build_middlewares(
    config: &Config,
    services: &HashMap<String, Arc<ServiceRuntime>>,
    env: &CompileEnv<'_>,
    out: &mut Vec<Diagnostic>,
) -> HashMap<String, Arc<dyn Middleware>> {
    let client = env.client.clone();
    let lookup = |reference: &str| -> Option<Arc<dyn ServiceClient>> {
        let service = services.get(local(reference)?)?;
        Some(Arc::new(ServiceFetcher {
            service: service.clone(),
            client: client.clone(),
        }))
    };
    let build_env = BuildEnv {
        service: &lookup,
        client: env.client.clone(),
    };
    let mut built = HashMap::new();
    for (name, middleware) in &config.middlewares {
        match rdock_middleware::build(name, middleware, &build_env) {
            Ok(m) => {
                built.insert(name.clone(), m);
            }
            Err(e) => out.push(Diagnostic::error(
                path_key("middlewares", name),
                e.to_string(),
            )),
        }
    }
    built
}

/// The expression of a route's match, and the rule length used as its default priority.
fn route_expr(route: &Route) -> Option<(Expr, usize)> {
    match &route.matcher {
        MatchSpec::Rule(text) => rdock_rules::parse(text).ok().map(|e| (e, text.len())),
        MatchSpec::Structured(s) => s.to_expr().map(|e| {
            let len = e.to_string().len();
            (e, len)
        }),
    }
}

fn wants_auto_tls(config: &Config, route: &Route) -> bool {
    match &route.tls {
        None => config.defaults.tls == TlsMode::Auto,
        Some(RouteTls::Mode(mode)) => *mode == TlsMode::Auto,
        Some(RouteTls::Options(o)) => o.auto && o.certificate.is_none(),
    }
}

fn compile_listeners(
    config: &Config,
    services: &HashMap<String, Arc<ServiceRuntime>>,
    middlewares: &HashMap<String, Arc<dyn Middleware>>,
    certs: &CertIndex,
    mode: Mode,
    out: &mut Vec<Diagnostic>,
) -> BTreeMap<String, ListenerRuntime> {
    let effective = config.effective_listeners();
    let mut listeners: BTreeMap<String, ListenerRuntime> = effective
        .iter()
        .filter(|(_, l)| {
            matches!(
                l.effective_protocol(),
                ListenerProtocol::Http | ListenerProtocol::Https
            )
        })
        .map(|(name, l)| (name.clone(), new_listener(name, l)))
        .collect();
    let mut tls_hosts = HostSet::Some(std::collections::BTreeSet::new());
    for (name, route) in config.routes.iter().filter(|(_, r)| r.enabled) {
        let path = path_key("routes", name);
        let Some((expr, length)) = route_expr(route) else {
            continue;
        };
        let Some(compiled) = compile_route(name, route, &expr, length, services, middlewares, out)
        else {
            continue;
        };
        let attached = route
            .listeners
            .as_ref()
            .unwrap_or(&config.defaults.listeners);
        for listener_name in attached {
            let Some(listener) = listeners.get_mut(listener_name) else {
                continue;
            };
            if listener.tls.is_some() {
                tls_hosts.extend(HostSet::of(&expr));
                if wants_auto_tls(config, route) {
                    check_coverage(&path, &expr, certs, config, mode, out);
                }
            }
            listener.routes.push(compiled.clone());
        }
    }
    let https_port = listeners
        .values()
        .find(|l| l.tls.is_some())
        .map(|l| l.address.port());
    for listener in listeners.values_mut() {
        listener.routes.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.name.cmp(&b.name))
        });
        if listener.tls.is_none()
            && config.defaults.redirect_http_to_https
            && let Some(port) = https_port
        {
            listener.https_redirect = Some(HttpsRedirect {
                hosts: tls_hosts.clone(),
                port,
            });
        }
    }
    listeners
}

fn new_listener(name: &str, listener: &Listener) -> ListenerRuntime {
    ListenerRuntime {
        name: Arc::from(name),
        address: listener.address,
        tls: listener.tls.map(|t| t.policy),
        timeouts: listener.timeouts,
        routes: Vec::new(),
        https_redirect: None,
    }
}

fn compile_route(
    name: &str,
    route: &Route,
    expr: &Expr,
    length: usize,
    services: &HashMap<String, Arc<ServiceRuntime>>,
    middlewares: &HashMap<String, Arc<dyn Middleware>>,
    out: &mut Vec<Diagnostic>,
) -> Option<Arc<RouteRuntime>> {
    let path = path_key("routes", name);
    let rule = match Rule::compile(expr) {
        Ok(rule) => rule,
        Err(e) => {
            out.push(Diagnostic::error(format!("{path}.match"), e.to_string()));
            return None;
        }
    };
    let unavailable = |what: &str, reference: &str| {
        Diagnostic::error(
            &path,
            format!(
                "{what} `{reference}` is not available (only this file's objects exist in this version)"
            ),
        )
    };
    let Some(service) = local(&route.service).and_then(|n| services.get(n)) else {
        out.push(unavailable("service", &route.service));
        return None;
    };
    let mut chain = Vec::new();
    for reference in &route.middlewares {
        let Some(m) = local(reference).and_then(|n| middlewares.get(n)) else {
            out.push(unavailable("middleware", reference));
            return None;
        };
        chain.push(m.clone());
    }
    let priority = if route.priority == 0 {
        i64::try_from(length).unwrap_or(i64::MAX)
    } else {
        route.priority
    };
    Some(Arc::new(RouteRuntime {
        name: Arc::from(name),
        priority,
        rule,
        service: service.clone(),
        middlewares: chain.into(),
        timeouts: route.timeouts,
    }))
}

/// Before ACME exists, a route asking for automatic HTTPS needs a manual certificate for each
/// of its hosts, or a default certificate.
fn check_coverage(
    path: &str,
    expr: &Expr,
    certs: &CertIndex,
    config: &Config,
    mode: Mode,
    out: &mut Vec<Diagnostic>,
) {
    if config.defaults.certificate.is_some() {
        return;
    }
    let hosts = expr.positive_hosts();
    let uncovered: Vec<&str> = hosts
        .iter()
        .copied()
        .filter(|h| *h != "*" && !certs.covers(&crate::router::normalize_host(h)))
        .collect();
    let message = if hosts.is_empty() {
        "the route has no Host and no default certificate is set".to_owned()
    } else if uncovered.is_empty() {
        return;
    } else {
        format!("no certificate covers {}", uncovered.join(", "))
    };
    let text =
        format!("{message}; automatic certificates are not supported yet (planned for v0.3)");
    let hint = "add the certificate under `certificates`, set `defaults.certificate`, or use `tls: off` on a plain listener";
    out.push(
        match mode {
            Mode::Validate => Diagnostic::warning(format!("{path}.tls"), text),
            Mode::Run => Diagnostic::error(format!("{path}.tls"), text),
        }
        .with_hint(hint),
    );
}
