//! Compilation: a validated `Config` becomes a [`Runtime`]. Compilation reads the files the
//! configuration refers to (certificates, user lists, pages) but does no network I/O, so
//! `rdock validate` runs it too.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use rdock_tls::{CertIndex, CertRequest, LoadedCert};

use crate::forwarded::{ClientIpPolicy, CloudflareRanges};
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
    /// Cloudflare's edge ranges, trusted when `trusted_proxies` contains `cloudflare`.
    pub cloudflare: &'a CloudflareRanges,
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
    let mut auto_tls = AutoTls {
        certs: &index,
        acme: config.effective_acme().is_some(),
        mode: env.mode,
        requests: BTreeSet::new(),
    };
    let listeners = compile_listeners(config, &services, &middlewares, &mut auto_tls, &mut out);
    let cert_requests = auto_tls.requests.into_iter().collect();
    let runtime = (!out.iter().any(Diagnostic::is_error)).then(|| Runtime {
        generation: env.generation,
        listeners,
        client_ip: client_ip_policy(config, env.cloudflare),
        limits: config.security.limits,
        access_log: access_log(config, env.previous),
        certificates: index,
        cert_requests,
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

fn client_ip_policy(config: &Config, cloudflare: &CloudflareRanges) -> ClientIpPolicy {
    let proxies = &config.security.trusted_proxies;
    let trusted = proxies
        .iter()
        .filter_map(|p| match p {
            TrustedProxy::Network(net) => net.to_string().parse().ok(),
            TrustedProxy::Cloudflare => None,
        })
        .collect();
    let policy = ClientIpPolicy::new(trusted, config.security.client_ip_header);
    if proxies.contains(&TrustedProxy::Cloudflare) {
        policy.with_cloudflare(cloudflare.clone())
    } else {
        policy
    }
}

/// The key a reference names: `name@file` is the file's `name`; other providers' objects are
/// merged under their `name@provider` key (ADR-0018).
fn key(reference: &str) -> &str {
    reference.strip_suffix("@file").unwrap_or(reference)
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
        let service = services.get(key(reference))?;
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
    auto_tls: &mut AutoTls<'_>,
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
                    auto_tls.route(&path, route, &expr, config, out);
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
        Diagnostic::error(&path, format!("{what} `{reference}` does not exist"))
    };
    let Some(service) = services.get(key(&route.service)) else {
        out.push(unavailable("service", &route.service));
        return None;
    };
    let mut chain = Vec::new();
    for reference in &route.middlewares {
        let Some(m) = middlewares.get(key(reference)) else {
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

/// Collects the certificates that routes with `tls: auto` need and no configured certificate
/// covers.
struct AutoTls<'a> {
    certs: &'a CertIndex,
    /// Whether automatic certificates are on.
    acme: bool,
    mode: Mode,
    requests: BTreeSet<CertRequest>,
}

impl AutoTls<'_> {
    fn route(
        &mut self,
        path: &str,
        route: &Route,
        expr: &Expr,
        config: &Config,
        out: &mut Vec<Diagnostic>,
    ) {
        let options = match &route.tls {
            Some(RouteTls::Options(options)) => Some(options),
            _ => None,
        };
        let hosts: Vec<String> = match options.filter(|o| !o.domains.is_empty()) {
            Some(o) => o.domains.iter().map(|d| d.to_ascii_lowercase()).collect(),
            None => expr
                .positive_hosts()
                .into_iter()
                .filter(|h| *h != "*")
                .map(crate::router::normalize_host)
                .collect(),
        };
        let uncovered: Vec<String> = hosts
            .iter()
            .filter(|h| !self.certs.covers(h))
            .cloned()
            .collect();
        if !self.acme {
            self.report_uncovered(path, &hosts, &uncovered, config, out);
            return;
        }
        let (private, public): (Vec<String>, Vec<String>) = uncovered
            .into_iter()
            .partition(|h| rdock_tls::is_private_name(h));
        if !private.is_empty() {
            out.push(
                Diagnostic::warning(
                    format!("{path}.tls"),
                    format!(
                        "public certificate authorities do not issue certificates for {}",
                        private.join(", ")
                    ),
                )
                .with_hint(
                    "add a certificate under `certificates`, or use `tls: off` on a plain listener",
                ),
            );
        }
        let dns_provider = options
            .and_then(|o| o.dns_provider.clone())
            .or_else(|| config.effective_acme().and_then(|a| a.dns_provider.clone()));
        if options.is_some_and(|o| !o.domains.is_empty()) {
            if !public.is_empty() {
                self.requests.insert(CertRequest {
                    names: hosts,
                    dns_provider,
                });
            }
            return;
        }
        for name in public {
            self.requests.insert(CertRequest {
                names: vec![name],
                dns_provider: dns_provider.clone(),
            });
        }
    }

    /// With automatic certificates off, every host needs a configured certificate.
    fn report_uncovered(
        &self,
        path: &str,
        hosts: &[String],
        uncovered: &[String],
        config: &Config,
        out: &mut Vec<Diagnostic>,
    ) {
        if config.defaults.certificate.is_some() {
            return;
        }
        let message = if hosts.is_empty() {
            "the route has no Host and no default certificate is set".to_owned()
        } else if uncovered.is_empty() {
            return;
        } else {
            format!(
                "no certificate covers {}, and automatic certificates are off (`acme: false`)",
                uncovered.join(", ")
            )
        };
        let hint = "add the certificate under `certificates`, set `defaults.certificate`, or use `tls: off` on a plain listener";
        out.push(
            match self.mode {
                Mode::Validate => Diagnostic::warning(format!("{path}.tls"), message),
                Mode::Run => Diagnostic::error(format!("{path}.tls"), message),
            }
            .with_hint(hint),
        );
    }
}
