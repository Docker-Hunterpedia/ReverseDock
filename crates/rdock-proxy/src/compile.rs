//! Compilation: a validated `Config` becomes a [`Runtime`]. Compilation reads the files the
//! configuration refers to (certificates, user lists, pages) but does no network I/O, so
//! `rdock validate` runs it too.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use rdock_balancer::{
    Balancer, EjectPolicy, HashRing, ProbePolicy, Registry, RoundRobin, StickyKeys,
};
use rdock_middleware::{BuildEnv, HttpClient, Middleware, ServiceClient};
use rdock_model::config::{Config, Listener, ListenerProtocol};
use rdock_model::diagnostics::{Diagnostic, path_key};
use rdock_model::route::{MatchSpec, Route, RouteTls, TlsMode};
use rdock_model::service::{
    Health, HealthMethod, LbPolicy, SameSite, Service, Sticky, WhenAllDown,
};
use rdock_model::values::{BackendAddress, TrustedProxy};
use rdock_observability::AccessLog;
use rdock_rules::Expr;
use rdock_tls::{CertIndex, CertRequest, LoadedCert};

use crate::forwarded::{ClientIpPolicy, CloudflareRanges};
use crate::gate::{self, Mode};
use crate::router::{HostSet, Rule};
use crate::runtime::{
    ActiveCheck, BackendRuntime, Endpoint, HashOn, HealthRuntime, HttpsRedirect, ListenerRuntime,
    MirrorRuntime, PassiveCheck, RouteRuntime, Runtime, ServiceRuntime, StickyRuntime, UpstreamTls,
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
    /// Per-backend state shared across generations.
    pub backends: &'a Registry,
    /// Signs sticky cookies of services without their own `secret`.
    pub sticky_key: &'a [u8],
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
    let services = compile_services(config, env, &mut out);
    let tracer = tracer(config, env, &mut out);
    let middlewares = build_middlewares(config, &services, env, &mut out);
    let mut auto_tls = AutoTls {
        certs: &index,
        acme: config.effective_acme().is_some(),
        mode: env.mode,
        requests: BTreeSet::new(),
        local: BTreeSet::new(),
    };
    let listeners = compile_listeners(config, &services, &middlewares, &mut auto_tls, &mut out);
    let cert_requests = auto_tls.requests.into_iter().collect();
    let local_cert_names = auto_tls.local.into_iter().collect();
    let runtime = (!out.iter().any(Diagnostic::is_error)).then(|| Runtime {
        generation: env.generation,
        listeners,
        client_ip: client_ip_policy(config, env.cloudflare),
        limits: config.security.limits,
        access_log: access_log(config, env.previous),
        certificates: index,
        cert_requests,
        local_cert_names,
        cert_expiry: certs
            .iter()
            .map(|c| (c.name.clone(), c.not_after))
            .collect(),
        services: services
            .iter()
            .map(|(name, s)| (name.clone(), s.clone()))
            .collect(),
        tracer,
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

/// The tracer for `observability.tracing`: the running one when its settings are unchanged
/// (it holds the export queue), otherwise a new one. `rdock validate` starts none.
fn tracer(
    config: &Config,
    env: &CompileEnv<'_>,
    out: &mut Vec<Diagnostic>,
) -> Option<Arc<rdock_observability::Tracer>> {
    let settings = config.observability.tracing.as_ref()?;
    if env.mode == Mode::Validate {
        return None;
    }
    let url = settings.otlp.as_url();
    if let Some(running) = env
        .previous
        .and_then(|p| p.tracer.clone())
        .filter(|t| t.is_for(url, settings.sample_ratio))
    {
        return Some(running);
    }
    match rdock_observability::Tracer::new(url, settings.sample_ratio, env!("CARGO_PKG_VERSION")) {
        Ok(tracer) => Some(Arc::new(tracer)),
        Err(e) => {
            out.push(Diagnostic::error("observability.tracing", e.to_string()));
            None
        }
    }
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

/// Mirrored copies in flight per route; more are dropped rather than queued.
const MIRRORS_IN_FLIGHT: usize = 64;

/// Nested `split` services deeper than this are refused.
const MAX_SPLIT_DEPTH: usize = 4;

fn compile_services(
    config: &Config,
    env: &CompileEnv<'_>,
    out: &mut Vec<Diagnostic>,
) -> HashMap<String, Arc<ServiceRuntime>> {
    let mut services = HashMap::new();
    let mut depth: HashMap<String, usize> = HashMap::new();
    let mut pending: Vec<(&String, &Service)> = Vec::new();
    for (name, service) in &config.services {
        if !service.split.is_empty() {
            pending.push((name, service));
            continue;
        }
        match compile_service(name, service, Vec::new(), env) {
            Ok(runtime) => {
                services.insert(name.clone(), Arc::new(runtime));
                depth.insert(name.clone(), 0);
            }
            Err(message) => out.push(Diagnostic::error(path_key("services", name), message)),
        }
    }
    // Splits refer to other services: compile each once all its targets exist.
    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|(name, service)| {
            let targets: Option<Vec<_>> = service
                .split
                .iter()
                .map(|t| services.get(key(&t.service)).map(|s| (s.clone(), t.weight)))
                .collect();
            let Some(targets) = targets else {
                return true;
            };
            let path = path_key("services", name);
            let level = 1 + service
                .split
                .iter()
                .filter_map(|t| depth.get(key(&t.service)))
                .max()
                .unwrap_or(&0);
            if level > MAX_SPLIT_DEPTH {
                out.push(Diagnostic::error(
                    format!("{path}.split"),
                    format!("splits are nested more than {MAX_SPLIT_DEPTH} levels deep"),
                ));
            } else {
                match compile_service(name, service, targets, env) {
                    Ok(runtime) => {
                        services.insert((*name).clone(), Arc::new(runtime));
                        depth.insert((*name).clone(), level);
                    }
                    Err(message) => out.push(Diagnostic::error(path, message)),
                }
            }
            false
        });
        if pending.len() == before {
            for (name, _) in &pending {
                out.push(Diagnostic::error(
                    format!("{}.split", path_key("services", name)),
                    "a split target does not exist or the splits form a cycle",
                ));
            }
            break;
        }
    }
    services
}

fn compile_service(
    name: &str,
    service: &Service,
    split: Vec<(Arc<ServiceRuntime>, u32)>,
    env: &CompileEnv<'_>,
) -> Result<ServiceRuntime, String> {
    let dns = env.dns;
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
                BackendAddress::Srv(name) => Endpoint::Srv {
                    name: name.clone(),
                    targets: dns.srv_cell(name),
                },
            },
            weight: b.weight,
            backup: b.backup,
        })
        .collect();
    let tls = service.tls.as_ref();
    let ca = match tls.and_then(|t| t.ca_file.as_deref()) {
        Some(file) => Some(load_ca(file)?),
        None => None,
    };
    let client_cert = match tls.and_then(|t| t.cert_file.as_deref().zip(t.key_file.as_deref())) {
        Some((cert, key)) => Some(load_client_cert(cert, key)?),
        None => None,
    };
    let verify = tls.is_none_or(|t| t.verify);
    let server_name = tls.and_then(|t| t.server_name.clone());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (
        verify,
        &server_name,
        tls.and_then(|t| t.ca_file.as_ref()),
        tls.and_then(|t| t.cert_file.as_ref()),
    )
        .hash(&mut hasher);
    Ok(ServiceRuntime {
        name: Arc::from(name),
        scheme: service.scheme,
        backends,
        balancer: balancer(service.load_balancer.policy),
        hash_on: hash_on(service),
        sticky: match &service.sticky {
            Some(sticky) => Some(compile_sticky(sticky, env.sticky_key)?),
            None => None,
        },
        pool: env.backends.pool(name),
        members: ArcSwapOption::empty(),
        health: compile_health(service.health.as_ref())?,
        split,
        split_balancer: RoundRobin::default(),
        retries: service.retries.clone().filter(|r| r.attempts > 0),
        max_requests: service.max_requests,
        max_per_backend: service.max_connections_per_backend,
        timeouts: service.timeouts,
        tls: UpstreamTls {
            verify,
            server_name,
            ca,
            client_cert,
            group_key: hasher.finish(),
        },
        pass_host_header: service.pass_host_header,
    })
}

fn balancer(policy: LbPolicy) -> Balancer {
    match policy {
        LbPolicy::RoundRobin => Balancer::RoundRobin(RoundRobin::default()),
        LbPolicy::Random => Balancer::Random,
        LbPolicy::LeastConn | LbPolicy::LeastRequests => Balancer::LeastRequests,
        LbPolicy::P2c => Balancer::P2c,
        LbPolicy::IpHash | LbPolicy::HeaderHash | LbPolicy::CookieHash => {
            Balancer::Hash(Box::<HashRing>::default())
        }
    }
}

fn compile_health(health: Option<&Health>) -> Result<HealthRuntime, String> {
    let Some(health) = health else {
        return Ok(HealthRuntime {
            fail_open: true,
            ..HealthRuntime::default()
        });
    };
    let active = match &health.active {
        Some(a) => Some(ActiveCheck {
            mode: a.mode,
            method: match a.method {
                HealthMethod::Get => http::Method::GET,
                HealthMethod::Head => http::Method::HEAD,
            },
            path: a.path.clone(),
            hostname: a.hostname.clone(),
            headers: a
                .headers
                .iter()
                .map(|(k, v)| {
                    Ok((
                        http::HeaderName::try_from(k.as_str()).map_err(|_| {
                            format!("health.active.headers: `{k}` is not a header name")
                        })?,
                        http::HeaderValue::try_from(v.as_str())
                            .map_err(|_| format!("health.active.headers.{k}: invalid value"))?,
                    ))
                })
                .collect::<Result<_, String>>()?,
            expected_status: rdock_model::status_range(&a.expected_status)
                .ok_or_else(|| format!("health.active.expected_status: `{}`", a.expected_status))?,
            expected_body: a.expected_body.clone(),
            grpc_service: a.grpc_service.clone(),
            port: a.port,
            interval: a.interval.as_std(),
            timeout: a.timeout.as_std(),
            policy: ProbePolicy {
                healthy: a.healthy,
                unhealthy: a.unhealthy,
            },
        }),
        None => None,
    };
    let passive = health.passive.as_ref().map(|p| PassiveCheck {
        policy: EjectPolicy {
            failures: p.failures,
            window: p.window.as_std(),
            ejection: p.ejection.as_std(),
        },
        statuses: p.statuses.clone(),
        max_percent: p.max_ejection_percent,
    });
    Ok(HealthRuntime {
        active,
        passive,
        fail_open: health.when_all_down == WhenAllDown::FailOpen,
        slow_start: health.slow_start.map(rdock_model::values::Duration::as_std),
    })
}

fn hash_on(service: &Service) -> HashOn {
    let name = service.load_balancer.hash_on.as_deref();
    match service.load_balancer.policy {
        LbPolicy::IpHash => HashOn::ClientIp,
        LbPolicy::HeaderHash => name
            .and_then(|n| http::HeaderName::try_from(n).ok())
            .map_or(HashOn::Nothing, HashOn::Header),
        LbPolicy::CookieHash => name.map_or(HashOn::Nothing, |n| HashOn::Cookie(n.to_owned())),
        _ => HashOn::Nothing,
    }
}

fn compile_sticky(sticky: &Sticky, default_key: &[u8]) -> Result<StickyRuntime, String> {
    let resolve = |reference: &str| {
        rdock_config::interpolate::expand(reference, &rdock_config::System)
            .map(std::borrow::Cow::into_owned)
            .map_err(|e| format!("sticky.cookie: {e}"))
    };
    let cookie = &sticky.cookie;
    let current = match &cookie.secret {
        Some(reference) => resolve(reference)?.into_bytes(),
        None => default_key.to_vec(),
    };
    let previous = cookie
        .previous_secrets
        .iter()
        .map(|r| resolve(r).map(String::into_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let previous: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
    let mut attributes = format!("; Path={}", cookie.path);
    if let Some(max_age) = cookie.max_age {
        attributes = format!("{attributes}; Max-Age={}", max_age.as_std().as_secs());
    }
    if cookie.secure {
        attributes.push_str("; Secure");
    }
    if cookie.http_only {
        attributes.push_str("; HttpOnly");
    }
    attributes.push_str(match cookie.same_site {
        SameSite::Lax => "; SameSite=Lax",
        SameSite::Strict => "; SameSite=Strict",
        SameSite::None => "; SameSite=None",
    });
    Ok(StickyRuntime {
        name: cookie.name.clone(),
        keys: StickyKeys::new(&current, &previous),
        attributes,
    })
}

/// Reads the client certificate chain and key that a service presents to its backends. They
/// are checked here because Pingora asserts a non-empty chain and unwraps the key conversion.
fn load_client_cert(
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
) -> Result<Arc<pingora::utils::tls::CertKey>, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use x509_parser::prelude::FromDer;

    let chain = CertificateDer::pem_file_iter(cert_file)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("cannot read `{}`: {e}", cert_file.display()))?;
    if chain.is_empty() {
        return Err(format!("`{}` holds no certificate", cert_file.display()));
    }
    for der in &chain {
        x509_parser::certificate::X509Certificate::from_der(der.as_ref())
            .map_err(|e| format!("invalid certificate in `{}`: {e}", cert_file.display()))?;
    }
    let key = PrivateKeyDer::from_pem_file(key_file)
        .map_err(|e| format!("cannot read the key `{}`: {e}", key_file.display()))?;
    rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("unusable key `{}`: {e}", key_file.display()))?;
    let key = key.secret_der().to_vec();
    if PrivateKeyDer::try_from(key.clone()).is_err() {
        return Err(format!(
            "unsupported key format in `{}`",
            key_file.display()
        ));
    }
    Ok(Arc::new(pingora::utils::tls::CertKey::new(
        chain.into_iter().map(|c| c.to_vec()).collect(),
        key,
    )))
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

/// Rules that match every request.
const CATCH_ALL: [&str; 2] = ["PathPrefix(`/`)", "Host(`*`)"];

/// Warns about routes that can never match because an earlier route on the same listener has
/// the same rule or matches everything (M-RT-02).
fn report_shadowed(listener: &str, routes: &[Arc<RouteRuntime>], out: &mut Vec<Diagnostic>) {
    for (i, route) in routes.iter().enumerate() {
        let earlier = routes[..i]
            .iter()
            .find(|e| e.expr == route.expr || CATCH_ALL.contains(&e.expr.as_str()));
        if let Some(earlier) = earlier {
            out.push(
                Diagnostic::warning(
                    format!("{}.match", path_key("routes", &route.name)),
                    format!(
                        "this route never matches on listener `{listener}`: route `{}` comes first and matches the same requests",
                        earlier.name
                    ),
                )
                .with_hint("give this route a higher `priority`, or make its rule more specific"),
            );
        }
    }
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
        .filter_map(|(name, l)| match new_listener(name, l) {
            Ok(listener) => Some((name.clone(), listener)),
            Err(message) => {
                out.push(Diagnostic::error(
                    format!("{}.tls.client_auth", path_key("listeners", name)),
                    message,
                ));
                None
            }
        })
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
        for listener_name in &config.route_listeners(route) {
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
        report_shadowed(&listener.name, &listener.routes, out);
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

fn new_listener(name: &str, listener: &Listener) -> Result<ListenerRuntime, String> {
    let tls = match &listener.tls {
        Some(tls) => Some(crate::runtime::ListenerTls {
            policy: tls.policy,
            client_auth: tls.client_auth.as_ref().map(client_auth).transpose()?,
        }),
        None => None,
    };
    Ok(ListenerRuntime {
        name: Arc::from(name),
        address: listener.address,
        tls,
        timeouts: listener.timeouts,
        ping: listener.ping.clone(),
        routes: Vec::new(),
        https_redirect: None,
    })
}

/// The CA bundles of a listener's `client_auth`, read now so a missing file fails the reload.
fn client_auth(config: &rdock_model::config::ClientAuth) -> Result<rdock_tls::ClientAuth, String> {
    let mut bundles = Vec::new();
    for file in &config.ca_files {
        let text = std::fs::read_to_string(file)
            .map_err(|e| format!("cannot read `{}`: {e}", file.display()))?;
        bundles.push((file.display().to_string(), text));
    }
    if config.cloudflare {
        bundles.push((
            "Cloudflare origin-pull CA".to_owned(),
            rdock_tls::CLOUDFLARE_ORIGIN_PULL_CA.to_owned(),
        ));
    }
    rdock_tls::ClientAuth::new(
        config.mode == rdock_model::config::ClientAuthMode::Required,
        &bundles,
    )
    .map_err(|e| e.to_string())
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
    let mirror = match &route.mirror {
        Some(m) => {
            let Some(target) = services.get(key(&m.service)) else {
                out.push(unavailable("mirror service", &m.service));
                return None;
            };
            Some(MirrorRuntime {
                service: target.clone(),
                percent: m.percent,
                slots: Arc::new(tokio::sync::Semaphore::new(MIRRORS_IN_FLIGHT)),
            })
        }
        None => None,
    };
    Some(Arc::new(RouteRuntime {
        name: Arc::from(name),
        priority,
        rule,
        service: service.clone(),
        expr: expr.to_string(),
        max_body: route.max_body,
        grpc_web: chain.iter().any(|m| m.translates_grpc_web()),
        middlewares: chain.into(),
        timeouts: route.timeouts,
        mirror,
    }))
}

/// Collects the certificates that routes with `tls: auto` need and no configured certificate
/// covers: public names go to ACME, private names to the local CA (ADR-0020).
struct AutoTls<'a> {
    certs: &'a CertIndex,
    /// Whether automatic certificates are on.
    acme: bool,
    mode: Mode,
    requests: BTreeSet<CertRequest>,
    /// Names the local CA certifies.
    local: BTreeSet<String>,
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
        self.local_names(path, private, out);
        let dns_provider = options
            .and_then(|o| o.dns_provider.clone())
            .or_else(|| config.effective_acme().and_then(|a| a.dns_provider.clone()));
        if options.is_some_and(|o| !o.domains.is_empty()) {
            if !public.is_empty() {
                // Private names would make the whole order fail; the local CA covers them.
                self.requests.insert(CertRequest {
                    names: hosts
                        .into_iter()
                        .filter(|h| !rdock_tls::is_private_name(h))
                        .collect(),
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

    /// Hands private names to the local CA, except single-label names, which name constraints
    /// cannot express.
    fn local_names(&mut self, path: &str, private: Vec<String>, out: &mut Vec<Diagnostic>) {
        let (local, single): (Vec<String>, Vec<String>) = private
            .into_iter()
            .partition(|h| rdock_tls::is_local_ca_name(h));
        self.local.extend(local);
        if single.is_empty() {
            return;
        }
        let suggestion = single
            .iter()
            .map(|h| {
                let h = h.strip_prefix("*.").unwrap_or(h);
                format!("`{h}.internal` or `{h}.home.arpa`")
            })
            .collect::<Vec<_>>()
            .join(", ");
        out.push(
            Diagnostic::warning(
                format!("{path}.tls"),
                format!(
                    "no certificate authority, not even the local one, can certify the single-label name {}",
                    single.join(", ")
                ),
            )
            .with_hint(format!(
                "use {suggestion}, add a certificate under `certificates`, or use `tls: off` on a plain listener"
            )),
        );
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
