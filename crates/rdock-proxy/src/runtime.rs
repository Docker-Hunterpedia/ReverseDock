//! The compiled configuration the data plane serves from. A `Runtime` is immutable; a reload
//! builds a new one and swaps it in, and each request keeps the one it started with.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use rdock_balancer::{BackendState, Balancer, Pool, StickyKeys};
use rdock_middleware::Middleware;
use rdock_model::config::{ListenerTimeouts, TlsPolicy};
use rdock_model::route::RouteTimeouts;
use rdock_model::service::{Scheme, Timeouts};
use rdock_model::settings::Limits;
use rdock_model::values::ListenAddress;
use rdock_observability::AccessLog;

use crate::forwarded::ClientIpPolicy;
use crate::router::{HostSet, Rule};

/// Everything the data plane needs for one configuration generation.
#[derive(Debug)]
pub struct Runtime {
    /// Generation number, increased by every applied configuration.
    pub generation: u64,
    /// HTTP listeners by name.
    pub listeners: BTreeMap<String, ListenerRuntime>,
    /// Client IP policy.
    pub client_ip: ClientIpPolicy,
    /// Request size limits.
    pub limits: Limits,
    /// Access log writer.
    pub access_log: Arc<AccessLog>,
    /// Certificates, served through the shared resolver.
    pub certificates: Arc<rdock_tls::CertIndex>,
    /// Certificates to issue automatically.
    pub cert_requests: Vec<rdock_tls::CertRequest>,
    /// Names that get a certificate from the local CA (private names, ADR-0020).
    pub local_cert_names: Vec<String>,
    /// Expiry of each certificate (name, Unix seconds), for metrics.
    pub cert_expiry: Vec<(String, i64)>,
    /// Every service, for health checks.
    pub services: BTreeMap<String, Arc<ServiceRuntime>>,
    /// OpenTelemetry tracer, when `observability.tracing` is set.
    pub tracer: Option<Arc<rdock_observability::Tracer>>,
}

impl Runtime {
    /// A runtime with nothing configured, served before the first configuration is applied.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            generation: 0,
            listeners: BTreeMap::new(),
            client_ip: ClientIpPolicy::default(),
            limits: Limits::default(),
            access_log: Arc::new(AccessLog::new(&rdock_model::settings::AccessLog {
                format: rdock_model::settings::LogFormat::Off,
                redact: Vec::new(),
                sample: 1.0,
            })),
            certificates: Arc::new(rdock_tls::CertIndex::default()),
            cert_requests: Vec::new(),
            local_cert_names: Vec::new(),
            cert_expiry: Vec::new(),
            services: BTreeMap::new(),
            tracer: None,
        }
    }
}

/// One listener: where it binds and which routes it serves.
#[derive(Debug)]
pub struct ListenerRuntime {
    /// Listener name.
    pub name: Arc<str>,
    /// Bind address.
    pub address: ListenAddress,
    /// TLS settings, for HTTPS listeners.
    pub tls: Option<ListenerTls>,
    /// Client-side timeouts.
    pub timeouts: ListenerTimeouts,
    /// Routes in evaluation order.
    pub routes: Vec<Arc<RouteRuntime>>,
    /// Path answered `200 OK` before routing, for load-balancer monitors.
    pub ping: Option<String>,
    /// Plain-HTTP listeners: redirect these hosts to HTTPS when no route of the listener
    /// matches.
    pub https_redirect: Option<HttpsRedirect>,
}

/// TLS settings of a listener. Equal settings keep the running acceptor across reloads.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenerTls {
    /// Versions and cipher suites.
    pub policy: TlsPolicy,
    /// Client certificate verification.
    pub client_auth: Option<rdock_tls::ClientAuth>,
}

/// The automatic HTTP to HTTPS redirect of a plain listener.
#[derive(Debug, Clone)]
pub struct HttpsRedirect {
    /// Hosts that have an HTTPS route.
    pub hosts: HostSet,
    /// Port of the HTTPS listener (omitted from the URL when 443).
    pub port: u16,
}

/// A route, compiled.
#[derive(Debug)]
pub struct RouteRuntime {
    /// Route name.
    pub name: Arc<str>,
    /// Effective priority (explicit, or the rule length).
    pub priority: i64,
    /// Compiled rule.
    pub rule: Rule,
    /// The rule in canonical form, to find routes that can never match.
    pub expr: String,
    /// Target service.
    pub service: Arc<ServiceRuntime>,
    /// Middlewares, in order.
    pub middlewares: Arc<[Arc<dyn Middleware>]>,
    /// Per-route timeout overrides.
    pub timeouts: RouteTimeouts,
    /// Copies of requests sent to another service.
    pub mirror: Option<MirrorRuntime>,
    /// Live traffic of this route for the dashboard.
    pub live: Arc<rdock_observability::live::Ring>,
    /// Translate gRPC-Web to gRPC (the `grpc_web` middleware).
    pub grpc_web: bool,
    /// Request body limit of this route, overriding `security.limits.max_body_bytes`.
    pub max_body: Option<rdock_model::values::ByteSize>,
}

/// Request mirroring of a route.
#[derive(Debug)]
pub struct MirrorRuntime {
    /// The service that receives copies.
    pub service: Arc<ServiceRuntime>,
    /// Share of requests copied, in percent.
    pub percent: u32,
    /// Bounds the copies in flight; a copy that finds no slot is dropped.
    pub slots: Arc<tokio::sync::Semaphore>,
}

/// A backend pool.
#[derive(Debug)]
pub struct ServiceRuntime {
    /// Service name.
    pub name: Arc<str>,
    /// Protocol to the backends.
    pub scheme: Scheme,
    /// Backends.
    pub backends: Vec<BackendRuntime>,
    /// Backend selection.
    pub balancer: Balancer,
    /// What hash policies hash.
    pub hash_on: HashOn,
    /// Session affinity.
    pub sticky: Option<StickyRuntime>,
    /// Per-backend state, shared with other generations.
    pub pool: Arc<Pool>,
    /// Live traffic of this service for the dashboard.
    pub live: Arc<rdock_observability::live::Ring>,
    /// Health checks and ejection.
    pub health: HealthRuntime,
    /// Weighted targets of a `split` service (then `backends` is empty).
    pub split: Vec<(Arc<ServiceRuntime>, u32)>,
    /// Chooses among `split` targets.
    pub split_balancer: rdock_balancer::RoundRobin,
    /// Retry policy.
    pub retries: Option<rdock_model::service::Retries>,
    /// Requests in flight across the pool before new ones get `503`.
    pub max_requests: Option<u32>,
    /// Requests in flight to one backend before it gets no more.
    pub max_per_backend: Option<u32>,
    /// Backend addresses with their state, rebuilt when DNS changes an address list.
    pub(crate) members: ArcSwapOption<Members>,
    /// Upstream timeouts.
    pub timeouts: Timeouts,
    /// TLS to the backends.
    pub tls: UpstreamTls,
    /// Forward the client's `Host`.
    pub pass_host_header: bool,
}

/// TLS settings towards backends.
#[derive(Clone, Default)]
pub struct UpstreamTls {
    /// Verify certificate and host name.
    pub verify: bool,
    /// SNI and verification name, when it differs from the backend host.
    pub server_name: Option<String>,
    /// CA certificates replacing the system roots.
    pub ca: Option<Arc<[pingora::utils::tls::WrappedX509]>>,
    /// Client certificate and key presented to backends (upstream mTLS).
    pub client_cert: Option<Arc<pingora::utils::tls::CertKey>>,
    /// Distinguishes connection pools with different trust settings (Pingora's pool key does
    /// not include the CA).
    pub group_key: u64,
}

impl std::fmt::Debug for UpstreamTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTls")
            .field("verify", &self.verify)
            .field("server_name", &self.server_name)
            .field("custom_ca", &self.ca.is_some())
            .field("client_cert", &self.client_cert.is_some())
            .finish_non_exhaustive()
    }
}

/// Where a backend is reached.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// TCP: the host as configured (for SNI and `Host`) and its resolved addresses, refreshed in
    /// the background for DNS names.
    Tcp {
        /// Host name or IP literal as written.
        host: String,
        /// Port.
        port: u16,
        /// Resolved addresses.
        addrs: Arc<ArcSwap<Vec<SocketAddr>>>,
    },
    /// A Unix domain socket.
    Unix(std::path::PathBuf),
    /// The targets of an SRV record, refreshed in the background.
    Srv {
        /// SRV name as written.
        name: String,
        /// Resolved targets.
        targets: Arc<crate::dns::SrvCell>,
    },
}

/// One backend.
#[derive(Debug, Clone)]
pub struct BackendRuntime {
    /// Address.
    pub endpoint: Endpoint,
    /// Relative weight.
    pub weight: u32,
    /// Used only when no primary backend is available.
    pub backup: bool,
}

/// Health settings, compiled.
#[derive(Debug, Clone, Default)]
pub struct HealthRuntime {
    /// Periodic probes.
    pub active: Option<ActiveCheck>,
    /// Ejection after observed failures.
    pub passive: Option<PassiveCheck>,
    /// Send to every backend when none is available.
    pub fail_open: bool,
    /// Weight ramp after recovery.
    pub slow_start: Option<std::time::Duration>,
}

/// Periodic probes of every backend.
#[derive(Debug, Clone)]
pub struct ActiveCheck {
    /// Probe type.
    pub mode: rdock_model::service::HealthMode,
    /// HTTP method.
    pub method: http::Method,
    /// Path (HTTP).
    pub path: String,
    /// `Host` header (HTTP), when not the backend address.
    pub hostname: Option<String>,
    /// Extra headers (HTTP).
    pub headers: Vec<(http::HeaderName, http::HeaderValue)>,
    /// Accepted status range (HTTP).
    pub expected_status: (u16, u16),
    /// Text the body must contain (HTTP).
    pub expected_body: Option<String>,
    /// gRPC service name.
    pub grpc_service: String,
    /// Port to probe instead of the backend's.
    pub port: Option<u16>,
    /// Time between probes.
    pub interval: std::time::Duration,
    /// Probe timeout.
    pub timeout: std::time::Duration,
    /// Streaks.
    pub policy: rdock_balancer::ProbePolicy,
}

/// Passive health, compiled.
#[derive(Debug, Clone)]
pub struct PassiveCheck {
    /// Ejection thresholds.
    pub policy: rdock_balancer::EjectPolicy,
    /// Answers that count as failures.
    pub statuses: Vec<u16>,
    /// Largest ejected share, in percent.
    pub max_percent: u32,
}

/// The request value that hash policies hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashOn {
    /// No hashing (the policy is not a hash policy).
    Nothing,
    /// The client IP.
    ClientIp,
    /// A request header.
    Header(http::HeaderName),
    /// A cookie.
    Cookie(String),
}

/// Sticky-session settings, compiled.
#[derive(Debug)]
pub struct StickyRuntime {
    /// Cookie name.
    pub name: String,
    /// Signing keys.
    pub keys: StickyKeys,
    /// `; Path=…; Secure; …`, appended to `name=value` in `Set-Cookie`.
    pub attributes: String,
}

/// One backend address that can be picked, with its shared state.
#[derive(Debug)]
pub struct Member {
    /// Where to connect.
    pub candidate: Candidate,
    /// Identity: the resolved address, or `unix:` and the socket path.
    pub id: String,
    /// Relative weight.
    pub weight: u32,
    /// Used only when no primary backend is available.
    pub backup: bool,
    /// State shared across generations.
    pub state: Arc<BackendState>,
    /// The sticky cookie value naming this backend, when the service is sticky.
    pub sticky: Option<String>,
}

/// The resolved answer of one backend, as of a moment.
#[derive(Debug, Clone)]
enum Source {
    Addrs(Arc<Vec<SocketAddr>>),
    Srv(Arc<Vec<crate::dns::SrvTarget>>),
    Fixed,
}

impl Source {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Addrs(a), Self::Addrs(b)) => Arc::ptr_eq(a, b),
            (Self::Srv(a), Self::Srv(b)) => Arc::ptr_eq(a, b),
            (Self::Fixed, Self::Fixed) => true,
            _ => false,
        }
    }
}

/// The member list and the DNS answers it was built from.
#[derive(Debug)]
pub(crate) struct Members {
    sources: Vec<Source>,
    list: Arc<[Arc<Member>]>,
}

impl ServiceRuntime {
    /// Every resolved address of every backend, with the backend's weight and shared state.
    #[must_use]
    pub fn members(&self) -> Arc<[Arc<Member>]> {
        let sources: Vec<Source> = self
            .backends
            .iter()
            .map(|b| match &b.endpoint {
                Endpoint::Tcp { addrs, .. } => Source::Addrs(addrs.load_full()),
                Endpoint::Srv { targets, .. } => Source::Srv(targets.load_full()),
                Endpoint::Unix(_) => Source::Fixed,
            })
            .collect();
        if let Some(cached) = self.members.load().as_ref()
            && cached.sources.len() == sources.len()
            && cached.sources.iter().zip(&sources).all(|(a, b)| a.same(b))
        {
            return cached.list.clone();
        }
        let list = self.build_members(&sources);
        self.members.store(Some(Arc::new(Members {
            sources,
            list: list.clone(),
        })));
        list
    }

    fn build_members(&self, sources: &[Source]) -> Arc<[Arc<Member>]> {
        let mut list = Vec::new();
        for (backend, source) in self.backends.iter().zip(sources) {
            // (candidate, weight, backup)
            let candidates: Vec<(Candidate, u32, bool)> = match (&backend.endpoint, source) {
                (Endpoint::Tcp { host, .. }, Source::Addrs(addrs)) => addrs
                    .iter()
                    .map(|addr| {
                        let candidate = Candidate::Tcp {
                            host: host.clone(),
                            addr: *addr,
                        };
                        (candidate, backend.weight, backend.backup)
                    })
                    .collect(),
                (Endpoint::Srv { .. }, Source::Srv(targets)) => {
                    // RFC 2782: the lowest priority is used; higher ones only as backups.
                    let best = targets.iter().map(|t| t.priority).min().unwrap_or(0);
                    targets
                        .iter()
                        .map(|t| {
                            let candidate = Candidate::Tcp {
                                host: t.host.clone(),
                                addr: t.addr,
                            };
                            let weight = backend.weight.saturating_mul(u32::from(t.weight.max(1)));
                            (candidate, weight, backend.backup || t.priority > best)
                        })
                        .collect()
                }
                (Endpoint::Unix(path), _) => {
                    vec![(
                        Candidate::Unix(path.clone()),
                        backend.weight,
                        backend.backup,
                    )]
                }
                _ => Vec::new(),
            };
            for (candidate, weight, backup) in candidates {
                let id = candidate.to_string();
                list.push(Arc::new(Member {
                    state: self.pool.state(&id),
                    sticky: self.sticky.as_ref().map(|s| s.keys.token(&id)),
                    candidate,
                    id,
                    weight,
                    backup,
                }));
            }
        }
        self.pool
            .retain(&list.iter().map(|m| m.id.as_str()).collect());
        list.into()
    }
}

/// A concrete backend address chosen for one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    /// TCP address and the configured host name.
    Tcp {
        /// Configured host.
        host: String,
        /// Resolved address.
        addr: SocketAddr,
    },
    /// Unix socket.
    Unix(std::path::PathBuf),
}

impl std::fmt::Display for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp { addr, .. } => addr.fmt(f),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}
