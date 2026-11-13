//! The compiled configuration the data plane serves from. A `Runtime` is immutable; a reload
//! builds a new one and swaps it in, and each request keeps the one it started with.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use rdock_balancer::{BackendState, Balancer, Pool, StickyKeys};
use rdock_middleware::Chain;
use rdock_model::config::{
    ListenerProtocol, ListenerTimeouts, ProxyProtocolIn, StartTls, TlsPolicy,
};
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
    /// Listeners by name.
    pub listeners: BTreeMap<String, ListenerRuntime>,
    /// Client IP policy.
    pub client_ip: ClientIpPolicy,
    /// Request size limits.
    pub limits: Limits,
    /// Access log writer.
    pub access_log: Arc<AccessLog>,
    /// Certificates, served through the shared resolver.
    pub certificates: Arc<rdock_tls::CertIndex>,
    /// Certificates served by one listener only (listener name → its certificates).
    pub listener_certificates: std::collections::HashMap<String, Arc<rdock_tls::CertIndex>>,
    /// Certificates to issue automatically.
    pub cert_requests: Vec<rdock_tls::CertRequest>,
    /// Names that get a certificate from the local CA (private names, ADR-0020).
    pub local_cert_names: Vec<String>,
    /// Expiry of each certificate (name, Unix seconds), for metrics.
    pub cert_expiry: Vec<(String, i64)>,
    /// Every service, for health checks.
    pub services: BTreeMap<String, Arc<ServiceRuntime>>,
    /// The backend pools of UDP services, by service name, for their TCP health checks.
    pub udp_pools: BTreeMap<String, Arc<ServiceRuntime>>,
    /// OpenTelemetry tracer, when `observability.tracing` is set.
    pub tracer: Option<Arc<rdock_observability::Tracer>>,
    /// How rdock's own error answers are rendered outside routes (`defaults.errors.format`).
    pub errors: rdock_model::config::ErrorFormat,
    /// Usage metering (`observability.metering`), when configured.
    pub metering: Option<Arc<rdock_observability::metering::Meter>>,
    /// GeoIP databases (`geoip`), when configured.
    pub geoip: Option<Arc<crate::geoip::GeoIp>>,
    /// Which GeoIP fields the access log carries (`geoip.log`).
    pub geoip_log: rdock_model::settings::GeoIpLog,
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
            listener_certificates: std::collections::HashMap::new(),
            cert_requests: Vec::new(),
            local_cert_names: Vec::new(),
            cert_expiry: Vec::new(),
            services: BTreeMap::new(),
            udp_pools: BTreeMap::new(),
            tracer: None,
            errors: rdock_model::config::ErrorFormat::Html,
            metering: None,
            geoip: None,
            geoip_log: rdock_model::settings::GeoIpLog::default(),
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
    /// `http`, `https`, `tcp` or `udp`.
    pub protocol: ListenerProtocol,
    /// `tcp` listeners: the protocol whose request to start TLS is answered.
    pub starttls: Option<StartTls>,
    /// TLS settings, for HTTPS listeners and `tcp` listeners that terminate TLS.
    pub tls: Option<ListenerTls>,
    /// Client-side timeouts.
    pub timeouts: ListenerTimeouts,
    /// Options of the listening socket and of accepted connections.
    pub socket: rdock_model::config::ListenerSocket,
    /// `https` listeners: TLS handshakes in progress at once; `None` is no bound.
    pub max_handshakes: Option<u32>,
    /// HTTP/2 settings (`http` and `https` listeners).
    pub http2: rdock_model::config::ListenerHttp2,
    /// `https` listeners: the TLS client fingerprints to compute (`tls.fingerprint`).
    pub fingerprint: Option<rdock_model::config::TlsFingerprint>,
    /// Inbound PROXY protocol.
    pub proxy_protocol: Option<ProxyProtocolIn>,
    /// Routes in evaluation order.
    pub routes: Vec<Arc<RouteRuntime>>,
    /// `routes` by host, built once the order is final; requests look routes up here.
    pub route_index: crate::router::RouteIndex,
    /// TCP routes in evaluation order. A connection keeps these, not the whole runtime, for
    /// as long as it is relayed.
    pub tcp_routes: Arc<[Arc<crate::tcp::TcpRouteRuntime>]>,
    /// UDP routes in evaluation order (`udp` listeners).
    pub udp_routes: Arc<[Arc<crate::udp::UdpRouteRuntime>]>,
    /// Session caps (`udp` listeners).
    pub udp_sessions: rdock_model::config::UdpSessions,
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
    /// Session resumption: tickets and the session cache.
    pub resumption: rdock_tls::ResumptionSettings,
    /// The listener's name when it serves certificates of its own (`tls.certificates`): its
    /// server identities differ from the shared ones, so it is a resumption class of its own.
    pub scope: Option<String>,
    /// Keys read from `tls.tickets.key_file`; a change rebuilds the acceptor, which replaces
    /// the keys of the class in place.
    pub file_keys: Option<Vec<rdock_tls::tickets::TicketKey>>,
}

impl ListenerTls {
    /// The resumption class of this listener (`rdock_tls::tickets`).
    #[must_use]
    pub fn class(&self) -> rdock_tls::ClassKey {
        rdock_tls::ClassKey {
            policy: format!("{:?}", self.policy).to_ascii_lowercase(),
            client_auth: self
                .client_auth
                .as_ref()
                .map(|auth| (auth.required, auth.identity())),
            scope: self.scope.clone(),
            settings: self.resumption.clone(),
        }
    }
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
    /// The route's class for `admission` load shedding.
    pub priority_class: rdock_model::route::PriorityClass,
    /// Compiled rule.
    pub rule: Rule,
    /// The rule in canonical form, to find routes that can never match.
    pub expr: String,
    /// Target service; none when the last middleware answers every request.
    pub service: Option<Arc<ServiceRuntime>>,
    /// Middlewares, in order, with the phases they use (computed once, here).
    pub middlewares: Chain,
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
    /// The route's cache policy, when its chain has a `cache` middleware (F-WEB-03).
    pub cache: Option<Arc<rdock_cache::RoutePolicy>>,
    /// How rdock's own error answers are rendered on this route (F-GW-04).
    pub errors: rdock_model::config::ErrorFormat,
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
    /// A service that answers every request itself with this status (`respond`); then
    /// `backends` and `split` are empty.
    pub respond: Option<u16>,
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
    /// Tiers, locality and Peak-EWMA settings (ADR-0031).
    pub selection: Selection,
}

/// How a backend is chosen beyond the balancing policy: priority tiers, the preferred zone and
/// what `peak_ewma` measures.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    /// Movement of traffic between priority tiers.
    pub failover: Failover,
    /// The zone whose backends are preferred (`locality: prefer` with a known zone); `None`
    /// ignores zones.
    pub zone: Option<Arc<str>>,
    /// Latency sampling of `peak_ewma`; `None` for other policies.
    pub peak: Option<PeakRuntime>,
}

/// Movement of traffic between priority tiers.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum Failover {
    /// The first tier with an available backend gets everything.
    #[default]
    Strict,
    /// Tiers share traffic by health × this overprovisioning factor (Envoy).
    Spill(f64),
}

/// Latency sampling of `peak_ewma`.
#[derive(Debug, Clone, Copy)]
pub struct PeakRuntime {
    /// Time constant of the average.
    pub decay: std::time::Duration,
    /// What a sample measures.
    pub measure: rdock_model::service::LatencyMeasure,
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
    /// Priority tier, 0 first (a `backup` is tier 1).
    pub priority: u8,
    /// Zones the backend is local to: its `for_zones` hints, else its `zone`.
    pub zones: Arc<[Arc<str>]>,
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
    /// Weight ramp after recovery or joining.
    pub slow_start: Option<rdock_balancer::SlowStart>,
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
    /// Statistical outlier detectors and how often they run.
    pub outlier: Option<(rdock_balancer::Outlier, std::time::Duration)>,
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
    /// Not in priority tier 0.
    pub backup: bool,
    /// Priority tier, 0 first.
    pub priority: u8,
    /// In the service's preferred zone.
    pub local: bool,
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
    /// Whether `endpoint` still has the answer this source was taken from, read in place
    /// (no reference count is taken).
    fn is_current(&self, endpoint: &Endpoint) -> bool {
        match (endpoint, self) {
            (Endpoint::Tcp { addrs, .. }, Self::Addrs(a)) => Arc::ptr_eq(&addrs.load(), a),
            (Endpoint::Srv { targets, .. }, Self::Srv(a)) => Arc::ptr_eq(&targets.load(), a),
            (Endpoint::Unix(_), Self::Fixed) => true,
            _ => false,
        }
    }

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
        // The request path: compare the cached answers with the live ones in place.
        if let Some(cached) = self.members.load().as_ref()
            && cached.sources.len() == self.backends.len()
            && cached
                .sources
                .iter()
                .zip(&self.backends)
                .all(|(source, backend)| source.is_current(&backend.endpoint))
        {
            return cached.list.clone();
        }
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
        let now = std::time::Instant::now();
        let slow = self.health.slow_start.as_ref();
        // A backend that joins ramps up only when the pool already has one at full weight.
        let join = slow.is_some_and(|s| s.on_join) && self.pool.has_settled_backend(slow, now);
        let mut list = Vec::new();
        for (backend, source) in self.backends.iter().zip(sources) {
            // (candidate, weight, priority)
            let candidates: Vec<(Candidate, u32, u8)> = match (&backend.endpoint, source) {
                (Endpoint::Tcp { host, .. }, Source::Addrs(addrs)) => addrs
                    .iter()
                    .map(|addr| {
                        let candidate = Candidate::Tcp {
                            host: host.clone(),
                            addr: *addr,
                        };
                        (candidate, backend.weight, backend.priority)
                    })
                    .collect(),
                (Endpoint::Srv { .. }, Source::Srv(targets)) => {
                    // RFC 2782: the lowest priority is used; higher ones only as backups, one
                    // tier below the backend's own.
                    let best = targets.iter().map(|t| t.priority).min().unwrap_or(0);
                    targets
                        .iter()
                        .map(|t| {
                            let candidate = Candidate::Tcp {
                                host: t.host.clone(),
                                addr: t.addr,
                            };
                            let weight = backend.weight.saturating_mul(u32::from(t.weight.max(1)));
                            let tier = backend.priority + u8::from(t.priority > best);
                            (candidate, weight, tier.min(MAX_TIER))
                        })
                        .collect()
                }
                (Endpoint::Unix(path), _) => {
                    vec![(
                        Candidate::Unix(path.clone()),
                        backend.weight,
                        backend.priority,
                    )]
                }
                _ => Vec::new(),
            };
            let local = self
                .selection
                .zone
                .as_ref()
                .is_some_and(|zone| backend.zones.iter().any(|z| z == zone));
            for (candidate, weight, priority) in candidates {
                let id = candidate.to_string();
                let (state, created) = self.pool.state_created(&id);
                if created && join {
                    state.join(now);
                }
                list.push(Arc::new(Member {
                    state,
                    sticky: self.sticky.as_ref().map(|s| s.keys.token(&id)),
                    candidate,
                    id,
                    weight,
                    backup: priority > 0,
                    priority,
                    local,
                }));
            }
        }
        self.pool
            .retain(&list.iter().map(|m| m.id.as_str()).collect());
        list.into()
    }
}

/// The lowest priority tier (ADR-0031).
pub const MAX_TIER: u8 = 7;

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
