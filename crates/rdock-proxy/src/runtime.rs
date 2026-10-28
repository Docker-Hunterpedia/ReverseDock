//! The compiled configuration the data plane serves from. A `Runtime` is immutable; a reload
//! builds a new one and swaps it in, and each request keeps the one it started with.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rdock_balancer::Balancer;
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
            })),
            certificates: Arc::new(rdock_tls::CertIndex::default()),
            cert_requests: Vec::new(),
            local_cert_names: Vec::new(),
            cert_expiry: Vec::new(),
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
    /// TLS policy, for HTTPS listeners.
    pub tls: Option<TlsPolicy>,
    /// Client-side timeouts.
    pub timeouts: ListenerTimeouts,
    /// Routes in evaluation order.
    pub routes: Vec<Arc<RouteRuntime>>,
    /// Plain-HTTP listeners: redirect these hosts to HTTPS when no route of the listener
    /// matches.
    pub https_redirect: Option<HttpsRedirect>,
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
    /// Target service.
    pub service: Arc<ServiceRuntime>,
    /// Middlewares, in order.
    pub middlewares: Arc<[Arc<dyn Middleware>]>,
    /// Per-route timeout overrides.
    pub timeouts: RouteTimeouts,
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
}

/// One backend.
#[derive(Debug, Clone)]
pub struct BackendRuntime {
    /// Address.
    pub endpoint: Endpoint,
    /// Relative weight.
    pub weight: u32,
}

impl ServiceRuntime {
    /// Weighted candidates: every resolved address of every backend, with the backend's weight.
    #[must_use]
    pub fn candidates(&self) -> Vec<(Candidate, u32)> {
        let mut out = Vec::new();
        for backend in &self.backends {
            match &backend.endpoint {
                Endpoint::Tcp { host, addrs, .. } => {
                    for addr in addrs.load().iter() {
                        out.push((
                            Candidate::Tcp {
                                host: host.clone(),
                                addr: *addr,
                            },
                            backend.weight,
                        ));
                    }
                }
                Endpoint::Unix(path) => out.push((Candidate::Unix(path.clone()), backend.weight)),
            }
        }
        out
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
