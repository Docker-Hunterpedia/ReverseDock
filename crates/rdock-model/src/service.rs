//! HTTP and TCP services: backend pools, balancing, health, retries and timeouts.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::{BackendAddress, Duration};

/// An HTTP service: either a pool of backends or a weighted split over other services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Service {
    /// Backend servers. Set this or `split`.
    #[serde(default)]
    pub backends: Vec<Backend>,
    /// Weighted traffic split over other services (canary, blue/green). Set this or `backends`.
    #[serde(default)]
    pub split: Vec<SplitTarget>,
    /// Protocol spoken to the backends. gRPC uses `h2c` (cleartext) or `https`.
    #[serde(default)]
    pub scheme: Scheme,
    /// How a backend is chosen for each request.
    #[serde(default)]
    pub load_balancer: LoadBalancer,
    /// Active and passive health checks.
    #[serde(default)]
    pub health: Option<Health>,
    /// Retries of failed requests (transport failures only, see ADR-0010).
    #[serde(default)]
    pub retries: Option<Retries>,
    /// Upstream timeouts.
    #[serde(default)]
    pub timeouts: Timeouts,
    /// TLS to the backends when `scheme` is `https`.
    #[serde(default)]
    pub tls: Option<UpstreamTls>,
    /// Session affinity with a cookie.
    #[serde(default)]
    pub sticky: Option<Sticky>,
    /// Forward the client's `Host` header (otherwise the backend address is used).
    #[serde(default = "crate::defaults::yes")]
    pub pass_host_header: bool,
}

/// One backend server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Backend {
    /// `host:port`, `[ipv6]:port` or `unix:///path.sock`.
    pub address: BackendAddress,
    /// Relative share of traffic.
    #[serde(default = "one")]
    pub weight: u32,
}

const fn one() -> u32 {
    1
}

/// One target of a weighted split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SplitTarget {
    /// Another service (`name` or `name@provider`).
    pub service: String,
    /// Relative share of traffic.
    pub weight: u32,
}

/// Protocols spoken to backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// HTTP/1.1 in cleartext.
    #[default]
    Http,
    /// HTTP/1.1 or HTTP/2 over TLS.
    Https,
    /// HTTP/2 in cleartext (gRPC without TLS).
    H2c,
}

/// Backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LoadBalancer {
    /// Selection policy.
    pub policy: LbPolicy,
    /// Header or cookie name for `header_hash` and `cookie_hash`.
    pub hash_on: Option<String>,
}

/// Backend selection policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LbPolicy {
    /// Weighted round-robin.
    #[default]
    RoundRobin,
    /// Weighted random.
    Random,
    /// Fewest open connections.
    LeastConn,
    /// Fewest in-flight requests.
    LeastRequests,
    /// Power of two random choices.
    P2c,
    /// Consistent hash of the client IP.
    IpHash,
    /// Consistent hash of a request header (`hash_on`).
    HeaderHash,
    /// Consistent hash of a cookie (`hash_on`).
    CookieHash,
}

/// Health checks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Health {
    /// Periodic probes.
    pub active: Option<ActiveHealth>,
    /// Ejection based on observed failures.
    pub passive: Option<PassiveHealth>,
}

/// Periodic HTTP probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ActiveHealth {
    /// Path to request.
    pub path: String,
    /// Time between probes.
    pub interval: Duration,
    /// Probe timeout.
    pub timeout: Duration,
    /// Consecutive successes before a backend is healthy.
    pub healthy: u32,
    /// Consecutive failures before a backend is unhealthy.
    pub unhealthy: u32,
    /// Accepted status codes, e.g. `200` or `200-399`.
    pub expected_status: String,
    /// Probe this port instead of the backend's.
    pub port: Option<u16>,
}

impl Default for ActiveHealth {
    fn default() -> Self {
        Self {
            path: "/".to_owned(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(2),
            healthy: 2,
            unhealthy: 3,
            expected_status: "200-399".to_owned(),
            port: None,
        }
    }
}

/// Ejection of backends that keep failing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PassiveHealth {
    /// Failures within `window` that eject a backend.
    pub failures: u32,
    /// Sliding window for counting failures.
    pub window: Duration,
    /// How long an ejected backend stays out before it is tried again.
    pub ejection: Duration,
}

impl Default for PassiveHealth {
    fn default() -> Self {
        Self {
            failures: 5,
            window: Duration::from_secs(30),
            ejection: Duration::from_secs(30),
        }
    }
}

/// Retry policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Retries {
    /// Additional attempts after the first.
    pub attempts: u32,
    /// Failures that are retried.
    pub on: Vec<RetryOn>,
    /// Maximum share of retries relative to requests, in percent, to avoid retry storms.
    pub budget_percent: u32,
    /// Also retry non-idempotent methods such as POST. Only safe if backends are idempotent.
    pub retry_non_idempotent: bool,
}

impl Default for Retries {
    fn default() -> Self {
        Self {
            attempts: 2,
            on: vec![RetryOn::Connect],
            budget_percent: 20,
            retry_non_idempotent: false,
        }
    }
}

/// Retryable failures (before upstream response headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetryOn {
    /// The connection to the backend could not be established.
    Connect,
    /// The connection was reset before response headers arrived.
    Reset,
    /// The backend did not answer within `timeouts.read`.
    Timeout,
}

/// Upstream timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Timeouts {
    /// Establishing a connection.
    pub connect: Duration,
    /// Waiting for response data.
    pub read: Duration,
    /// Sending request data.
    pub write: Duration,
    /// Keeping an idle pooled connection.
    pub idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(60),
            write: Duration::from_secs(60),
            idle: Duration::from_secs(90),
        }
    }
}

/// TLS to backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UpstreamTls {
    /// Verify the backend certificate and host name.
    #[serde(default = "crate::defaults::yes")]
    pub verify: bool,
    /// SNI and verification name, when it differs from the backend host.
    #[serde(default)]
    pub server_name: Option<String>,
    /// CA bundle used instead of the system roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Client certificate for upstream mTLS.
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    /// Client key for upstream mTLS.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
}

/// Session affinity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Sticky {
    /// Affinity cookie.
    pub cookie: StickyCookie,
}

/// Affinity cookie settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StickyCookie {
    /// Cookie name.
    pub name: String,
    /// Send only over HTTPS.
    #[serde(default = "crate::defaults::yes")]
    pub secure: bool,
    /// Hide from JavaScript.
    #[serde(default = "crate::defaults::yes")]
    pub http_only: bool,
    /// `SameSite` attribute.
    #[serde(default)]
    pub same_site: SameSite,
    /// Lifetime; a session cookie when omitted.
    #[serde(default)]
    pub max_age: Option<Duration>,
}

/// `SameSite` cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SameSite {
    /// `Lax`.
    #[default]
    Lax,
    /// `Strict`.
    Strict,
    /// `None` (requires `secure`).
    None,
}

/// A TCP service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TcpService {
    /// Backend servers.
    pub backends: Vec<Backend>,
    /// Send a PROXY protocol header to backends.
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocolVersion>,
}

/// PROXY protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolVersion {
    /// Text format.
    V1,
    /// Binary format.
    V2,
}
