//! HTTP, TCP and UDP services: backend pools, balancing, health, retries and timeouts.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::{BackendAddress, Duration};

/// An HTTP service: a pool of backends, a weighted split over other services, or a fixed
/// answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Service {
    /// Backend servers. Set this, `split` or `respond`.
    #[serde(default)]
    pub backends: Vec<Backend>,
    /// Weighted traffic split over other services (canary, blue/green). Set this, `backends`
    /// or `respond`.
    #[serde(default)]
    pub split: Vec<SplitTarget>,
    /// Answer every request with this status instead of forwarding it, e.g. `500` for a
    /// share of a split that has no valid backend. Set this, `backends` or `split`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub respond: Option<Respond>,
    /// Protocol spoken to the backends. gRPC uses `h2c` (cleartext) or `https`.
    #[serde(default)]
    pub scheme: Scheme,
    /// How a backend is chosen for each request.
    #[serde(default)]
    pub load_balancer: LoadBalancer,
    /// Active and passive health checks.
    #[serde(default)]
    pub health: Option<Health>,
    /// Retries of failed requests (ADR-0010, ADR-0015, ADR-0022). Without this setting the
    /// defaults below apply: a connection that cannot be opened is tried again on another
    /// backend, up to twice, within the retry budget (ADR-0028). `attempts: 0` turns retries off.
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
    /// Requests in flight across the pool; more are answered `503` (circuit breaker).
    #[serde(default)]
    pub max_requests: Option<u32>,
    /// Requests in flight to one backend; a backend at the limit gets no more until one ends.
    #[serde(default)]
    pub max_connections_per_backend: Option<u32>,
}

/// A fixed answer of a service (`respond`): the status with ReverseDock's error page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Respond {
    /// Status code, from 200 to 599.
    pub status: u16,
}

/// One backend server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Backend {
    /// `host:port`, `[ipv6]:port` or `unix:///path.sock`.
    pub address: BackendAddress,
    /// Relative share of traffic.
    #[serde(default = "one")]
    pub weight: u32,
    /// Only used when no primary backend is available.
    #[serde(default)]
    pub backup: bool,
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
    /// Fewest requests in flight relative to the weight (an HTTP/1.1 request holds one
    /// connection, so this is also the least-connections policy).
    LeastConn,
    /// Fewest requests in flight relative to the weight.
    LeastRequests,
    /// Power of two random choices.
    P2c,
    /// Consistent hash of the client IP (Traefik's `hrw`).
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
    /// What happens when no backend is healthy.
    pub when_all_down: WhenAllDown,
    /// A backend that becomes healthy ramps up its weight over this time.
    pub slow_start: Option<Duration>,
}

/// Behaviour when every backend is unhealthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WhenAllDown {
    /// Send to every backend anyway: a broken health check must not cause an outage.
    #[default]
    FailOpen,
    /// Answer `503`.
    FailClosed,
}

/// How a probe checks a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthMode {
    /// An HTTP request with the service's scheme.
    #[default]
    Http,
    /// A TCP (or Unix socket) connection.
    Tcp,
    /// The gRPC health protocol (`grpc.health.v1.Health/Check`); healthy when `SERVING`.
    Grpc,
}

/// Periodic probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ActiveHealth {
    /// Probe type.
    pub mode: HealthMode,
    /// Path to request (HTTP).
    pub path: String,
    /// Method (HTTP).
    pub method: HealthMethod,
    /// `Host` of the probe (HTTP); the backend address when unset.
    pub hostname: Option<String>,
    /// Extra request headers (HTTP).
    pub headers: std::collections::BTreeMap<String, String>,
    /// Text the response body must contain (HTTP).
    pub expected_body: Option<String>,
    /// gRPC service name to check; empty checks the whole server.
    pub grpc_service: String,
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
            mode: HealthMode::Http,
            path: "/".to_owned(),
            method: HealthMethod::Get,
            hostname: None,
            headers: std::collections::BTreeMap::new(),
            expected_body: None,
            grpc_service: String::new(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(2),
            healthy: 2,
            unhealthy: 3,
            expected_status: "200-399".to_owned(),
            port: None,
        }
    }
}

/// Probe methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum HealthMethod {
    /// `GET`.
    #[default]
    Get,
    /// `HEAD`.
    Head,
}

/// Ejection of backends that keep failing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PassiveHealth {
    /// Failures within `window` that eject a backend.
    pub failures: u32,
    /// Sliding window for counting failures.
    pub window: Duration,
    /// How long an ejected backend stays out before one request tries it again; doubled for
    /// each ejection in a row, up to 5 minutes.
    pub ejection: Duration,
    /// Answers that count as failures, besides connection errors, resets and timeouts.
    pub statuses: Vec<u16>,
    /// Largest share of the pool ejected at once, in percent.
    pub max_ejection_percent: u32,
}

impl Default for PassiveHealth {
    fn default() -> Self {
        Self {
            failures: 5,
            window: Duration::from_secs(30),
            ejection: Duration::from_secs(30),
            statuses: vec![502, 503, 504],
            max_ejection_percent: 50,
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
    /// Retries in flight may be at most this share of the requests in flight, in percent
    /// (at least 3 are always allowed), so retries cannot overload a failing pool.
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

/// Retryable failures. Nothing is retried once the client has received a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetryOn {
    /// The connection to the backend could not be established (also a connect timeout).
    /// Nothing reached the backend, so this is retried for every method.
    Connect,
    /// The connection was reset before response headers arrived.
    Reset,
    /// The backend did not answer within `timeouts.read`.
    Timeout,
    /// The backend answered `502 Bad Gateway`.
    #[serde(rename = "502")]
    BadGateway,
    /// The backend answered `503 Service Unavailable`.
    #[serde(rename = "503")]
    ServiceUnavailable,
    /// The backend answered `504 Gateway Timeout`.
    #[serde(rename = "504")]
    GatewayTimeout,
}

impl RetryOn {
    /// The status code for the status variants.
    #[must_use]
    pub fn status(self) -> Option<u16> {
        match self {
            Self::BadGateway => Some(502),
            Self::ServiceUnavailable => Some(503),
            Self::GatewayTimeout => Some(504),
            Self::Connect | Self::Reset | Self::Timeout => None,
        }
    }
}

/// Upstream timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Timeouts {
    /// Establishing a connection.
    pub connect: Duration,
    /// Establishing a connection when a failed connect would be retried on another
    /// backend: the attempt gives up after this long, so a stopped backend costs about a
    /// second instead of `connect` (ADR-0026). The last attempt always waits `connect`.
    pub connect_attempt: Duration,
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
            connect_attempt: Duration::from_secs(1),
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
    /// `Path` attribute.
    #[serde(default = "root_path")]
    pub path: String,
    /// Key that signs the cookie, as a `${file:…}` or `${env:…}` reference. Without it, a key is
    /// generated once and kept in `$RDOCK_DATA_DIR/sticky.key`.
    #[serde(default)]
    pub secret: Option<String>,
    /// Keys of earlier rotations: cookies signed with them stay valid and are replaced.
    #[serde(default)]
    pub previous_secrets: Vec<String>,
}

fn root_path() -> String {
    "/".to_owned()
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
    /// Connection timeouts.
    #[serde(default)]
    pub timeouts: TcpTimeouts,
}

/// Timeouts of a TCP service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TcpTimeouts {
    /// Establishing a connection to a backend.
    pub connect: Duration,
    /// A connection with no data in either direction for this long is closed (NGINX
    /// `proxy_timeout`).
    pub idle: Duration,
    /// Once one side has finished sending, the other side gets this long to finish too
    /// before both are closed (Traefik `terminationDelay`).
    pub termination_delay: Duration,
}

impl Default for TcpTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            idle: Duration::from_secs(600),
            termination_delay: Duration::from_millis(100),
        }
    }
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

/// A UDP service: backends that receive the datagrams of UDP routes. Each session (one client
/// address and port) gets its own connected socket to one backend, chosen when the session
/// starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UdpService {
    /// Backend servers (`host:port`; Unix sockets are not supported). `weight` sets each
    /// one's share of new sessions; `backup` ones get sessions only when no other is up.
    pub backends: Vec<Backend>,
    /// How a new session's backend is chosen.
    #[serde(default)]
    pub load_balancer: UdpLoadBalancer,
    /// Session timeouts.
    #[serde(default)]
    pub timeouts: UdpTimeouts,
    /// End a session after this many datagrams from the backend (NGINX `proxy_responses`).
    /// `1` suits request-and-answer protocols such as DNS: the socket is released as soon as
    /// the answer is relayed. Omitted, a session ends only when idle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub responses: Option<u32>,
    /// Detach a session from its client address after this many datagrams from the client
    /// (NGINX `proxy_requests`): the next datagram opens a new session, possibly to another
    /// backend, while the detached one still relays its replies until `responses` or `idle`
    /// ends it. `1` balances every datagram on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<u32>,
    /// Backend health: passive ejection on ICMP "port unreachable", optional TCP probes.
    #[serde(default)]
    pub health: UdpHealth,
}

/// Timeouts of a UDP service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UdpTimeouts {
    /// A session with no datagram in either direction for this long is closed and its socket
    /// released. Default 60 s, Envoy's `udp_proxy` default; Traefik uses 3 s and NGINX
    /// 10 minutes (sources in docs/research/v0.8-cache-extensibility.md §5.1, checked
    /// 2026-11-11).
    pub idle: Duration,
}

impl Default for UdpTimeouts {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(60),
        }
    }
}

/// Backend selection for new UDP sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UdpLoadBalancer {
    /// Selection policy.
    pub policy: UdpLbPolicy,
}

/// How a UDP session's backend is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UdpLbPolicy {
    /// Weighted round-robin.
    #[default]
    RoundRobin,
    /// Weighted random.
    Random,
    /// Fewest open sessions relative to the weight.
    LeastSessions,
    /// Consistent hash of the client IP: every session of a client goes to the same backend
    /// while it is up.
    IpHash,
}

/// Health of the backends of a UDP service.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UdpHealth {
    /// Ejection after ICMP "port unreachable" answers (seen as refused sends or receives on a
    /// session's connected socket). On by default.
    pub passive: UdpPassiveHealth,
    /// Periodic TCP connection probes, for backends that also listen on TCP (a DNS server
    /// does on port 53). Off by default: a generic UDP probe cannot tell a healthy server
    /// from one that drops datagrams.
    pub tcp_check: Option<UdpTcpCheck>,
    /// What happens when no backend is healthy.
    pub when_all_down: WhenAllDown,
}

/// Passive health of a UDP service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UdpPassiveHealth {
    /// Count refusals and eject backends. `false` only ends the affected session.
    pub enabled: bool,
    /// Refusals within `window` that eject a backend.
    pub failures: u32,
    /// Sliding window for counting refusals.
    pub window: Duration,
    /// How long an ejected backend gets no new sessions before one session tries it again;
    /// doubled for each ejection in a row, up to 5 minutes.
    pub ejection: Duration,
    /// Largest share of the pool ejected at once, in percent.
    pub max_ejection_percent: u32,
}

impl Default for UdpPassiveHealth {
    fn default() -> Self {
        Self {
            enabled: true,
            failures: 3,
            window: Duration::from_secs(30),
            ejection: Duration::from_secs(30),
            max_ejection_percent: 50,
        }
    }
}

/// TCP probes of the backends of a UDP service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UdpTcpCheck {
    /// TCP port to connect to; the backend's port when omitted.
    pub port: Option<u16>,
    /// Time between probes.
    pub interval: Duration,
    /// Probe timeout.
    pub timeout: Duration,
    /// Consecutive successes before a backend is healthy.
    pub healthy: u32,
    /// Consecutive failures before a backend is unhealthy.
    pub unhealthy: u32,
}

impl Default for UdpTcpCheck {
    fn default() -> Self {
        Self {
            port: None,
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(2),
            healthy: 2,
            unhealthy: 3,
        }
    }
}
