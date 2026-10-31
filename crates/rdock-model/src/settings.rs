//! Security, admin, observability and lifecycle settings.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::acme::Webhook;
use crate::values::{ByteSize, Duration, HttpUrl, ListenAddress, TrustedProxy};

/// Client IP trust and request limits.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Security {
    /// Proxies whose forwarded headers are believed. Headers from anyone else are replaced.
    pub trusted_proxies: Vec<TrustedProxy>,
    /// Where the real client IP comes from.
    pub client_ip_header: ClientIpHeader,
    /// Request size limits.
    pub limits: Limits,
}

/// Sources of the client IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ClientIpHeader {
    /// `CF-Connecting-IP` when the peer is in Cloudflare's ranges, otherwise the right-most
    /// untrusted `X-Forwarded-For` entry.
    #[default]
    Auto,
    /// Right-most untrusted `X-Forwarded-For` entry.
    XForwardedFor,
    /// `X-Real-IP` from a trusted proxy.
    XRealIp,
    /// `CF-Connecting-IP` from a trusted proxy (Cloudflare's edge or a listed network); needs
    /// `cloudflare` in `trusted_proxies`.
    CfConnectingIp,
}

/// Request size limits. Requests over a limit are answered with 431, 414 or 413.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Limits {
    /// Total size of the request line and headers.
    pub max_header_bytes: ByteSize,
    /// Number of request headers.
    pub max_headers: u32,
    /// Request body size, also enforced for chunked bodies. Unlimited when omitted.
    pub max_body_bytes: Option<ByteSize>,
    /// Request target (path and query) length.
    pub max_uri_bytes: ByteSize,
    /// Requests in flight across every listener; more are answered `503` with `Retry-After`
    /// (load shedding). Unlimited when omitted.
    pub max_in_flight: Option<u32>,
    /// Idle keep-alive connections to backends kept per listener for reuse. Connections
    /// beyond it are closed when their request ends, so a busy listener keeps opening new
    /// ones. Applies to listeners started after the change.
    pub upstream_idle_connections: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: ByteSize::kib(64),
            max_headers: 100,
            max_body_bytes: None,
            max_uri_bytes: ByteSize::kib(8),
            max_in_flight: None,
            upstream_idle_connections: 4096,
        }
    }
}

/// Admin API and dashboard (ADR-0024).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Admin {
    /// Serve the admin API.
    pub enabled: bool,
    /// Address of the admin API. Loopback by default; any other address needs `tls`.
    pub listener: ListenAddress,
    /// Serve the embedded dashboard on the admin listener.
    pub dashboard: bool,
    /// TLS for the admin listener. Required when `listener` is not a loopback address.
    pub tls: Option<AdminTls>,
    /// Unix socket for the local CLI (`rdock reload`, `rdock status`), mode 0600. Default:
    /// `$RDOCK_DATA_DIR/admin.sock`.
    pub socket: Option<PathBuf>,
    /// Host names the admin listener answers to; other `Host` headers get 421 (DNS-rebinding
    /// defence). Default: `localhost`, `127.0.0.1` and `::1` on loopback, the listener's IP
    /// otherwise. Required when `listener` is on all interfaces.
    pub allowed_hosts: Vec<String>,
    /// Worker threads of the admin runtime, kept apart from the proxy's (1–16).
    pub threads: u8,
}

impl Default for Admin {
    fn default() -> Self {
        Self {
            enabled: true,
            listener: ListenAddress::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 2080),
            dashboard: true,
            tls: None,
            socket: None,
            allowed_hosts: Vec::new(),
            threads: 2,
        }
    }
}

/// Certificate and key the admin listener presents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminTls {
    /// PEM certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// PEM private key.
    pub key_file: PathBuf,
}

/// Logs, metrics and traces.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Observability {
    /// Access log.
    pub access_log: AccessLog,
    /// Metrics.
    pub metrics: Metrics,
    /// Distributed tracing.
    pub tracing: Option<Tracing>,
    /// Where certificate alerts (renewal failures, near expiry) are sent besides the log,
    /// the metrics and `rdock status`.
    pub alerts: Alerts,
}

/// Alert delivery.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Alerts {
    /// Receives each alert as a JSON `POST`.
    pub webhook: Option<Webhook>,
}

/// Access log settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AccessLog {
    /// Output format.
    pub format: LogFormat,
    /// Header names whose values are replaced by `***`.
    pub redact: Vec<String>,
    /// Share of successful requests (status below 400) that are logged, from 0 to 1. Errors
    /// and failed requests are always logged.
    pub sample: f64,
}

impl Default for AccessLog {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            redact: [
                "authorization",
                "proxy-authorization",
                "cookie",
                "set-cookie",
            ]
            .map(str::to_owned)
            .to_vec(),
            sample: 1.0,
        }
    }
}

/// Access log formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line.
    #[default]
    Json,
    /// Human-readable text.
    Text,
    /// No access log.
    Off,
}

/// Metrics settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Metrics {
    /// Serve Prometheus metrics at `/metrics` on the admin listener.
    pub prometheus: bool,
}

impl Default for Metrics {
    fn default() -> Self {
        Self { prometheus: true }
    }
}

/// OpenTelemetry tracing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Tracing {
    /// OTLP/HTTP collector endpoint, e.g. `http://tempo:4318`.
    pub otlp: HttpUrl,
    /// Share of requests traced, from 0 to 1.
    #[serde(default = "one")]
    pub sample_ratio: f64,
}

const fn one() -> f64 {
    1.0
}

/// Start-up and shutdown behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Lifecycle {
    /// On shutdown, how long open requests may finish before connections are closed. Keep it
    /// below the supervisor's stop timeout (Docker waits 10 s before it kills the process).
    pub drain_timeout: Duration,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            drain_timeout: Duration::from_secs(8),
        }
    }
}
