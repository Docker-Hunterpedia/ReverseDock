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
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent YAML switch (enabled, dashboard, api_writes, open \
              metrics); revisit if two of them ever become one mode"
)]
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
    /// Password rules for dashboard users.
    pub passwords: AdminPasswords,
    /// How long a dashboard login lasts.
    pub sessions: AdminSessions,
    /// Who must use a second factor (TOTP) to log in.
    pub mfa: MfaPolicy,
    /// API tokens for scripts and Prometheus.
    pub tokens: AdminTokens,
    /// Serve `/metrics` without a token when the listener is a loopback address, as before
    /// v0.5, for scrapers on the same machine that cannot send one.
    pub metrics_unauthenticated_on_loopback: bool,
    /// The hash-chained audit log in `$RDOCK_DATA_DIR/audit/`.
    pub audit: AdminAudit,
    /// Allow configuration changes through the admin API and the dashboard. Set `false`
    /// (`GitOps`) when Git and the file provider are the only source of truth.
    pub api_writes: bool,
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
            passwords: AdminPasswords::default(),
            sessions: AdminSessions::default(),
            mfa: MfaPolicy::default(),
            tokens: AdminTokens::default(),
            metrics_unauthenticated_on_loopback: false,
            audit: AdminAudit::default(),
            api_writes: true,
        }
    }
}

/// The audit log (ADR-0024): every admin write, login, MFA event, refusal and session end, as
/// JSON lines that each carry the SHA-256 of the line before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AdminAudit {
    /// How long rotated files are kept (1d–3650d).
    pub retention: Duration,
    /// A file is closed and a new one started at this size (1 MiB–1 GiB).
    pub max_file_size: ByteSize,
    /// Also send each record to a syslog server.
    pub forward: Option<AuditForward>,
}

impl Default for AdminAudit {
    fn default() -> Self {
        Self {
            retention: Duration::from_secs(400 * 86_400),
            max_file_size: ByteSize::mib(64),
            forward: None,
        }
    }
}

/// Where audit records are forwarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditForward {
    /// Syslog server as `host:port`; records are RFC 5424 messages with the JSON record as
    /// the message.
    pub syslog: String,
    /// `udp` (default) or `tcp` (octet counting, RFC 6587).
    #[serde(default)]
    pub transport: SyslogTransport,
}

/// How syslog messages travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SyslogTransport {
    /// One datagram per record.
    #[default]
    Udp,
    /// A stream with octet-counted framing.
    Tcp,
}

/// API token rules (ADR-0024).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AdminTokens {
    /// Lifetime of a new token when its creator gives none, in days (1–365).
    pub default_expiry_days: u16,
    /// Allow tokens that never expire. Off by default: a leaked token should stop working.
    pub allow_no_expiry: bool,
}

impl Default for AdminTokens {
    fn default() -> Self {
        Self {
            default_expiry_days: 90,
            allow_no_expiry: false,
        }
    }
}

/// Dashboard session lifetimes (ADR-0024; OWASP Session Management Cheat Sheet, checked
/// 2026-10-31). Both are between 5 minutes and 12 hours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AdminSessions {
    /// A session without requests for this long ends.
    pub idle: Duration,
    /// A session ends this long after login, however active.
    pub absolute: Duration,
}

impl Default for AdminSessions {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(30 * 60),
            absolute: Duration::from_secs(8 * 60 * 60),
        }
    }
}

/// Who must log in with a TOTP code besides the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MfaPolicy {
    /// Admins must enrol before they can do anything else; others may.
    #[default]
    RequiredForAdmins,
    /// Every user must enrol.
    Required,
    /// Nobody must; anyone may.
    Optional,
}

/// Password rules for dashboard users (ADR-0024). There are no composition rules: length and
/// a list of common passwords are what protect a password (NIST SP 800-63B §3.1.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AdminPasswords {
    /// Shortest password accepted, in characters (8–128). The longest is 128.
    pub min_length: u8,
    /// Argon2id cost. Values below the OWASP minimum are refused; existing hashes are
    /// upgraded at the next login after a change.
    pub argon2: Argon2Cost,
    /// A file with one password per line (for example a breached-password list) refused in
    /// addition to the bundled list of common passwords. Read once at start, offline.
    pub blocklist_file: Option<PathBuf>,
}

impl Default for AdminPasswords {
    fn default() -> Self {
        Self {
            min_length: 12,
            argon2: Argon2Cost::default(),
            blocklist_file: None,
        }
    }
}

/// Argon2id parameters. The default is the OWASP minimum, m=19456 KiB, t=2, p=1 (Password
/// Storage Cheat Sheet, checked 2026-10-31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Argon2Cost {
    /// Memory per hash in KiB (19456–262144).
    pub memory_kib: u32,
    /// Passes over the memory (2–10).
    pub iterations: u32,
    /// Lanes (1–8).
    pub parallelism: u32,
}

impl Default for Argon2Cost {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
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
