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
              metrics, trusted forwarding); revisit if two of them ever become one mode"
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
    /// Take the client's address from `X-Forwarded-For` on connections from loopback. Turn it
    /// on only when a route of this rdock forwards to the admin listener, so rate limits and
    /// token networks see real clients; any local process could otherwise claim an address.
    pub trust_forwarded_on_loopback: bool,
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
            trust_forwarded_on_loopback: false,
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
    /// `udp` (default), `tcp` (octet counting, RFC 6587) or `tls` (RFC 5425). Only `tls`
    /// protects records on the network.
    #[serde(default)]
    pub transport: SyslogTransport,
    /// CA that signed the syslog server's certificate, for `tls`; the system's CAs when unset.
    #[serde(default)]
    pub ca_file: Option<std::path::PathBuf>,
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
    /// The same stream over TLS, with the server's certificate and name verified.
    Tls,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Alerts {
    /// Receives each alert as a JSON `POST` (v0.3); works like a `webhook` channel.
    pub webhook: Option<Webhook>,
    /// Where alerts go, by a name you choose.
    pub channels: std::collections::BTreeMap<String, AlertChannel>,
    /// What raises an alert.
    pub rules: AlertRules,
    /// The same alert is sent again at most this often while it keeps firing.
    pub min_interval: Duration,
}

/// One alert destination (ADR-0024). URLs, secrets and passwords are secrets: write them as
/// `${file:…}` or `${env:…}` references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AlertChannel {
    /// A Slack incoming-webhook URL.
    Slack {
        /// `https://hooks.slack.com/services/…`.
        url: String,
        /// Only these rules; all when empty.
        #[serde(default)]
        rules: Vec<AlertRule>,
        /// Allow private, loopback and link-local addresses (an internal relay).
        #[serde(default)]
        allow_private_targets: bool,
    },
    /// A Discord webhook URL; mentions are disabled, so host names cannot ping anyone.
    Discord {
        /// `https://discord.com/api/webhooks/…`.
        url: String,
        /// Only these rules; all when empty.
        #[serde(default)]
        rules: Vec<AlertRule>,
        /// Allow private, loopback and link-local addresses (an internal relay).
        #[serde(default)]
        allow_private_targets: bool,
    },
    /// Anything that takes Slack's payload: Discord's `/slack` endpoint, Mattermost,
    /// Rocket.Chat.
    SlackCompatible {
        /// The incoming-webhook URL.
        url: String,
        /// Only these rules; all when empty.
        #[serde(default)]
        rules: Vec<AlertRule>,
        /// Allow private, loopback and link-local addresses (an internal relay).
        #[serde(default)]
        allow_private_targets: bool,
    },
    /// JSON `POST`, signed with Standard Webhooks when `secret` is set.
    Webhook {
        /// `https://…`.
        url: String,
        /// A `whsec_…` signing secret (Standard Webhooks).
        #[serde(default)]
        secret: Option<String>,
        /// A bearer token for `Authorization`.
        #[serde(default)]
        token: Option<String>,
        /// Only these rules; all when empty.
        #[serde(default)]
        rules: Vec<AlertRule>,
        /// Allow private, loopback and link-local addresses (an internal relay).
        #[serde(default)]
        allow_private_targets: bool,
    },
    /// E-mail through an SMTP server.
    Smtp {
        /// Server host name.
        host: String,
        /// Port: 587 for STARTTLS, 465 for implicit TLS.
        #[serde(default = "smtp_port")]
        port: u16,
        /// `starttls` (default), `implicit`, or `none` (only to a loopback relay).
        #[serde(default)]
        tls: SmtpTls,
        /// Login user.
        #[serde(default)]
        username: Option<String>,
        /// Login password.
        #[serde(default)]
        password: Option<String>,
        /// Sender address.
        from: String,
        /// Recipients.
        to: Vec<String>,
        /// Only these rules; all when empty.
        #[serde(default)]
        rules: Vec<AlertRule>,
    },
}

const fn smtp_port() -> u16 {
    587
}

/// How the SMTP connection is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    /// Plain connection upgraded with STARTTLS (port 587).
    #[default]
    Starttls,
    /// TLS from the first byte (port 465).
    Implicit,
    /// No encryption; refused unless the host is a loopback address.
    None,
}

/// A kind of alert.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AlertRule {
    /// Renewal keeps failing, or a certificate is about to expire.
    Certificates,
    /// A backend or a whole service is down.
    Backends,
    /// A service's 5xx share is above `error_rate`.
    ErrorRate,
    /// A service's p99 latency is above `latency`.
    Latency,
    /// A configuration was rejected.
    Config,
    /// Admin security events: login lockouts, user and second-factor changes, tokens used
    /// from a new address.
    Security,
}

/// What raises alerts. Certificates, backends, config and security are on; the thresholds are
/// off until set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AlertRules {
    /// Rules that are off.
    pub disabled: Vec<AlertRule>,
    /// Alert when a service's 5xx share over the window is above this, in percent.
    pub error_rate: Option<ErrorRateRule>,
    /// Alert when a service's p99 over the window is above this.
    pub latency: Option<LatencyRule>,
}

/// A 5xx-share threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorRateRule {
    /// Percent of responses that are 5xx (1–100).
    pub percent: u8,
    /// Window (1m–15m).
    #[serde(default = "five_minutes")]
    pub window: Duration,
    /// Fewer requests than this in the window never alert.
    #[serde(default = "twenty")]
    pub min_requests: u32,
}

/// A p99 latency threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LatencyRule {
    /// The p99 above which a service alerts.
    pub p99: Duration,
    /// Window (1m–15m).
    #[serde(default = "five_minutes")]
    pub window: Duration,
    /// Fewer requests than this in the window never alert.
    #[serde(default = "twenty")]
    pub min_requests: u32,
}

impl Default for Alerts {
    fn default() -> Self {
        Self {
            webhook: None,
            channels: std::collections::BTreeMap::new(),
            rules: AlertRules::default(),
            min_interval: Duration::from_secs(15 * 60),
        }
    }
}

const fn five_minutes() -> Duration {
    Duration::from_secs(300)
}

const fn twenty() -> u32 {
    20
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
