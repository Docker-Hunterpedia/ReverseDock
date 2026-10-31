#![doc = include_str!("../README.md")]

mod account;
pub mod audit;
mod auth;
mod bootstrap;
mod caller;
mod config_api;
mod dashboard;
mod guard;
mod limits;
mod manage;
mod openapi;
mod passwords;
mod resources;
mod routes;
mod server;
mod sessions;
mod stream;
mod telemetry;
mod tokens;
mod totp;
mod users;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

pub use openapi::json as openapi_json;
pub use server::{Running, StartError, start};

/// What the admin API reads from and asks of the running process.
#[async_trait]
pub trait Control: Send + Sync {
    /// Whether a configuration is applied and listeners are bound (and no shutdown started).
    fn ready(&self) -> bool;
    /// Prometheus text exposition, or `None` when metrics are disabled.
    fn metrics(&self) -> Option<String>;
    /// Status document for `GET /api/v1/status`.
    async fn status(&self) -> serde_json::Value;
    /// Reloads the configuration; returns whether it was applied, and the report.
    async fn reload(&self) -> (bool, serde_json::Value);
    /// The applied configuration, providers merged (`name@provider`), secrets as written.
    async fn effective_config(&self) -> serde_json::Value;
    /// The API provider's objects and their version tag (`"g<generation>-<hash>"`).
    async fn api_config(&self) -> (serde_json::Value, String);
    /// Validates and compiles with `candidate` as the API objects, applying nothing: whether
    /// it would be applied, and the diagnostics; `Err` when it is not a valid document.
    async fn dry_run(
        &self,
        candidate: serde_json::Value,
    ) -> Result<(bool, serde_json::Value), String>;
    /// Replaces the API objects when `if_match` is the current version tag.
    async fn write_api(&self, candidate: serde_json::Value, if_match: String) -> ApiWrite;
    /// The configuration history, newest first; each entry has an `id`.
    async fn history(&self) -> serde_json::Value;
    /// The API objects recorded with the history entry `id`.
    async fn history_api(&self, id: u64) -> Option<serde_json::Value>;
    /// Every service's backends: address, weight, requests in flight, breaker state, drained.
    async fn backends(&self) -> serde_json::Value;
    /// Drains or returns `backend` (its address) of `service`; `false` when there is none.
    async fn set_drained(&self, service: String, backend: String, drained: bool) -> bool;
    /// Asks for the automatic certificate covering `name` to be renewed now; `false` when
    /// none covers it.
    async fn renew_certificate(&self, name: String) -> bool;
    /// Live traffic of the last `window_seconds` (1–900): the whole proxy with one point per
    /// second, and every route and service without points.
    async fn metrics_summary(&self, window_seconds: u64) -> serde_json::Value;
    /// How a request would be routed on `listener` (the first one when empty): every route
    /// with why it does or does not match, the winner, its middlewares and the backends it
    /// would consider. `Err` for an unknown listener or an invalid request.
    async fn explain(&self, request: serde_json::Value) -> Result<serde_json::Value, String>;
}

/// The outcome of a conditional write of the API provider's objects.
#[derive(Debug)]
pub enum ApiWrite {
    /// Applied; the new version tag.
    Applied {
        /// The reload report.
        report: serde_json::Value,
        /// The version tag now current.
        etag: String,
    },
    /// The configuration was rejected; nothing changed.
    Rejected {
        /// The reload report with the diagnostics.
        report: serde_json::Value,
    },
    /// `If-Match` named an older version.
    Stale {
        /// The version tag now current.
        etag: String,
    },
    /// Not a valid document.
    Invalid(String),
}

/// Where and how the admin API listens (ADR-0024).
#[derive(Debug, Clone)]
pub struct Settings {
    /// TCP address of the admin listener.
    pub address: SocketAddr,
    /// Certificate and key for the TCP listener; required off loopback (checked by validation).
    pub tls: Option<TlsFiles>,
    /// Unix socket for the local CLI, created with mode 0600. Requests on it are trusted as
    /// the machine's administrator, like the data directory itself.
    pub socket: Option<PathBuf>,
    /// Host names accepted in `Host` and `Origin` on the TCP listener. Empty means the
    /// defaults for the address: `localhost`, `127.0.0.1` and `::1` on loopback, else the IP.
    pub allowed_hosts: Vec<String>,
    /// Worker threads of the admin runtime.
    pub threads: usize,
    /// Where users and the bootstrap token are kept: `$RDOCK_DATA_DIR/admin`.
    pub state_dir: PathBuf,
    /// Password rules for users.
    pub passwords: rdock_model::settings::AdminPasswords,
    /// Session lifetimes.
    pub sessions: rdock_model::settings::AdminSessions,
    /// Who must use a second factor.
    pub mfa: rdock_model::settings::MfaPolicy,
    /// Serve the embedded dashboard (`admin.dashboard`).
    pub dashboard: bool,
    /// API token rules (`admin.tokens`).
    pub tokens: rdock_model::settings::AdminTokens,
    /// Serve `/metrics` without a token on a loopback listener.
    pub metrics_unauthenticated_on_loopback: bool,
    /// Allow configuration writes through the API (`admin.api_writes`); off for `GitOps`.
    pub api_writes: bool,
    /// Where the audit log is written: `$RDOCK_DATA_DIR/audit`.
    pub audit_dir: PathBuf,
    /// Audit log rotation, retention and forwarding.
    pub audit: rdock_model::settings::AdminAudit,
    /// The data plane's live feeds for the log and event streams.
    pub feeds: Option<rdock_observability::feed::Feeds>,
}

/// PEM files for the admin listener's TLS.
#[derive(Debug, Clone)]
pub struct TlsFiles {
    /// Certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// Private key.
    pub key_file: PathBuf,
}

/// How a request reached the admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// The TCP listener, with or without TLS.
    Tcp { tls: bool },
    /// The local Unix socket.
    Socket,
}

/// Shared by every request.
struct State {
    control: Arc<dyn Control>,
    /// The proxy's runtime: engine calls run there, so whatever they start (health checks,
    /// providers) lives with the data plane and never on the admin runtime.
    main: tokio::runtime::Handle,
    allowed_hosts: Vec<String>,
    users: users::Users,
    bootstrap: bootstrap::Bootstrap,
    policy: passwords::Policy,
    limits: limits::LoginLimits,
    sessions: sessions::Sessions,
    mfa: rdock_model::settings::MfaPolicy,
    dashboard: bool,
    tokens: tokens::Tokens,
    token_rules: rdock_model::settings::AdminTokens,
    /// `/metrics` answers without a token (loopback listener and the setting on).
    metrics_open: bool,
    audit: audit::Audit,
    api_writes: bool,
    logs: Arc<stream::Hub>,
    events: Arc<stream::Hub>,
    quota: stream::Quota,
    telemetry: telemetry::Telemetry,
    /// Password hashes in progress: two at a time, sixteen waiting at most.
    hashing: rdock_limits::ConcurrencyLimiter,
}

/// Lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
