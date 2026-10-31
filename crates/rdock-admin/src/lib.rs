#![doc = include_str!("../README.md")]

mod account;
mod auth;
mod bootstrap;
mod dashboard;
mod guard;
mod limits;
mod passwords;
mod routes;
mod server;
mod sessions;
mod totp;
mod users;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

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
    /// Bearer token for `/api/v1` on the TCP listener.
    pub token: String,
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
    token: String,
    allowed_hosts: Vec<String>,
    users: users::Users,
    bootstrap: bootstrap::Bootstrap,
    policy: passwords::Policy,
    limits: limits::LoginLimits,
    sessions: sessions::Sessions,
    mfa: rdock_model::settings::MfaPolicy,
    dashboard: bool,
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
