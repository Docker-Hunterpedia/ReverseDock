#![doc = include_str!("../README.md")]

mod abuse;
mod account;
pub mod audit;
mod auth;
mod bootstrap;
mod cache;
mod caller;
mod cluster;
mod config_api;
mod consumers;
mod dashboard;
mod deprecated;
#[cfg(feature = "fault-injection")]
pub mod fault;
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
mod tenancy;
mod tokens;
mod totp;
mod users;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

pub use cache::{CachePurge, PurgeOutcome};
pub use cluster::{ClusterPublish, RolloutAction};
pub use openapi::json as openapi_json;
pub use server::{Running, Sockets, StartError, start, start_with};
pub use telemetry::metric_catalogue;

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
    /// Every HTTP cache store: name, kind, objects, bytes, limits and counters.
    async fn caches(&self) -> serde_json::Value;
    /// Removes what `selector` covers from the store `store` of this instance.
    async fn purge_cache(&self, store: String, selector: CachePurge) -> PurgeOutcome;
    /// Quota use on this instance: every `quota` middleware with its window and the keys it
    /// counted, only `consumer`'s when given.
    async fn quotas(&self, consumer: Option<String>) -> serde_json::Value {
        let _ = consumer;
        serde_json::json!({ "quotas": [] })
    }
    /// Forgets `consumer`'s counts in every quota, or in `middleware` only; returns how many
    /// counts were removed.
    async fn reset_quota(&self, consumer: String, middleware: Option<String>) -> usize {
        let _ = (consumer, middleware);
        0
    }
    /// The keys banned by `abuse` middlewares on this instance now: `{ "bans": [ { middleware,
    /// key, since, until, remaining_seconds } ] }`.
    async fn bans(&self) -> serde_json::Value {
        serde_json::json!({ "bans": [] })
    }
    /// Lifts the ban of `key` in every `abuse` middleware, or in `middleware` only; returns
    /// how many bans were lifted.
    async fn unban(&self, key: String, middleware: Option<String>) -> usize {
        let _ = (key, middleware);
        0
    }
    /// The control plane's enrolled instances with their state; `None` on a data plane.
    async fn cluster_instances(&self) -> Option<serde_json::Value> {
        None
    }
    /// Revokes an enrolled instance: `Some(Ok(false))` when there is no such instance; `None`
    /// on a data plane.
    async fn cluster_revoke(&self, instance: String) -> Option<Result<bool, String>> {
        let _ = instance;
        None
    }
    /// Creates a join token valid for `ttl_seconds` (the configured default when `None`) on
    /// behalf of `actor`: `token` (shown once), `id`, `expires_at`, `ca_pin`; `None` on a data
    /// plane.
    async fn cluster_create_token(
        &self,
        ttl_seconds: Option<u64>,
        actor: String,
    ) -> Option<Result<serde_json::Value, String>> {
        let _ = (ttl_seconds, actor);
        None
    }
    /// Published revisions, newest first; `None` on a data plane.
    async fn cluster_revisions(&self) -> Option<serde_json::Value> {
        None
    }
    /// Publishes `{ "document": … }` or `{ "rollback_to": N }` on behalf of `actor`; `None`
    /// on a data plane.
    async fn cluster_publish(
        &self,
        request: serde_json::Value,
        actor: String,
    ) -> Option<ClusterPublish> {
        let _ = (request, actor);
        None
    }
    /// The rollout of the newest revision; `None` on a data plane.
    async fn cluster_rollout(&self) -> Option<serde_json::Value> {
        None
    }
    /// Resumes a halted or soaking rollout on behalf of `actor`; `None` on a data plane.
    async fn cluster_rollout_resume(&self, actor: String) -> Option<RolloutAction> {
        let _ = actor;
        None
    }
    /// Abandons a running or halted rollout on behalf of `actor` (publishes the stable
    /// revision again); `None` on a data plane.
    async fn cluster_rollout_abandon(&self, actor: String) -> Option<RolloutAction> {
        let _ = actor;
        None
    }
    /// The configuration's tenants (H-SEC-07), for scoping users and tokens; none by default,
    /// which refuses every scoped caller.
    async fn tenants(&self) -> rdock_model::tenant::Tenants {
        rdock_model::tenant::Tenants::new()
    }
    /// Replaces the running binary by handing the listeners to a new process (ADR-0031);
    /// returns once the new process serves or the attempt failed. Only offered on the Unix
    /// socket.
    async fn upgrade(&self, request: UpgradeRequest) -> UpgradeOutcome {
        let _ = request;
        UpgradeOutcome::Refused(serde_json::json!({ "error": "binary upgrades are not available" }))
    }
}

/// A binary upgrade asked for over the admin socket (`rdock upgrade`).
#[derive(Debug, Clone)]
pub struct UpgradeRequest {
    /// The binary to run; `upgrade.binary` when not given.
    pub binary: Option<std::path::PathBuf>,
    /// Install it even when its version is older than the running one.
    pub allow_downgrade: bool,
    /// Who asked, as the audit log names them.
    pub actor: String,
}

/// How a binary upgrade ended.
#[derive(Debug, Clone)]
pub enum UpgradeOutcome {
    /// The new process serves; this one drains. The document describes it.
    Serving(serde_json::Value),
    /// Not attempted (a check failed, or another upgrade runs); nothing changed.
    Refused(serde_json::Value),
    /// Attempted and rolled back: this process serves on.
    Failed(serde_json::Value),
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
    /// Not applied because its stored copy (history entry, API snapshot) could not be written,
    /// typically a full disk; nothing changed (ADR-0033). Answered `507 Insufficient Storage`.
    NotStored(String),
}

/// Where and how the admin API listens (ADR-0024).
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent switches from `admin:`, each with its own meaning"
)]
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
    /// Take the client's address from `X-Forwarded-For` on connections from loopback.
    pub trust_forwarded_on_loopback: bool,
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent switches from `admin:`, each with its own meaning"
)]
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
    trust_forwarded: bool,
    audit: Arc<audit::Audit>,
    api_writes: bool,
    logs: Arc<stream::Hub>,
    events: Arc<stream::Hub>,
    quota: stream::Quota,
    telemetry: telemetry::Telemetry,
    /// Password hashes in progress: two at a time, sixteen waiting at most.
    hashing: rdock_limits::ConcurrencyLimiter,
    /// Configuration writes and dry runs, shared by every caller: each one compiles a whole
    /// configuration on the proxy's runtime, so an unbounded loop of them would slow it down
    /// (H-ENG-04).
    config_work: rdock_limits::RateLimiter,
    /// Requests per caller (token, user or socket): the admin side shares the proxy's CPU, so
    /// no single caller may drive it hard enough to slow requests down (H-ENG-04).
    api_rate: rdock_limits::RateLimiter,
}

/// Lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    rdock_credentials::hex(bytes)
}

/// Fuzzing entry point (`tests/fuzz`, target `admin_input`): arbitrary text as every JSON
/// request body the admin API reads, as the query string of every operation that takes one
/// (through axum's own `Query` extractor), and through the small parsers in front of
/// authentication (user names, admin token values, TOTP codes, the tenancy table). Only
/// refusals are expected; the properties checked are those the handlers rely on.
#[doc(hidden)]
pub fn fuzz_admin_input(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Request bodies, as the handlers' `Json` extractor reads them.
    macro_rules! bodies {
        ($($t:ty),* $(,)?) => { $( let _ = serde_json::from_str::<$t>(text); )* };
    }
    bodies!(
        manage::NewUser,
        manage::UserChange,
        manage::TokenRequest,
        auth::Credentials,
        account::Code,
        account::Reauth,
        account::PasswordChange,
        cache::PurgeRequest,
        cluster::JoinTokenRequest,
        cluster::ClusterPublishRequest,
        config_api::Rollback,
        config_api::Import,
        consumers::ConsumerSpec,
        consumers::NewKey,
        resources::BackendRef,
    );
    // Query strings, as the `Query` extractor reads them.
    if let Ok(uri) = http::Uri::try_from(format!("/api/v1/x?{text}")) {
        use axum::extract::Query;
        let _ = Query::<abuse::BanScope>::try_from_uri(&uri);
        let _ = Query::<consumers::QuotaScope>::try_from_uri(&uri);
        let _ = Query::<manage::AuditQuery>::try_from_uri(&uri);
        let _ = Query::<resources::Window>::try_from_uri(&uri);
        let _ = Query::<stream::Filter>::try_from_uri(&uri);
    }
    // A user name is lower case, 1-64 characters of a fixed set, and normalising is idempotent.
    if let Some(name) = users::normalize_name(text) {
        assert!(!name.is_empty() && name.len() <= 64, "{name:?}");
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)),
            "{name:?}"
        );
        assert_eq!(users::normalize_name(&name).as_deref(), Some(name.as_str()));
    }
    // A token value splits into an ID and a secret taken from the value itself.
    if let Some((id, secret)) = tokens::parse_value(text) {
        assert!(text.contains(id) && text.contains(secret));
    }
    // A TOTP code is accepted for one step at most, and only a step newer than the last one.
    let mut parts = text.splitn(4, '\n');
    if let (Some(secret), Some(code), Some(now), Some(last)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    {
        let now = now.trim().parse::<u64>().unwrap_or_default();
        let last = last.trim().parse::<u64>().unwrap_or_default();
        if let Some(step) = totp::verify(secret, code, now, last) {
            assert!(step > last, "step {step} not after {last}");
            assert!(
                step.abs_diff(now / 30) <= 1,
                "step {step} too far from {now}"
            );
        }
    }
    // The tenancy table answers for any method and route template.
    if let Some((method, template)) = text.split_once(' ')
        && let Ok(method) = http::Method::from_bytes(method.as_bytes())
    {
        let _ = tenancy::classify(&method, Some(template));
    }
}
