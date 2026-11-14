//! Clusters (H-HA-01…03, ADR-0031): the data-plane side (`cluster`) and the control-plane side
//! (`control`, read by `rdock control run`).
//!
//! A data plane with `cluster.control` enrols with the control plane once (a single-use join
//! token over TLS pinned to the cluster CA), then pulls configuration bundles over mutual TLS and
//! shares certificates through a store. Without `cluster.control` a `cluster.store` of type
//! `directory` shares certificates through a directory every instance mounts.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::{Duration, HttpUrl, ListenAddress};

/// The data-plane side of a cluster.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Cluster {
    /// This instance's name in leases and the control plane's instance list: letters, digits,
    /// `.`, `-` and `_`, at most 63 characters. Default: the identity the control plane gave
    /// at enrolment, or (without a control plane) an id generated once and kept in
    /// `$RDOCK_DATA_DIR/cluster/instance`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// The control plane this data plane takes its configuration from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<ClusterControl>,
    /// Where certificates, the ACME account, leases and challenge answers are shared. Default:
    /// the control plane when `control` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<ClusterStore>,
    /// How `rate_limit` and `quota` with `scope: cluster` share their budgets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<ClusterLimits>,
}

/// Where cluster-scoped limits keep their shared counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LimitStoreType {
    /// The cluster store (`cluster.store`: the control plane or the shared directory).
    #[default]
    Cluster,
    /// A Redis-compatible server (`redis`).
    Redis,
}

/// What an instance enforces while the limit store cannot be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LimitFallback {
    /// Its share: the limit divided by the number of instances it last knew of, against what
    /// it admitted itself in the window. The cluster stays near the limit under even load.
    #[default]
    Share,
    /// The whole limit on its own, as with `scope: instance` (N instances admit up to N times
    /// the limit).
    Instance,
}

/// Shared budgets for `rate_limit` and `quota` with `scope: cluster` (ADR-0031).
///
/// Each instance claims a part of each key's budget from the store ahead of use and admits
/// requests against what it claimed, so the request path never waits on the store. The
/// cluster admits at most `L + N × max(c, ⌈L / N⌉)` per key and window, where `L` is the
/// limit, `N` the number of instances, `c = max(1, ⌈L × headroom_percent / (100 × N)⌉)` the
/// headroom an instance may use beyond its claims, and `⌈L / N⌉` what an instance admits for a
/// key new to it until its first claim returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterLimits {
    /// `cluster` (default) or `redis`.
    pub store: LimitStoreType,
    /// The Redis-compatible server, for `store: redis`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis: Option<RedisStore>,
    /// How often claims, membership and recovery are attended to (claims a request needs are
    /// sent at once). Default 1s (100ms–10s).
    pub sync_interval: Duration,
    /// How far an instance may admit beyond the budget it has claimed, as a percentage of the
    /// limit split between the instances: larger values absorb store latency at high request
    /// rates, smaller ones tighten the bound. Default 10 (0–100).
    pub headroom_percent: u8,
    /// `share` (default) or `instance`: what an instance enforces while the store is away.
    pub fallback: LimitFallback,
}

impl Default for ClusterLimits {
    fn default() -> Self {
        Self {
            store: LimitStoreType::Cluster,
            redis: None,
            sync_interval: Duration::from_secs(1),
            headroom_percent: 10,
            fallback: LimitFallback::Share,
        }
    }
}

/// A Redis-compatible server (Redis, Valkey, …) for cluster-scoped limits. rdock uses
/// `INCRBY`, `DECRBY`, `PEXPIREAT`, `ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`, `TIME` (membership is
/// judged by the server's clock; without it, by each instance's), `AUTH`, `SELECT` and
/// `PING`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedisStore {
    /// `rediss://host:6379/0` (TLS) or `redis://host:6379/0`; the path is the database
    /// number. Plain `redis://` is accepted for loopback addresses only, unless
    /// `allow_plaintext` is set. Credentials belong in `username` and `password`, not here.
    pub url: String,
    /// The ACL user name (Redis 6 and later); without it `AUTH` sends only the password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The password. A secret: reference a file or a variable, e.g.
    /// `"${file:/run/secrets/redis}"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// CA certificates (PEM) to verify the server with instead of the system's roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    /// The longest a connection or a command may take before the store counts as away.
    /// Default 1s (100ms–10s).
    #[serde(default = "default_redis_timeout")]
    pub timeout: Duration,
    /// Prefix of every key rdock writes. Default `rdock:`.
    #[serde(default = "default_redis_prefix")]
    pub key_prefix: String,
    /// Allow `redis://` (no TLS) to an address that is not a loopback address. Off by default:
    /// the password and the counters would cross the network in clear.
    #[serde(default)]
    pub allow_plaintext: bool,
}

fn default_redis_timeout() -> Duration {
    Duration::from_secs(1)
}

fn default_redis_prefix() -> String {
    "rdock:".to_owned()
}

/// How a data plane reaches its control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterControl {
    /// The control plane's cluster address, e.g. `https://control.example.com:7443`. Always
    /// `https`.
    pub url: HttpUrl,
    /// The cluster CA certificate (PEM), as `rdock control ca` prints it. One of `ca_file` and
    /// `ca_pin` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    /// The SHA-256 of the cluster CA certificate (DER), as `sha256:<64 hex digits>`; `rdock
    /// control token create` prints it. The first connection accepts the control plane only
    /// when its chain contains a CA with this digest; the CA is then kept in `identity_dir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pin: Option<String>,
    /// Where the instance's key, certificate and the cluster CA are kept (mode 0700). Default
    /// `$RDOCK_DATA_DIR/cluster`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_dir: Option<PathBuf>,
    /// The single-use join token from `rdock control token create`, used only while the
    /// instance has no identity yet. A secret: reference a file, e.g.
    /// `"${file:/run/secrets/rdock-join}"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_token: Option<String>,
    /// How long one request for the next bundle waits on the control plane before it is asked
    /// again. Default 30s (5s–5m).
    #[serde(default = "default_poll_timeout")]
    pub poll_timeout: Duration,
}

fn default_poll_timeout() -> Duration {
    Duration::from_secs(30)
}

/// The kinds of cluster store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterStoreType {
    /// The control plane serves the store to enrolled members over mutual TLS. Leases carry a
    /// fencing token the control plane checks on every write.
    #[default]
    Control,
    /// A directory every instance mounts (NFS, EFS, a shared volume). Best effort: lock files
    /// with an expiry that depends on the instances' clocks, and no enforced fencing.
    Directory,
}

/// Where a cluster shares certificates, the ACME account, leases and challenge answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterStore {
    /// `control` (default) or `directory`.
    #[serde(rename = "type")]
    pub kind: ClusterStoreType,
    /// The shared directory, for `type: directory`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// How long a lease on a certificate name lasts unless its holder renews it (every third of
    /// it). Default 60s (10s–10m).
    pub lease_ttl: Duration,
    /// How long the instance that orders a certificate waits for every live member to hold an
    /// HTTP-01 or TLS-ALPN-01 answer before the CA is told to validate. Members that have not
    /// confirmed by then cannot answer; validation goes ahead. Default 10s (1s–2m).
    pub barrier_timeout: Duration,
}

impl Default for ClusterStore {
    fn default() -> Self {
        Self {
            kind: ClusterStoreType::Control,
            path: None,
            lease_ttl: Duration::from_secs(60),
            barrier_timeout: Duration::from_secs(10),
        }
    }
}

impl Cluster {
    /// The store in effect: the configured one, else the control plane's when `control` is set.
    #[must_use]
    pub fn effective_store(&self) -> Option<ClusterStore> {
        match (&self.store, &self.control) {
            (Some(store), _) => Some(store.clone()),
            (None, Some(_)) => Some(ClusterStore::default()),
            (None, None) => None,
        }
    }
}

/// The control-plane side of a cluster, read by `rdock control run` (never by `rdock run`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ControlPlane {
    /// The cluster listener data planes connect to (mutual TLS, HTTP/2). Default
    /// `127.0.0.1:7443`: set an address other machines reach.
    pub listener: ListenAddress,
    /// DNS names and IP addresses on the control plane's server certificate, as data planes
    /// write them in `cluster.control.url`. `localhost`, `127.0.0.1`, `::1` and the listener's
    /// IP are always included.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// A display name for the cluster.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Lifetime of the client certificate each data plane receives; it is renewed when a third
    /// is left. A data plane whose certificate expires while the control plane is away keeps
    /// serving but must enrol again with a new token. Default 30d (1h–90d).
    pub identity_lifetime: Duration,
    /// How long a join token from `rdock control token create` stays usable. Default 1h
    /// (1m–30d).
    pub join_token_ttl: Duration,
    /// Published revisions kept for listing and rollback. Default 50 (1–1000).
    pub history: u32,
    /// A data plane that has not asked for a bundle for this long is shown as offline and is
    /// not chosen as a canary. Default 90s (10s–1h).
    pub offline_after: Duration,
    /// How a published revision reaches the data planes: one canary first, then the rest.
    pub rollout: Rollout,
}

/// How a revision is rolled out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RolloutMode {
    /// One canary takes the revision first; the rest follow after `soak` once it acknowledged
    /// it. A refusal (NACK) by any instance halts the rollout.
    #[default]
    Canary,
    /// Every connected data plane takes the revision at once.
    All,
}

/// Staged rollout of published revisions (H-HA-02, ADR-0031).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Rollout {
    /// `canary` (default) or `all`. The first revision of a cluster and rollbacks (including
    /// an abandoned rollout) always go to every instance at once.
    pub mode: RolloutMode,
    /// The instance that takes each revision first. When it is offline or not set, the first
    /// online instance by name is chosen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary: Option<String>,
    /// How long the canary serves a revision it acknowledged before the rest take it. Default
    /// 60s (0s–24h).
    pub soak: Duration,
    /// How long the canary has to report on a revision; without a report by then the rollout
    /// halts. Default 2m (10s–1h).
    pub canary_timeout: Duration,
    /// Rolling back automatically when the canary's health drops: planned, only `false` is
    /// accepted.
    pub auto_rollback: bool,
}

impl Default for Rollout {
    fn default() -> Self {
        Self {
            mode: RolloutMode::Canary,
            canary: None,
            soak: Duration::from_secs(60),
            canary_timeout: Duration::from_secs(120),
            auto_rollback: false,
        }
    }
}

impl Default for ControlPlane {
    fn default() -> Self {
        Self {
            listener: ListenAddress::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 7443),
            names: Vec::new(),
            name: None,
            identity_lifetime: Duration::from_secs(30 * 24 * 3600),
            join_token_ttl: Duration::from_secs(3600),
            history: 50,
            offline_after: Duration::from_secs(90),
            rollout: Rollout::default(),
        }
    }
}

/// Top-level sections a data plane with `cluster.control` keeps from its own file: everything
/// else comes from the control plane's bundle (ADR-0031).
pub const INSTANCE_SECTIONS: [&str; 11] = [
    "$schema",
    "version",
    "cluster",
    "admin",
    "providers",
    "runtime",
    "upgrade",
    "locality",
    "lifecycle",
    "observability",
    "secrets",
];

/// Top-level sections a bundle may not carry.
pub const NOT_IN_BUNDLES: [&str; 2] = ["cluster", "control"];

/// Whether `value` is an instance name: letters, digits, `.`, `-`, `_`; 1–63 characters.
#[must_use]
pub fn is_instance_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Whether `value` is `sha256:` and 64 lower-case hex digits.
#[must_use]
pub fn is_ca_pin(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The sections of a data plane's own file that a control plane's bundle provides instead
/// (`cluster.control` is set): one error for each.
#[must_use]
pub fn instance_file_diagnostics(source: &serde_json::Value) -> Vec<crate::Diagnostic> {
    let Some(map) = source.as_object() else {
        return Vec::new();
    };
    map.keys()
        .filter(|key| !INSTANCE_SECTIONS.contains(&key.as_str()))
        .map(|key| {
            crate::Diagnostic::error(
                key.clone(),
                format!(
                    "with `cluster.control` set, `{key}` comes from the control plane's bundle"
                ),
            )
            .with_hint(format!(
                "publish it with `rdock control publish`; this file keeps only {}",
                INSTANCE_SECTIONS[2..].join(", ")
            ))
        })
        .collect()
}

/// The sections a bundle may not carry: one error for each.
#[must_use]
pub fn bundle_diagnostics(document: &serde_json::Value) -> Vec<crate::Diagnostic> {
    let Some(map) = document.as_object() else {
        return vec![crate::Diagnostic::error(
            "",
            "a bundle is a configuration document (an object)",
        )];
    };
    NOT_IN_BUNDLES
        .iter()
        .filter(|key| map.contains_key(**key))
        .map(|key| {
            crate::Diagnostic::error(
                *key,
                format!("`{key}` is set on each instance, never published in a bundle"),
            )
        })
        .collect()
}

/// The configuration a data plane runs: `bundle` with the instance sections of `local` in
/// place of the bundle's (ADR-0031).
#[must_use]
pub fn compose(bundle: &serde_json::Value, local: &serde_json::Value) -> serde_json::Value {
    let mut out = bundle.as_object().cloned().unwrap_or_default();
    if let Some(local) = local.as_object() {
        for key in INSTANCE_SECTIONS {
            if let Some(value) = local.get(key) {
                out.insert(key.to_owned(), value.clone());
            }
        }
    }
    serde_json::Value::Object(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn instance_files_keep_only_instance_sections() {
        let local = json!({ "cluster": {}, "admin": {}, "routes": {}, "listeners": {} });
        let paths: Vec<String> = instance_file_diagnostics(&local)
            .into_iter()
            .map(|d| d.path)
            .collect();
        assert_eq!(paths, ["listeners", "routes"]);
        assert_eq!(bundle_diagnostics(&json!({ "routes": {} })).len(), 0);
        assert_eq!(bundle_diagnostics(&json!({ "cluster": {} })).len(), 1);
        assert_eq!(bundle_diagnostics(&json!([])).len(), 1);
    }

    #[test]
    fn composition_takes_instance_sections_from_the_local_file() {
        let bundle = json!({ "routes": { "a": 1 }, "admin": { "enabled": false }, "lifecycle": 1 });
        let local = json!({ "cluster": { "instance": "x" }, "admin": { "enabled": true }, "routes": { "b": 2 } });
        assert_eq!(
            compose(&bundle, &local),
            json!({ "routes": { "a": 1 }, "admin": { "enabled": true }, "lifecycle": 1, "cluster": { "instance": "x" } })
        );
    }
}

/// A parsed `cluster.limits.redis.url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisAddress {
    /// `rediss://`.
    pub tls: bool,
    /// The host name or IP address (without brackets).
    pub host: String,
    /// The port (6379 by default).
    pub port: u16,
    /// The database number (0 by default).
    pub database: u32,
}

impl RedisAddress {
    /// Parses `redis://host:port/db` or `rediss://…`; the message says what is wrong.
    pub fn parse(text: &str) -> Result<Self, String> {
        let url = url::Url::parse(text).map_err(|e| format!("not a URL: {e}"))?;
        let tls = match url.scheme() {
            "rediss" => true,
            "redis" => false,
            other => return Err(format!("the scheme is `redis` or `rediss`, not `{other}`")),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(
                "credentials do not belong in the URL; use `username` and `password`".to_owned(),
            );
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err("the URL takes no query or fragment".to_owned());
        }
        let host = match url.host() {
            Some(url::Host::Domain(d)) => d.to_owned(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => return Err("the URL names no host".to_owned()),
        };
        let path = url.path().trim_matches('/');
        let database = if path.is_empty() {
            0
        } else {
            path.parse::<u32>()
                .map_err(|_| "the path is the database number, e.g. `/0`".to_owned())?
        };
        Ok(Self {
            tls,
            host,
            port: url.port().unwrap_or(6379),
            database,
        })
    }

    /// Whether the host is a loopback address or `localhost`.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.host == "localhost"
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }
}
