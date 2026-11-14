//! The data plane's side of a cluster (ADR-0031): who this instance is, and the store it
//! shares certificates through. Read from the configuration file at start, like `runtime`; a
//! change needs a restart.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rdock_cluster::ClusterStore;
use rdock_model::cluster::{Cluster, ClusterStoreType};

/// What `cluster` gives this process.
pub(crate) struct ClusterContext {
    /// The section as read at start.
    pub(crate) settings: Cluster,
    /// The certificate manager's share of the cluster.
    pub(crate) acme: Option<rdock_acme::ClusterAcme>,
    /// The channel to the control plane, with `cluster.control`.
    pub(crate) channel: Option<rdock_cluster::agent::Channel>,
    /// The cluster store, when there is one.
    pub(crate) store: Option<Arc<dyn ClusterStore>>,
    /// This instance's name.
    pub(crate) instance: String,
}

/// Reads `cluster` from the configuration file. A file that cannot be loaded or has errors
/// gives `None`; the start then reports its problems as usual.
pub(crate) fn read(config: Option<&Path>) -> Option<Cluster> {
    let path = config?;
    rdock_config::load_file(path)
        .ok()
        .filter(|loaded| !loaded.has_errors())
        .and_then(|loaded| loaded.config.cluster)
        .map(|cluster| *cluster)
}

/// This instance's name: `cluster.instance`, else an id generated once and kept in
/// `$RDOCK_DATA_DIR/cluster/instance`.
pub(crate) fn instance_name(settings: &Cluster, data_dir: &Path) -> anyhow::Result<String> {
    if let Some(name) = &settings.instance {
        return Ok(name.clone());
    }
    let path = data_dir.join("cluster").join("instance");
    match std::fs::read_to_string(&path) {
        Ok(text) if rdock_model::cluster::is_instance_name(text.trim()) => {
            Ok(text.trim().to_owned())
        }
        Ok(_) | Err(_) => {
            let id = format!(
                "rdock-{}",
                rdock_credentials::random_base62(10)
                    .context("the system random generator failed")?
            );
            rdock_cluster::dir::write_private(&path, format!("{id}\n").as_bytes())
                .with_context(|| format!("writing the instance id {}", path.display()))?;
            Ok(id)
        }
    }
}

/// The agent's settings from `cluster.control`.
fn agent_settings(
    settings: &Cluster,
    control: &rdock_model::cluster::ClusterControl,
    data_dir: &Path,
) -> anyhow::Result<rdock_cluster::agent::AgentSettings> {
    let ca_pem = match &control.ca_file {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading cluster.control.ca_file {}", path.display()))?,
        ),
        None => None,
    };
    let join_token = match &control.join_token {
        Some(token) => Some(
            rdock_config::interpolate::expand(token, &rdock_config::System)
                .map_err(|e| anyhow::anyhow!("cluster.control.join_token: {e}"))?
                .trim()
                .to_owned(),
        ),
        None => None,
    };
    Ok(rdock_cluster::agent::AgentSettings {
        url: control
            .url
            .as_url()
            .as_str()
            .trim_end_matches('/')
            .to_owned(),
        ca_pem,
        ca_pin: control.ca_pin.clone(),
        identity_dir: control
            .identity_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("cluster")),
        join_token,
        instance: settings.instance.clone(),
        poll_timeout: control.poll_timeout.as_std(),
        version: crate::VERSION.to_owned(),
    })
}

/// The cluster context for `settings`: with `cluster.control`, the instance is enrolled first
/// (once; later starts use the identity on disk and need no control plane), and the store it
/// names is opened.
pub(crate) async fn context(
    settings: Cluster,
    data_dir: &Path,
    metrics: &rdock_observability::Metrics,
) -> anyhow::Result<ClusterContext> {
    let channel = match &settings.control {
        Some(control) => {
            let agent = agent_settings(&settings, control, data_dir)?;
            Some(
                rdock_cluster::agent::connect(agent)
                    .await
                    .map_err(|e| anyhow::anyhow!("cannot join the cluster: {e}"))?,
            )
        }
        None => None,
    };
    let instance = match &channel {
        Some(channel) => channel.identity().instance,
        None => instance_name(&settings, data_dir)?,
    };
    let mut shared_store: Option<Arc<dyn ClusterStore>> = None;
    let acme = match settings.effective_store() {
        Some(store) => {
            let shared: Arc<dyn ClusterStore> = match store.kind {
                ClusterStoreType::Directory => Arc::new(rdock_cluster::DirStore::shared(
                    store
                        .path
                        .clone()
                        .context("cluster.store.path is required for `type: directory`")?,
                )),
                ClusterStoreType::Control => channel
                    .as_ref()
                    .context("`cluster.store.type: control` needs `cluster.control`")?
                    .store(),
            };
            shared_store = Some(shared.clone());
            Some(rdock_acme::ClusterAcme {
                store: shared,
                instance: instance.clone(),
                lease_ttl: store.lease_ttl.as_std(),
                barrier_timeout: store.barrier_timeout.as_std(),
                metrics: Some(metrics.clone()),
            })
        }
        None => None,
    };
    Ok(ClusterContext {
        settings,
        acme,
        channel,
        store: shared_store,
        instance,
    })
}

/// How long a member waits at start for its first copy of the challenge answers.
const PRIME_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Before the listeners accept: writes this member's heartbeat and copies the challenge answers
/// in the store, so a member that has just started can already answer a validation another
/// member started (a CA may ask any member). Bounded: with the store away the start goes on
/// after [`PRIME_WITHIN`] and the answers follow once it answers.
pub(crate) async fn prime(context: &ClusterContext, challenges: &Arc<rdock_tls::Challenges>) {
    let Some(acme) = &context.acme else {
        return;
    };
    if acme.prime(challenges, PRIME_WITHIN).await {
        tracing::debug!("copied the cluster's challenge answers before accepting");
    } else {
        tracing::warn!(
            within = ?PRIME_WITHIN,
            "the cluster store did not answer at start; starting without the challenge answers, which follow once it answers"
        );
    }
}

/// Hands bundles to the engine and the channel's state to the status and metrics.
struct EngineSink {
    engine: Arc<crate::engine::Engine>,
    metrics: rdock_observability::Metrics,
}

#[async_trait::async_trait]
impl rdock_cluster::agent::BundleSink for EngineSink {
    fn serving(&self) -> u64 {
        self.engine
            .control
            .as_ref()
            .map_or(0, crate::engine::control::ControlState::serving)
    }

    async fn apply(
        &self,
        bundle: rdock_cluster::protocol::Bundle,
    ) -> Result<Vec<serde_json::Value>, Vec<serde_json::Value>> {
        self.engine.apply_bundle(bundle).await
    }

    fn connection(&self, connected: bool, error: Option<String>) {
        self.metrics
            .cluster_control_connected
            .set(i64::from(connected));
        if let Some(control) = &self.engine.control {
            control.set_connection(connected, error);
        }
    }

    fn counted(&self, result: &str) {
        self.metrics
            .cluster_bundles
            .with_label_values(&[result])
            .inc();
    }
}

/// Starts the agent's bundle loop for `engine`; runs until `stop` turns true.
pub(crate) fn start_agent(
    context: &ClusterContext,
    engine: &Arc<crate::engine::Engine>,
    metrics: &rdock_observability::Metrics,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    let Some(channel) = context.channel.clone() else {
        return;
    };
    let sink = Arc::new(EngineSink {
        engine: engine.clone(),
        metrics: metrics.clone(),
    });
    tokio::spawn(channel.run(sink, stop));
}

/// Reports the limit driver's state as metrics.
struct LimitMetrics(rdock_observability::Metrics);

impl rdock_cluster::limits::Observer for LimitMetrics {
    fn store(&self, up: bool) {
        self.0.cluster_limits_store_up.set(i64::from(up));
    }

    fn claim(&self, outcome: &'static str) {
        self.0
            .cluster_limit_claims
            .with_label_values(&[outcome])
            .inc();
    }

    fn members(&self, count: u64) {
        self.0
            .cluster_limits_members
            .set(i64::try_from(count).unwrap_or(i64::MAX));
    }
}

/// The backend of cluster-scoped limits: Redis with `cluster.limits.store: redis`, else the
/// cluster store.
fn limit_backend(
    context: &ClusterContext,
    limits: &rdock_model::cluster::ClusterLimits,
) -> anyhow::Result<Option<(Arc<dyn rdock_cluster::limits::ShareBackend>, &'static str)>> {
    use rdock_model::cluster::LimitStoreType;
    match (limits.store, &limits.redis) {
        (LimitStoreType::Redis, Some(redis)) => {
            let address = rdock_model::cluster::RedisAddress::parse(&redis.url)
                .map_err(|e| anyhow::anyhow!("cluster.limits.redis.url: {e}"))?;
            let tls = if address.tls {
                let ca = match &redis.ca_file {
                    Some(path) => Some(std::fs::read_to_string(path).with_context(|| {
                        format!("reading cluster.limits.redis.ca_file {}", path.display())
                    })?),
                    None => None,
                };
                Some(
                    rdock_cluster::resp::tls_config(ca.as_deref())
                        .map_err(|e| anyhow::anyhow!("cluster.limits.redis TLS: {e}"))?,
                )
            } else {
                None
            };
            // The password is resolved here, from its reference, and kept only in the client.
            let password = match &redis.password {
                Some(reference) => Some(
                    rdock_config::interpolate::expand(reference, &rdock_config::System)
                        .map_err(|e| anyhow::anyhow!("cluster.limits.redis.password: {e}"))?
                        .trim_end_matches(['\r', '\n'])
                        .to_owned(),
                ),
                None => None,
            };
            let client = rdock_cluster::resp::RespClient::new(rdock_cluster::resp::RespSettings {
                host: address.host,
                port: address.port,
                database: address.database,
                tls,
                username: redis.username.clone(),
                password,
                timeout: redis.timeout.as_std(),
            });
            Ok(Some((
                Arc::new(rdock_cluster::limits::RedisShares::new(
                    client,
                    &redis.key_prefix,
                )),
                "redis",
            )))
        }
        (LimitStoreType::Redis, None) => Ok(None),
        (LimitStoreType::Cluster, _) => Ok(context.store.clone().map(|store| {
            (
                Arc::new(rdock_cluster::limits::StoreShares::new(store))
                    as Arc<dyn rdock_cluster::limits::ShareBackend>,
                "cluster store",
            )
        })),
    }
}

/// Starts sharing cluster-scoped limits (`scope: cluster`) through the store `cluster.limits`
/// names; runs until `stop` turns true. Without a store, cluster-scoped limits count per
/// instance.
pub(crate) fn start_limits(
    context: &ClusterContext,
    shared: &rdock_limits::shared::SharedLimits,
    metrics: &rdock_observability::Metrics,
    stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let limits = context.settings.limits.clone().unwrap_or_default();
    let Some((backend, store_name)) = limit_backend(context, &limits)? else {
        return Ok(());
    };
    shared.configure(
        limits.headroom_percent,
        limits.fallback == rdock_model::cluster::LimitFallback::Instance,
    );
    metrics.cluster_limits_store_up.set(0);
    let driver = rdock_cluster::limits::LimitsDriver {
        limits: shared.clone(),
        backend,
        instance: context.instance.clone(),
        sync_interval: limits.sync_interval.as_std(),
        observer: Arc::new(LimitMetrics(metrics.clone())),
        store_name,
    };
    tokio::spawn(driver.run(stop));
    Ok(())
}
