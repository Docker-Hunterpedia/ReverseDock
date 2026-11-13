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
    })
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
