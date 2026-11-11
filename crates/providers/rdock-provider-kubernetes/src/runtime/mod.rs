//! The runtime half of the provider (ADR-0029): watches, the inventory, translation every
//! 100 ms at most when something changed, snapshots to the engine, and (leader only) status,
//! Events, per-Gateway Services; Secret and ConfigMap files on every replica.
//!
//! **Owner:** the cluster runtime. Only this module (and files below `src/runtime/`) changes
//! for it.
//!
//! Status: a stub. [`run`] reports the provider degraded and publishes no snapshot, so a
//! configuration with `providers.kubernetes` stays not ready (`/ready`) until it is built.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rdock_model::providers::KubernetesProvider;
use tokio::sync::watch;

/// What the provider reports to the engine; the type every provider shares. `snapshot` stays
/// `None` until every store has been listed once; the engine's readiness waits for it.
pub use rdock_config::merge::ProviderState as State;

/// The provider name and the suffix of its objects (`name@kubernetes`).
pub const PROVIDER: &str = "kubernetes";

/// Environment variable with the pod's namespace (downward API).
pub const POD_NAMESPACE_ENV: &str = "RDOCK_POD_NAMESPACE";
/// Environment variable with the pod's name (downward API).
pub const POD_NAME_ENV: &str = "RDOCK_POD_NAME";
/// The service account's namespace file, read when [`POD_NAMESPACE_ENV`] is unset.
pub const SERVICE_ACCOUNT_NAMESPACE_FILE: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Where the provider runs: what it needs from the process besides `providers.kubernetes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunContext {
    /// rdock's data directory (`--data-dir`); Secret and ConfigMap files go below it
    /// ([`crate::translate::secret_paths`]).
    pub data_dir: PathBuf,
    /// The controller's namespace: per-Gateway Services (by default) and the Lease live there.
    pub pod_namespace: String,
    /// The pod's name: the Lease holder identity and the source of Events.
    pub pod_name: String,
    /// The pod's labels, the default selector of the per-Gateway Services when
    /// `gateway.pod_selector` is empty. Filled by the runtime (downward API); empty here.
    pub pod_labels: BTreeMap<String, String>,
}

impl RunContext {
    /// The context from the environment: [`POD_NAMESPACE_ENV`], else the service account's
    /// namespace file, else `default`; [`POD_NAME_ENV`], else `HOSTNAME`, else `rdock`.
    #[must_use]
    pub fn from_env(data_dir: PathBuf) -> Self {
        let non_empty = |v: String| Some(v.trim().to_owned()).filter(|v| !v.is_empty());
        let pod_namespace = std::env::var(POD_NAMESPACE_ENV)
            .ok()
            .and_then(non_empty)
            .or_else(|| {
                std::fs::read_to_string(SERVICE_ACCOUNT_NAMESPACE_FILE)
                    .ok()
                    .and_then(non_empty)
            })
            .unwrap_or_else(|| "default".to_owned());
        let pod_name = std::env::var(POD_NAME_ENV)
            .ok()
            .and_then(non_empty)
            .or_else(|| std::env::var("HOSTNAME").ok().and_then(non_empty))
            .unwrap_or_else(|| "rdock".to_owned());
        Self {
            data_dir,
            pod_namespace,
            pod_name,
            pod_labels: BTreeMap::new(),
        }
    }

    /// The translator's settings for `provider` in this context.
    #[must_use]
    pub fn settings(&self, provider: &KubernetesProvider) -> crate::translate::Settings {
        crate::translate::Settings {
            provider: provider.clone(),
            controller_namespace: self.pod_namespace.clone(),
            data_dir: self.data_dir.clone(),
        }
    }
}

/// Why the provider cannot talk to the API server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The client configuration could not be inferred or loaded.
    #[error("cannot configure the Kubernetes client: {0}")]
    Config(String),
    /// An API call failed.
    #[error("Kubernetes API: {0}")]
    Api(#[from] kube::Error),
}

/// Runs until `shutdown` turns true, publishing on `tx`.
///
/// Stub: reports the provider degraded ("not implemented yet") and waits for shutdown.
pub async fn run(
    settings: KubernetesProvider,
    context: RunContext,
    tx: watch::Sender<State>,
    mut shutdown: watch::Receiver<bool>,
) {
    let reason = "the Kubernetes provider's cluster runtime is not implemented yet".to_owned();
    tracing::warn!(
        provider = PROVIDER,
        namespace = %context.pod_namespace,
        controller = %settings.controller_name,
        "{reason}"
    );
    tx.send_modify(|state| state.degraded = Some(reason));
    let _ = shutdown.wait_for(|stop| *stop).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_come_from_the_context() {
        let context = RunContext {
            data_dir: PathBuf::from("/var/lib/rdock"),
            pod_namespace: "rdock-system".to_owned(),
            pod_name: "rdock-0".to_owned(),
            pod_labels: BTreeMap::new(),
        };
        let settings = context.settings(&KubernetesProvider::default());
        assert_eq!(settings.controller_namespace, "rdock-system");
        assert_eq!(settings.data_dir, PathBuf::from("/var/lib/rdock"));
    }

    #[tokio::test]
    async fn the_stub_reports_degraded_and_stops_on_shutdown() {
        let (tx, mut rx) = watch::channel(State::default());
        let (stop, stop_rx) = watch::channel(false);
        let context = RunContext::from_env(PathBuf::from("/tmp/rdock-test"));
        let task = tokio::spawn(run(KubernetesProvider::default(), context, tx, stop_rx));
        rx.changed().await.unwrap();
        assert!(rx.borrow().degraded.is_some());
        assert!(rx.borrow().snapshot.is_none());
        stop.send(true).unwrap();
        task.await.unwrap();
    }
}
