//! Starts the providers the configuration enables and hands their snapshots to the engine
//! (ADR-0018). Provider settings are read once at start; changing them needs a restart.

use std::path::Path;
use std::sync::Arc;

#[cfg(any(feature = "docker", feature = "swarm", feature = "kubernetes"))]
use rdock_config::merge::ProviderState;
use rdock_model::Config;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::engine::Engine;

/// Snapshots arriving this close together cause one reload (architecture §5).
#[cfg(any(feature = "docker", feature = "swarm", feature = "kubernetes"))]
const COALESCE: std::time::Duration = std::time::Duration::from_millis(250);

/// Starts the enabled providers. `changed` receives one message per snapshot to apply.
/// `data_dir` is rdock's data directory (the Kubernetes provider writes Secret files there).
pub(crate) fn start(
    engine: &Arc<Engine>,
    config: &Config,
    data_dir: &Path,
    stop: &watch::Receiver<bool>,
    changed: &mpsc::Sender<()>,
) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::new();
    if let Some(settings) = &config.providers.docker {
        start_docker(engine, settings, stop, changed, &mut tasks);
    }
    if let Some(settings) = &config.providers.swarm {
        start_swarm(engine, settings, stop, changed, &mut tasks);
    }
    if let Some(settings) = &config.providers.kubernetes {
        start_kubernetes(engine, settings, data_dir, stop, changed, &mut tasks);
    }
    tasks
}

#[cfg(feature = "docker")]
fn start_docker(
    engine: &Arc<Engine>,
    settings: &rdock_model::providers::DockerProvider,
    stop: &watch::Receiver<bool>,
    changed: &mpsc::Sender<()>,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    use rdock_provider_docker::watch::{PROVIDER, State, run};

    let (tx, rx) = watch::channel(State::default());
    tracing::info!(provider = PROVIDER, endpoint = %settings.endpoint, "watching Docker containers");
    tasks.push(tokio::spawn(run(settings.clone(), tx, stop.clone())));
    tasks.push(tokio::spawn(follow(
        engine.clone(),
        PROVIDER,
        rx,
        changed.clone(),
    )));
}

#[cfg(not(feature = "docker"))]
fn start_docker(
    _engine: &Arc<Engine>,
    _settings: &rdock_model::providers::DockerProvider,
    _stop: &watch::Receiver<bool>,
    _changed: &mpsc::Sender<()>,
    _tasks: &mut Vec<JoinHandle<()>>,
) {
    tracing::warn!(
        "`providers.docker` is set, but this build has no Docker provider (cargo feature `docker`)"
    );
}

#[cfg(feature = "swarm")]
fn start_swarm(
    engine: &Arc<Engine>,
    settings: &rdock_model::providers::SwarmProvider,
    stop: &watch::Receiver<bool>,
    changed: &mpsc::Sender<()>,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    use rdock_provider_swarm::watch::{PROVIDER, State, run};

    let (tx, rx) = watch::channel(State::default());
    tracing::info!(provider = PROVIDER, endpoint = %settings.endpoint,
        endpoint_mode = ?settings.endpoint_mode, poll_interval = %settings.poll_interval,
        "watching Swarm services");
    tasks.push(tokio::spawn(run(settings.clone(), tx, stop.clone())));
    tasks.push(tokio::spawn(follow(
        engine.clone(),
        PROVIDER,
        rx,
        changed.clone(),
    )));
}

#[cfg(not(feature = "swarm"))]
fn start_swarm(
    _engine: &Arc<Engine>,
    _settings: &rdock_model::providers::SwarmProvider,
    _stop: &watch::Receiver<bool>,
    _changed: &mpsc::Sender<()>,
    _tasks: &mut Vec<JoinHandle<()>>,
) {
    tracing::warn!(
        "`providers.swarm` is set, but this build has no Swarm provider (cargo feature `swarm`)"
    );
}

#[cfg(feature = "kubernetes")]
fn start_kubernetes(
    engine: &Arc<Engine>,
    settings: &rdock_model::providers::KubernetesProvider,
    data_dir: &Path,
    stop: &watch::Receiver<bool>,
    changed: &mpsc::Sender<()>,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    use rdock_provider_kubernetes::{PROVIDER, RunContext, State, run};

    let context = RunContext::from_env(data_dir.to_path_buf());
    // Ready only once the provider has published its first complete view (ADR-0029).
    engine.await_provider(PROVIDER);
    let (tx, rx) = watch::channel(State::default());
    tracing::info!(provider = PROVIDER, namespace = %context.pod_namespace,
        controller = %settings.controller_name, "watching Kubernetes");
    tasks.push(tokio::spawn(run(
        settings.clone(),
        context,
        tx,
        stop.clone(),
    )));
    tasks.push(tokio::spawn(follow(
        engine.clone(),
        PROVIDER,
        rx,
        changed.clone(),
    )));
}

#[cfg(not(feature = "kubernetes"))]
fn start_kubernetes(
    _engine: &Arc<Engine>,
    _settings: &rdock_model::providers::KubernetesProvider,
    _data_dir: &Path,
    _stop: &watch::Receiver<bool>,
    _changed: &mpsc::Sender<()>,
    _tasks: &mut Vec<JoinHandle<()>>,
) {
    tracing::warn!(
        "`providers.kubernetes` is set, but this build has no Kubernetes provider (cargo feature `kubernetes`)"
    );
}

/// Hands each new state of a provider to the engine and asks for a reload.
#[cfg(any(feature = "docker", feature = "swarm", feature = "kubernetes"))]
async fn follow(
    engine: Arc<Engine>,
    provider: &'static str,
    mut rx: watch::Receiver<ProviderState>,
    changed: mpsc::Sender<()>,
) {
    while rx.changed().await.is_ok() {
        tokio::time::sleep(COALESCE).await;
        let state = rx.borrow_and_update().clone();
        engine.set_degraded(provider, state.degraded);
        if let Some(snapshot) = state.snapshot {
            engine.set_live_snapshot(snapshot);
            // A full queue already holds a pending reload.
            let _ = changed.try_send(());
        }
    }
}
