//! Starts the providers the configuration enables and hands their snapshots to the engine
//! (ADR-0018). Provider settings are read once at start; changing them needs a restart.

use std::sync::Arc;

use rdock_model::Config;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::engine::Engine;

/// Snapshots arriving this close together cause one reload (architecture §5).
#[cfg(feature = "docker")]
const COALESCE: std::time::Duration = std::time::Duration::from_millis(250);

/// Starts the enabled providers. `changed` receives one message per snapshot to apply.
pub(crate) fn start(
    engine: &Arc<Engine>,
    config: &Config,
    stop: &watch::Receiver<bool>,
    changed: &mpsc::Sender<()>,
) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::new();
    if let Some(settings) = &config.providers.docker {
        start_docker(engine, settings, stop, changed, &mut tasks);
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

    let (tx, mut rx) = watch::channel(State::default());
    tracing::info!(provider = PROVIDER, endpoint = %settings.endpoint, "watching Docker containers");
    tasks.push(tokio::spawn(run(settings.clone(), tx, stop.clone())));
    let engine = engine.clone();
    let changed = changed.clone();
    tasks.push(tokio::spawn(async move {
        while rx.changed().await.is_ok() {
            tokio::time::sleep(COALESCE).await;
            let state = rx.borrow_and_update().clone();
            engine.set_degraded(PROVIDER, state.degraded);
            if let Some(snapshot) = state.snapshot {
                engine.set_snapshot(snapshot);
                // A full queue already holds a pending reload.
                let _ = changed.try_send(());
            }
        }
    }));
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
