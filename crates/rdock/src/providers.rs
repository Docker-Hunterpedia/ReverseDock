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
    use rdock_provider_kubernetes::runtime::{Options, run_with};
    use rdock_provider_kubernetes::{PROVIDER, RunContext, State};

    // Namespace and pod name from the downward API; `run` resolves the rest and logs one line
    // with the namespace, identity, scopes and what is enabled.
    let context = RunContext::from_env(data_dir.to_path_buf());
    // Ready only once the provider has published its first complete view (ADR-0029).
    engine.await_provider(PROVIDER);
    let (tx, rx) = watch::channel(State::default());
    // The provider's internal listeners the data plane could not bind, so their Gateway
    // listeners do not report `Programmed=True` while they do not serve.
    let (unbound_tx, unbound_rx) = watch::channel(std::collections::BTreeSet::new());
    tasks.push(tokio::spawn(own_unbound(
        engine.unbound(),
        PROVIDER,
        unbound_tx,
    )));
    let options = Options {
        unbound: Some(unbound_rx),
        ..Options::default()
    };
    tasks.push(tokio::spawn(run_with(
        settings.clone(),
        context,
        options,
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

/// Forwards the names of `provider`'s listeners in the engine's unbound set (without the
/// `@provider` suffix) until the provider stops listening.
#[cfg(feature = "kubernetes")]
async fn own_unbound(
    mut unbound: watch::Receiver<crate::engine::Unbound>,
    provider: &'static str,
    tx: watch::Sender<std::collections::BTreeSet<String>>,
) {
    let suffix = format!("@{provider}");
    loop {
        let names: std::collections::BTreeSet<String> = unbound
            .borrow_and_update()
            .keys()
            .filter_map(|name| name.strip_suffix(&suffix).map(str::to_owned))
            .collect();
        tx.send_if_modified(|current| {
            let changed = *current != names;
            if changed {
                *current = names;
            }
            changed
        });
        tokio::select! {
            changed = unbound.changed() => if changed.is_err() { return },
            () = tx.closed() => return,
        }
    }
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

#[cfg(all(test, feature = "kubernetes"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_provider_sees_its_own_unbound_listeners_without_the_suffix() {
        let address = rdock_model::values::ListenAddress::any(20004);
        let udp = rdock_model::config::ListenerProtocol::Udp;
        let (engine_tx, engine_rx) = watch::channel(crate::engine::Unbound::from([
            ("gwu-a@kubernetes".to_owned(), (address, udp)),
            ("web@docker".to_owned(), (address, udp)),
        ]));
        let (tx, mut rx) = watch::channel(std::collections::BTreeSet::new());
        let task = tokio::spawn(own_unbound(engine_rx, "kubernetes", tx));
        rx.changed().await.unwrap();
        assert_eq!(
            *rx.borrow_and_update(),
            std::collections::BTreeSet::from(["gwu-a".to_owned()])
        );
        engine_tx.send_replace(crate::engine::Unbound::new());
        rx.changed().await.unwrap();
        assert!(rx.borrow_and_update().is_empty());
        drop(rx);
        task.await.unwrap();
    }
}
