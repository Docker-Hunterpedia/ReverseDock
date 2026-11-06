//! The Swarm loop (W-SWM-01, ADR-0026): list services, tasks and networks, translate, then
//! list again every `poll_interval` and on each Swarm event.
//!
//! Swarm emits no task events, so polling is what notices a task that starts or stops; the
//! `service`, `node`, `network`, `secret` and `config` events only make the next listing come
//! sooner. Only read calls are made. When the manager is unreachable the last snapshot stays
//! in service and the loop reconnects with backoff, like the Docker provider's.

use std::collections::{BTreeSet, HashMap};

use bollard::Docker;
use bollard::query_parameters::{EventsOptionsBuilder, ListNetworksOptionsBuilder};
use futures_util::StreamExt;
use rdock_config::merge::Snapshot;
use rdock_model::providers::SwarmProvider;
use rdock_provider_docker::watch::{EngineAddress, connect, drain, publish_snapshot, supervise};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

pub use rdock_provider_docker::watch::State;

use crate::convert::{Inventory, translate};
use crate::tasks;

/// The provider's name in `name@swarm` keys.
pub const PROVIDER: &str = "swarm";

/// Runs until `shutdown` turns true, publishing on `tx`.
pub async fn run(
    settings: SwarmProvider,
    tx: watch::Sender<State>,
    shutdown: watch::Receiver<bool>,
) {
    let session = || session(&settings, &tx);
    supervise(PROVIDER, "the Swarm manager", session, &tx, shutdown).await;
}

/// One connection: list, then list again on events and every poll interval.
async fn session(settings: &SwarmProvider, tx: &watch::Sender<State>) -> Result<(), String> {
    let address = EngineAddress::parse(&settings.endpoint)?;
    // Negotiation only lowers bollard's default version, for Engines older than it.
    let docker = connect(&settings.endpoint)?
        .negotiate_version()
        .await
        .map_err(|err| err.to_string())?;
    let filters: HashMap<&str, Vec<&str>> = HashMap::from([(
        "type",
        vec!["service", "node", "network", "secret", "config"],
    )]);
    // Subscribe before listing so no change between the two is missed.
    let mut events = docker.events(Some(
        EventsOptionsBuilder::default().filters(&filters).build(),
    ));
    let proxy_networks = own_networks(&docker).await;
    let source = Source {
        docker: &docker,
        address: &address,
        settings,
        proxy_networks: proxy_networks.as_ref(),
    };
    source.publish(tx).await?;
    let mut poll = tokio::time::interval(settings.poll_interval.as_std());
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    poll.tick().await;
    loop {
        tokio::select! {
            event = events.next() => match event {
                Some(Ok(_)) => {
                    drain(&mut events, |_| {}).await?;
                    source.publish(tx).await?;
                    poll.reset();
                }
                Some(Err(err)) => return Err(err.to_string()),
                None => return Ok(()),
            },
            _ = poll.tick() => source.publish(tx).await?,
        }
    }
}

/// Where a listing comes from and what translating it needs.
struct Source<'a> {
    docker: &'a Docker,
    address: &'a EngineAddress,
    settings: &'a SwarmProvider,
    proxy_networks: Option<&'a BTreeSet<String>>,
}

impl Source<'_> {
    /// Lists, translates and publishes a new snapshot when it differs from the last one.
    async fn publish(&self, tx: &watch::Sender<State>) -> Result<(), String> {
        let inventory = self.list().await?;
        let translation = translate(&inventory, self.settings, self.proxy_networks);
        publish_snapshot(
            tx,
            Snapshot {
                provider: PROVIDER.to_owned(),
                fragment: translation.fragment,
                diagnostics: translation.diagnostics,
            },
        );
        Ok(())
    }

    async fn list(&self) -> Result<Inventory, String> {
        let scope: HashMap<&str, Vec<&str>> = HashMap::from([("scope", vec!["swarm"])]);
        let networks = self
            .docker
            .list_networks(Some(
                ListNetworksOptionsBuilder::default()
                    .filters(&scope)
                    .build(),
            ))
            .await
            .map_err(|err| err.to_string())?;
        let services = self
            .docker
            .list_services(None)
            .await
            .map_err(|err| err.to_string())?;
        let tasks = tasks::list(self.address).await?;
        Ok(Inventory {
            services,
            tasks,
            networks,
        })
    }
}

/// The networks of ReverseDock's own container, found by its hostname (Docker sets it to the
/// short container ID unless `hostname:` is set). `None` when ReverseDock does not run in a
/// container of this Engine; a task on several networks then needs a network named for it.
async fn own_networks(docker: &Docker) -> Option<BTreeSet<String>> {
    let hostname = own_hostname().await?;
    let inspected = match docker.inspect_container(&hostname, None).await {
        Ok(inspected) => inspected,
        Err(err) => {
            tracing::info!(provider = PROVIDER, %hostname, error = %err,
                "ReverseDock's own container was not found; a task on several networks needs `rdock.network` or `providers.swarm.network`");
            return None;
        }
    };
    // A container that happens to be named like this host is not ours.
    if inspected
        .config
        .as_ref()
        .and_then(|c| c.hostname.as_deref())
        != Some(hostname.as_str())
    {
        tracing::info!(provider = PROVIDER, %hostname,
            "the container named like this host has another hostname; it is not ReverseDock's own");
        return None;
    }
    let networks: BTreeSet<String> = inspected
        .network_settings
        .and_then(|n| n.networks)
        .unwrap_or_default()
        .into_keys()
        .collect();
    tracing::info!(
        provider = PROVIDER,
        ?networks,
        "found ReverseDock's own container"
    );
    Some(networks)
}

/// `/etc/hostname`, which Docker writes into every container, else `$HOSTNAME`.
async fn own_hostname() -> Option<String> {
    let from_file = tokio::fs::read_to_string("/etc/hostname").await.ok();
    from_file
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
}
