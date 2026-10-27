//! The Engine API loop (W-DKR-01, ADR-0018): list and inspect running containers, translate
//! their labels, then follow container and network events and list again on each change.
//!
//! Only read calls are made (`containers/json`, `containers/{id}/json`, `events`), so a
//! read-only socket proxy is enough. When the socket is lost, the last snapshot stays in
//! service and the loop reconnects with backoff; traffic never stops because Docker did.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use bollard::Docker;
use bollard::models::{ContainerInspectResponse, EventMessage, HealthStatusEnum};
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptionsBuilder};
use futures_util::StreamExt;
use rdock_config::merge::Snapshot;
use rdock_model::providers::DockerProvider;
use tokio::sync::watch;

use crate::labels::{Container, Health, translate};

/// The provider's name in `name@docker` keys.
pub const PROVIDER: &str = "docker";
/// Seconds before an Engine API request gives up.
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// Events that arrive this close together cause one listing.
const COALESCE: Duration = Duration::from_millis(100);
/// A full listing even without events, as a safety net.
const RECONCILE: Duration = Duration::from_secs(60);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// What the provider reports: its latest snapshot and whether Docker is reachable.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {
    /// The latest snapshot; `None` until the first listing succeeds.
    pub snapshot: Option<Snapshot>,
    /// Why Docker is unreachable, while it is.
    pub degraded: Option<String>,
}

/// Runs until `shutdown` turns true, publishing on `tx`.
pub async fn run(
    settings: DockerProvider,
    tx: watch::Sender<State>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = BACKOFF_MIN;
    loop {
        let outcome = tokio::select! {
            outcome = session(&settings, &tx) => outcome,
            _ = shutdown.wait_for(|stop| *stop) => return,
        };
        match outcome {
            // The event stream ended (the daemon restarted, or a proxy closed it): start over.
            Ok(()) => backoff = BACKOFF_MIN,
            Err(reason) => {
                tracing::warn!(provider = PROVIDER, error = %reason, retry_in = ?backoff,
                    "Docker is unreachable; the last routes stay in service");
                tx.send_modify(|state| state.degraded = Some(reason));
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    _ = shutdown.wait_for(|stop| *stop) => return,
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// One connection: list, then follow events until the stream ends or fails.
async fn session(settings: &DockerProvider, tx: &watch::Sender<State>) -> Result<(), String> {
    let docker = connect(settings)?;
    let filters: HashMap<&str, Vec<&str>> = HashMap::from([
        ("type", vec!["container", "network"]),
        (
            "event",
            vec![
                "start",
                "stop",
                "die",
                "destroy",
                "kill",
                "pause",
                "unpause",
                "rename",
                "update",
                "health_status",
                "connect",
                "disconnect",
            ],
        ),
    ]);
    // Subscribe before listing so no change between the two is missed.
    let mut events = docker.events(Some(
        EventsOptionsBuilder::default().filters(&filters).build(),
    ));
    let mut stopping = Stopping::default();
    publish(&docker, settings, tx, &mut stopping).await?;
    let mut reconcile = tokio::time::interval(RECONCILE);
    reconcile.tick().await;
    loop {
        tokio::select! {
            event = events.next() => match event {
                Some(Ok(event)) => {
                    stopping.note(&event);
                    drain(&mut events, &mut stopping).await?;
                    publish(&docker, settings, tx, &mut stopping).await?;
                }
                Some(Err(err)) => return Err(err.to_string()),
                None => return Ok(()),
            },
            _ = reconcile.tick() => publish(&docker, settings, tx, &mut stopping).await?,
        }
    }
}

/// Containers Docker has been told to stop or pause, by name. `docker stop` sends a `kill`
/// event when it signals the container and `die` only when the process has exited; taking the
/// container out of its pool at `kill` lets requests already sent finish while no new ones
/// arrive, instead of new ones waiting on a container that is about to vanish (W-DKR-06).
#[derive(Debug, Default)]
struct Stopping(HashSet<String>);

impl Stopping {
    fn note(&mut self, event: &EventMessage) {
        let Some(name) = event
            .actor
            .as_ref()
            .and_then(|a| a.attributes.as_ref())
            .and_then(|a| a.get("name"))
        else {
            return;
        };
        match event.action.as_deref() {
            Some("kill" | "stop" | "pause") => {
                self.0.insert(name.clone());
            }
            Some("start" | "unpause" | "die" | "destroy") => {
                self.0.remove(name);
            }
            _ => {}
        }
    }

    /// Marks the listed containers that are stopping, and forgets the ones that are gone.
    fn apply(&mut self, containers: &mut [Container]) {
        let listed: HashSet<&str> = containers.iter().map(|c| c.name.as_str()).collect();
        self.0.retain(|name| listed.contains(name.as_str()));
        for container in containers {
            container.stopping = self.0.contains(&container.name);
        }
    }
}

/// Waits for a pause in a burst of events (a Compose `up` sends dozens).
async fn drain<S>(events: &mut S, stopping: &mut Stopping) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<bollard::models::EventMessage, bollard::errors::Error>>
        + Unpin,
{
    loop {
        match tokio::time::timeout(COALESCE, events.next()).await {
            Err(_) | Ok(None) => return Ok(()),
            Ok(Some(Ok(event))) => stopping.note(&event),
            Ok(Some(Err(err))) => return Err(err.to_string()),
        }
    }
}

fn connect(settings: &DockerProvider) -> Result<Docker, String> {
    let url = settings.endpoint.as_url();
    let version = bollard::API_DEFAULT_VERSION;
    match url.scheme() {
        "unix" => Docker::connect_with_unix(url.path(), REQUEST_TIMEOUT_SECS, version),
        "tcp" | "http" => {
            let host = url.host_str().unwrap_or_default();
            let port = url.port().unwrap_or(2375);
            Docker::connect_with_http(&format!("{host}:{port}"), REQUEST_TIMEOUT_SECS, version)
        }
        other => {
            return Err(format!(
                "`{other}://` Docker endpoints are not supported in this version; use a unix socket or a socket proxy on tcp://"
            ));
        }
    }
    .map_err(|err| err.to_string())
}

/// Lists, translates and publishes a new snapshot when it differs from the last one.
async fn publish(
    docker: &Docker,
    settings: &DockerProvider,
    tx: &watch::Sender<State>,
    stopping: &mut Stopping,
) -> Result<(), String> {
    let mut containers = list(docker).await?;
    stopping.apply(&mut containers);
    let translation = translate(&containers, settings);
    let snapshot = Snapshot {
        provider: PROVIDER.to_owned(),
        fragment: translation.fragment,
        diagnostics: translation.diagnostics,
    };
    tx.send_if_modified(|state| {
        let changed = state.snapshot.as_ref() != Some(&snapshot) || state.degraded.is_some();
        state.snapshot = Some(snapshot);
        state.degraded = None;
        changed
    });
    Ok(())
}

/// Running containers, inspected (inspect has the health status on every Engine API version,
/// including the 1.40 API Podman serves).
async fn list(docker: &Docker) -> Result<Vec<Container>, String> {
    let summaries = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::default().all(false).build(),
        ))
        .await
        .map_err(|err| err.to_string())?;
    let mut containers = Vec::with_capacity(summaries.len());
    for id in summaries.into_iter().filter_map(|s| s.id) {
        match docker.inspect_container(&id, None).await {
            Ok(inspected) => containers.extend(container(inspected)),
            // Gone between the listing and the inspection: the next event lists again.
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(err) => return Err(err.to_string()),
        }
    }
    containers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(containers)
}

/// What the translator needs from an inspection; `None` for a container that is not running.
fn container(inspected: ContainerInspectResponse) -> Option<Container> {
    let state = inspected.state?;
    if state.running != Some(true) {
        return None;
    }
    let config = inspected.config.unwrap_or_default();
    let network_mode = inspected.host_config.and_then(|h| h.network_mode);
    let networks = inspected
        .network_settings
        .and_then(|n| n.networks)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, endpoint)| {
            let ip = endpoint
                .ip_address
                .filter(|ip| !ip.is_empty())
                .or(endpoint.global_ipv6_address.filter(|ip| !ip.is_empty()))
                .and_then(|ip| ip.parse::<IpAddr>().ok());
            (name, ip)
        })
        .collect::<BTreeMap<_, _>>();
    let exposed_ports: BTreeSet<u16> = config
        .exposed_ports
        .unwrap_or_default()
        .iter()
        .filter_map(|p| {
            let (port, proto) = p.split_once('/').unwrap_or((p, "tcp"));
            (proto == "tcp").then(|| port.parse().ok()).flatten()
        })
        .collect();
    let health = match state.health.and_then(|h| h.status) {
        Some(HealthStatusEnum::STARTING) => Health::Starting,
        Some(HealthStatusEnum::HEALTHY) => Health::Healthy,
        Some(HealthStatusEnum::UNHEALTHY) => Health::Unhealthy,
        _ => Health::None,
    };
    Some(Container {
        name: inspected
            .name
            .unwrap_or_default()
            .trim_start_matches('/')
            .to_owned(),
        labels: config.labels.unwrap_or_default().into_iter().collect(),
        networks,
        host_network: network_mode.as_deref() == Some("host"),
        exposed_ports,
        health,
        stopping: false,
    })
}

#[cfg(test)]
mod tests {
    use bollard::models::{
        ContainerConfig, ContainerState, EndpointSettings, HostConfig, NetworkSettings,
    };

    use super::*;

    fn inspected(
        running: bool,
        mode: &str,
        health: Option<HealthStatusEnum>,
    ) -> ContainerInspectResponse {
        ContainerInspectResponse {
            name: Some("/web-1".to_owned()),
            state: Some(ContainerState {
                running: Some(running),
                health: health.map(|status| bollard::models::Health {
                    status: Some(status),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            config: Some(ContainerConfig {
                labels: Some(HashMap::from([(
                    "rdock.enable".to_owned(),
                    "true".to_owned(),
                )])),
                exposed_ports: Some(vec!["80/tcp".to_owned(), "53/udp".to_owned()]),
                ..Default::default()
            }),
            host_config: Some(HostConfig {
                network_mode: Some(mode.to_owned()),
                ..Default::default()
            }),
            network_settings: Some(NetworkSettings {
                networks: Some(HashMap::from([(
                    "proxy".to_owned(),
                    EndpointSettings {
                        ip_address: Some("172.20.0.4".to_owned()),
                        ..Default::default()
                    },
                )])),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn inspections_become_containers() {
        let c = container(inspected(true, "proxy", Some(HealthStatusEnum::UNHEALTHY))).unwrap();
        assert_eq!(c.name, "web-1");
        assert_eq!(c.exposed_ports, BTreeSet::from([80]));
        assert_eq!(c.networks["proxy"], Some("172.20.0.4".parse().unwrap()));
        assert_eq!(c.health, Health::Unhealthy);
        assert!(!c.host_network);
        assert!(
            container(inspected(true, "host", None))
                .unwrap()
                .host_network
        );
        assert_eq!(container(inspected(false, "proxy", None)), None);
    }

    fn event(action: &str, name: &str) -> EventMessage {
        EventMessage {
            action: Some(action.to_owned()),
            actor: Some(bollard::models::EventActor {
                attributes: Some(HashMap::from([("name".to_owned(), name.to_owned())])),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn stop_signals_mark_containers_until_they_exit_or_start() {
        let mut stopping = Stopping::default();
        let mut listed = vec![container(inspected(true, "proxy", None)).unwrap()];
        stopping.note(&event("kill", "web-1"));
        stopping.apply(&mut listed);
        assert!(listed[0].stopping);
        stopping.note(&event("start", "web-1"));
        stopping.apply(&mut listed);
        assert!(!listed[0].stopping);
        stopping.note(&event("pause", "web-1"));
        stopping.apply(&mut []);
        assert!(
            stopping.0.is_empty(),
            "containers no longer listed are forgotten"
        );
    }

    #[test]
    fn unsupported_endpoints_say_why() {
        let settings = DockerProvider {
            endpoint: "https://docker.example.com:2376".parse().unwrap(),
            ..DockerProvider::default()
        };
        let err = connect(&settings).err().unwrap();
        assert!(
            err.contains("`https://` Docker endpoints are not supported"),
            "{err}"
        );
    }
}
