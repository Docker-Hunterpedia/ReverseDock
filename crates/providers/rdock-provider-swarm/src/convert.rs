//! Swarm services and tasks into the Docker translator's input (ADR-0026). Pure: no I/O.
//!
//! Each running task becomes a container named `<service>.<slot>` (global services:
//! `<service>.<task ID prefix>`) with the service's `Spec.Labels`, where Compose
//! `deploy.labels` land, and the task's address on each network. In `vip` mode the service
//! becomes one container whose address is its virtual IP. The translator does the rest, so
//! native labels, the Traefik subset and their diagnostics are the Docker provider's.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use bollard::models::{EndpointSpecModeEnum, Network, Service, ServiceSpec};
use rdock_model::providers::{SwarmEndpointMode, SwarmProvider};
use rdock_model::{Diagnostic, path_key};
use rdock_provider_docker::labels::{
    Container, Health, Platform, SWARM_LBSWARM, Settings, Translation, Workload, exposed,
    swarm_option, translate_workloads,
};

use crate::tasks::Task;

/// Characters of a task ID in the name of a global service's task.
const TASK_ID_PREFIX: usize = 12;

/// What the Engine API reports about a swarm.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Inventory {
    /// `GET /services`.
    pub services: Vec<Service>,
    /// `GET /tasks`, running and stopping ones.
    pub tasks: Vec<Task>,
    /// `GET /networks` of swarm scope, to name virtual IPs' networks and find `ingress`.
    pub networks: Vec<Network>,
}

/// Translates the swarm's services. `proxy_networks` are the networks of ReverseDock's own
/// container, when it was found.
#[must_use]
pub fn translate(
    inventory: &Inventory,
    provider: &SwarmProvider,
    proxy_networks: Option<&BTreeSet<String>>,
) -> Translation {
    let entrypoints = BTreeMap::new();
    let settings = Settings {
        platform: Platform::Swarm,
        expose_by_default: provider.expose_by_default,
        network: provider.network.as_deref(),
        traefik_labels: provider.traefik_labels,
        entrypoints: &entrypoints,
        // Swarm tasks are never in host network mode as far as the translator is concerned:
        // a task on `host` has no attachment and is reported as on no network.
        host_address: IpAddr::from([127, 0, 0, 1]),
        proxy_networks,
        allow_local_backends: provider.allow_local_backends,
    };
    let mut diagnostics = Vec::new();
    let workloads = workloads(inventory, provider, &settings, &mut diagnostics);
    let mut translation = translate_workloads(&workloads, &settings);
    diagnostics.append(&mut translation.diagnostics);
    translation.diagnostics = diagnostics;
    translation
}

/// The translator's input for every service, in service-name order.
fn workloads(
    inventory: &Inventory,
    provider: &SwarmProvider,
    settings: &Settings<'_>,
    out: &mut Vec<Diagnostic>,
) -> Vec<Workload> {
    let networks = NetworkNames::new(inventory);
    let mut running: BTreeMap<&str, Vec<&Task>> = BTreeMap::new();
    for task in inventory
        .tasks
        .iter()
        .filter(|t| t.status.state == "running")
    {
        running
            .entry(task.service_id.as_str())
            .or_default()
            .push(task);
    }
    let mut services: Vec<(&str, &str, &ServiceSpec, &Service)> = inventory
        .services
        .iter()
        .filter_map(|service| {
            let spec = service.spec.as_ref()?;
            Some((spec.name.as_deref()?, service.id.as_deref()?, spec, service))
        })
        .collect();
    services.sort_by_key(|(name, ..)| *name);
    let mut workloads = Vec::new();
    for (name, id, spec, service) in services {
        let labels: BTreeMap<String, String> = spec
            .labels
            .iter()
            .flatten()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut scope = ServiceScope {
            name,
            labels: &labels,
            exposed: exposed(&labels, settings),
            out: &mut *out,
        };
        if is_job(spec) {
            scope.warn(
                "job-mode services run to completion and are not routed; the service is ignored",
            );
            continue;
        }
        if scope.uses_virtual_ip(provider) {
            workloads.extend(scope.virtual_ip(service, &networks));
        } else {
            let tasks = running.remove(id).unwrap_or_default();
            workloads.extend(scope.tasks(tasks, is_global(spec), &networks));
        }
    }
    workloads
}

fn is_job(spec: &ServiceSpec) -> bool {
    spec.mode
        .as_ref()
        .is_some_and(|m| m.replicated_job.is_some() || m.global_job.is_some())
}

fn is_global(spec: &ServiceSpec) -> bool {
    spec.mode.as_ref().is_some_and(|m| m.global.is_some())
}

/// Network names by ID, and which networks are the routing mesh's `ingress`.
struct NetworkNames {
    names: BTreeMap<String, String>,
    ingress: BTreeSet<String>,
}

impl NetworkNames {
    fn new(inventory: &Inventory) -> Self {
        let mut names = BTreeMap::new();
        let mut ingress = BTreeSet::new();
        for network in &inventory.networks {
            let (Some(id), Some(name)) = (&network.id, &network.name) else {
                continue;
            };
            names.insert(id.clone(), name.clone());
            if network.ingress == Some(true) {
                ingress.insert(id.clone());
            }
        }
        // A network created after the listing is still named by the tasks attached to it.
        let attachments = inventory
            .tasks
            .iter()
            .flat_map(|t| t.networks_attachments.iter().flatten());
        for attachment in attachments {
            let network = &attachment.network;
            names
                .entry(network.id.clone())
                .or_insert_with(|| network.spec.name.clone());
        }
        Self { names, ingress }
    }

    /// The network's name, unless it is `ingress`, which ReverseDock cannot join: the routing
    /// mesh hands it requests, it never sends any.
    fn reachable(&self, id: &str) -> Option<&str> {
        let name = self.names.get(id)?;
        let ingress = self.ingress.contains(id) || name == "ingress";
        (!ingress).then_some(name.as_str())
    }
}

/// One service being converted.
struct ServiceScope<'a> {
    name: &'a str,
    labels: &'a BTreeMap<String, String>,
    /// Whether the service's labels expose it; the Swarm-specific warnings are only for those.
    exposed: bool,
    out: &'a mut Vec<Diagnostic>,
}

impl ServiceScope<'_> {
    fn warn(&mut self, message: &str) {
        if self.exposed {
            self.out
                .push(Diagnostic::warning(path_key("swarm", self.name), message));
        }
    }

    /// `rdock.swarm.lbswarm` / `traefik.swarm.lbswarm`, else the provider's endpoint mode.
    fn uses_virtual_ip(&mut self, provider: &SwarmProvider) -> bool {
        let default = provider.endpoint_mode == SwarmEndpointMode::Vip;
        match swarm_option(self.labels, SWARM_LBSWARM, "lbswarm") {
            None => default,
            Some("true") => true,
            Some("false") => false,
            Some(other) => {
                let message = format!(
                    "the `lbswarm` label is `{other}`, not `true` or `false`; the provider's endpoint mode is used"
                );
                self.warn(&message);
                default
            }
        }
    }

    /// One container for the service, addressed by its virtual IP on each reachable network.
    fn virtual_ip(&mut self, service: &Service, networks: &NetworkNames) -> Option<Workload> {
        let endpoint = service.endpoint.as_ref();
        // The Engine leaves `Endpoint.Spec` empty for `dnsrr` services; the spec has the mode.
        let mode = service
            .spec
            .as_ref()
            .and_then(|s| s.endpoint_spec.as_ref())
            .or_else(|| endpoint.and_then(|e| e.spec.as_ref()))
            .and_then(|s| s.mode);
        if mode == Some(EndpointSpecModeEnum::DNSRR) {
            self.warn("the service uses `dnsrr` and has no virtual IP; it gets no backends (route to its tasks instead: `rdock.swarm.lbswarm=false` or `providers.swarm.endpoint_mode: tasks`)");
            return None;
        }
        let addresses = endpoint
            .and_then(|e| e.virtual_ips.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|vip| Some((vip.network_id.as_deref()?, vip.addr.as_deref())));
        let networks = self.reachable(addresses, networks)?;
        Some(Workload {
            container: self.container(self.name.to_owned(), networks, false),
            group: Some(self.name.to_owned()),
            virtual_ip: true,
        })
    }

    /// One container per running task of the service.
    fn tasks(
        &mut self,
        mut running: Vec<&Task>,
        global: bool,
        networks: &NetworkNames,
    ) -> Vec<Workload> {
        running.sort_by_key(|t| (t.slot, t.id.as_str()));
        let mut workloads = Vec::new();
        for task in running {
            let addresses = task.networks_attachments.iter().flatten().map(|a| {
                let first = a.addresses.iter().flatten().next();
                (a.network.id.as_str(), first.map(String::as_str))
            });
            let Some(networks) = self.reachable(addresses, networks) else {
                // One warning for the service is enough; its other tasks are attached alike.
                return Vec::new();
            };
            // Swarm wants the task gone (scale-down, update, removal) but it still runs: it
            // leaves the pool now instead of when it exits (W-DKR-06).
            let stopping = task.desired_state != "running";
            workloads.push(Workload {
                container: self.container(self.task_name(task, global), networks, stopping),
                group: Some(self.name.to_owned()),
                virtual_ip: false,
            });
        }
        workloads
    }

    /// `web.2` for a replica, `web.<task ID prefix>` for a global service's task.
    fn task_name(&self, task: &Task, global: bool) -> String {
        match task.slot {
            Some(slot) if !global => format!("{}.{slot}", self.name),
            _ => {
                let prefix: String = task.id.chars().take(TASK_ID_PREFIX).collect();
                format!("{}.{prefix}", self.name)
            }
        }
    }

    /// Addresses by network name, leaving out `ingress`. `None`, with a warning, when the
    /// only networks are `ingress`.
    fn reachable<'n>(
        &mut self,
        addresses: impl Iterator<Item = (&'n str, Option<&'n str>)>,
        networks: &NetworkNames,
    ) -> Option<BTreeMap<String, Option<IpAddr>>> {
        let mut attached = false;
        let mut out = BTreeMap::new();
        for (id, address) in addresses {
            attached = true;
            if let Some(name) = networks.reachable(id) {
                out.insert(name.to_owned(), address.and_then(ip));
            }
        }
        if attached && out.is_empty() {
            self.warn("the service is only on the `ingress` network, which ReverseDock cannot reach; attach it to an overlay network that ReverseDock is on");
            return None;
        }
        Some(out)
    }

    fn container(
        &self,
        name: String,
        networks: BTreeMap<String, Option<IpAddr>>,
        stopping: bool,
    ) -> Container {
        Container {
            name,
            labels: self.labels.clone(),
            networks,
            // Swarm reports a task `running` only once its health check passes, and replaces
            // tasks that turn unhealthy.
            health: Health::Healthy,
            stopping,
            ..Container::default()
        }
    }
}

/// `10.0.1.5/24` → `10.0.1.5`.
fn ip(cidr: &str) -> Option<IpAddr> {
    cidr.split('/').next()?.parse().ok()
}
