//! Container labels into routes, services and middlewares (ADR-0018). Pure: no I/O.
//!
//! [`translate`] takes what the Engine API reports about running containers and returns the
//! Docker provider's [`Fragment`] with its diagnostics. The provider, the conformance suite and
//! `rdock migrate traefik` all go through it, so they agree by construction. The Swarm provider
//! turns tasks into containers and goes through [`translate_workloads`] (ADR-0026).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rdock_config::merge::Fragment;
use rdock_model::middleware::Middleware;
use rdock_model::providers::DockerProvider;
use rdock_model::route::Route;
use rdock_model::service::Service;
use rdock_model::{Diagnostic, path_key};
use serde_json::Value;

mod native;
mod traefik;
pub(crate) mod tree;

use tree::{Tree, decode};

/// Longest object name (the model's limit).
const MAX_NAME_LEN: usize = 63;

/// What the Engine API reports about one running container.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Container {
    /// Container name, without the leading `/`.
    pub name: String,
    /// Labels as set on the container.
    pub labels: BTreeMap<String, String>,
    /// Networks the container is attached to, with its address on each (none when the
    /// network gives it no IP).
    pub networks: BTreeMap<String, Option<IpAddr>>,
    /// The container shares the host's network stack.
    pub host_network: bool,
    /// Ports the image or container exposes.
    pub exposed_ports: BTreeSet<u16>,
    /// Result of the container's Docker health check.
    pub health: Health,
    /// Docker is stopping or pausing the container: it should get no new requests.
    pub stopping: bool,
    /// A DNS name to reach the container by when it has no network address, such as the
    /// Compose service name in `rdock migrate traefik`.
    pub dns_name: Option<String>,
}

/// Docker health check status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Health {
    /// The container has no health check.
    #[default]
    None,
    /// The health check has not passed yet.
    Starting,
    /// The health check passes.
    Healthy,
    /// The health check fails.
    Unhealthy,
}

impl Health {
    fn serves(self) -> bool {
        matches!(self, Self::None | Self::Healthy)
    }
}

/// Where the containers come from. It decides the diagnostic paths and which platform labels
/// (`traefik.docker.*` or `traefik.swarm.*`) are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Containers of one Docker Engine.
    Docker,
    /// Tasks and services of a Docker Swarm.
    Swarm,
}

impl Platform {
    /// The provider's name: `docker` or `swarm`.
    #[must_use]
    pub fn provider(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Swarm => "swarm",
        }
    }

    /// What one input is called in messages.
    fn noun(self) -> &'static str {
        match self {
            Self::Docker => "container",
            Self::Swarm => "task",
        }
    }
}

/// The provider settings the translator reads.
#[derive(Debug, Clone, Copy)]
pub struct Settings<'a> {
    /// Where the containers come from.
    pub platform: Platform,
    /// Expose containers without `rdock.enable=true`.
    pub expose_by_default: bool,
    /// Network used to reach containers that are on several networks.
    pub network: Option<&'a str>,
    /// Also read `traefik.*` labels.
    pub traefik_labels: bool,
    /// Traefik entrypoint name → listener name.
    pub entrypoints: &'a BTreeMap<String, String>,
    /// Address used for containers in host network mode.
    pub host_address: IpAddr,
    /// Networks ReverseDock's own container is on, when it runs in one that could be found
    /// (Swarm): a container on several networks is reached on the one it shares with them.
    pub proxy_networks: Option<&'a BTreeSet<String>>,
}

impl<'a> Settings<'a> {
    /// The Docker provider's settings.
    #[must_use]
    pub fn docker(provider: &'a DockerProvider) -> Self {
        Self {
            platform: Platform::Docker,
            expose_by_default: provider.expose_by_default,
            network: provider.network.as_deref(),
            traefik_labels: provider.traefik_labels,
            entrypoints: &provider.entrypoints,
            host_address: provider.host_address,
            proxy_networks: None,
        }
    }
}

/// A container with what its platform knows beyond it (Swarm).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Workload {
    /// The container, or the service in Swarm's `vip` mode.
    pub container: Container,
    /// Objects without an explicit name are named after this (the Swarm service) instead of
    /// the container.
    pub group: Option<String>,
    /// The address is a virtual IP that balances between replicas by itself (Swarm's `vip`
    /// endpoint mode): active health checks and sticky sessions have nothing to act on.
    pub virtual_ip: bool,
}

/// The provider's objects and what was found while building them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Translation {
    /// Routes, services and middlewares by bare name.
    pub fragment: Fragment,
    /// Unsupported labels, missing ports, conflicts.
    pub diagnostics: Vec<Diagnostic>,
}

/// Translates the labels of running `containers` for the Docker provider.
#[must_use]
pub fn translate(containers: &[Container], settings: &DockerProvider) -> Translation {
    let settings = Settings::docker(settings);
    let inputs = containers.iter().map(|container| Input {
        container,
        group: None,
        virtual_ip: false,
    });
    translate_inputs(inputs, &settings)
}

/// Translates the labels of `workloads` (the Swarm provider's tasks and services).
#[must_use]
pub fn translate_workloads(workloads: &[Workload], settings: &Settings<'_>) -> Translation {
    let inputs = workloads.iter().map(|workload| Input {
        container: &workload.container,
        group: workload.group.as_deref(),
        virtual_ip: workload.virtual_ip,
    });
    translate_inputs(inputs, settings)
}

/// Whether a container with these labels is exposed: `rdock.enable`, then `traefik.enable`,
/// then `expose_by_default`. Invalid values count as not exposed.
#[must_use]
pub fn exposed(labels: &BTreeMap<String, String>, settings: &Settings<'_>) -> bool {
    let container = Container {
        labels: labels.clone(),
        ..Container::default()
    };
    let input = Input {
        container: &container,
        group: None,
        virtual_ip: false,
    };
    Scope::new(input, settings, &mut Vec::new()).eligible()
}

/// The value of a Swarm option label (`network`, `lbswarm`): the native label first, then
/// `traefik.swarm.<option>`, then the deprecated `traefik.docker.<option>` unless a
/// `traefik.swarm.*` label is set. Keys compare in lower case, as Traefik's do.
#[must_use]
pub fn swarm_option<'l>(
    labels: &'l BTreeMap<String, String>,
    native: &str,
    option: &str,
) -> Option<&'l str> {
    let lower: Vec<(String, &str)> = labels
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
        .collect();
    swarm_option_in(&lower, native, option)
}

fn swarm_option_in<'l>(
    labels: &[(String, &'l str)],
    native: &str,
    option: &str,
) -> Option<&'l str> {
    let get = |key: &str| labels.iter().find(|(k, _)| k == key).map(|(_, v)| *v);
    get(native)
        .or_else(|| get(&format!("traefik.swarm.{option}")))
        .or_else(|| {
            (!has_prefix(labels, SWARM_PREFIX))
                .then(|| get(&format!("traefik.docker.{option}")))
                .flatten()
        })
}

/// Swarm only: route to the service's virtual IP (`true`) or to each task (`false`). The
/// Swarm provider reads it, with [`swarm_option`].
pub const SWARM_LBSWARM: &str = "rdock.swarm.lbswarm";

/// Traefik's Swarm label prefix and its deprecated Docker spelling.
const SWARM_PREFIX: &str = "traefik.swarm.";
const DOCKER_PREFIX: &str = "traefik.docker.";

fn has_prefix(labels: &[(String, &str)], prefix: &str) -> bool {
    labels.iter().any(|(k, _)| k.starts_with(prefix))
}

/// One container to translate, with what its platform adds.
#[derive(Debug, Clone, Copy)]
struct Input<'a> {
    container: &'a Container,
    group: Option<&'a str>,
    virtual_ip: bool,
}

fn translate_inputs<'a>(
    inputs: impl Iterator<Item = Input<'a>>,
    settings: &Settings<'_>,
) -> Translation {
    let mut pools = Pools::default();
    let mut out = Translation::default();
    for input in inputs {
        let mut scope = Scope::new(input, settings, &mut out.diagnostics);
        if !scope.eligible() {
            continue;
        }
        let draft = scope.draft();
        scope.build(draft, &mut pools, &mut out.fragment);
    }
    pools.finish(&mut out);
    out
}

/// Objects one container declares, before decoding.
#[derive(Debug, Default)]
pub(crate) struct Draft {
    pub(crate) routes: BTreeMap<String, Tree>,
    pub(crate) services: BTreeMap<String, ServiceDraft>,
    pub(crate) middlewares: BTreeMap<String, Tree>,
    /// Traefik `retry` middlewares, which become `retries` of the services that routes using
    /// them point to.
    pub(crate) retries: BTreeMap<String, traefik::Retry>,
}

/// A service as labels describe it.
#[derive(Debug, Default)]
pub(crate) struct ServiceDraft {
    /// Model fields other than the backends.
    pub(crate) tree: Tree,
    /// Container port to send traffic to.
    pub(crate) port: Option<u16>,
    /// An explicit backend (`loadbalancer.server.url`), instead of the container's address.
    pub(crate) address: Option<String>,
}

/// One container being translated: its labels, settings and where diagnostics go.
pub(crate) struct Scope<'a> {
    container: &'a Container,
    group: Option<&'a str>,
    virtual_ip: bool,
    settings: &'a Settings<'a>,
    /// Labels with lower-case keys (Traefik's keys are case-insensitive), as (key, value).
    labels: Vec<(String, &'a str)>,
    out: &'a mut Vec<Diagnostic>,
}

impl<'a> Scope<'a> {
    fn new(input: Input<'a>, settings: &'a Settings<'a>, out: &'a mut Vec<Diagnostic>) -> Self {
        let container = input.container;
        let labels = container
            .labels
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
            .collect();
        Self {
            container,
            group: input.group,
            virtual_ip: input.virtual_ip,
            settings,
            labels,
            out,
        }
    }

    /// The platform the container comes from.
    pub(crate) fn platform(&self) -> Platform {
        self.settings.platform
    }

    /// Whether any label key starts with `prefix`.
    pub(crate) fn has_prefix(&self, prefix: &str) -> bool {
        has_prefix(&self.labels, prefix)
    }

    fn label(&self, key: &str) -> Option<&'a str> {
        self.labels.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
    }

    /// The diagnostic path of the container, or of one of its labels.
    pub(crate) fn path(&self, label: Option<&str>) -> String {
        let container = path_key(self.platform().provider(), &self.container.name);
        match label {
            Some(label) => path_key(&format!("{container}.labels"), label),
            None => container,
        }
    }

    pub(crate) fn warn(&mut self, label: &str, message: impl Into<String>) {
        let path = self.path(Some(label));
        self.out.push(Diagnostic::warning(path, message));
    }

    fn warn_container(&mut self, message: impl Into<String>, hint: Option<String>) {
        let mut warning = Diagnostic::warning(self.path(None), message);
        if let Some(hint) = hint {
            warning = warning.with_hint(hint);
        }
        self.out.push(warning);
    }

    /// `rdock.enable`, then `traefik.enable` (when Traefik labels are read), then
    /// `expose_by_default` (B-SEC-10).
    fn eligible(&mut self) -> bool {
        let traefik = self.settings.traefik_labels;
        let flag = self
            .label("rdock.enable")
            .map(|v| ("rdock.enable", v))
            .or_else(|| {
                traefik
                    .then(|| self.label("traefik.enable").map(|v| ("traefik.enable", v)))
                    .flatten()
            });
        match flag {
            Some((_, "true")) => true,
            Some((_, "false")) => false,
            Some((label, other)) => {
                let message =
                    format!("`{other}` is not `true` or `false`; the container is not exposed");
                self.warn(label, message);
                false
            }
            None => self.settings.expose_by_default,
        }
    }

    /// Collects the container's objects from native and Traefik labels.
    fn draft(&mut self) -> Draft {
        let mut draft = Draft::default();
        let labels = self.labels.clone();
        for (key, value) in labels {
            let native = key.starts_with("rdock.");
            let traefik = key.starts_with("traefik.");
            if !native && !traefik {
                continue;
            }
            if traefik && !self.settings.traefik_labels {
                continue;
            }
            // Regular-expression replacements use `${1}` for capture groups (ADR-0016).
            if value.contains("${") && !key.ends_with(".replacement") {
                self.warn(
                    &key,
                    "`${…}` references are not allowed in labels; the label is ignored",
                );
                continue;
            }
            if native {
                native::label(self, &mut draft, &key, value);
            } else {
                traefik::label(self, &mut draft, &key, value);
            }
        }
        native::shorthand(self, &mut draft);
        draft
    }

    /// The name of the container's default route and service: its group (the Swarm service),
    /// else the Compose service and project (`web-shop`), else the container name, reduced to
    /// the characters names allow.
    pub(crate) fn default_name(&self) -> String {
        if let Some(group) = self.group {
            return normalize(group);
        }
        let compose = self
            .label("com.docker.compose.service")
            .zip(self.label("com.docker.compose.project"))
            .map(|(service, project)| format!("{service}-{project}"));
        normalize(&compose.unwrap_or_else(|| self.container.name.clone()))
    }

    /// Fills in default services, decodes the objects and adds them to the fragment.
    fn build(&mut self, mut draft: Draft, pools: &mut Pools, fragment: &mut Fragment) {
        draft.routes.retain(|_, tree| !tree.is_empty());
        self.link_services(&mut draft);
        traefik::apply_retries(self, &mut draft);
        for (name, service) in std::mem::take(&mut draft.services) {
            if let Some((service, backend)) = self.service(&name, service) {
                pools.add(self, name, &service, backend);
            }
        }
        // Objects whose every label was rejected are already explained by those warnings.
        draft.middlewares.retain(|_, tree| !tree.is_empty());
        for (name, tree) in std::mem::take(&mut draft.routes) {
            match decode::<Route>(tree.into_value()) {
                Ok(route) => pools.add_route(self, name, route, fragment),
                Err(err) => self.warn_object("route", &name, &err),
            }
        }
        for (name, tree) in std::mem::take(&mut draft.middlewares) {
            match decode::<Middleware>(tree.into_value()) {
                Ok(middleware) => pools.add_middleware(self, name, middleware, fragment),
                Err(err) => self.warn_object("middleware", &name, &err),
            }
        }
    }

    pub(crate) fn warn_object(&mut self, kind: &str, name: &str, error: &str) {
        let message = format!("{kind} `{name}` is ignored: {error}");
        self.warn_container(message, None);
    }

    /// Routes without a service get the container's only service, or a default one when the
    /// container declares none (Traefik's behaviour).
    fn link_services(&mut self, draft: &mut Draft) {
        let unlinked: Vec<String> = draft
            .routes
            .iter()
            .filter(|(_, tree)| !tree.has("service"))
            .map(|(name, _)| name.clone())
            .collect();
        if unlinked.is_empty() {
            return;
        }
        if draft.services.is_empty() {
            draft
                .services
                .insert(self.default_name(), ServiceDraft::default());
        }
        if draft.services.len() > 1 {
            for name in unlinked {
                draft.routes.remove(&name);
                let message = format!(
                    "route `{name}` names no service and the container has {} services; the route is ignored",
                    draft.services.len()
                );
                self.warn_container(message, Some("set the route's `service` label".to_owned()));
            }
            return;
        }
        let service = draft.services.keys().next().cloned().unwrap_or_default();
        for name in unlinked {
            if let Some(tree) = draft.routes.get_mut(&name) {
                let _ = tree.set("service", Value::String(service.clone()));
            }
        }
    }

    /// Decodes a service and works out its backend for this container.
    fn service(&mut self, name: &str, draft: ServiceDraft) -> Option<(Service, Backend)> {
        let (address, healthy) = if let Some(address) = draft.address {
            (address, true)
        } else {
            let port = self.port(name, draft.port)?;
            let host = match &self.container.dns_name {
                Some(name) if self.container.networks.is_empty() => name.clone(),
                _ => match self.address()? {
                    IpAddr::V6(v6) => format!("[{v6}]"),
                    IpAddr::V4(v4) => v4.to_string(),
                },
            };
            (
                format!("{host}:{port}"),
                self.container.health.serves() && !self.container.stopping,
            )
        };
        let mut tree = draft.tree;
        if let Err(err) = tree.set(
            "backends",
            serde_json::json!([{ "address": address.clone() }]),
        ) {
            self.warn_object("service", name, &err);
            return None;
        }
        match decode::<Service>(tree.into_value()) {
            Ok(mut service) => {
                if self.virtual_ip {
                    self.drop_per_task_settings(name, &mut service);
                }
                Some((
                    service,
                    Backend {
                        address,
                        healthy,
                        container: self.container.name.clone(),
                    },
                ))
            }
            Err(err) => {
                self.warn_object("service", name, &err);
                None
            }
        }
    }

    /// Behind a virtual IP there is one backend: active health checks would take the whole
    /// service out, and sticky sessions have nothing to choose between (ADR-0026).
    fn drop_per_task_settings(&mut self, name: &str, service: &mut Service) {
        if service.sticky.take().is_some() {
            let message = format!(
                "service `{name}`: sticky sessions do nothing behind a Swarm virtual IP; the setting is ignored"
            );
            self.warn_container(message, Some(VIP_HINT.to_owned()));
        }
        if service
            .health
            .as_mut()
            .and_then(|health| health.active.take())
            .is_some()
        {
            let message = format!(
                "service `{name}`: active health checks cannot see tasks behind a Swarm virtual IP; the setting is ignored"
            );
            self.warn_container(message, Some(VIP_HINT.to_owned()));
        }
    }

    /// Port: the label, else the only exposed port (W-DKR-05).
    fn port(&mut self, service: &str, label: Option<u16>) -> Option<u16> {
        if let Some(port) = label {
            return Some(port);
        }
        if self.platform() == Platform::Swarm {
            let message = format!(
                "service `{service}`: Swarm reports no ports for its tasks, so the port must be set"
            );
            self.warn_container(message, Some(SWARM_PORT_HINT.to_owned()));
            return None;
        }
        let ports = &self.container.exposed_ports;
        if self.container.host_network {
            let message =
                format!("service `{service}`: a container on the host network needs a port label");
            self.warn_container(
                message,
                Some("set `rdock.port` or `rdock.services.<name>.port`".to_owned()),
            );
            return None;
        }
        match ports.len() {
            1 => ports.iter().next().copied(),
            0 => {
                let message = format!("service `{service}`: the container exposes no port");
                self.warn_container(
                    message,
                    Some("set `rdock.port` or `rdock.services.<name>.port`".to_owned()),
                );
                None
            }
            n => {
                let list: Vec<String> = ports.iter().map(u16::to_string).collect();
                let message = format!(
                    "service `{service}`: the container exposes {n} ports ({}); set which one to use",
                    list.join(", ")
                );
                self.warn_container(
                    message,
                    Some("set `rdock.port` or `rdock.services.<name>.port`".to_owned()),
                );
                None
            }
        }
    }

    /// Address: the network named on the container, else the provider's network, else the
    /// container's only network (W-DKR-04). Host-network containers use `host_address`.
    fn address(&mut self) -> Option<IpAddr> {
        if self.container.host_network {
            return Some(self.settings.host_address);
        }
        let networks = &self.container.networks;
        let labelled = match self.platform() {
            Platform::Docker => self
                .label("rdock.network")
                .or_else(|| self.label("traefik.docker.network")),
            Platform::Swarm => swarm_option_in(&self.labels, "rdock.network", "network"),
        };
        let named = labelled
            .map(str::to_owned)
            .or_else(|| self.settings.network.map(str::to_owned));
        let noun = self.platform().noun();
        let chosen = match &named {
            Some(name) => {
                let Some(ip) = networks.get(name) else {
                    let message = format!("the {noun} is not on network `{name}`");
                    let hint = format!(
                        "it is on: {}",
                        networks.keys().cloned().collect::<Vec<_>>().join(", ")
                    );
                    self.warn_container(message, Some(hint));
                    return None;
                };
                ip.map(|ip| (name.clone(), ip))
            }
            None => match self.unnamed_network() {
                Ok(name) => networks
                    .get(name)
                    .copied()
                    .flatten()
                    .map(|ip| (name.to_owned(), ip)),
                Err(message) => {
                    let hint = format!(
                        "set `rdock.network` on the {} or `providers.{}.network`",
                        match self.platform() {
                            Platform::Docker => "container",
                            Platform::Swarm => "service",
                        },
                        self.platform().provider()
                    );
                    self.warn_container(message, Some(hint));
                    return None;
                }
            },
        };
        if chosen.is_none() {
            self.warn_container(format!("the {noun} has no IP address on its network"), None);
        }
        chosen.map(|(_, ip)| ip)
    }

    /// The network to use when none is named: the only one the container shares with
    /// ReverseDock's own container when that is known, else the container's only network.
    fn unnamed_network(&self) -> Result<&'a str, String> {
        let networks = &self.container.networks;
        let noun = self.platform().noun();
        let list = |names: &[&str]| names.join(", ");
        let all: Vec<&str> = networks.keys().map(String::as_str).collect();
        let Some(own) = self.settings.proxy_networks else {
            return match all.as_slice() {
                [only] => Ok(only),
                [] => Err(format!("the {noun} is on no network")),
                _ => Err(format!(
                    "the {noun} is on several networks ({}); choose one",
                    list(&all)
                )),
            };
        };
        let shared: Vec<&str> = all.iter().copied().filter(|n| own.contains(*n)).collect();
        match shared.as_slice() {
            [only] => Ok(only),
            [] if all.is_empty() => Err(format!("the {noun} is on no network")),
            [] => Err(format!(
                "the {noun} shares no network with ReverseDock's container (it is on: {})",
                list(&all)
            )),
            _ => Err(format!(
                "the {noun} shares several networks with ReverseDock's container ({}); choose one",
                list(&shared)
            )),
        }
    }
}

/// Hint for settings that a virtual IP makes useless.
const VIP_HINT: &str = "remove the setting, or route to each task (`providers.swarm.endpoint_mode: tasks`, or `rdock.swarm.lbswarm=false` on the service)";

/// Hint for a Swarm service without a port label.
const SWARM_PORT_HINT: &str = "set `rdock.port`, `rdock.services.<name>.port` or `traefik.http.services.<name>.loadbalancer.server.port` on the service";

/// `web-1`, `my_app.v2` and `Shop Web` → `web-1`, `my_app.v2`, `shop-web`.
fn normalize(name: &str) -> String {
    let mut out: String = name
        .trim_start_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while out.starts_with(['-', '_', '.']) {
        out.remove(0);
    }
    out.truncate(MAX_NAME_LEN);
    if out.is_empty() {
        "container".to_owned()
    } else {
        out
    }
}

/// One container's backend in a service.
#[derive(Debug, Clone)]
struct Backend {
    address: String,
    healthy: bool,
    container: String,
}

/// Services with the backends of every container that declares them (replicas share names).
#[derive(Debug, Default)]
struct Pools {
    services: BTreeMap<String, (Service, Vec<Backend>)>,
    conflicts: BTreeSet<(String, String)>,
}

impl Pools {
    fn add(&mut self, scope: &mut Scope<'_>, name: String, service: &Service, backend: Backend) {
        let mut shape = service.clone();
        shape.backends.clear();
        match self.services.get_mut(&name) {
            None => {
                self.services.insert(name, (shape, vec![backend]));
            }
            Some((existing, backends)) if *existing == shape => backends.push(backend),
            Some(_) => {
                self.conflicts.insert(("service".to_owned(), name.clone()));
                let message = format!(
                    "service `{name}` is declared differently by another container; both are ignored"
                );
                scope.warn_container(message, None);
            }
        }
    }

    fn add_route(
        &mut self,
        scope: &mut Scope<'_>,
        name: String,
        route: Route,
        fragment: &mut Fragment,
    ) {
        match fragment.routes.get(&name) {
            Some(existing) if *existing != route => {
                self.conflicts.insert(("route".to_owned(), name.clone()));
                let message = format!(
                    "route `{name}` is declared differently by another container; both are ignored"
                );
                scope.warn_container(message, None);
            }
            _ => {
                fragment.routes.insert(name, route);
            }
        }
    }

    fn add_middleware(
        &mut self,
        scope: &mut Scope<'_>,
        name: String,
        middleware: Middleware,
        fragment: &mut Fragment,
    ) {
        match fragment.middlewares.get(&name) {
            Some(existing) if *existing != middleware => {
                self.conflicts
                    .insert(("middleware".to_owned(), name.clone()));
                let message = format!(
                    "middleware `{name}` is declared differently by another container; both are ignored"
                );
                scope.warn_container(message, None);
            }
            _ => {
                fragment.middlewares.insert(name, middleware);
            }
        }
    }

    /// Drops conflicting objects and fills each service with its serving backends: the healthy
    /// ones, or all of them when none is healthy (fail open, with a warning).
    fn finish(self, out: &mut Translation) {
        for (kind, name) in &self.conflicts {
            if kind == "route" {
                out.fragment.routes.remove(name);
            } else if kind == "middleware" {
                out.fragment.middlewares.remove(name);
            }
        }
        for (name, (mut service, backends)) in self.services {
            if self
                .conflicts
                .contains(&("service".to_owned(), name.clone()))
            {
                continue;
            }
            let healthy: Vec<&Backend> = backends.iter().filter(|b| b.healthy).collect();
            let serving: Vec<&Backend> = if healthy.is_empty() {
                let containers: Vec<&str> = backends.iter().map(|b| b.container.as_str()).collect();
                out.diagnostics.push(Diagnostic::warning(
                    path_key("services", &name),
                    format!(
                        "no container of service `{name}` is healthy ({}); sending traffic to all of them",
                        containers.join(", ")
                    ),
                ));
                backends.iter().collect()
            } else {
                healthy
            };
            let mut addresses: Vec<&str> = serving.iter().map(|b| b.address.as_str()).collect();
            addresses.sort_unstable();
            addresses.dedup();
            service.backends = addresses
                .into_iter()
                .filter_map(|a| decode(serde_json::json!({ "address": a })).ok())
                .collect();
            out.fragment.services.insert(name, service);
        }
    }
}

#[cfg(test)]
mod tests;
