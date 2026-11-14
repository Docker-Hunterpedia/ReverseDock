//! Container labels into routes, services, middlewares, TCP routes and TCP services
//! (ADR-0018). Pure: no I/O.
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
use rdock_model::route::{Route, TcpRoute, UdpRoute};
use rdock_model::service::{Service, TcpService, UdpService};
use rdock_model::{Diagnostic, path_key};
use serde::de::DeserializeOwned;
use serde_json::Value;

mod native;
mod traefik;
mod traefik_tcp;
mod traefik_udp;
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

/// Whether the route's last middleware is a `static` of the same container that answers every
/// request (no `pass_through`).
fn ends_with_static(middlewares: &BTreeMap<String, Tree>, route: &Tree) -> bool {
    let Some(Value::Array(chain)) = route.top("middlewares") else {
        return false;
    };
    let Some(middleware) = chain
        .last()
        .and_then(Value::as_str)
        .and_then(|last| middlewares.get(last))
    else {
        return false;
    };
    middleware.top("type").and_then(Value::as_str) == Some("static")
        && middleware.top("pass_through") != Some(&Value::Bool(true))
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
    pub(crate) tcp_routes: BTreeMap<String, Tree>,
    pub(crate) tcp_services: BTreeMap<String, ServiceDraft>,
    pub(crate) udp_routes: BTreeMap<String, Tree>,
    pub(crate) udp_services: BTreeMap<String, ServiceDraft>,
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

    /// A deprecated label (ADR-0033): the registry's warning, at the label.
    pub(crate) fn deprecated(
        &mut self,
        label: &str,
        entry: &rdock_model::deprecation::Deprecation,
    ) {
        let path = self.path(Some(label));
        self.out
            .push(rdock_model::deprecation::diagnostic(entry, path));
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
        self.link_services(&mut draft.routes, &mut draft.services, &draft.middlewares);
        traefik::apply_retries(self, &mut draft);
        for (name, service) in std::mem::take(&mut draft.services) {
            if let Some((mut service, backend)) = self.service::<Service>(&name, service) {
                if self.virtual_ip {
                    self.drop_per_task_settings(&name, &mut service);
                }
                pools.add(self, name, service, backend);
            }
        }
        self.build_tcp(&mut draft, pools, fragment);
        self.build_udp(&mut draft, pools, fragment);
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

    /// TCP routes and services: like HTTP ones, except that a TCP route must name its
    /// listeners (Traefik attaches a router without entry points to all of them).
    fn build_tcp(&mut self, draft: &mut Draft, pools: &mut Pools, fragment: &mut Fragment) {
        draft.tcp_routes.retain(|_, tree| !tree.is_empty());
        let unattached: Vec<String> = draft
            .tcp_routes
            .iter()
            .filter(|(_, tree)| !tree.has("listeners"))
            .map(|(name, _)| name.clone())
            .collect();
        for name in unattached {
            draft.tcp_routes.remove(&name);
            let message = format!("TCP route `{name}` names no listener; the route is ignored");
            let hint = "set `traefik.tcp.routers.<name>.entrypoints` or `rdock.tcp_routes.<name>.listeners`";
            self.warn_container(message, Some(hint.to_owned()));
        }
        self.link_services(
            &mut draft.tcp_routes,
            &mut draft.tcp_services,
            &BTreeMap::new(),
        );
        for (name, service) in std::mem::take(&mut draft.tcp_services) {
            if let Some((service, backend)) = self.service::<TcpService>(&name, service) {
                pools.add_tcp(self, name, service, backend);
            }
        }
        for (name, tree) in std::mem::take(&mut draft.tcp_routes) {
            match decode::<TcpRoute>(tree.into_value()) {
                Ok(route) => pools.add_tcp_route(self, name, route, fragment),
                Err(err) => self.warn_object("TCP route", &name, &err),
            }
        }
    }

    /// UDP routes and services: like TCP ones, a UDP route must name its listeners.
    fn build_udp(&mut self, draft: &mut Draft, pools: &mut Pools, fragment: &mut Fragment) {
        draft.udp_routes.retain(|_, tree| !tree.is_empty());
        let unattached: Vec<String> = draft
            .udp_routes
            .iter()
            .filter(|(_, tree)| !tree.has("listeners"))
            .map(|(name, _)| name.clone())
            .collect();
        for name in unattached {
            draft.udp_routes.remove(&name);
            let message = format!("UDP route `{name}` names no listener; the route is ignored");
            let hint = "set `traefik.udp.routers.<name>.entrypoints` or `rdock.udp_routes.<name>.listeners`";
            self.warn_container(message, Some(hint.to_owned()));
        }
        self.link_services(
            &mut draft.udp_routes,
            &mut draft.udp_services,
            &BTreeMap::new(),
        );
        for (name, service) in std::mem::take(&mut draft.udp_services) {
            // Docker reports exposed UDP ports apart from TCP ones, and a TCP port is no
            // guess for a UDP service: the port is always named.
            if service.port.is_none() && service.address.is_none() {
                let message = format!("UDP service `{name}` names no port; the service is ignored");
                let hint = "set `rdock.udp_services.<name>.port` or `traefik.udp.services.<name>.loadbalancer.server.port`";
                self.warn_container(message, Some(hint.to_owned()));
                continue;
            }
            if let Some((service, backend)) = self.service::<UdpService>(&name, service) {
                pools.add_udp(self, name, service, backend);
            }
        }
        for (name, tree) in std::mem::take(&mut draft.udp_routes) {
            match decode::<UdpRoute>(tree.into_value()) {
                Ok(route) => pools.add_udp_route(self, name, route, fragment),
                Err(err) => self.warn_object("UDP route", &name, &err),
            }
        }
    }

    /// Routes without a service get the container's only service, or a default one when the
    /// container declares none (Traefik's behaviour). A route that ends with one of
    /// `middlewares` that is a `static` middleware is answered by it and needs none.
    fn link_services(
        &mut self,
        routes: &mut BTreeMap<String, Tree>,
        services: &mut BTreeMap<String, ServiceDraft>,
        middlewares: &BTreeMap<String, Tree>,
    ) {
        let unlinked: Vec<String> = routes
            .iter()
            .filter(|(_, tree)| !tree.has("service") && !ends_with_static(middlewares, tree))
            .map(|(name, _)| name.clone())
            .collect();
        if unlinked.is_empty() {
            return;
        }
        if services.is_empty() {
            services.insert(self.default_name(), ServiceDraft::default());
        }
        if services.len() > 1 {
            for name in unlinked {
                routes.remove(&name);
                let message = format!(
                    "route `{name}` names no service and the container has {} services; the route is ignored",
                    services.len()
                );
                self.warn_container(message, Some("set the route's `service` label".to_owned()));
            }
            return;
        }
        let service = services.keys().next().cloned().unwrap_or_default();
        for name in unlinked {
            if let Some(tree) = routes.get_mut(&name) {
                let _ = tree.set("service", Value::String(service.clone()));
            }
        }
    }

    /// Decodes a service (HTTP or TCP) and works out its backend for this container.
    fn service<T: DeserializeOwned>(
        &mut self,
        name: &str,
        draft: ServiceDraft,
    ) -> Option<(T, Backend)> {
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
        match decode::<T>(tree.into_value()) {
            Ok(service) => Some((
                service,
                Backend {
                    address,
                    healthy,
                    container: self.container.name.clone(),
                },
            )),
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

/// A service type whose backends are the containers that declare it.
trait Pooled: Clone + PartialEq {
    fn backends_mut(&mut self) -> &mut Vec<rdock_model::service::Backend>;
}

impl Pooled for Service {
    fn backends_mut(&mut self) -> &mut Vec<rdock_model::service::Backend> {
        &mut self.backends
    }
}

impl Pooled for TcpService {
    fn backends_mut(&mut self) -> &mut Vec<rdock_model::service::Backend> {
        &mut self.backends
    }
}

impl Pooled for UdpService {
    fn backends_mut(&mut self) -> &mut Vec<rdock_model::service::Backend> {
        &mut self.backends
    }
}

/// Services by name, each with the backends of every container that declares it.
type PoolMap<T> = BTreeMap<String, (T, Vec<Backend>)>;

/// Services with the backends of every container that declares them (replicas share names).
#[derive(Debug, Default)]
struct Pools {
    services: PoolMap<Service>,
    tcp_services: PoolMap<TcpService>,
    udp_services: PoolMap<UdpService>,
    /// (kind, name) of objects declared differently by two containers.
    conflicts: BTreeSet<(&'static str, String)>,
}

impl Pools {
    fn add(&mut self, scope: &mut Scope<'_>, name: String, service: Service, backend: Backend) {
        pool(
            &mut self.services,
            &mut self.conflicts,
            "service",
            scope,
            name,
            service,
            backend,
        );
    }

    fn add_tcp(
        &mut self,
        scope: &mut Scope<'_>,
        name: String,
        service: TcpService,
        backend: Backend,
    ) {
        let (services, conflicts) = (&mut self.tcp_services, &mut self.conflicts);
        pool(
            services,
            conflicts,
            "TCP service",
            scope,
            name,
            service,
            backend,
        );
    }

    fn add_udp(
        &mut self,
        scope: &mut Scope<'_>,
        name: String,
        service: UdpService,
        backend: Backend,
    ) {
        let (services, conflicts) = (&mut self.udp_services, &mut self.conflicts);
        pool(
            services,
            conflicts,
            "UDP service",
            scope,
            name,
            service,
            backend,
        );
    }

    fn add_udp_route(
        &mut self,
        scope: &mut Scope<'_>,
        name: String,
        route: UdpRoute,
        fragment: &mut Fragment,
    ) {
        let routes = &mut fragment.udp_routes;
        insert(routes, &mut self.conflicts, "UDP route", scope, name, route);
    }

    fn add_route(
        &mut self,
        scope: &mut Scope<'_>,
        name: String,
        route: Route,
        fragment: &mut Fragment,
    ) {
        let routes = &mut fragment.routes;
        insert(routes, &mut self.conflicts, "route", scope, name, route);
    }

    fn add_tcp_route(
        &mut self,
        scope: &mut Scope<'_>,
        name: String,
        route: TcpRoute,
        fragment: &mut Fragment,
    ) {
        let routes = &mut fragment.tcp_routes;
        insert(routes, &mut self.conflicts, "TCP route", scope, name, route);
    }

    fn add_middleware(
        &mut self,
        scope: &mut Scope<'_>,
        name: String,
        middleware: Middleware,
        fragment: &mut Fragment,
    ) {
        let middlewares = &mut fragment.middlewares;
        insert(
            middlewares,
            &mut self.conflicts,
            "middleware",
            scope,
            name,
            middleware,
        );
    }

    /// Drops conflicting objects and fills each service with its serving backends.
    fn finish(self, out: &mut Translation) {
        for (kind, name) in &self.conflicts {
            match *kind {
                "route" => drop(out.fragment.routes.remove(name)),
                "TCP route" => drop(out.fragment.tcp_routes.remove(name)),
                "UDP route" => drop(out.fragment.udp_routes.remove(name)),
                "middleware" => drop(out.fragment.middlewares.remove(name)),
                _ => {}
            }
        }
        let conflicts = &self.conflicts;
        out.fragment.services = fill(self.services, "service", conflicts, &mut out.diagnostics);
        out.fragment.tcp_services = fill(
            self.tcp_services,
            "TCP service",
            conflicts,
            &mut out.diagnostics,
        );
        out.fragment.udp_services = fill(
            self.udp_services,
            "UDP service",
            conflicts,
            &mut out.diagnostics,
        );
    }
}

/// Adds one container's backend to the service `name`; a container that declares the service
/// differently makes it a conflict.
fn pool<T: Pooled>(
    services: &mut PoolMap<T>,
    conflicts: &mut BTreeSet<(&'static str, String)>,
    kind: &'static str,
    scope: &mut Scope<'_>,
    name: String,
    mut shape: T,
    backend: Backend,
) {
    shape.backends_mut().clear();
    match services.get_mut(&name) {
        None => {
            services.insert(name, (shape, vec![backend]));
        }
        Some((existing, backends)) if *existing == shape => backends.push(backend),
        Some(_) => {
            let message = format!(
                "{kind} `{name}` is declared differently by another container; both are ignored"
            );
            conflicts.insert((kind, name));
            scope.warn_container(message, None);
        }
    }
}

/// Adds an object to the fragment; another container's different object of the same name
/// makes it a conflict.
fn insert<T: PartialEq>(
    objects: &mut BTreeMap<String, T>,
    conflicts: &mut BTreeSet<(&'static str, String)>,
    kind: &'static str,
    scope: &mut Scope<'_>,
    name: String,
    object: T,
) {
    match objects.get(&name) {
        Some(existing) if *existing != object => {
            let message = format!(
                "{kind} `{name}` is declared differently by another container; both are ignored"
            );
            conflicts.insert((kind, name));
            scope.warn_container(message, None);
        }
        _ => {
            objects.insert(name, object);
        }
    }
}

/// Each service with its serving backends: the healthy ones, or all of them when none is
/// healthy (fail open, with a warning).
fn fill<T: Pooled>(
    services: PoolMap<T>,
    kind: &'static str,
    conflicts: &BTreeSet<(&'static str, String)>,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<String, T> {
    let mut filled = BTreeMap::new();
    for (name, (mut service, backends)) in services {
        if conflicts.contains(&(kind, name.clone())) {
            continue;
        }
        let healthy: Vec<&Backend> = backends.iter().filter(|b| b.healthy).collect();
        let serving: Vec<&Backend> = if healthy.is_empty() {
            let containers: Vec<&str> = backends.iter().map(|b| b.container.as_str()).collect();
            let section = match kind {
                "service" => "services",
                "UDP service" => "udp_services",
                _ => "tcp_services",
            };
            diagnostics.push(Diagnostic::warning(
                path_key(section, &name),
                format!(
                    "no container of {kind} `{name}` is healthy ({}); sending traffic to all of them",
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
        *service.backends_mut() = addresses
            .into_iter()
            .filter_map(|a| decode(serde_json::json!({ "address": a })).ok())
            .collect();
        filled.insert(name, service);
    }
    filled
}

#[cfg(test)]
mod tests;
