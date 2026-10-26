//! Dynamic configuration providers.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::Endpoint;

/// Configuration sources besides this file.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Providers {
    /// More configuration files, merged with this one.
    pub file: Option<FileProvider>,
    /// Docker containers and their labels.
    pub docker: Option<DockerProvider>,
    /// Docker Swarm services and their `deploy.labels`.
    pub swarm: Option<SwarmProvider>,
    /// Kubernetes Gateway API and Ingress resources.
    pub kubernetes: Option<KubernetesProvider>,
}

/// File provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileProvider {
    /// Files or glob patterns (`/etc/rdock/conf.d/*.yaml`).
    pub paths: Vec<String>,
    /// Reload when the files change.
    #[serde(default = "crate::defaults::yes")]
    pub watch: bool,
}

/// Docker provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct DockerProvider {
    /// Docker Engine API endpoint. Read-only access is enough; a socket proxy is recommended.
    pub endpoint: Endpoint,
    /// Expose containers without `rdock.enable=true`. Off by default.
    pub expose_by_default: bool,
    /// Network used to reach containers that are on several networks.
    pub network: Option<String>,
    /// Also read `traefik.*` labels (supported subset).
    pub traefik_labels: bool,
    /// Traefik entrypoint name → listener name, for Traefik labels.
    pub entrypoints: BTreeMap<String, String>,
    /// Address used for containers in host network mode.
    pub host_address: IpAddr,
}

impl Default for DockerProvider {
    fn default() -> Self {
        Self {
            endpoint: default_docker_endpoint(),
            expose_by_default: false,
            network: None,
            traefik_labels: true,
            entrypoints: BTreeMap::new(),
            host_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }
}

fn default_docker_endpoint() -> Endpoint {
    "unix:///var/run/docker.sock"
        .parse()
        .unwrap_or_else(|_| unreachable!("constant endpoint"))
}

/// Docker Swarm provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SwarmProvider {
    /// Docker Engine API endpoint of a manager node.
    pub endpoint: Endpoint,
    /// Expose services without `rdock.enable=true`. Off by default.
    pub expose_by_default: bool,
    /// Overlay network used to reach services.
    pub network: Option<String>,
    /// Also read `traefik.*` labels (supported subset).
    pub traefik_labels: bool,
    /// Route to the service's virtual IP or to each task.
    pub endpoint_mode: SwarmEndpointMode,
}

impl Default for SwarmProvider {
    fn default() -> Self {
        Self {
            endpoint: default_docker_endpoint(),
            expose_by_default: false,
            network: None,
            traefik_labels: true,
            endpoint_mode: SwarmEndpointMode::Vip,
        }
    }
}

/// How Swarm services are reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SwarmEndpointMode {
    /// The service's virtual IP; Swarm balances between tasks.
    #[default]
    Vip,
    /// Each running task directly; ReverseDock balances and health-checks.
    Tasks,
}

/// Kubernetes provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct KubernetesProvider {
    /// `GatewayClass` name this instance serves.
    pub gateway_class: String,
    /// Namespaces to watch; all when empty.
    pub namespaces: Vec<String>,
    /// Also translate `networking.k8s.io/v1` Ingress resources.
    pub ingress: bool,
}

impl Default for KubernetesProvider {
    fn default() -> Self {
        Self {
            gateway_class: "reversedock".to_owned(),
            namespaces: Vec::new(),
            ingress: false,
        }
    }
}
