//! Dynamic configuration providers.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::{Duration, Endpoint};

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
    /// Directories on ReverseDock's file system that `static` middlewares from labels may
    /// serve (`rdock.static.root`). Empty, the default, refuses every such middleware, so a
    /// container cannot read ReverseDock's own files.
    pub static_roots: Vec<PathBuf>,
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
            static_roots: Vec::new(),
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
    /// Route to each running task (the default) or to the service's virtual IP.
    pub endpoint_mode: SwarmEndpointMode,
    /// How often services and tasks are listed. Swarm sends no events when a task starts or
    /// stops, so this bounds how long a new or stopping task waits to join or leave its pool.
    /// At least `1s`.
    pub poll_interval: Duration,
    /// Directories on ReverseDock's file system that `static` middlewares from service labels
    /// may serve (`rdock.static.root`). Empty, the default, refuses every such middleware, so a
    /// service cannot read ReverseDock's own files (ADR-0027).
    pub static_roots: Vec<PathBuf>,
}

impl Default for SwarmProvider {
    fn default() -> Self {
        Self {
            endpoint: default_docker_endpoint(),
            expose_by_default: false,
            network: None,
            traefik_labels: true,
            endpoint_mode: SwarmEndpointMode::Tasks,
            poll_interval: Duration::from_secs(5),
            static_roots: Vec::new(),
        }
    }
}

/// How Swarm services are reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SwarmEndpointMode {
    /// Each running task directly; ReverseDock balances, health-checks and drains them.
    #[default]
    Tasks,
    /// The service's virtual IP; Swarm balances between tasks. Active health checks and
    /// sticky sessions have nothing to act on and are ignored.
    Vip,
}

/// Kubernetes provider (ADR-0029): a Gateway API controller and, optionally, an Ingress
/// controller in the same process as the data plane. Every replica watches, translates and
/// serves; only the leader writes status, Events and the per-Gateway Services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct KubernetesProvider {
    /// Path of a kubeconfig file. Unset, the in-cluster service account is used, then the
    /// `KUBECONFIG` variable and `~/.kube/config`.
    pub kubeconfig: Option<PathBuf>,
    /// Namespaces whose objects are watched; all namespaces when empty. Cluster-scoped kinds
    /// (`GatewayClass`, `IngressClass`, `Namespace`) are always watched.
    pub namespaces: Vec<String>,
    /// The `spec.controllerName` of the `GatewayClass` objects this instance serves. A
    /// domain-prefixed path, as the Gateway API requires.
    pub controller_name: String,
    /// Gateway API (`gateway.networking.k8s.io/v1`).
    pub gateway: KubernetesGateway,
    /// Ingress (`networking.k8s.io/v1`), for migrations.
    pub ingress: KubernetesIngress,
    /// Leader election: only the leader writes to the cluster.
    pub leader_election: KubernetesLeaderElection,
    /// Allow automatic certificates (`acme`) together with this provider. Off by default:
    /// replicas share no certificate storage, so ACME is only safe with one replica and a
    /// persistent data directory. Use cert-manager in a cluster.
    pub allow_acme: bool,
}

impl Default for KubernetesProvider {
    fn default() -> Self {
        Self {
            kubeconfig: None,
            namespaces: Vec::new(),
            controller_name: "reversedock.dev/gateway-controller".to_owned(),
            gateway: KubernetesGateway::default(),
            ingress: KubernetesIngress::default(),
            leader_election: KubernetesLeaderElection::default(),
            allow_acme: false,
        }
    }
}

/// Gateway API settings of the Kubernetes provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct KubernetesGateway {
    /// Serve `Gateway` objects of the `GatewayClass` objects with our `controller_name`.
    pub enabled: bool,
    /// Type of the Service created for each Gateway; its addresses become the Gateway's
    /// `status.addresses`.
    pub service_type: KubernetesServiceType,
    /// Namespace of the per-Gateway Services; the controller's own namespace when unset.
    pub service_namespace: Option<String>,
    /// Labels that select the ReverseDock pods, used as the selector of the per-Gateway
    /// Services. Empty, the default, uses the pod's own labels.
    pub pod_selector: BTreeMap<String, String>,
    /// Internal ports allocated to (Gateway, listener port) pairs, as `start-end`, inside
    /// 1024–65535. Each pair opens one listener in every ReverseDock pod; running out is
    /// reported on the Gateway (`Programmed=False`).
    pub port_range: String,
    /// Allow `backendRefs` to `ExternalName` Services. Off by default: such a Service can
    /// point anywhere, including at cluster-internal names its author cannot otherwise reach.
    pub allow_external_name: bool,
}

impl Default for KubernetesGateway {
    fn default() -> Self {
        Self {
            enabled: true,
            service_type: KubernetesServiceType::LoadBalancer,
            service_namespace: None,
            pod_selector: BTreeMap::new(),
            port_range: "20000-29999".to_owned(),
            allow_external_name: false,
        }
    }
}

impl KubernetesGateway {
    /// The first and last port of `port_range`, when it is well formed (`start-end`, both
    /// numbers). Validation checks the bounds.
    #[must_use]
    pub fn ports(&self) -> Option<(u16, u16)> {
        let (start, end) = self.port_range.split_once('-')?;
        Some((start.trim().parse().ok()?, end.trim().parse().ok()?))
    }
}

/// Kubernetes Service types for the per-Gateway Services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesServiceType {
    /// `LoadBalancer`: an external address from the cluster's load-balancer integration.
    #[default]
    LoadBalancer,
    /// `ClusterIP`: reachable inside the cluster only; the cluster IP is the Gateway address.
    ClusterIp,
    /// `NodePort`: a port on every node.
    NodePort,
}

/// Ingress settings of the Kubernetes provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct KubernetesIngress {
    /// Translate `Ingress` objects. Off by default.
    pub enabled: bool,
    /// Ingress class served: Ingresses whose `ingressClassName` names an `IngressClass` with
    /// controller `reversedock.dev/ingress-controller`, or whose deprecated
    /// `kubernetes.io/ingress.class` annotation equals this value.
    pub class: String,
    /// Also claim Ingresses without any class. Without this, they are claimed only when our
    /// `IngressClass` is the cluster default.
    pub claim_without_class: bool,
    /// Service (`namespace/name`) whose load-balancer addresses are published in the
    /// Ingresses' `status.loadBalancer`.
    pub publish_service: Option<String>,
    /// Address (IP or host name) published in the Ingresses' `status.loadBalancer`, instead
    /// of `publish_service`.
    pub publish_address: Option<String>,
    /// Honour the `nginx.ingress.kubernetes.io/*` annotations that map one to one onto a
    /// middleware; other annotations of that prefix are reported, `*-snippet` ones refused.
    pub nginx_annotations: bool,
}

impl Default for KubernetesIngress {
    fn default() -> Self {
        Self {
            enabled: false,
            class: "reversedock".to_owned(),
            claim_without_class: false,
            publish_service: None,
            publish_address: None,
            nginx_annotations: true,
        }
    }
}

/// Leader election through a `coordination.k8s.io/v1` Lease in the controller's namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct KubernetesLeaderElection {
    /// Elect a leader. `false` makes this instance the only writer (one replica, or outside
    /// a cluster). Serving and readiness never depend on leadership.
    pub enabled: bool,
    /// Name of the Lease.
    pub lease: String,
}

impl Default for KubernetesLeaderElection {
    fn default() -> Self {
        Self {
            enabled: true,
            lease: "reversedock-leader".to_owned(),
        }
    }
}
