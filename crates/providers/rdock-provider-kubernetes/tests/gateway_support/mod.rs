//! Test support for the Gateway API translator: an [`Inventory`] built from the upstream
//! conformance manifests the way a cluster would hold them, and a real compile of the
//! translated fragment to ask which backend a request reaches.
//!
//! What a cluster adds and these helpers synthesise:
//! - the conformance GatewayClass (`gateway-conformance`, our controller) and the
//!   `{GATEWAY_CLASS_NAME}`/`{GATEWAY_CONTROLLER_NAME}` placeholders;
//! - `metadata.generation` 1 and increasing `creationTimestamp`s in manifest order;
//! - namespace labels, including `kubernetes.io/metadata.name`;
//! - pods for every Deployment (fabricated IPs, one per replica) and an EndpointSlice for
//!   every Service whose selector matches them; manual EndpointSlices without endpoints get
//!   the `infra-backend-v1` pods, as `HTTPRouteServiceTypes` does;
//! - the Secrets and ConfigMaps the suite creates programmatically (`suite.go`), valid;
//! - the per-Gateway Services: [`Cluster::translate`] runs the translation once, allocates
//!   internal ports and an address for every desired Service (what the leader does), and
//!   translates again.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_self
)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort, EndpointSlice};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use rdock_config::merge::{Snapshot, assemble};
use rdock_model::middleware::Middleware;
use rdock_model::providers::KubernetesProvider;
use rdock_model::route::Route;
use rdock_provider_kubernetes::api::{
    BackendTLSPolicy, GRPCRoute, Gateway, GatewayClass, GatewayStatusAddress, HTTPRoute,
    ListenerSet, ReferenceGrant, TCPRoute, TLSRoute, UDPRoute,
};
use rdock_provider_kubernetes::inventory::{
    ConfigMapInfo, GatewayService, Inventory, SERVICE_NAME_LABEL, SecretInfo,
};
use rdock_provider_kubernetes::translate::{
    DesiredCondition, DesiredGateway, DesiredListener, DesiredRouteParent, RouteKind, RouteRef,
    Settings, Translation, translate,
};
use serde_json::Value;

/// The conformance GatewayClass.
pub const CLASS: &str = "gateway-conformance";
/// Our controller name.
pub const CONTROLLER: &str = "reversedock.dev/gateway-controller";
/// The infrastructure namespace of the suite.
pub const INFRA: &str = "gateway-conformance-infra";
/// The web backend namespace.
pub const WEB: &str = "gateway-conformance-web-backend";
/// The app backend namespace.
pub const APP: &str = "gateway-conformance-app-backend";

/// Secrets the suite creates at run time (`suite.go`), as (namespace, name).
const PROGRAMMATIC_SECRETS: &[(&str, &str)] = &[
    (WEB, "certificate"),
    (INFRA, "tls-validity-checks-certificate"),
    (INFRA, "tls-validity-checks-client-certificate"),
    (INFRA, "tls-validity-checks-per-port-client-certificate"),
    (INFRA, "tls-checks-certificate"),
    (INFRA, "tls-checks-client-certificate"),
    (INFRA, "tls-passthrough-checks-certificate"),
    (APP, "tls-passthrough-checks-certificate"),
    (INFRA, "tls-terminate-checks-certificate"),
];

/// ConfigMaps the suite creates at run time.
const PROGRAMMATIC_CONFIG_MAPS: &[(&str, &str)] = &[
    (WEB, "web-backend-cm"),
    (INFRA, "tls-validity-checks-ca-certificate"),
    (INFRA, "tls-validity-checks-per-port-ca-certificate"),
    (INFRA, "tls-checks-ca-certificate"),
    (INFRA, "mismatch-ca-certificate"),
];

/// A simulated cluster.
pub struct Cluster {
    /// What the watches would hold.
    pub inventory: Inventory,
    /// Translator settings.
    pub settings: Settings,
    /// Pod IP → (namespace, Deployment).
    pub pods: BTreeMap<String, (String, String)>,
    next_port: u16,
    created: u32,
    deployments: Vec<Deployment>,
    dir: tempfile::TempDir,
}

struct Deployment {
    namespace: String,
    name: String,
    labels: BTreeMap<String, String>,
    ips: Vec<String>,
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

impl Cluster {
    /// The base manifests and the upstream test manifests `tests` (file names without
    /// `.yaml` in `tests/fixtures/upstream`).
    pub fn upstream(tests: &[&str]) -> Self {
        let mut files = vec!["upstream/base-manifests.yaml".to_owned()];
        files.extend(tests.iter().map(|t| format!("upstream/{t}.yaml")));
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        Self::from_files(&files)
    }

    /// Manifests from files below `tests/fixtures`.
    pub fn from_files(files: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            provider: KubernetesProvider::default(),
            controller_namespace: "reversedock-system".to_owned(),
            data_dir: dir.path().to_owned(),
        };
        let mut cluster = Self {
            inventory: Inventory::default(),
            settings,
            pods: BTreeMap::new(),
            next_port: 20000,
            created: 0,
            deployments: Vec::new(),
            dir,
        };
        cluster.inventory.crd_bundle_version = Some("v1.7.0".to_owned());
        cluster.apply_yaml(&format!(
            "apiVersion: gateway.networking.k8s.io/v1\nkind: GatewayClass\nmetadata: {{name: {CLASS}}}\nspec: {{controllerName: \"{CONTROLLER}\"}}\n"
        ));
        for file in files {
            let text =
                std::fs::read_to_string(fixture(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
            cluster.apply_yaml(&text);
        }
        for (ns, name) in PROGRAMMATIC_SECRETS {
            let key = ((*ns).to_owned(), (*name).to_owned());
            cluster.inventory.secrets.entry(key).or_insert(SecretInfo {
                namespace: (*ns).to_owned(),
                name: (*name).to_owned(),
                kind: "kubernetes.io/tls".to_owned(),
                valid: Ok(()),
            });
        }
        for (ns, name) in PROGRAMMATIC_CONFIG_MAPS {
            let key = ((*ns).to_owned(), (*name).to_owned());
            cluster
                .inventory
                .config_maps
                .entry(key)
                .or_insert(ConfigMapInfo {
                    namespace: (*ns).to_owned(),
                    name: (*name).to_owned(),
                    ca_bundle: Ok(()),
                });
        }
        cluster.make_endpoints();
        cluster
    }

    /// Applies multi-document YAML (placeholders replaced, generation and creation time set).
    pub fn apply_yaml(&mut self, text: &str) {
        let text = text
            .replace("{GATEWAY_CLASS_NAME}", CLASS)
            .replace("{GATEWAY_CONTROLLER_NAME}", CONTROLLER);
        let docs: Vec<Value> = serde_saphyr::from_multiple(&text).unwrap();
        for doc in docs {
            if doc.is_null() {
                continue;
            }
            self.apply(doc);
        }
    }

    fn apply(&mut self, mut doc: Value) {
        self.created += 1;
        let meta = doc
            .as_object_mut()
            .unwrap()
            .entry("metadata")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let meta = meta.as_object_mut().unwrap();
        meta.entry("generation").or_insert(Value::from(1));
        let (h, m, s) = (
            self.created / 3600,
            (self.created / 60) % 60,
            self.created % 60,
        );
        meta.entry("creationTimestamp")
            .or_insert(Value::from(format!("2026-01-01T{h:02}:{m:02}:{s:02}Z")));
        let name = meta["name"].as_str().unwrap_or_default().to_owned();
        let namespace = meta
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let key = (namespace.clone(), name.clone());
        let kind = doc["kind"].as_str().unwrap_or_default().to_owned();
        let inv = &mut self.inventory;
        match kind.as_str() {
            "Namespace" => {
                let mut labels: BTreeMap<String, String> =
                    serde_json::from_value(doc["metadata"]["labels"].clone()).unwrap_or_default();
                labels.insert("kubernetes.io/metadata.name".to_owned(), name.clone());
                inv.namespaces.insert(name, labels);
            }
            "GatewayClass" => {
                inv.gateway_classes
                    .insert(name, typed::<GatewayClass>(&doc));
            }
            "Gateway" => {
                self.ensure_namespace(&namespace);
                self.inventory.gateways.insert(key, typed::<Gateway>(&doc));
            }
            "HTTPRoute" => {
                inv.http_routes.insert(key, typed::<HTTPRoute>(&doc));
            }
            "GRPCRoute" => {
                inv.grpc_routes.insert(key, typed::<GRPCRoute>(&doc));
            }
            "TLSRoute" => {
                inv.tls_routes.insert(key, typed::<TLSRoute>(&doc));
            }
            "TCPRoute" => {
                inv.tcp_routes.insert(key, typed::<TCPRoute>(&doc));
            }
            "UDPRoute" => {
                inv.udp_routes.insert(key, typed::<UDPRoute>(&doc));
            }
            "ReferenceGrant" => {
                inv.reference_grants
                    .insert(key, typed::<ReferenceGrant>(&doc));
            }
            "ListenerSet" => {
                inv.listener_sets.insert(key, typed::<ListenerSet>(&doc));
            }
            "BackendTLSPolicy" => {
                inv.backend_tls_policies
                    .insert(key, typed::<BackendTLSPolicy>(&doc));
            }
            "Ingress" => {
                inv.ingresses.insert(key, typed::<Ingress>(&doc));
            }
            "IngressClass" => {
                inv.ingress_classes
                    .insert(name, typed::<IngressClass>(&doc));
            }
            "Service" => {
                inv.services.insert(key, typed::<Service>(&doc));
            }
            "EndpointSlice" => {
                inv.endpoint_slices
                    .insert(key, typed::<EndpointSlice>(&doc));
            }
            "Secret" => {
                let data = &doc["data"];
                let decode = |field: &str| {
                    data[field]
                        .as_str()
                        .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default()
                };
                let valid = if decode("tls.crt").contains("BEGIN CERTIFICATE")
                    && decode("tls.key").contains("PRIVATE KEY")
                {
                    Ok(())
                } else {
                    Err("tls.crt and tls.key do not hold a PEM certificate and key".to_owned())
                };
                inv.secrets.insert(
                    key,
                    SecretInfo {
                        namespace,
                        name,
                        kind: doc["type"].as_str().unwrap_or("Opaque").to_owned(),
                        valid,
                    },
                );
            }
            "ConfigMap" => {
                let ok = doc["data"]["ca.crt"]
                    .as_str()
                    .is_some_and(|v| v.contains("BEGIN CERTIFICATE"));
                inv.config_maps.insert(
                    key,
                    ConfigMapInfo {
                        namespace,
                        name,
                        ca_bundle: if ok {
                            Ok(())
                        } else {
                            Err("no ca.crt".to_owned())
                        },
                    },
                );
            }
            "Deployment" => {
                let labels: BTreeMap<String, String> =
                    serde_json::from_value(doc["spec"]["template"]["metadata"]["labels"].clone())
                        .unwrap_or_default();
                let replicas = doc["spec"]["replicas"].as_u64().unwrap_or(1);
                let index = self.deployments.len() + 1;
                let ips: Vec<String> = (1..=replicas)
                    .map(|i| format!("10.{}.{}.{i}", index / 250, index % 250))
                    .collect();
                for ip in &ips {
                    self.pods
                        .insert(ip.clone(), (namespace.clone(), name.clone()));
                }
                self.deployments.push(Deployment {
                    namespace,
                    name,
                    labels,
                    ips,
                });
            }
            _ => {}
        }
    }

    fn ensure_namespace(&mut self, namespace: &str) {
        self.inventory
            .namespaces
            .entry(namespace.to_owned())
            .or_insert_with(|| {
                [(
                    "kubernetes.io/metadata.name".to_owned(),
                    namespace.to_owned(),
                )]
                .into()
            });
    }

    /// EndpointSlices for Services with selectors, and pods in empty manual slices.
    fn make_endpoints(&mut self) {
        let services: Vec<((String, String), Service)> = self
            .inventory
            .services
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for ((ns, name), service) in services {
            let Some(spec) = service.spec else { continue };
            let Some(selector) = spec.selector.filter(|s| !s.is_empty()) else {
                continue;
            };
            let ips: Vec<String> = self
                .deployments
                .iter()
                .filter(|d| {
                    d.namespace == ns && selector.iter().all(|(k, v)| d.labels.get(k) == Some(v))
                })
                .flat_map(|d| d.ips.clone())
                .collect();
            let ports: Vec<EndpointPort> = spec
                .ports
                .unwrap_or_default()
                .into_iter()
                .map(|p| EndpointPort {
                    name: p.name.clone(),
                    port: Some(match p.target_port {
                        Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(n)) => {
                            n
                        }
                        _ => p.port,
                    }),
                    protocol: p.protocol.clone(),
                    app_protocol: p.app_protocol.clone(),
                })
                .collect();
            let slice = endpoint_slice(&ns, &format!("{name}-auto"), &name, "IPv4", &ips, ports);
            self.inventory
                .endpoint_slices
                .insert((ns.clone(), format!("{name}-auto")), slice);
        }
        let infra_v1: Vec<String> = self
            .deployments
            .iter()
            .filter(|d| d.namespace == INFRA && d.name == "infra-backend-v1")
            .flat_map(|d| d.ips.clone())
            .collect();
        for (key, slice) in &mut self.inventory.endpoint_slices {
            if !slice.endpoints.is_empty() || key.1.ends_with("-auto") {
                continue;
            }
            let ips: Vec<String> = if slice.address_type == "IPv6" {
                infra_v1
                    .iter()
                    .map(|ip| format!("fd00::{}", ip.replace('.', ":")))
                    .collect()
            } else {
                infra_v1.clone()
            };
            for ip in &ips {
                self.pods.insert(
                    ip.clone(),
                    (INFRA.to_owned(), "infra-backend-v1".to_owned()),
                );
            }
            slice.endpoints = ips.iter().map(|ip| endpoint(ip)).collect();
        }
    }

    /// Translates like the controller: once, then again after the leader has created the
    /// per-Gateway Services with internal ports and an address.
    pub fn translate(&mut self) -> Translation {
        let first = translate(&self.inventory, &self.settings);
        let mut changed = false;
        for desired in &first.services {
            let existing = self
                .inventory
                .gateway_services
                .get(&desired.gateway)
                .cloned();
            let mut service = existing.unwrap_or_else(|| GatewayService {
                namespace: desired.namespace.clone(),
                name: desired.name.clone(),
                ports: BTreeMap::new(),
                udp_ports: BTreeMap::new(),
                addresses: vec![GatewayStatusAddress {
                    kind: Some("IPAddress".to_owned()),
                    value: format!("192.0.2.{}", self.inventory.gateway_services.len() + 1),
                }],
            });
            service.ports.retain(|port, _| desired.ports.contains(port));
            for port in &desired.ports {
                if !service.ports.contains_key(port) {
                    service.ports.insert(*port, self.next_port);
                    self.next_port += 1;
                }
            }
            service
                .udp_ports
                .retain(|port, _| desired.udp_ports.contains(port));
            for port in &desired.udp_ports {
                if !service.udp_ports.contains_key(port) {
                    service.udp_ports.insert(*port, self.next_port);
                    self.next_port += 1;
                }
            }
            if self.inventory.gateway_services.get(&desired.gateway) != Some(&service) {
                changed = true;
                self.inventory
                    .gateway_services
                    .insert(desired.gateway.clone(), service);
            }
        }
        if changed {
            translate(&self.inventory, &self.settings)
        } else {
            first
        }
    }

    /// The data directory.
    pub fn data_dir(&self) -> &Path {
        self.dir.path()
    }
}

fn typed<T: serde::de::DeserializeOwned>(doc: &Value) -> T {
    serde_json::from_value(doc.clone()).unwrap_or_else(|e| panic!("{e}: {doc:#}"))
}

fn endpoint(ip: &str) -> Endpoint {
    Endpoint {
        addresses: vec![ip.to_owned()],
        conditions: Some(EndpointConditions {
            ready: Some(true),
            serving: Some(true),
            terminating: Some(false),
        }),
        ..Endpoint::default()
    }
}

fn endpoint_slice(
    ns: &str,
    name: &str,
    service: &str,
    address_type: &str,
    ips: &[String],
    ports: Vec<EndpointPort>,
) -> EndpointSlice {
    EndpointSlice {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some(ns.to_owned()),
            labels: Some([(SERVICE_NAME_LABEL.to_owned(), service.to_owned())].into()),
            ..Default::default()
        },
        address_type: address_type.to_owned(),
        endpoints: ips.iter().map(|ip| endpoint(ip)).collect(),
        ports: Some(ports),
    }
}

// ---------------------------------------------------------------------------------------
// Status assertions.

/// The desired status of Gateway `ns/name`.
pub fn gateway<'a>(t: &'a Translation, ns: &str, name: &str) -> &'a DesiredGateway {
    t.status
        .gateways
        .get(&(ns.to_owned(), name.to_owned()))
        .unwrap_or_else(|| panic!("no status for Gateway {ns}/{name}"))
}

/// A listener of a Gateway status.
pub fn listener<'a>(gw: &'a DesiredGateway, name: &str) -> &'a DesiredListener {
    gw.listeners
        .iter()
        .find(|l| l.name == name)
        .unwrap_or_else(|| panic!("no listener {name} in {gw:#?}"))
}

/// Asserts a condition, like the upstream `findConditionInList` (an empty reason matches
/// any reason).
pub fn assert_condition(conditions: &[DesiredCondition], kind: &str, status: bool, reason: &str) {
    let found = conditions
        .iter()
        .find(|c| c.kind == kind)
        .unwrap_or_else(|| panic!("no {kind} condition in {conditions:#?}"));
    assert_eq!(found.status, status, "{kind}: {found:#?}");
    if !reason.is_empty() {
        assert_eq!(found.reason, reason, "{kind}: {found:#?}");
    }
    assert_eq!(found.observed_generation, Some(1), "{kind}: {found:#?}");
}

/// Asserts a listener's `supportedKinds` (kinds only, group `gateway.networking.k8s.io`)
/// and `attachedRoutes`, like `GatewayStatusMustHaveListeners`.
pub fn assert_listener(gw: &DesiredGateway, name: &str, kinds: &[&str], attached: i32) {
    let l = listener(gw, name);
    let actual: Vec<&str> = l.supported_kinds.iter().map(|k| k.kind.as_str()).collect();
    if kinds.is_empty() {
        assert!(actual.is_empty(), "{name}: supportedKinds {actual:?}");
    }
    for kind in kinds {
        assert!(actual.contains(kind), "{name}: {kind} not in {actual:?}");
    }
    for k in &l.supported_kinds {
        assert_eq!(k.group.as_deref(), Some("gateway.networking.k8s.io"));
    }
    assert_eq!(l.attached_routes, attached, "{name}: attachedRoutes");
}

/// Our `status.parents` entries of a route.
pub fn parents<'a>(
    t: &'a Translation,
    kind: RouteKind,
    ns: &str,
    name: &str,
) -> &'a [DesiredRouteParent] {
    t.status
        .routes
        .get(&RouteRef {
            kind,
            namespace: ns.to_owned(),
            name: name.to_owned(),
        })
        .map_or(&[], Vec::as_slice)
}

/// Our `status.parents` entry of a route for Gateway `gateway` (in `gateway_ns`), like
/// `HTTPRouteMustHaveCondition` (the first entry for that Gateway).
pub fn parent<'a>(
    t: &'a Translation,
    kind: RouteKind,
    route: (&str, &str),
    gateway: (&str, &str),
) -> &'a DesiredRouteParent {
    parents(t, kind, route.0, route.1)
        .iter()
        .find(|p| {
            p.parent_ref.name == gateway.1
                && p.parent_ref.namespace.as_deref().unwrap_or(route.0) == gateway.0
        })
        .unwrap_or_else(|| {
            panic!(
                "no parent {gateway:?} for {kind:?} {route:?}: {:#?}",
                t.status.routes
            )
        })
}

/// Asserts that a route is accepted by a Gateway with resolved references, and that every
/// listener of the Gateway is accepted, programmed and resolved
/// (`GatewayAndHTTPRoutesMustBeAccepted` + `HTTPRouteMustHaveResolvedRefsConditionsTrue`).
pub fn assert_accepted(t: &Translation, kind: RouteKind, route: (&str, &str), gw: (&str, &str)) {
    let p = parent(t, kind, route, gw);
    assert_condition(&p.conditions, "Accepted", true, "Accepted");
    assert_gateway_ready(t, gw);
}

/// Every listener of the Gateway is accepted, programmed and resolved, and the Gateway has
/// an address.
pub fn assert_gateway_ready(t: &Translation, gw: (&str, &str)) {
    let g = gateway(t, gw.0, gw.1);
    assert!(!g.addresses.is_empty(), "{gw:?} has no address");
    assert_condition(&g.conditions, "Accepted", true, "");
    assert_condition(&g.conditions, "Programmed", true, "");
    for l in &g.listeners {
        assert_condition(&l.conditions, "Accepted", true, "");
        assert_condition(&l.conditions, "Programmed", true, "");
        assert_condition(&l.conditions, "ResolvedRefs", true, "");
    }
}

/// Asserts the route's `ResolvedRefs` for a Gateway.
pub fn assert_resolved(
    t: &Translation,
    kind: RouteKind,
    route: (&str, &str),
    gw: (&str, &str),
    status: bool,
    reason: &str,
) {
    let p = parent(t, kind, route, gw);
    assert_condition(&p.conditions, "ResolvedRefs", status, reason);
}

// ---------------------------------------------------------------------------------------
// Routing.

/// Where a request ends up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No route: 404.
    NotFound,
    /// Forwarded to these backends (Deployment names), with the route's middlewares.
    Backends(BTreeSet<String>),
    /// Answered with a fixed status by the service.
    Status(u16),
}

/// The result of routing one request.
#[derive(Debug, Clone)]
pub struct Routed {
    /// Where it goes.
    pub outcome: Outcome,
    /// The route (fragment name), when one matched.
    pub route: Option<Route>,
    /// The route's middlewares, in order.
    pub middlewares: Vec<Middleware>,
    /// For a split, each target's outcome and weight.
    pub split: Vec<(Outcome, u32)>,
}

impl Routed {
    /// The redirect middleware, when the route has one.
    pub fn redirect(&self) -> Option<&rdock_model::middleware::RedirectConfig> {
        self.middlewares.iter().find_map(|m| match m {
            Middleware::Redirect(r) => Some(r),
            _ => None,
        })
    }
}

/// A compiled fragment.
pub struct Router {
    /// The translation.
    pub translation: Translation,
    runtime: rdock_proxy::Runtime,
    gateway_ports: BTreeMap<(String, String), BTreeMap<u16, u16>>,
    gateway_udp_ports: BTreeMap<(String, String), BTreeMap<u16, u16>>,
    pods: BTreeMap<String, (String, String)>,
}

/// A request.
#[derive(Debug, Clone, Default)]
pub struct Request<'a> {
    /// `Host`.
    pub host: &'a str,
    /// Path and query.
    pub path: &'a str,
    /// Method (`GET` when empty).
    pub method: &'a str,
    /// Headers.
    pub headers: &'a [(&'a str, &'a str)],
}

impl Router {
    /// Translates `cluster`, checks that the fragment assembles with nothing left out,
    /// writes test certificates for the Secrets it names, and compiles it.
    pub fn new(cluster: &mut Cluster) -> Self {
        let translation = cluster.translate();
        Self::compile(cluster, translation)
    }

    /// Compiles an existing translation of `cluster`.
    pub fn compile(cluster: &Cluster, translation: Translation) -> Self {
        let ca = rdock_testkit::certs::TestCa::new();
        for (ns, name) in &translation.secrets {
            let (crt, key) =
                rdock_provider_kubernetes::translate::secret_paths(cluster.data_dir(), ns, name);
            std::fs::create_dir_all(crt.parent().unwrap()).unwrap();
            let issued = ca.issue(
                crt.parent().unwrap(),
                "issued",
                &["example.org", "test.example"],
            );
            std::fs::rename(&issued.cert, &crt).unwrap();
            std::fs::rename(&issued.key, &key).unwrap();
        }
        for (ns, name) in &translation.config_maps {
            let path =
                rdock_provider_kubernetes::translate::config_map_path(cluster.data_dir(), ns, name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, ca.pem()).unwrap();
        }
        let base = rdock_config::load_str(
            "acme: false\nlisteners:\n  web: { address: \"127.0.0.1:1\" }\n  websecure: { address: \"127.0.0.1:2\", tls: {} }\n",
            rdock_config::Format::Yaml,
        )
        .unwrap();
        assert!(!base.has_errors(), "{:?}", base.diagnostics);
        let snapshot = Snapshot {
            provider: "kubernetes".to_owned(),
            fragment: translation.fragment.clone(),
            diagnostics: Vec::new(),
            revision: None,
        };
        let merged = assemble(&base.config, &[&snapshot], &BTreeSet::new());
        assert_eq!(merged.errors, Vec::new(), "assemble errors");
        assert_eq!(merged.skipped, Vec::new(), "objects left out by assemble");
        let compiled = rdock_proxy::compile(
            &merged.config,
            &rdock_proxy::CompileEnv {
                mode: rdock_proxy::Mode::Run,
                generation: 1,
                dns: &rdock_proxy::upstream::Dns::default(),
                client: Arc::new(rdock_middleware::HttpClient::default()),
                previous: None,
                cloudflare: &rdock_proxy::forwarded::CloudflareRanges::default(),
                backends: &rdock_balancer::Registry::default(),
                sticky_key: b"test",
                live: &rdock_observability::live::Live::default(),
                caches: None,
                plugins: &rdock_plugin_api::Registry::new(),
                metrics: None,
            },
        );
        let errors: Vec<_> = compiled
            .diagnostics
            .iter()
            .filter(|d| d.is_error())
            .collect();
        assert!(errors.is_empty(), "compile errors: {errors:#?}");
        Self {
            translation,
            runtime: compiled.runtime.unwrap(),
            gateway_ports: cluster
                .inventory
                .gateway_services
                .iter()
                .map(|(k, s)| (k.clone(), s.ports.clone()))
                .collect(),
            gateway_udp_ports: cluster
                .inventory
                .gateway_services
                .iter()
                .map(|(k, s)| (k.clone(), s.udp_ports.clone()))
                .collect(),
            pods: cluster.pods.clone(),
        }
    }

    /// The internal listener of Gateway `gw` port `port` (`name@kubernetes`).
    pub fn listener(&self, gw: (&str, &str), port: u16) -> String {
        let name = rdock_provider_kubernetes::gateway::listeners::internal_listener_name(
            &(gw.0.to_owned(), gw.1.to_owned()),
            port,
        );
        format!("{name}@kubernetes")
    }

    /// Whether the internal listener of `gw:port` exists.
    pub fn has_listener(&self, gw: (&str, &str), port: u16) -> bool {
        self.runtime
            .listeners
            .contains_key(&self.listener(gw, port))
    }

    /// Routes `request` arriving on Gateway `gw`, listener port `port`.
    pub fn route(&self, gw: (&str, &str), port: u16, request: &Request<'_>) -> Routed {
        let listener = self.listener(gw, port);
        assert!(
            self.gateway_ports
                .get(&(gw.0.to_owned(), gw.1.to_owned()))
                .is_some_and(|p| p.contains_key(&port)),
            "Gateway {gw:?} has no port {port}"
        );
        let mut headers = http::HeaderMap::new();
        for (name, value) in request.headers {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        let explained = rdock_proxy::explain::explain(
            &self.runtime,
            &listener,
            &rdock_proxy::explain::Request {
                host: request.host.to_owned(),
                path: request.path.to_owned(),
                method: request.method.to_owned(),
                headers,
                client_ip: None,
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let Some(route_name) = explained["outcome"]["route"].as_str() else {
            return Routed {
                outcome: Outcome::NotFound,
                route: None,
                middlewares: Vec::new(),
                split: Vec::new(),
            };
        };
        let fragment = &self.translation.fragment;
        let route = fragment.routes[strip(route_name)].clone();
        let middlewares = route
            .middlewares
            .iter()
            .map(|m| fragment.middlewares[m].clone())
            .collect();
        let service = route.service.clone().unwrap();
        let (outcome, split) = self.service_outcome(&service);
        Routed {
            outcome,
            route: Some(route),
            middlewares,
            split,
        }
    }

    /// Runs the request phase of the compiled middleware chain of the route `request` matches
    /// on Gateway `gw`, listener port `port`, as the proxy would, and returns the first reply
    /// (status and `Location`), or `None` when every middleware lets the request through.
    /// Without a `Host`, the request carries the Gateway's address the way an HTTP client
    /// writes it (no port for the scheme's default port).
    pub fn execute(
        &self,
        gw: (&str, &str),
        port: u16,
        request: &Request<'_>,
    ) -> Option<(u16, Option<String>)> {
        let name = self.listener(gw, port);
        let listener = self.runtime.listeners.get(&name).unwrap();
        let tls = listener.protocol == rdock_model::config::ListenerProtocol::Https;
        let route_name = self.explained_route(gw, port, request)?;
        let route = listener
            .routes
            .iter()
            .find(|r| *r.name == *route_name)
            .unwrap_or_else(|| panic!("route {route_name} not on {name}"));
        let authority = if !request.host.is_empty() {
            request.host.to_owned()
        } else if port == if tls { 443 } else { 80 } {
            "192.0.2.1".to_owned()
        } else {
            format!("192.0.2.1:{port}")
        };
        let method = if request.method.is_empty() {
            "GET"
        } else {
            request.method
        };
        let mut req =
            pingora::http::RequestHeader::build(method, request.path.as_bytes(), None).unwrap();
        req.insert_header("host", authority.as_str()).unwrap();
        for (header, value) in request.headers {
            req.append_header((*header).to_owned(), *value).unwrap();
        }
        let mut cx = rdock_middleware::Context::new(
            IpAddr::from([127, 0, 0, 1]),
            tls,
            route.name.clone(),
            Arc::from("test"),
            authority,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            for middleware in route.middlewares.middlewares() {
                if let rdock_middleware::Flow::Reply(reply) =
                    rdock_middleware::Middleware::request(&**middleware, &mut req, &mut cx).await
                {
                    let location = reply
                        .headers
                        .iter()
                        .find(|(k, _)| k == http::header::LOCATION)
                        .map(|(_, v)| v.to_str().unwrap().to_owned());
                    return Some((reply.status, location));
                }
            }
            None
        })
    }

    /// The name of the route `request` matches (`name@kubernetes`), if any.
    fn explained_route(
        &self,
        gw: (&str, &str),
        port: u16,
        request: &Request<'_>,
    ) -> Option<String> {
        let mut headers = http::HeaderMap::new();
        for (name, value) in request.headers {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        let explained = rdock_proxy::explain::explain(
            &self.runtime,
            &self.listener(gw, port),
            &rdock_proxy::explain::Request {
                host: request.host.to_owned(),
                path: request.path.to_owned(),
                method: request.method.to_owned(),
                headers,
                client_ip: None,
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        explained["outcome"]["route"].as_str().map(str::to_owned)
    }

    fn service_outcome(&self, name: &str) -> (Outcome, Vec<(Outcome, u32)>) {
        let service = &self.translation.fragment.services[name];
        if let Some(respond) = &service.respond {
            return (Outcome::Status(respond.status), Vec::new());
        }
        if !service.split.is_empty() {
            let split: Vec<(Outcome, u32)> = service
                .split
                .iter()
                .map(|t| (self.service_outcome(&t.service).0, t.weight))
                .collect();
            let mut all = BTreeSet::new();
            for (outcome, _) in &split {
                if let Outcome::Backends(b) = outcome {
                    all.extend(b.iter().cloned());
                }
            }
            return (Outcome::Backends(all), split);
        }
        (
            Outcome::Backends(self.deployments(&service.backends)),
            Vec::new(),
        )
    }

    fn deployments(&self, backends: &[rdock_model::service::Backend]) -> BTreeSet<String> {
        backends
            .iter()
            .map(|b| {
                let address = b.address.to_string();
                let host = address
                    .rsplit_once(':')
                    .map_or(address.as_str(), |(h, _)| h)
                    .trim_matches(['[', ']']);
                self.pods
                    .get(host)
                    .map_or_else(|| format!("unknown {address}"), |(_, d)| d.clone())
            })
            .collect()
    }

    /// The TCP route a TLS connection with `sni` (or a plain one, `None`) to `gw:port`
    /// reaches, and its backends; `None` when the connection is refused.
    pub fn connect(
        &self,
        gw: (&str, &str),
        port: u16,
        sni: Option<&str>,
    ) -> Option<BTreeSet<String>> {
        let listener = self.runtime.listeners.get(&self.listener(gw, port))?;
        let hello = rdock_tls::clienthello::ClientHello {
            sni: sni.map(str::to_owned),
            alpn: Vec::new(),
        };
        let facts = rdock_proxy::tcp::rule::TcpFacts {
            hello: sni.map(|_| &hello),
            client_ip: IpAddr::from([127, 0, 0, 1]),
        };
        let route = listener
            .tcp_routes
            .iter()
            .find(|r| r.rule.matches(&facts))?;
        let fragment = &self.translation.fragment;
        let tcp_route = &fragment.tcp_routes[strip(&route.name)];
        let service = &fragment.tcp_services[&tcp_route.service];
        Some(self.deployments(&service.backends))
    }
}

impl Router {
    /// The internal port the Gateway's Service maps UDP port `port` of `gw` to.
    pub fn udp_target(&self, gw: (&str, &str), port: u16) -> Option<u16> {
        self.gateway_udp_ports
            .get(&(gw.0.to_owned(), gw.1.to_owned()))?
            .get(&port)
            .copied()
    }

    /// The UDP route a datagram from `client` to `gw:port` reaches, and the Deployments behind
    /// its backends (as many times as each has backend entries); `None` when it is dropped.
    pub fn datagram(&self, gw: (&str, &str), port: u16) -> Option<BTreeSet<String>> {
        let name = rdock_provider_kubernetes::gateway::listeners::internal_udp_listener_name(
            &(gw.0.to_owned(), gw.1.to_owned()),
            port,
        );
        let listener = self.runtime.listeners.get(&format!("{name}@kubernetes"))?;
        assert_eq!(
            listener.protocol,
            rdock_model::config::ListenerProtocol::Udp
        );
        let route = rdock_proxy::udp::select(&listener.udp_routes, IpAddr::from([192, 0, 2, 9]))?;
        let fragment = &self.translation.fragment;
        let udp_route = &fragment.udp_routes[strip(&route.name)];
        let service = &fragment.udp_services[&udp_route.service];
        Some(self.deployments(&service.backends))
    }

    /// The UDP service a datagram to `gw:port` reaches, as compiled.
    pub fn udp_service(
        &self,
        gw: (&str, &str),
        port: u16,
    ) -> Option<&rdock_model::service::UdpService> {
        let name = rdock_provider_kubernetes::gateway::listeners::internal_udp_listener_name(
            &(gw.0.to_owned(), gw.1.to_owned()),
            port,
        );
        let listener = self.runtime.listeners.get(&format!("{name}@kubernetes"))?;
        let route = rdock_proxy::udp::select(&listener.udp_routes, IpAddr::from([192, 0, 2, 9]))?;
        let fragment = &self.translation.fragment;
        let udp_route = &fragment.udp_routes[strip(&route.name)];
        fragment.udp_services.get(&udp_route.service)
    }
}

fn strip(name: &str) -> &str {
    name.strip_suffix("@kubernetes").unwrap_or(name)
}

/// A GET request for `path` with no `Host`.
pub fn get(path: &str) -> Request<'_> {
    Request {
        host: "",
        path,
        method: "GET",
        headers: &[],
    }
}

/// A set of Deployment names.
pub fn backends(names: &[&str]) -> Outcome {
    Outcome::Backends(names.iter().map(|n| (*n).to_owned()).collect())
}
