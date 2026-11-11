//! The cluster runtime against a real API server (kube-apiserver and etcd; no nodes, so no
//! pods run and nothing assigns load-balancer addresses).
//!
//! Set `RDOCK_TEST_KUBECONFIG` to a kubeconfig with cluster-admin rights and the Gateway API
//! v1.7.0 standard CRDs installed; without it every test prints a note and passes. Each test
//! works in its own fresh namespace (and a uniquely named GatewayClass), so the tests run in
//! parallel and repeatedly.
//!
//! The RBAC test also needs `RDOCK_TEST_RBAC_KUBECONFIG` (a kubeconfig whose user is a
//! `ServiceAccount` bound to the chart's rendered RBAC) and `RDOCK_TEST_RBAC_NAMESPACE` (the
//! release namespace the chart's Role lives in); with `RDOCK_TEST_RBAC_WATCH_NAMESPACE` it
//! runs in the chart's namespaced mode (`watchNamespaces` set to that one namespace).

// Each test is one scenario against the API server, read top to bottom.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret, Service};
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, ResourceExt};
use rdock_model::providers::{KubernetesProvider, KubernetesServiceType};
use rdock_provider_kubernetes::api::{
    Gateway, GatewayClass, HTTPRoute, ParentReference, RouteGroupKind, SupportedFeature,
};
use rdock_provider_kubernetes::inventory::Inventory;
use rdock_provider_kubernetes::runtime::{
    Elector, LeaseTimings, Options, RunContext, State, run_with,
};
use rdock_provider_kubernetes::translate::{
    DesiredCondition, DesiredGateway, DesiredGatewayClass, DesiredListener, DesiredRouteParent,
    DesiredService, LoadBalancerAddress, RouteKind, RouteRef, Settings, Translation,
    gateway_service_name, secret_paths,
};
use serde_json::json;
use tokio::sync::watch;

const CONTROLLER: &str = "reversedock.dev/gateway-controller";

fn kubeconfig_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

async fn client_for(path: &Path) -> Client {
    let kubeconfig = Kubeconfig::read_from(path).unwrap();
    let mut config =
        kube::Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .unwrap();
    // kube takes `HTTPS_PROXY` for the API server and has no proxy support in this build.
    config.proxy_url = None;
    Client::try_from(config).unwrap()
}

/// The admin kubeconfig and client, or `None` (with a note) when the variable is unset.
async fn cluster(test: &str) -> Option<(PathBuf, Client)> {
    let Some(path) = kubeconfig_path("RDOCK_TEST_KUBECONFIG") else {
        eprintln!("{test}: skipped (set RDOCK_TEST_KUBECONFIG to run it against an API server)");
        return None;
    };
    let client = client_for(&path).await;
    Some((path, client))
}

fn unique(tag: &str) -> String {
    format!("rdock-{tag}-{:06x}", fastrand::u32(..0x00ff_ffff))
}

async fn namespace(client: &Client, tag: &str) -> String {
    let name = unique(tag);
    let ns: Namespace = serde_json::from_value(json!({ "metadata": { "name": name } })).unwrap();
    Api::<Namespace>::all(client.clone())
        .create(&PostParams::default(), &ns)
        .await
        .unwrap();
    name
}

fn provider(kubeconfig: &Path, ns: &str) -> KubernetesProvider {
    let mut provider = KubernetesProvider {
        kubeconfig: Some(kubeconfig.to_owned()),
        namespaces: vec![ns.to_owned()],
        ..KubernetesProvider::default()
    };
    provider.gateway.service_type = KubernetesServiceType::ClusterIp;
    provider.gateway.pod_selector = BTreeMap::from([("app".to_owned(), "rdock-test".to_owned())]);
    "20000-20009".clone_into(&mut provider.gateway.port_range);
    provider.leader_election.enabled = false;
    provider
}

fn context(ns: &str, data_dir: &Path) -> RunContext {
    RunContext {
        data_dir: data_dir.to_owned(),
        pod_namespace: ns.to_owned(),
        pod_name: "rdock-test".to_owned(),
    }
}

struct Running {
    state: watch::Receiver<State>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

fn start(provider: KubernetesProvider, context: RunContext, options: Options) -> Running {
    let (tx, state) = watch::channel(State::default());
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(run_with(provider, context, options, tx, stop_rx));
    Running { state, stop, task }
}

impl Running {
    async fn stop(self) {
        self.stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("the runtime stops promptly")
            .unwrap();
    }
}

/// Polls `check` every 100 ms until it holds, for at most `limit`.
async fn eventually<F, Fut>(what: &str, limit: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = Instant::now();
    while !check().await {
        assert!(start.elapsed() < limit, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Changes a ConfigMap in `ns`, which every runtime with gateways on watches: a new
/// translation runs.
async fn poke(client: &Client, ns: &str) {
    let api: Api<ConfigMap> = Api::namespaced(client.clone(), ns);
    let cm = json!({ "apiVersion": "v1", "kind": "ConfigMap", "metadata": { "name": "poke" },
        "data": { "at": format!("{:?}", Instant::now()) } });
    api.patch(
        "poke",
        &PatchParams::apply("rdock-test"),
        &Patch::Apply(&cm),
    )
    .await
    .unwrap();
}

fn cond(kind: &str, status: bool, reason: &str, generation: Option<i64>) -> DesiredCondition {
    DesiredCondition {
        kind: kind.to_owned(),
        status,
        reason: reason.to_owned(),
        message: String::new(),
        observed_generation: generation,
    }
}

type Seen = Arc<Mutex<Option<Inventory>>>;

// (1) The stores sync, the CRD bundle version is read and an empty translation publishes.
#[tokio::test(flavor = "multi_thread")]
async fn stores_sync_and_an_empty_translation_is_published() {
    let Some((kubeconfig, client)) = cluster("stores_sync").await else {
        return;
    };
    let ns = namespace(&client, "sync").await;
    let data = tempfile::tempdir().unwrap();
    let seen: Seen = Arc::default();
    let translate = {
        let seen = seen.clone();
        Arc::new(move |inventory: &Inventory, _: &Settings| {
            *seen.lock().unwrap() = Some(inventory.clone());
            Translation::default()
        })
    };
    let mut provider = provider(&kubeconfig, &ns);
    provider.ingress.enabled = true;
    let mut running = start(
        provider,
        context(&ns, data.path()),
        Options {
            translate,
            ..Options::default()
        },
    );
    tokio::time::timeout(
        Duration::from_secs(20),
        running.state.wait_for(|s| s.snapshot.is_some()),
    )
    .await
    .expect("a snapshot within 20 s")
    .unwrap();
    {
        let state = running.state.borrow();
        assert_eq!(state.degraded, None);
        let snapshot = state.snapshot.as_ref().unwrap();
        assert_eq!(snapshot.provider, "kubernetes");
        assert_eq!(snapshot.revision, None);
    }
    let inventory = seen.lock().unwrap().clone().unwrap();
    assert_eq!(inventory.crd_bundle_version.as_deref(), Some("v1.7.0"));
    assert!(
        inventory.missing_kinds.is_empty(),
        "{:?}",
        inventory.missing_kinds
    );
    assert!(inventory.namespaces.contains_key(&ns));
    running.stop().await;
}

// (2) Per-Gateway Services: created with allocated ports, read back into the inventory,
// distinct ports for a second Gateway, deleted when no longer desired. The writer only acts
// once this replica leads (election on, short timings).
#[tokio::test(flavor = "multi_thread")]
async fn per_gateway_services_follow_the_desired_set() {
    let Some((kubeconfig, client)) = cluster("services").await else {
        return;
    };
    let ns = namespace(&client, "svc").await;
    let data = tempfile::tempdir().unwrap();
    let seen: Seen = Arc::default();
    let desired: Arc<Mutex<Vec<DesiredService>>> = Arc::default();
    let translate = {
        let (seen, desired) = (seen.clone(), desired.clone());
        Arc::new(move |inventory: &Inventory, _: &Settings| {
            *seen.lock().unwrap() = Some(inventory.clone());
            Translation {
                services: desired.lock().unwrap().clone(),
                ..Translation::default()
            }
        })
    };
    let service = |gateway: &str, ports: Vec<u16>| DesiredService {
        namespace: ns.clone(),
        name: gateway_service_name("apps", gateway),
        gateway: ("apps".to_owned(), gateway.to_owned()),
        ports,
        labels: BTreeMap::from([("team".to_owned(), "a".to_owned())]),
        annotations: BTreeMap::from([("example.com/note".to_owned(), gateway.to_owned())]),
    };
    let mut provider = provider(&kubeconfig, &ns);
    provider.leader_election.enabled = true;
    let (leader_tx, mut leader_rx) = watch::channel(false);
    let options = Options {
        translate,
        lease: LeaseTimings {
            lease_duration: Duration::from_secs(2),
            renew_deadline: Duration::from_millis(1500),
            retry_period: Duration::from_millis(300),
        },
        leadership: Some(leader_tx),
        ..Options::default()
    };
    let running = start(provider, context(&ns, data.path()), options);
    tokio::time::timeout(Duration::from_secs(10), leader_rx.wait_for(|l| *l))
        .await
        .expect("the only replica leads")
        .unwrap();

    let services: Api<Service> = Api::namespaced(client.clone(), &ns);
    *desired.lock().unwrap() = vec![service("web", vec![80, 443])];
    poke(&client, &ns).await;
    let target_ports = |s: &Service| -> BTreeMap<i32, String> {
        s.spec
            .as_ref()
            .unwrap()
            .ports
            .as_ref()
            .unwrap()
            .iter()
            .map(|p| (p.port, format!("{:?}", p.target_port.as_ref().unwrap())))
            .collect()
    };
    eventually("Service apps-web", Duration::from_secs(10), || async {
        services.get_opt("apps-web").await.unwrap().is_some()
    })
    .await;
    let web = services.get("apps-web").await.unwrap();
    assert_eq!(
        target_ports(&web),
        BTreeMap::from([
            (80, "Int(20000)".to_owned()),
            (443, "Int(20001)".to_owned())
        ])
    );
    let labels = web.labels();
    assert_eq!(labels["app.kubernetes.io/managed-by"], "reversedock");
    assert_eq!(labels["gateway.networking.k8s.io/gateway-name"], "web");
    assert_eq!(labels["reversedock.dev/gateway-namespace"], "apps");
    assert_eq!(labels["team"], "a");
    assert_eq!(web.annotations()["example.com/note"], "web");
    let spec = web.spec.as_ref().unwrap();
    assert_eq!(spec.type_.as_deref(), Some("ClusterIP"));
    assert_eq!(spec.selector.as_ref().unwrap()["app"], "rdock-test");
    let cluster_ip = spec.cluster_ip.clone().unwrap();

    // The next pass sees it as the record of the allocation, with its address.
    eventually(
        "the Service in the inventory",
        Duration::from_secs(10),
        || async {
            seen.lock().unwrap().as_ref().is_some_and(|i| {
                i.gateway_services
                    .get(&("apps".to_owned(), "web".to_owned()))
                    .is_some_and(|g| {
                        g.ports == BTreeMap::from([(80, 20000), (443, 20001)])
                            && g.addresses.first().is_some_and(|a| a.value == cluster_ip)
                    })
            })
        },
    )
    .await;
    let rv = services.get("apps-web").await.unwrap().resource_version();

    // A second Gateway gets other ports; the first is not rewritten.
    *desired.lock().unwrap() = vec![service("web", vec![80, 443]), service("api", vec![80])];
    poke(&client, &ns).await;
    eventually("Service apps-api", Duration::from_secs(10), || async {
        services.get_opt("apps-api").await.unwrap().is_some()
    })
    .await;
    let api_svc = services.get("apps-api").await.unwrap();
    assert_eq!(
        target_ports(&api_svc),
        BTreeMap::from([(80, "Int(20002)".to_owned())])
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        services.get("apps-web").await.unwrap().resource_version(),
        rv,
        "unchanged Service rewritten"
    );

    // No longer desired: deleted.
    *desired.lock().unwrap() = vec![service("api", vec![80])];
    poke(&client, &ns).await;
    eventually(
        "Service apps-web deleted",
        Duration::from_secs(10),
        || async { services.get_opt("apps-web").await.unwrap().is_none() },
    )
    .await;
    assert!(services.get_opt("apps-api").await.unwrap().is_some());
    running.stop().await;
}

fn status_translation(class: String, ns: String, counter: Arc<AtomicUsize>) -> Options {
    let translate = Arc::new(move |inventory: &Inventory, _: &Settings| {
        counter.fetch_add(1, Ordering::SeqCst);
        let mut t = Translation::default();
        for (name, gc) in &inventory.gateway_classes {
            if *name == class {
                t.status.gateway_classes.insert(
                    name.clone(),
                    DesiredGatewayClass {
                        conditions: vec![
                            cond("Accepted", true, "Accepted", gc.metadata.generation),
                            cond(
                                "SupportedVersion",
                                true,
                                "SupportedVersion",
                                gc.metadata.generation,
                            ),
                        ],
                        supported_features: vec![
                            SupportedFeature {
                                name: "HTTPRoute".to_owned(),
                            },
                            SupportedFeature {
                                name: "Gateway".to_owned(),
                            },
                        ],
                    },
                );
            }
        }
        for (key, gw) in &inventory.gateways {
            if key.0 != ns || gw.spec.gateway_class_name != class {
                continue;
            }
            let generation = gw.metadata.generation;
            t.status.gateways.insert(
                key.clone(),
                DesiredGateway {
                    conditions: vec![
                        cond("Accepted", true, "Accepted", generation),
                        cond("Programmed", true, "Programmed", generation),
                    ],
                    addresses: Vec::new(),
                    listeners: gw
                        .spec
                        .listeners
                        .iter()
                        .map(|l| DesiredListener {
                            name: l.name.clone(),
                            supported_kinds: vec![RouteGroupKind {
                                group: None,
                                kind: "HTTPRoute".to_owned(),
                            }],
                            attached_routes: 1,
                            conditions: vec![
                                cond("Accepted", true, "Accepted", generation),
                                cond("Programmed", true, "Programmed", generation),
                                cond("ResolvedRefs", true, "ResolvedRefs", generation),
                            ],
                        })
                        .collect(),
                    attached_listener_sets: None,
                },
            );
        }
        for (key, route) in &inventory.http_routes {
            if key.0 != ns {
                continue;
            }
            let parents = route
                .spec
                .parent_refs
                .iter()
                .map(|p| DesiredRouteParent {
                    parent_ref: p.clone(),
                    conditions: vec![
                        cond("Accepted", true, "Accepted", route.metadata.generation),
                        cond(
                            "ResolvedRefs",
                            true,
                            "ResolvedRefs",
                            route.metadata.generation,
                        ),
                    ],
                })
                .collect();
            t.status.routes.insert(
                RouteRef {
                    kind: RouteKind::Http,
                    namespace: key.0.clone(),
                    name: key.1.clone(),
                },
                parents,
            );
        }
        for key in inventory.ingresses.keys() {
            if key.0 == ns {
                t.status.ingresses.insert(
                    key.clone(),
                    vec![LoadBalancerAddress {
                        ip: Some("192.0.2.10".to_owned()),
                        hostname: None,
                    }],
                );
            }
        }
        t
    });
    Options {
        translate,
        ..Options::default()
    }
}

const STALE: &str = "conformance.gateway.networking.k8s.io/StaleCondition";
const STALE_CONTROLLER: &str = "gateway-conformance.network.k8s.io/stale-controller";

fn condition_of<'a>(
    conditions: &'a [k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition],
    kind: &str,
) -> Option<&'a k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition> {
    conditions.iter().find(|c| c.type_ == kind)
}

async fn create_gateway_objects(client: &Client, ns: &str, class: &str) {
    let gc: GatewayClass = serde_json::from_value(json!({
        "metadata": { "name": class }, "spec": { "controllerName": CONTROLLER }
    }))
    .unwrap();
    Api::<GatewayClass>::all(client.clone())
        .create(&PostParams::default(), &gc)
        .await
        .unwrap();
    let gw: Gateway = serde_json::from_value(json!({
        "metadata": { "name": "web", "namespace": ns },
        "spec": { "gatewayClassName": class, "listeners": [{ "name": "http", "port": 80, "protocol": "HTTP" }] }
    })).unwrap();
    Api::<Gateway>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &gw)
        .await
        .unwrap();
    let route: HTTPRoute = serde_json::from_value(json!({
        "metadata": { "name": "route", "namespace": ns },
        "spec": { "parentRefs": [{ "name": "web" }], "rules": [{ "matches": [{ "path": { "type": "PathPrefix", "value": "/" } }] }] }
    })).unwrap();
    Api::<HTTPRoute>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &route)
        .await
        .unwrap();
}

// (3) Status: written, merged with foreign conditions and parents[] entries, not rewritten
// when unchanged, and following a spec edit's generation.
#[tokio::test(flavor = "multi_thread")]
async fn status_is_written_merged_and_left_alone_when_unchanged() {
    let Some((kubeconfig, client)) = cluster("status").await else {
        return;
    };
    let ns = namespace(&client, "status").await;
    let class = unique("class");
    create_gateway_objects(&client, &ns, &class).await;
    let ingress: Ingress = serde_json::from_value(json!({
        "metadata": { "name": "ing", "namespace": ns },
        "spec": { "defaultBackend": { "service": { "name": "x", "port": { "number": 80 } } } }
    }))
    .unwrap();
    let ingresses: Api<Ingress> = Api::namespaced(client.clone(), &ns);
    ingresses
        .create(&PostParams::default(), &ingress)
        .await
        .unwrap();
    // A GatewayClass of another controller: never written.
    let other_class = unique("other");
    let other: GatewayClass = serde_json::from_value(json!({
        "metadata": { "name": other_class }, "spec": { "controllerName": "example.com/other" }
    }))
    .unwrap();
    let classes: Api<GatewayClass> = Api::all(client.clone());
    classes
        .create(&PostParams::default(), &other)
        .await
        .unwrap();

    let data = tempfile::tempdir().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut provider = provider(&kubeconfig, &ns);
    provider.ingress.enabled = true;
    let running = start(
        provider,
        context(&ns, data.path()),
        status_translation(class.clone(), ns.clone(), counter.clone()),
    );

    let gateways: Api<Gateway> = Api::namespaced(client.clone(), &ns);
    let routes: Api<HTTPRoute> = Api::namespaced(client.clone(), &ns);
    eventually("Gateway accepted", Duration::from_secs(20), || async {
        let gw = gateways.get("web").await.unwrap();
        gw.status.as_ref().is_some_and(|s| {
            condition_of(&s.conditions, "Accepted").is_some_and(|c| c.status == "True")
                && s.listeners.first().is_some_and(|l| l.attached_routes == 1)
        })
    })
    .await;
    eventually("route accepted", Duration::from_secs(10), || async {
        let r = routes.get("route").await.unwrap();
        r.status
            .as_ref()
            .is_some_and(|s| s.parents.iter().any(|p| p.controller_name == CONTROLLER))
    })
    .await;
    eventually("class accepted", Duration::from_secs(10), || async {
        let gc = classes.get(&class).await.unwrap();
        gc.status.as_ref().is_some_and(|s| {
            s.supported_features.len() == 2
                && condition_of(&s.conditions, "Accepted").is_some_and(|c| c.status == "True")
        })
    })
    .await;
    eventually("ingress address", Duration::from_secs(10), || async {
        let i = ingresses.get("ing").await.unwrap();
        i.status
            .and_then(|s| s.load_balancer)
            .and_then(|l| l.ingress)
            .is_some_and(|i| i.len() == 1 && i[0].ip.as_deref() == Some("192.0.2.10"))
    })
    .await;
    let gc = classes.get(&class).await.unwrap();
    let names: Vec<_> = gc
        .status
        .unwrap()
        .supported_features
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert_eq!(names, vec!["Gateway", "HTTPRoute"], "sorted");
    assert!(
        classes
            .get(&other_class)
            .await
            .unwrap()
            .status
            .is_none_or(|s| s.conditions.iter().all(|c| c.status == "Unknown")),
        "another controller's class is never written"
    );

    // Seed a foreign condition on the Gateway and its listener, and a foreign parents[] entry
    // on the route (what the conformance tests do), each with optimistic concurrency.
    let gw = gateways.get("web").await.unwrap();
    let mut status = gw.status.clone().unwrap();
    let seeded = k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
        type_: STALE.to_owned(),
        status: "True".to_owned(),
        reason: "Seeded".to_owned(),
        message: String::new(),
        observed_generation: gw.metadata.generation,
        last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::from_second(1_700_000_000).unwrap(),
        ),
    };
    status.conditions.push(seeded.clone());
    status.listeners[0].conditions.push(seeded.clone());
    gateways
        .patch_status(
            "web",
            &PatchParams::default(),
            &Patch::Merge(json!({
                "metadata": { "resourceVersion": gw.resource_version() },
                "status": { "conditions": status.conditions, "listeners": status.listeners },
            })),
        )
        .await
        .unwrap();
    let route = routes.get("route").await.unwrap();
    let mut parents = route.status.clone().unwrap().parents;
    let foreign = json!({
        "parentRef": { "group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "unmanaged-gateway", "namespace": ns },
        "controllerName": STALE_CONTROLLER,
        "conditions": [{ "type": "Accepted", "status": "True", "reason": "Accepted",
            "observedGeneration": route.metadata.generation, "lastTransitionTime": "2023-11-14T22:13:20Z", "message": "" }],
    });
    parents.push(serde_json::from_value(foreign).unwrap());
    routes
        .patch_status(
            "route",
            &PatchParams::default(),
            &Patch::Merge(json!({
                "metadata": { "resourceVersion": route.resource_version() },
                "status": { "parents": parents },
            })),
        )
        .await
        .unwrap();
    // An outdated resourceVersion is refused (the writer's 409 path).
    let stale = routes.patch_status("route", &PatchParams::default(), &Patch::Merge(json!({
        "metadata": { "resourceVersion": route.resource_version() }, "status": { "parents": [] },
    }))).await;
    assert!(
        matches!(stale, Err(kube::Error::Api(ref s)) if s.code == 409),
        "{stale:?}"
    );
    let seeded_entry = routes
        .get("route")
        .await
        .unwrap()
        .status
        .unwrap()
        .parents
        .into_iter()
        .find(|p| p.controller_name == STALE_CONTROLLER)
        .unwrap();

    // Bump both generations: our status must catch up while keeping the foreign parts.
    gateways.patch("web", &PatchParams::default(), &Patch::Merge(json!({
        "spec": { "listeners": [{ "name": "http", "port": 80, "protocol": "HTTP", "hostname": "second.example.com" }] }
    }))).await.unwrap();
    routes
        .patch(
            "route",
            &PatchParams::default(),
            &Patch::Merge(json!({ "spec": { "hostnames": ["a.example.com"] } })),
        )
        .await
        .unwrap();
    eventually(
        "observedGeneration 2 on the Gateway",
        Duration::from_secs(10),
        || async {
            let gw = gateways.get("web").await.unwrap();
            let s = gw.status.unwrap();
            gw.metadata.generation == Some(2)
                && s.conditions
                    .iter()
                    .filter(|c| c.type_ != STALE)
                    .all(|c| c.observed_generation == Some(2))
                && s.listeners[0]
                    .conditions
                    .iter()
                    .filter(|c| c.type_ != STALE)
                    .all(|c| c.observed_generation == Some(2))
        },
    )
    .await;
    eventually(
        "observedGeneration 2 on the route",
        Duration::from_secs(10),
        || async {
            let r = routes.get("route").await.unwrap();
            r.status
                .unwrap()
                .parents
                .iter()
                .filter(|p| p.controller_name == CONTROLLER)
                .all(|p| {
                    p.conditions
                        .iter()
                        .all(|c| c.observed_generation == Some(2))
                })
        },
    )
    .await;
    let gw = gateways.get("web").await.unwrap();
    let s = gw.status.unwrap();
    assert_eq!(
        condition_of(&s.conditions, STALE),
        Some(&seeded),
        "foreign Gateway condition kept"
    );
    assert_eq!(
        condition_of(&s.listeners[0].conditions, STALE),
        Some(&seeded),
        "foreign listener condition kept"
    );
    let r = routes.get("route").await.unwrap();
    let parents = r.status.unwrap().parents;
    assert_eq!(parents.len(), 2);
    assert_eq!(
        parents
            .iter()
            .find(|p| p.controller_name == STALE_CONTROLLER),
        Some(&seeded_entry),
        "foreign entry kept"
    );
    let ours = parents
        .iter()
        .find(|p| p.controller_name == CONTROLLER)
        .unwrap();
    assert_eq!(
        ours.parent_ref,
        ParentReference {
            group: Some("gateway.networking.k8s.io".to_owned()),
            kind: Some("Gateway".to_owned()),
            name: "web".to_owned(),
            ..ParentReference::default()
        }
    );

    // Unchanged desired status: a new translation writes nothing.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let gw_rv = gateways.get("web").await.unwrap().resource_version();
    let route_rv = routes.get("route").await.unwrap().resource_version();
    let class_rv = classes.get(&class).await.unwrap().resource_version();
    let ingress_rv = ingresses.get("ing").await.unwrap().resource_version();
    let before = counter.load(Ordering::SeqCst);
    poke(&client, &ns).await;
    eventually("a new translation", Duration::from_secs(5), || async {
        counter.load(Ordering::SeqCst) > before
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        gateways.get("web").await.unwrap().resource_version(),
        gw_rv,
        "Gateway rewritten"
    );
    assert_eq!(
        routes.get("route").await.unwrap().resource_version(),
        route_rv,
        "route rewritten"
    );
    assert_eq!(
        classes.get(&class).await.unwrap().resource_version(),
        class_rv,
        "class rewritten"
    );
    assert_eq!(
        ingresses.get("ing").await.unwrap().resource_version(),
        ingress_rv,
        "Ingress rewritten"
    );

    running.stop().await;
    for name in [&class, &other_class] {
        let _ = classes.delete(name, &DeleteParams::default()).await;
    }
}

fn timings() -> LeaseTimings {
    LeaseTimings {
        lease_duration: Duration::from_secs(2),
        renew_deadline: Duration::from_millis(1500),
        retry_period: Duration::from_millis(300),
    }
}

async fn lease_record(api: &Api<Lease>, name: &str) -> (String, i32) {
    let lease = api.get(name).await.unwrap();
    let spec = lease.spec.unwrap();
    (
        spec.holder_identity.unwrap_or_default(),
        spec.lease_transitions.unwrap_or_default(),
    )
}

// (4) Leader election: exactly one of two leads; a released Lease is taken over at once, an
// abandoned one after the lease duration.
#[tokio::test(flavor = "multi_thread")]
async fn exactly_one_replica_leads_and_another_takes_over() {
    let Some((_, client)) = cluster("leader_election").await else {
        return;
    };
    let ns = namespace(&client, "lease").await;
    let api: Api<Lease> = Api::namespaced(client.clone(), &ns);
    let (stop_a, rx_a) = watch::channel(false);
    let (stop_b, rx_b) = watch::channel(false);
    let (lead_a, task_a) = Elector::new(api.clone(), "leader", "a_1", timings()).spawn(rx_a);
    let (lead_b, task_b) = Elector::new(api.clone(), "leader", "b_2", timings()).spawn(rx_b);
    eventually("a leader", Duration::from_secs(5), || async {
        *lead_a.borrow() || *lead_b.borrow()
    })
    .await;
    // Stable for longer than a lease duration: still exactly one, the holder of the Lease.
    for _ in 0..30 {
        assert!(*lead_a.borrow() ^ *lead_b.borrow(), "exactly one leads");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (holder, transitions) = lease_record(&api, "leader").await;
    let (leader_stop, leader_task, follower, follower_id, follower_stop, follower_task) =
        if *lead_a.borrow() {
            assert_eq!(holder, "a_1");
            (stop_a, task_a, lead_b, "b_2", stop_b, task_b)
        } else {
            assert_eq!(holder, "b_2");
            (stop_b, task_b, lead_a, "a_1", stop_a, task_a)
        };

    // Graceful stop: the leader releases, the follower takes over within about one retry
    // period, well inside the lease duration.
    let stopped = Instant::now();
    leader_stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), leader_task)
        .await
        .unwrap()
        .unwrap();
    eventually("takeover after release", Duration::from_secs(4), || async {
        *follower.borrow()
    })
    .await;
    let took = stopped.elapsed();
    assert!(
        took < timings().lease_duration + Duration::from_millis(1000),
        "took {took:?}"
    );
    let (holder, after) = lease_record(&api, "leader").await;
    assert_eq!(holder, follower_id);
    assert_eq!(after, transitions + 1);

    // Crash (no release): a new candidate waits out the lease duration, then takes over.
    let (stop_c, rx_c) = watch::channel(false);
    follower_task.abort();
    drop(follower_stop);
    let crashed = Instant::now();
    let (lead_c, task_c) = Elector::new(api.clone(), "leader", "c_3", timings()).spawn(rx_c);
    eventually("takeover after expiry", Duration::from_secs(6), || async {
        *lead_c.borrow()
    })
    .await;
    let took = crashed.elapsed();
    assert!(
        took >= timings().lease_duration,
        "took over before expiry: {took:?}"
    );
    assert!(
        took < timings().lease_duration + timings().retry_period * 3 + Duration::from_secs(1),
        "took {took:?}"
    );
    assert_eq!(
        lease_record(&api, "leader").await,
        ("c_3".to_owned(), transitions + 2)
    );
    stop_c.send_replace(true);
    task_c.await.unwrap();
    assert_eq!(
        lease_record(&api, "leader").await.0,
        "",
        "released on shutdown"
    );
}

fn tls_pair(name: &str) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.pem(), key.serialize_pem())
}

fn tls_secret(name: &str, crt: &str, key: &str) -> Secret {
    use k8s_openapi::ByteString;
    Secret {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_owned()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".to_owned()),
        data: Some(BTreeMap::from([
            ("tls.crt".to_owned(), ByteString(crt.as_bytes().to_vec())),
            ("tls.key".to_owned(), ByteString(key.as_bytes().to_vec())),
        ])),
        ..Default::default()
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// (5) Secret → files: written with the right bytes and modes, rewritten on update with a new
// snapshot revision, removed on delete.
#[tokio::test(flavor = "multi_thread")]
async fn tls_secrets_become_private_files() {
    let Some((kubeconfig, client)) = cluster("secret_files").await else {
        return;
    };
    let ns = namespace(&client, "secret").await;
    let data = tempfile::tempdir().unwrap();
    let translate = {
        let ns = ns.clone();
        Arc::new(move |inventory: &Inventory, _: &Settings| Translation {
            secrets: inventory
                .secrets
                .iter()
                .filter(|(k, s)| k.0 == ns && s.valid.is_ok())
                .map(|(k, _)| k.clone())
                .collect::<BTreeSet<_>>(),
            ..Translation::default()
        })
    };
    let mut running = start(
        provider(&kubeconfig, &ns),
        context(&ns, data.path()),
        Options {
            translate,
            ..Options::default()
        },
    );
    tokio::time::timeout(
        Duration::from_secs(20),
        running.state.wait_for(|s| s.snapshot.is_some()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        running.state.borrow().snapshot.as_ref().unwrap().revision,
        None
    );

    let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let (crt, key) = tls_pair("web.example");
    secrets
        .patch(
            "web-tls",
            &PatchParams::apply("rdock-test"),
            &Patch::Apply(&tls_secret("web-tls", &crt, &key)),
        )
        .await
        .unwrap();
    let (crt_path, key_path) = secret_paths(data.path(), &ns, "web-tls");
    eventually("the files", Duration::from_secs(10), || async {
        key_path.exists()
    })
    .await;
    assert_eq!(std::fs::read_to_string(&crt_path).unwrap(), crt);
    assert_eq!(std::fs::read_to_string(&key_path).unwrap(), key);
    #[cfg(unix)]
    {
        assert_eq!(mode(&crt_path), 0o600);
        assert_eq!(mode(&key_path), 0o600);
        assert_eq!(mode(crt_path.parent().unwrap()), 0o700);
    }
    let revision = |s: &watch::Receiver<State>| {
        s.borrow()
            .snapshot
            .as_ref()
            .and_then(|s| s.revision.clone())
    };
    eventually("a revision", Duration::from_secs(5), || async {
        revision(&running.state).is_some()
    })
    .await;
    let first = revision(&running.state);
    // The snapshot never carries key material.
    let published =
        serde_json::to_string(running.state.borrow().snapshot.as_ref().unwrap()).unwrap();
    assert!(!published.contains("PRIVATE KEY"));

    // Renewed certificate: new bytes, new revision (the fragment is the same).
    let (crt2, key2) = tls_pair("web.example");
    secrets
        .patch(
            "web-tls",
            &PatchParams::apply("rdock-test"),
            &Patch::Apply(&tls_secret("web-tls", &crt2, &key2)),
        )
        .await
        .unwrap();
    eventually("the renewed files", Duration::from_secs(10), || async {
        std::fs::read_to_string(&crt_path).is_ok_and(|c| c == crt2)
    })
    .await;
    assert_eq!(std::fs::read_to_string(&key_path).unwrap(), key2);
    eventually("a new revision", Duration::from_secs(5), || async {
        revision(&running.state) != first
    })
    .await;

    // Deleted: the files and their directory go.
    secrets
        .delete("web-tls", &DeleteParams::default())
        .await
        .unwrap();
    eventually("files removed", Duration::from_secs(10), || async {
        !crt_path.exists() && !key_path.exists()
    })
    .await;
    assert!(!crt_path.parent().unwrap().exists());
    eventually("no revision", Duration::from_secs(5), || async {
        revision(&running.state).is_none()
    })
    .await;
    running.stop().await;
}

// (6) RBAC: a ServiceAccount bound to the chart's rendered ClusterRole and Roles can do
// everything the runtime does: list and watch every kind, read the CRD bundle version,
// create and delete per-Gateway Services, write Gateway, GatewayClass, HTTPRoute and Ingress
// status, and take and release the Lease.
#[tokio::test(flavor = "multi_thread")]
async fn the_chart_rbac_is_sufficient() {
    let Some((_, admin)) = cluster("rbac").await else {
        return;
    };
    let (Some(rbac_kubeconfig), Some(release_ns)) = (
        kubeconfig_path("RDOCK_TEST_RBAC_KUBECONFIG"),
        std::env::var("RDOCK_TEST_RBAC_NAMESPACE").ok(),
    ) else {
        eprintln!("rbac: skipped (set RDOCK_TEST_RBAC_KUBECONFIG and RDOCK_TEST_RBAC_NAMESPACE)");
        return;
    };
    // Namespaced mode (`watchNamespaces`): the chart's Roles cover only that namespace.
    let watched = std::env::var("RDOCK_TEST_RBAC_WATCH_NAMESPACE").ok();
    let ns = match &watched {
        Some(ns) => ns.clone(),
        None => namespace(&admin, "rbac").await,
    };
    let class = unique("rbacclass");
    create_gateway_objects(&admin, &ns, &class).await;
    let ingress: Ingress = serde_json::from_value(json!({
        "metadata": { "name": "ing", "namespace": ns },
        "spec": { "defaultBackend": { "service": { "name": "x", "port": { "number": 80 } } } }
    }))
    .unwrap();
    Api::<Ingress>::namespaced(admin.clone(), &ns)
        .create(&PostParams::default(), &ingress)
        .await
        .unwrap();
    let (crt, key) = tls_pair("rbac.example");
    Api::<Secret>::namespaced(admin.clone(), &ns)
        .patch(
            "tls",
            &PatchParams::apply("rdock-test"),
            &Patch::Apply(&tls_secret("tls", &crt, &key)),
        )
        .await
        .unwrap();

    // The chart's shape: cluster-wide watches, election on with the chart's Lease name, the
    // Services in the release namespace.
    let mut provider = KubernetesProvider {
        kubeconfig: Some(rbac_kubeconfig),
        namespaces: watched.into_iter().collect(),
        ..KubernetesProvider::default()
    };
    provider.gateway.service_type = KubernetesServiceType::ClusterIp;
    provider.gateway.pod_selector = BTreeMap::from([("app".to_owned(), "rdock-rbac".to_owned())]);
    provider.ingress.enabled = true;
    let counter = Arc::new(AtomicUsize::new(0));
    let mut options = status_translation(class.clone(), ns.clone(), counter);
    let inner = options.translate.clone();
    let service_name = gateway_service_name(&ns, "web");
    let (svc_ns, gw_ns, svc_name) = (release_ns.clone(), ns.clone(), service_name.clone());
    let wanted = Arc::new(Mutex::new(true));
    let wanted_in = wanted.clone();
    options.translate = Arc::new(move |inventory: &Inventory, settings: &Settings| {
        let mut t = inner(inventory, settings);
        if *wanted_in.lock().unwrap() {
            t.services.push(DesiredService {
                namespace: svc_ns.clone(),
                name: svc_name.clone(),
                gateway: (gw_ns.clone(), "web".to_owned()),
                ports: vec![80],
                ..DesiredService::default()
            });
        }
        t.secrets = inventory
            .secrets
            .keys()
            .filter(|k| k.0 == gw_ns)
            .cloned()
            .collect();
        t
    });
    let (leader_tx, mut leader_rx) = watch::channel(false);
    options.leadership = Some(leader_tx);
    options.lease = timings();
    let data = tempfile::tempdir().unwrap();
    let mut running = start(provider, context(&release_ns, data.path()), options);
    tokio::time::timeout(
        Duration::from_secs(20),
        running.state.wait_for(|s| s.snapshot.is_some()),
    )
    .await
    .expect("synced with the chart's RBAC")
    .unwrap();
    assert_eq!(running.state.borrow().degraded, None);
    tokio::time::timeout(Duration::from_secs(10), leader_rx.wait_for(|l| *l))
        .await
        .expect("leads")
        .unwrap();

    let services: Api<Service> = Api::namespaced(admin.clone(), &release_ns);
    eventually("Service created", Duration::from_secs(10), || async {
        services.get_opt(&service_name).await.unwrap().is_some()
    })
    .await;
    let gateways: Api<Gateway> = Api::namespaced(admin.clone(), &ns);
    eventually("Gateway status", Duration::from_secs(10), || async {
        gateways.get("web").await.unwrap().status.is_some_and(|s| {
            condition_of(&s.conditions, "Accepted").is_some_and(|c| c.status == "True")
        })
    })
    .await;
    let routes: Api<HTTPRoute> = Api::namespaced(admin.clone(), &ns);
    eventually("route status", Duration::from_secs(10), || async {
        routes
            .get("route")
            .await
            .unwrap()
            .status
            .is_some_and(|s| s.parents.iter().any(|p| p.controller_name == CONTROLLER))
    })
    .await;
    let classes: Api<GatewayClass> = Api::all(admin.clone());
    eventually("class status", Duration::from_secs(10), || async {
        classes
            .get(&class)
            .await
            .unwrap()
            .status
            .is_some_and(|s| !s.supported_features.is_empty())
    })
    .await;
    let ingresses: Api<Ingress> = Api::namespaced(admin.clone(), &ns);
    eventually("ingress status", Duration::from_secs(10), || async {
        ingresses
            .get("ing")
            .await
            .unwrap()
            .status
            .and_then(|s| s.load_balancer)
            .and_then(|l| l.ingress)
            .is_some()
    })
    .await;
    let (crt_path, _) = secret_paths(data.path(), &ns, "tls");
    eventually("secret file", Duration::from_secs(10), || async {
        crt_path.exists()
    })
    .await;

    *wanted.lock().unwrap() = false;
    poke(&admin, &ns).await;
    eventually("Service deleted", Duration::from_secs(10), || async {
        services.get_opt(&service_name).await.unwrap().is_none()
    })
    .await;
    running.stop().await;
    let leases: Api<Lease> = Api::namespaced(admin.clone(), &release_ns);
    assert_eq!(
        lease_record(&leases, "reversedock-leader").await.0,
        "",
        "released"
    );
    let _ = classes.delete(&class, &DeleteParams::default()).await;
}

/// A TCP forwarder to the API server that the test can cut and restore.
struct Forwarder {
    port: u16,
    target: String,
    tasks: tokio::task::JoinSet<()>,
}

impl Forwarder {
    async fn start(target: String) -> Self {
        let mut f = Self {
            port: 0,
            target,
            tasks: tokio::task::JoinSet::new(),
        };
        f.listen().await;
        f
    }

    async fn listen(&mut self) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", self.port))
            .await
            .unwrap();
        self.port = listener.local_addr().unwrap().port();
        let target = self.target.clone();
        self.tasks.spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    return;
                };
                let target = target.clone();
                connections.spawn(async move {
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
    }

    /// Drops the listener and every open connection (the `JoinSet`s abort their tasks).
    fn cut(&mut self) {
        self.tasks.abort_all();
    }
}

// The API server becomes unreachable: the last snapshot stays, the provider reports itself
// degraded after `degraded_after`, and recovers (degraded cleared, changes flow again) when
// the API server is back.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_api_server_keeps_the_last_snapshot_and_recovers() {
    let Some((kubeconfig, client)) = cluster("degraded").await else {
        return;
    };
    let ns = namespace(&client, "degraded").await;
    let text = std::fs::read_to_string(&kubeconfig).unwrap();
    let server = text
        .split("server: \"https://")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap()
        .to_owned();
    let mut forwarder = Forwarder::start(server.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let via_forwarder = dir.path().join("kubeconfig");
    std::fs::write(
        &via_forwarder,
        text.replace(&server, &format!("127.0.0.1:{}", forwarder.port)),
    )
    .unwrap();
    let translate = {
        let ns = ns.clone();
        Arc::new(move |inventory: &Inventory, _: &Settings| {
            // Make the poke visible in the snapshot: one diagnostic per ConfigMap.
            Translation {
                diagnostics: inventory
                    .config_maps
                    .keys()
                    .filter(|k| k.0 == ns)
                    .map(|k| rdock_model::Diagnostic::warning(k.1.clone(), "seen"))
                    .collect(),
                ..Translation::default()
            }
        })
    };
    let options = Options {
        translate,
        degraded_after: Duration::from_millis(500),
        recovered_after: Duration::from_secs(5),
        ..Options::default()
    };
    let mut running = start(
        provider(&via_forwarder, &ns),
        context(&ns, dir.path()),
        options,
    );
    tokio::time::timeout(
        Duration::from_secs(20),
        running.state.wait_for(|s| s.snapshot.is_some()),
    )
    .await
    .unwrap()
    .unwrap();
    let first = running.state.borrow().snapshot.clone();

    forwarder.cut();
    tokio::time::timeout(
        Duration::from_secs(20),
        running.state.wait_for(|s| s.degraded.is_some()),
    )
    .await
    .expect("degraded once the API server is gone")
    .unwrap();
    {
        let state = running.state.borrow();
        assert!(
            state
                .degraded
                .as_ref()
                .unwrap()
                .contains("cannot watch the Kubernetes API"),
            "{:?}",
            state.degraded
        );
        assert_eq!(state.snapshot, first, "the last snapshot stays");
    }

    forwarder.listen().await;
    poke(&client, &ns).await;
    tokio::time::timeout(
        Duration::from_secs(60),
        running.state.wait_for(|s| {
            s.degraded.is_none()
                && s.snapshot
                    .as_ref()
                    .is_some_and(|s| !s.diagnostics.is_empty())
        }),
    )
    .await
    .expect("recovered: degraded cleared and the change after the outage published")
    .unwrap();
    running.stop().await;
}

// Without a reachable API server the provider never publishes and says why.
#[tokio::test(flavor = "multi_thread")]
async fn no_api_server_means_degraded_and_no_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kubeconfig");
    std::fs::write(&path, "apiVersion: v1\nkind: Config\nclusters: [{name: c, cluster: {server: \"https://127.0.0.1:1\"}}]\n\
        users: [{name: u, user: {token: t}}]\ncontexts: [{name: x, context: {cluster: c, user: u}}]\ncurrent-context: x\n").unwrap();
    let options = Options {
        degraded_after: Duration::from_millis(200),
        ..Options::default()
    };
    let mut running = start(
        provider(&path, "default"),
        context("default", dir.path()),
        options,
    );
    tokio::time::timeout(
        Duration::from_secs(20),
        running.state.wait_for(|s| s.degraded.is_some()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(running.state.borrow().snapshot.is_none());
    running.stop().await;
}
