//! The watches (ADR-0029, "Crate and client"): one watcher per kind (per namespace when
//! `providers.kubernetes.namespaces` is set) with kube's default backoff, each keeping its
//! part of the [`Stores`] current like a reflector does (the whole list is swapped in at once
//! after every (re-)list), and nudging the translation loop on every change.
//!
//! Secrets and ConfigMaps are reduced as they arrive ([`super::secrets`]): the translator
//! sees only [`crate::inventory::SecretInfo`]; the bytes stay in this private store.
//!
//! A kind whose CRD is absent (404 on list) is recorded in `missing_kinds` and its watch is
//! started again every 60 s, so the Gateway API may be installed after rdock.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::Api;
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Client, Resource, ResourceExt};
use serde::de::DeserializeOwned;
use tokio::sync::{Notify, watch};
use tokio::task::JoinSet;

use super::secrets::{
    StoredConfigMap, StoredSecret, TLS_SECRET_TYPE, reduce_config_map, reduce_secret,
};
use crate::api::{
    BackendTLSPolicy, GRPCRoute, Gateway, GatewayClass, HTTPRoute, ListenerSet, ReferenceGrant,
    TCPRoute, TLSRoute, UDPRoute, kinds,
};
use crate::inventory::{Inventory, ObjectKey};
use crate::translate::{GATEWAY_NAME_LABEL, MANAGED_BY, MANAGED_BY_LABEL, Settings};

/// How often a kind whose CRD is absent, and the CRD bundle version, are checked again.
pub const RECHECK: Duration = Duration::from_secs(60);
/// The CRD whose `gateway.networking.k8s.io/bundle-version` annotation is read.
pub const GATEWAY_CRD: &str = "gateways.gateway.networking.k8s.io";
/// The annotation with the Gateway API release of the installed CRDs.
pub const BUNDLE_VERSION_ANNOTATION: &str = "gateway.networking.k8s.io/bundle-version";

/// Everything the watches hold. Cluster-scoped objects are keyed with an empty namespace.
#[derive(Debug, Default)]
pub(crate) struct Stores {
    pub gateway_classes: BTreeMap<ObjectKey, GatewayClass>,
    pub gateways: BTreeMap<ObjectKey, Gateway>,
    pub http_routes: BTreeMap<ObjectKey, HTTPRoute>,
    pub grpc_routes: BTreeMap<ObjectKey, GRPCRoute>,
    pub tls_routes: BTreeMap<ObjectKey, TLSRoute>,
    pub tcp_routes: BTreeMap<ObjectKey, TCPRoute>,
    pub udp_routes: BTreeMap<ObjectKey, UDPRoute>,
    pub reference_grants: BTreeMap<ObjectKey, ReferenceGrant>,
    pub listener_sets: BTreeMap<ObjectKey, ListenerSet>,
    pub backend_tls_policies: BTreeMap<ObjectKey, BackendTLSPolicy>,
    pub services: BTreeMap<ObjectKey, Service>,
    pub endpoint_slices: BTreeMap<ObjectKey, EndpointSlice>,
    pub secrets: BTreeMap<ObjectKey, StoredSecret>,
    pub config_maps: BTreeMap<ObjectKey, StoredConfigMap>,
    pub namespaces: BTreeMap<ObjectKey, BTreeMap<String, String>>,
    pub ingresses: BTreeMap<ObjectKey, Ingress>,
    pub ingress_classes: BTreeMap<ObjectKey, IngressClass>,
    /// The per-Gateway Services (label-selected, in the service namespace).
    pub managed_services: BTreeMap<ObjectKey, Service>,
    pub crd_bundle_version: Option<String>,
    pub missing_kinds: BTreeSet<String>,
}

fn by_name<V: Clone>(map: &BTreeMap<ObjectKey, V>) -> BTreeMap<String, V> {
    map.iter()
        .map(|((_, name), v)| (name.clone(), v.clone()))
        .collect()
}

impl Stores {
    /// The inventory the translator reads: plain copies, without Secret or ConfigMap bytes.
    pub fn inventory(&self) -> Inventory {
        Inventory {
            gateway_classes: by_name(&self.gateway_classes),
            gateways: self.gateways.clone(),
            http_routes: self.http_routes.clone(),
            grpc_routes: self.grpc_routes.clone(),
            tls_routes: self.tls_routes.clone(),
            tcp_routes: self.tcp_routes.clone(),
            udp_routes: self.udp_routes.clone(),
            reference_grants: self.reference_grants.clone(),
            listener_sets: self.listener_sets.clone(),
            backend_tls_policies: self.backend_tls_policies.clone(),
            services: self.services.clone(),
            endpoint_slices: self.endpoint_slices.clone(),
            secrets: self
                .secrets
                .iter()
                .map(|(k, s)| (k.clone(), s.info.clone()))
                .collect(),
            config_maps: self
                .config_maps
                .iter()
                .map(|(k, c)| (k.clone(), c.info.clone()))
                .collect(),
            namespaces: by_name(&self.namespaces),
            ingresses: self.ingresses.clone(),
            ingress_classes: by_name(&self.ingress_classes),
            gateway_services: self
                .managed_services
                .values()
                .filter_map(super::services::gateway_service)
                .collect(),
            crd_bundle_version: self.crd_bundle_version.clone(),
            missing_kinds: self.missing_kinds.clone(),
        }
    }

    /// The managed Services by name.
    pub fn managed_by_name(&self) -> BTreeMap<String, Service> {
        by_name(&self.managed_services)
    }
}

/// Watch health and sync progress, shared by the watch tasks and the loop.
#[derive(Debug, Default)]
pub(crate) struct Progress {
    /// Watches that have not listed once yet.
    pending: BTreeSet<String>,
    /// Watches whose last attempt failed: since when, when last, and why.
    failing: BTreeMap<String, Failure>,
}

/// A run of failures of one watch.
#[derive(Debug)]
struct Failure {
    since: Instant,
    last: Instant,
    reason: String,
}

/// The state shared between the watch tasks and the translation loop.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    pub stores: Mutex<Stores>,
    progress: Mutex<Progress>,
    /// Woken on every change.
    pub changed: Notify,
}

impl Shared {
    pub fn lock(&self) -> std::sync::MutexGuard<'_, Stores> {
        self.stores.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn progress(&self) -> std::sync::MutexGuard<'_, Progress> {
        self.progress.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, id: &str) {
        self.progress().pending.insert(id.to_owned());
    }

    fn synced(&self, id: &str) {
        let mut progress = self.progress();
        progress.pending.remove(id);
        progress.failing.remove(id);
    }

    fn healthy(&self, id: &str) {
        self.progress().failing.remove(id);
    }

    fn failing(&self, id: &str, reason: String) {
        let now = Instant::now();
        self.progress()
            .failing
            .entry(id.to_owned())
            .and_modify(|f| {
                f.last = now;
                f.reason.clone_from(&reason);
            })
            .or_insert(Failure {
                since: now,
                last: now,
                reason,
            });
    }

    /// Whether every watch has listed once.
    pub fn all_synced(&self) -> bool {
        self.progress().pending.is_empty()
    }

    /// The watches that have not listed yet (for logs).
    pub fn pending(&self) -> Vec<String> {
        self.progress().pending.iter().cloned().collect()
    }

    /// Why the provider is degraded: watches failing for longer than `after`.
    ///
    /// A watch that recovers says so only when something changes (kube's watcher resumes a
    /// watch without an event), but a failing one keeps failing at least every 30 s (its
    /// backoff's ceiling): a watch with no failure for `recovered` counts as recovered.
    pub fn degraded(&self, after: Duration, recovered: Duration) -> Option<String> {
        let mut progress = self.progress();
        progress.failing.retain(|_, f| f.last.elapsed() < recovered);
        let failing: Vec<String> = progress
            .failing
            .iter()
            .filter(|(_, f)| f.since.elapsed() >= after)
            .map(|(id, f)| format!("{id}: {}", f.reason))
            .collect();
        (!failing.is_empty()).then(|| {
            format!(
                "cannot watch the Kubernetes API ({}); the last routes stay in service",
                failing.join("; ")
            )
        })
    }
}

fn key_of<K: Resource>(object: &K) -> ObjectKey {
    (object.namespace().unwrap_or_default(), object.name_any())
}

/// How one watch is set up.
struct Spec<K: Resource, V> {
    /// Unique id, e.g. `HTTPRoute` or `Secret in apps`.
    id: String,
    /// The kind, as recorded in `missing_kinds`.
    kind: &'static str,
    /// Whether a 404 on list means the kind's CRD is absent.
    crd: bool,
    api: Api<K>,
    config: watcher::Config,
    /// The namespace this watch covers (a re-list replaces only its entries), `None` for all.
    scope: Option<String>,
    reduce: fn(&K) -> Option<V>,
    slot: fn(&mut Stores) -> &mut BTreeMap<ObjectKey, V>,
}

fn in_scope(scope: Option<&str>, key: &ObjectKey) -> bool {
    scope.is_none_or(|ns| key.0 == ns)
}

fn is_not_found(err: &watcher::Error) -> bool {
    matches!(
        err,
        watcher::Error::InitialListFailed(kube::Error::Api(status))
            | watcher::Error::WatchStartFailed(kube::Error::Api(status))
            if status.code == 404
    )
}

async fn watch_kind<K, V>(spec: Spec<K, V>, shared: Arc<Shared>)
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
    V: Send + 'static,
{
    let scope = spec.scope.as_deref();
    loop {
        let mut stream = std::pin::pin!(
            watcher::watcher(spec.api.clone(), spec.config.clone()).default_backoff()
        );
        let mut buffer: Vec<(ObjectKey, V)> = Vec::new();
        let mut absent = false;
        while let Some(item) = stream.next().await {
            match item {
                Ok(Event::Init) => buffer.clear(),
                Ok(Event::InitApply(object)) => {
                    if let Some(value) = (spec.reduce)(&object) {
                        buffer.push((key_of(&object), value));
                    }
                }
                Ok(Event::InitDone) => {
                    {
                        let mut stores = shared.lock();
                        let slot = (spec.slot)(&mut stores);
                        slot.retain(|key, _| !in_scope(scope, key));
                        slot.extend(buffer.drain(..));
                        if spec.crd && stores.missing_kinds.remove(spec.kind) {
                            tracing::info!(
                                provider = crate::PROVIDER,
                                kind = spec.kind,
                                "the kind's CRD is installed now; watching it"
                            );
                        }
                    }
                    shared.synced(&spec.id);
                    shared.changed.notify_one();
                }
                Ok(Event::Apply(object)) => {
                    let key = key_of(&object);
                    {
                        let mut stores = shared.lock();
                        let slot = (spec.slot)(&mut stores);
                        match (spec.reduce)(&object) {
                            Some(value) => {
                                slot.insert(key, value);
                            }
                            None => {
                                slot.remove(&key);
                            }
                        }
                    }
                    shared.healthy(&spec.id);
                    shared.changed.notify_one();
                }
                Ok(Event::Delete(object)) => {
                    let key = key_of(&object);
                    (spec.slot)(&mut shared.lock()).remove(&key);
                    shared.healthy(&spec.id);
                    shared.changed.notify_one();
                }
                Err(err) if spec.crd && is_not_found(&err) => {
                    absent = true;
                    break;
                }
                Err(err) => {
                    tracing::debug!(provider = crate::PROVIDER, watch = %spec.id, error = %err, "watch failed; retrying");
                    shared.failing(&spec.id, err.to_string());
                }
            }
        }
        if absent {
            let newly = {
                let mut stores = shared.lock();
                (spec.slot)(&mut stores).retain(|key, _| !in_scope(scope, key));
                stores.missing_kinds.insert(spec.kind.to_owned())
            };
            if newly {
                tracing::info!(
                    provider = crate::PROVIDER,
                    kind = spec.kind,
                    "the kind's CRD is not installed; skipping it and checking again every 60 s"
                );
            }
            shared.synced(&spec.id);
            shared.changed.notify_one();
        }
        // A finished stream (it never ends on its own) or an absent CRD: start over later.
        tokio::time::sleep(RECHECK).await;
    }
}

#[allow(clippy::unnecessary_wraps)] // the shape every `Spec::reduce` has
fn keep<K: Clone>(object: &K) -> Option<K> {
    Some(object.clone())
}

/// Labels of a Namespace (for `allowedRoutes` selectors).
#[allow(clippy::unnecessary_wraps)] // the shape every `Spec::reduce` has
fn namespace_labels(namespace: &Namespace) -> Option<BTreeMap<String, String>> {
    Some(namespace.metadata.labels.clone().unwrap_or_default())
}

/// Starts every watch the settings call for. Returns when they are spawned; they run until
/// the set is dropped or aborted.
#[allow(clippy::too_many_lines)] // one entry per watched kind
pub(crate) fn spawn_watches(
    client: &Client,
    settings: &Settings,
    shared: &Arc<Shared>,
    tasks: &mut JoinSet<()>,
) {
    let provider = &settings.provider;
    let namespaces: Vec<Option<String>> = if provider.namespaces.is_empty() {
        vec![None]
    } else {
        let mut list: Vec<String> = provider.namespaces.clone();
        list.sort();
        list.dedup();
        list.into_iter().map(Some).collect()
    };

    macro_rules! namespaced {
        ($ty:ty, $kind:expr, $crd:expr, $slot:ident, $reduce:expr, $config:expr) => {
            for ns in &namespaces {
                let api: Api<$ty> = match ns {
                    Some(ns) => Api::namespaced(client.clone(), ns),
                    None => Api::all(client.clone()),
                };
                let id = match ns {
                    Some(ns) => format!("{} in {ns}", $kind),
                    None => $kind.to_owned(),
                };
                shared.register(&id);
                tasks.spawn(watch_kind(
                    Spec {
                        id,
                        kind: $kind,
                        crd: $crd,
                        api,
                        config: $config,
                        scope: ns.clone(),
                        reduce: $reduce,
                        slot: |s: &mut Stores| &mut s.$slot,
                    },
                    shared.clone(),
                ));
            }
        };
    }
    macro_rules! cluster {
        ($ty:ty, $kind:expr, $crd:expr, $slot:ident, $reduce:expr) => {{
            let id = $kind.to_owned();
            shared.register(&id);
            tasks.spawn(watch_kind(
                Spec {
                    id,
                    kind: $kind,
                    crd: $crd,
                    api: Api::<$ty>::all(client.clone()),
                    config: watcher::Config::default(),
                    scope: None,
                    reduce: $reduce,
                    slot: |s: &mut Stores| &mut s.$slot,
                },
                shared.clone(),
            ));
        }};
    }
    let all = watcher::Config::default;

    namespaced!(Service, "Service", false, services, keep, all());
    namespaced!(
        EndpointSlice,
        "EndpointSlice",
        false,
        endpoint_slices,
        keep,
        all()
    );
    // Only TLS Secrets (the field selector works on list and watch; checked against
    // kube-apiserver 1.37 on 2026-11-11), reduced to what the translator may know.
    namespaced!(
        Secret,
        "Secret",
        false,
        secrets,
        |s: &Secret| Some(reduce_secret(s)),
        all().fields(&format!("type={TLS_SECRET_TYPE}"))
    );
    if provider.gateway.enabled {
        cluster!(
            GatewayClass,
            kinds::GATEWAY_CLASS,
            true,
            gateway_classes,
            keep
        );
        namespaced!(Gateway, kinds::GATEWAY, true, gateways, keep, all());
        namespaced!(HTTPRoute, kinds::HTTP_ROUTE, true, http_routes, keep, all());
        namespaced!(GRPCRoute, kinds::GRPC_ROUTE, true, grpc_routes, keep, all());
        namespaced!(TLSRoute, kinds::TLS_ROUTE, true, tls_routes, keep, all());
        namespaced!(TCPRoute, kinds::TCP_ROUTE, true, tcp_routes, keep, all());
        namespaced!(UDPRoute, kinds::UDP_ROUTE, true, udp_routes, keep, all());
        namespaced!(
            ReferenceGrant,
            kinds::REFERENCE_GRANT,
            true,
            reference_grants,
            keep,
            all()
        );
        namespaced!(
            ListenerSet,
            kinds::LISTENER_SET,
            true,
            listener_sets,
            keep,
            all()
        );
        namespaced!(
            BackendTLSPolicy,
            kinds::BACKEND_TLS_POLICY,
            true,
            backend_tls_policies,
            keep,
            all()
        );
        namespaced!(
            ConfigMap,
            "ConfigMap",
            false,
            config_maps,
            |c: &ConfigMap| Some(reduce_config_map(c)),
            all()
        );
        cluster!(Namespace, "Namespace", false, namespaces, namespace_labels);
        // The per-Gateway Services, wherever they live (the namespaced watches above may not
        // cover the service namespace).
        let id = "managed Service".to_owned();
        shared.register(&id);
        tasks.spawn(watch_kind(
            Spec {
                id,
                kind: "Service",
                crd: false,
                api: Api::<Service>::namespaced(client.clone(), settings.service_namespace()),
                config: all().labels(&format!(
                    "{MANAGED_BY_LABEL}={MANAGED_BY},{GATEWAY_NAME_LABEL}"
                )),
                scope: None,
                reduce: keep,
                slot: |s: &mut Stores| &mut s.managed_services,
            },
            shared.clone(),
        ));
        let id = "CRD bundle version".to_owned();
        shared.register(&id);
        tasks.spawn(watch_bundle_version(client.clone(), shared.clone(), id));
    }
    if provider.ingress.enabled {
        namespaced!(Ingress, "Ingress", false, ingresses, keep, all());
        cluster!(IngressClass, "IngressClass", false, ingress_classes, keep);
    }
}

/// Reads the Gateway API bundle version from the `gateways` CRD now and every 60 s.
async fn watch_bundle_version(client: Client, shared: Arc<Shared>, id: String) {
    let api: Api<CustomResourceDefinition> = Api::all(client);
    let mut reported: Option<Result<Option<String>, String>> = None;
    loop {
        let read = match tokio::time::timeout(
            super::CALL_TIMEOUT,
            api.get_metadata_opt(GATEWAY_CRD),
        )
        .await
        {
            Ok(Ok(meta)) => Ok(meta
                .and_then(|m| m.metadata.annotations)
                .and_then(|a| a.get(BUNDLE_VERSION_ANNOTATION).cloned())),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err("the request timed out".to_owned()),
        };
        if reported.as_ref() != Some(&read) {
            match &read {
                Ok(Some(version)) => {
                    tracing::info!(provider = crate::PROVIDER, %version, "Gateway API CRDs installed");
                }
                Ok(None) => tracing::warn!(
                    provider = crate::PROVIDER,
                    "the Gateway API CRDs are not installed (or carry no bundle version); install v1.7.0"
                ),
                Err(err) => tracing::warn!(provider = crate::PROVIDER, error = %err,
                    "cannot read the Gateway API CRD bundle version"),
            }
            if let Ok(version) = &read {
                let changed = {
                    let mut stores = shared.lock();
                    let changed = stores.crd_bundle_version != *version;
                    stores.crd_bundle_version.clone_from(version);
                    changed
                };
                if changed {
                    shared.changed.notify_one();
                }
            }
            reported = Some(read);
        }
        // The first attempt counts as listed whatever it found: the version is informative.
        shared.synced(&id);
        tokio::time::sleep(RECHECK).await;
    }
}

/// The shared state for a test or a start: fresh stores, nothing registered.
pub(crate) fn shared() -> Arc<Shared> {
    Arc::new(Shared::default())
}

/// A shutdown-aware helper for the loop: resolves when `shutdown` turns true.
pub(crate) async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::SecretInfo;

    #[test]
    fn the_inventory_is_built_from_the_stores_without_secret_bytes() {
        let mut stores = Stores::default();
        stores.gateway_classes.insert(
            (String::new(), "rdock".to_owned()),
            GatewayClass::new("rdock", crate::api::GatewayClassSpec::default()),
        );
        stores.namespaces.insert(
            (String::new(), "apps".to_owned()),
            BTreeMap::from([("team".to_owned(), "a".to_owned())]),
        );
        let info = SecretInfo {
            namespace: "apps".to_owned(),
            name: "tls".to_owned(),
            kind: TLS_SECRET_TYPE.to_owned(),
            valid: Ok(()),
        };
        stores.secrets.insert(
            ("apps".to_owned(), "tls".to_owned()),
            StoredSecret {
                info: info.clone(),
                crt: Some(b"CRT".to_vec()),
                key: Some(b"KEY".to_vec()),
            },
        );
        let service: Service = serde_json::from_value(serde_json::json!({
            "metadata": {
                "namespace": "rdock-system", "name": "apps-web",
                "labels": {
                    MANAGED_BY_LABEL: MANAGED_BY, GATEWAY_NAME_LABEL: "web",
                    crate::translate::GATEWAY_NAMESPACE_LABEL: "apps"
                },
                "annotations": {
                    crate::translate::GATEWAY_NAMESPACE_ANNOTATION: "apps",
                    crate::translate::GATEWAY_NAME_ANNOTATION: "web"
                }
            },
            "spec": { "type": "ClusterIP", "clusterIP": "10.96.0.9", "ports": [{ "port": 80, "targetPort": 20000 }] }
        }))
        .unwrap();
        stores
            .managed_services
            .insert(("rdock-system".to_owned(), "apps-web".to_owned()), service);
        stores.missing_kinds.insert("UDPRoute".to_owned());
        stores.crd_bundle_version = Some("v1.7.0".to_owned());

        let inventory = stores.inventory();
        assert!(inventory.gateway_classes.contains_key("rdock"));
        assert_eq!(inventory.namespaces["apps"]["team"], "a");
        assert_eq!(
            inventory.secrets[&("apps".to_owned(), "tls".to_owned())],
            info
        );
        let gs = &inventory.gateway_services[&("apps".to_owned(), "web".to_owned())];
        assert_eq!(gs.name, "apps-web");
        assert_eq!(gs.ports, BTreeMap::from([(80, 20000)]));
        assert_eq!(gs.addresses[0].value, "10.96.0.9");
        assert!(inventory.missing_kinds.contains("UDPRoute"));
        assert_eq!(inventory.crd_bundle_version.as_deref(), Some("v1.7.0"));
        assert!(!format!("{inventory:?}").contains("KEY"));
        assert_eq!(stores.managed_by_name().len(), 1);
    }

    #[test]
    fn progress_tracks_sync_and_failures() {
        let shared = shared();
        shared.register("a");
        shared.register("b");
        assert!(!shared.all_synced());
        shared.synced("a");
        assert_eq!(shared.pending(), vec!["b".to_owned()]);
        shared.failing("b", "connection refused".to_owned());
        let long = Duration::from_secs(60);
        assert!(
            shared
                .degraded(Duration::ZERO, long)
                .unwrap()
                .contains("b: connection refused")
        );
        assert_eq!(shared.degraded(long, long), None);
        shared.synced("b");
        assert!(shared.all_synced());
        assert_eq!(shared.degraded(Duration::ZERO, long), None);
        // A watch that has not failed again for `recovered` counts as recovered.
        shared.failing("c", "timeout".to_owned());
        assert_eq!(shared.degraded(Duration::ZERO, Duration::ZERO), None);
        assert_eq!(shared.degraded(Duration::ZERO, long), None);
    }

    #[test]
    fn a_relist_replaces_only_its_namespace() {
        let key = |ns: &str| (ns.to_owned(), "x".to_owned());
        assert!(in_scope(Some("a"), &key("a")));
        assert!(!in_scope(Some("a"), &key("b")));
        assert!(in_scope(None, &key("b")));
    }
}
