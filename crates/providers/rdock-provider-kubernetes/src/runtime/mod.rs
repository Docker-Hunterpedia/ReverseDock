//! The runtime half of the provider (ADR-0029): watches, the inventory, translation every
//! 100 ms at most when something changed, snapshots to the engine, and (leader only) status
//! and the per-Gateway Services; Secret and ConfigMap files on every replica.
//!
//! **Owner:** the cluster runtime. Only this module (and files below `src/runtime/`) changes
//! for it.
//!
//! The loop, once every watch has listed once ([`store`]):
//! 1. translate the inventory with the pure [`crate::translate::translate`];
//! 2. write the Secret and ConfigMap files the translation names ([`files`]);
//! 3. publish the snapshot when it changed (a changed file changes its `revision`, so the
//!    engine reloads and reads the files again even when the fragment is the same);
//! 4. hand the desired status and Services to the writer task, which acts only while this
//!    replica leads ([`lease`]): Services first ([`services`]), then status ([`status`]).
//!
//! Services and listeners take two passes: a new Gateway's translation asks for a Service;
//! the leader creates it with internal ports allocated from `gateway.port_range`; its watch
//! puts it in `Inventory::gateway_services`; the next translation opens those ports as
//! listeners on every replica and reports the Service's addresses.

pub(crate) mod client;
mod files;
pub mod lease;
pub mod secrets;
pub mod services;
pub mod status;
mod store;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::Service;
use kube::Client;
use rdock_config::merge::Snapshot;
use rdock_model::Diagnostic;
use rdock_model::providers::KubernetesProvider;
use tokio::sync::watch;
use tokio::task::JoinSet;

pub use lease::{Elector, LeaseTimings};

use crate::inventory::Inventory;
use crate::translate::{DesiredService, DesiredStatus, Settings, Translation};

/// What the provider reports to the engine; the type every provider shares. `snapshot` stays
/// `None` until every store has been listed once; the engine's readiness waits for it.
pub use rdock_config::merge::ProviderState as State;

/// The provider name and the suffix of its objects (`name@kubernetes`).
pub const PROVIDER: &str = "kubernetes";

/// Environment variable with the pod's namespace (downward API).
pub const POD_NAMESPACE_ENV: &str = "RDOCK_POD_NAMESPACE";
/// Environment variable with the pod's name (downward API).
pub const POD_NAME_ENV: &str = "RDOCK_POD_NAME";
/// The service account's namespace file, read when [`POD_NAMESPACE_ENV`] is unset.
pub const SERVICE_ACCOUNT_NAMESPACE_FILE: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Translations run at most this often.
pub const COALESCE: Duration = Duration::from_millis(100);
/// A watch failing for this long marks the provider degraded.
pub const DEGRADED_AFTER: Duration = Duration::from_secs(10);
/// A failing watch that has not failed again for this long counts as recovered (kube's
/// watcher retries at least every 30 s while it fails, and resumes without an event).
pub const RECOVERED_AFTER: Duration = Duration::from_secs(45);
/// The longest a single API call (not a watch) may take.
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the provider runs: what it needs from the process besides `providers.kubernetes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunContext {
    /// rdock's data directory (`--data-dir`); Secret and ConfigMap files go below it
    /// ([`crate::translate::secret_paths`]).
    pub data_dir: PathBuf,
    /// The controller's namespace: per-Gateway Services (by default) and the Lease live there.
    /// Empty until known: [`run`] then takes the kubeconfig's namespace, else `default`.
    pub pod_namespace: String,
    /// The pod's name: the first part of the Lease holder identity.
    pub pod_name: String,
}

impl RunContext {
    /// The context from the environment: [`POD_NAMESPACE_ENV`], else the service account's
    /// namespace file, else empty (resolved by [`run`]); [`POD_NAME_ENV`], else `HOSTNAME`,
    /// else `rdock`.
    #[must_use]
    pub fn from_env(data_dir: PathBuf) -> Self {
        let non_empty = |v: String| Some(v.trim().to_owned()).filter(|v| !v.is_empty());
        let pod_namespace = std::env::var(POD_NAMESPACE_ENV)
            .ok()
            .and_then(non_empty)
            .or_else(|| {
                std::fs::read_to_string(SERVICE_ACCOUNT_NAMESPACE_FILE)
                    .ok()
                    .and_then(non_empty)
            })
            .unwrap_or_default();
        let pod_name = std::env::var(POD_NAME_ENV)
            .ok()
            .and_then(non_empty)
            .or_else(|| std::env::var("HOSTNAME").ok().and_then(non_empty))
            .unwrap_or_else(|| "rdock".to_owned());
        Self {
            data_dir,
            pod_namespace,
            pod_name,
        }
    }

    /// The translator's settings for `provider` in this context.
    #[must_use]
    pub fn settings(&self, provider: &KubernetesProvider) -> Settings {
        Settings {
            provider: provider.clone(),
            controller_namespace: self.pod_namespace.clone(),
            data_dir: self.data_dir.clone(),
        }
    }
}

/// Why the provider cannot talk to the API server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The client configuration could not be inferred or loaded, or the settings cannot work.
    #[error("cannot configure the Kubernetes provider: {0}")]
    Config(String),
    /// An API call failed.
    #[error("Kubernetes API: {0}")]
    Api(#[from] kube::Error),
}

/// The translation function: [`crate::translate::translate`] in production, a stand-in in
/// tests.
pub type TranslateFn = Arc<dyn Fn(&Inventory, &Settings) -> Translation + Send + Sync>;

/// How [`run_with`] runs. [`Options::default`] is what [`run`] uses.
#[derive(Clone)]
pub struct Options {
    /// Turns the inventory into a translation.
    pub translate: TranslateFn,
    /// Leader-election timings (client-go's defaults).
    pub lease: LeaseTimings,
    /// How long a watch may fail before the provider reports itself degraded.
    pub degraded_after: Duration,
    /// How long a failed watch must stay quiet to count as recovered ([`RECOVERED_AFTER`]).
    pub recovered_after: Duration,
    /// Receives every change of leadership, for tests and observers.
    pub leadership: Option<watch::Sender<bool>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            translate: Arc::new(crate::translate::translate),
            lease: LeaseTimings::default(),
            degraded_after: DEGRADED_AFTER,
            recovered_after: RECOVERED_AFTER,
            leadership: None,
        }
    }
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("lease", &self.lease)
            .field("degraded_after", &self.degraded_after)
            .field("recovered_after", &self.recovered_after)
            .finish_non_exhaustive()
    }
}

/// Runs until `shutdown` turns true, publishing on `tx`.
pub async fn run(
    settings: KubernetesProvider,
    context: RunContext,
    tx: watch::Sender<State>,
    shutdown: watch::Receiver<bool>,
) {
    run_with(settings, context, Options::default(), tx, shutdown).await;
}

/// Everything resolved before the watches start.
struct Prepared {
    client: Client,
    settings: Settings,
    identity: String,
}

async fn prepare(
    provider: &KubernetesProvider,
    mut context: RunContext,
) -> Result<Prepared, Error> {
    if provider.gateway.enabled && provider.gateway.pod_selector.is_empty() {
        return Err(Error::Config(
            "`providers.kubernetes.gateway.pod_selector` is empty: the per-Gateway Services \
             need the labels of the ReverseDock pods (the controller does not read pods); the \
             Helm chart sets it"
                .to_owned(),
        ));
    }
    let config = client::config(provider).await?;
    if context.pod_namespace.is_empty() {
        context.pod_namespace = if config.default_namespace.is_empty() {
            "default".to_owned()
        } else {
            config.default_namespace.clone()
        };
    }
    let client = Client::try_from(config)?;
    let identity = format!("{}_{:08x}", context.pod_name, fastrand::u32(..));
    Ok(Prepared {
        client,
        settings: context.settings(provider),
        identity,
    })
}

/// What the writer task works on: one translation and the live objects it was made from.
struct Work {
    inventory: Arc<Inventory>,
    status: DesiredStatus,
    services: Vec<DesiredService>,
    managed: BTreeMap<String, Service>,
}

/// [`run`] with explicit [`Options`] (tests pass their own translation and timings).
pub async fn run_with(
    provider: KubernetesProvider,
    context: RunContext,
    options: Options,
    tx: watch::Sender<State>,
    mut shutdown: watch::Receiver<bool>,
) {
    let Prepared {
        client,
        settings,
        identity,
    } = match prepare(&provider, context).await {
        Ok(prepared) => prepared,
        Err(err) => {
            tracing::error!(provider = PROVIDER, error = %err, "the Kubernetes provider cannot start");
            tx.send_modify(|state| state.degraded = Some(err.to_string()));
            let _ = shutdown.wait_for(|stop| *stop).await;
            return;
        }
    };
    log_start(&provider, &settings, &identity);

    let shared = store::shared();
    let mut tasks = JoinSet::new();
    store::spawn_watches(&client, &settings, &shared, &mut tasks);

    let (leader, elector) = leadership(
        &client, &provider, &settings, &identity, &options, &shutdown, &mut tasks,
    );

    let (work_tx, work_rx) = watch::channel::<Option<Arc<Work>>>(None);
    let (extra_tx, mut extra_rx) = watch::channel::<Vec<Diagnostic>>(Vec::new());
    tasks.spawn(writer(
        client.clone(),
        settings.clone(),
        work_rx,
        leader.clone(),
        extra_tx,
    ));

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut dirty = true;
    let mut last: Option<Instant> = None;
    let mut pass = Pass {
        settings: &settings,
        shared: &shared,
        translate: &options.translate,
        tx: &tx,
        work: &work_tx,
        revision: 0,
        first: true,
    };
    let mut degraded: Option<String> = None;
    let mut waiting_logged = Instant::now();
    loop {
        tokio::select! {
            () = shared.changed.notified() => dirty = true,
            r = extra_rx.changed() => if r.is_ok() { dirty = true },
            _ = tick.tick() => {}
            () = store::stopped(&mut shutdown) => break,
        }
        let now_degraded = shared.degraded(options.degraded_after, options.recovered_after);
        if now_degraded != degraded {
            if let Some(reason) = &now_degraded {
                tracing::warn!(provider = PROVIDER, %reason, "the Kubernetes provider is degraded");
            } else {
                tracing::info!(provider = PROVIDER, "the Kubernetes API is reachable again");
            }
            degraded.clone_from(&now_degraded);
            let reason = now_degraded.clone();
            tx.send_if_modified(|state| {
                let changed = state.degraded != reason;
                state.degraded = reason;
                changed
            });
        }
        if !dirty {
            continue;
        }
        if !shared.all_synced() {
            if waiting_logged.elapsed() >= Duration::from_secs(10) {
                waiting_logged = Instant::now();
                tracing::info!(provider = PROVIDER, pending = ?shared.pending(), "waiting for the first list of every watched kind");
            }
            continue;
        }
        if let Some(at) = last {
            let wait = COALESCE.saturating_sub(at.elapsed());
            if !wait.is_zero() {
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = store::stopped(&mut shutdown) => break,
                }
            }
        }
        dirty = false;
        last = Some(Instant::now());
        let extra = extra_rx.borrow_and_update().clone();
        pass.run(&extra, degraded.clone());
    }

    tasks.abort_all();
    if let Some(elector) = elector {
        // The elector saw the same shutdown and releases the Lease.
        let _ = tokio::time::timeout(Duration::from_secs(5), elector).await;
    }
    while tasks.join_next().await.is_some() {}
    tracing::info!(provider = PROVIDER, "the Kubernetes provider stopped");
}

fn log_start(provider: &KubernetesProvider, settings: &Settings, identity: &str) {
    let scopes = if provider.namespaces.is_empty() {
        "all namespaces".to_owned()
    } else {
        provider.namespaces.join(", ")
    };
    let on = |b: bool| if b { "on" } else { "off" };
    tracing::info!(
        provider = PROVIDER,
        namespace = %settings.controller_namespace,
        identity = %identity,
        scopes = %scopes,
        controller = %provider.controller_name,
        gateway = on(provider.gateway.enabled),
        ingress = on(provider.ingress.enabled),
        leader_election = on(provider.leader_election.enabled),
        "starting the Kubernetes provider"
    );
}

/// Leadership: only the leader writes to the cluster. Without election this replica always
/// leads.
fn leadership(
    client: &Client,
    provider: &KubernetesProvider,
    settings: &Settings,
    identity: &str,
    options: &Options,
    shutdown: &watch::Receiver<bool>,
    tasks: &mut JoinSet<()>,
) -> (watch::Receiver<bool>, Option<tokio::task::JoinHandle<()>>) {
    let (leader, elector) = if provider.leader_election.enabled {
        let api = kube::Api::namespaced(client.clone(), &settings.controller_namespace);
        let (rx, task) = Elector::new(
            api,
            &provider.leader_election.lease,
            identity,
            options.lease,
        )
        .spawn(shutdown.clone());
        (rx, Some(task))
    } else {
        let (keep, rx) = watch::channel(true);
        tasks.spawn(async move {
            keep.closed().await;
        });
        (rx, None)
    };
    if let Some(mirror) = options.leadership.clone() {
        let mut leader = leader.clone();
        tasks.spawn(async move {
            mirror.send_replace(*leader.borrow_and_update());
            while leader.changed().await.is_ok() {
                mirror.send_replace(*leader.borrow_and_update());
            }
        });
    }

    (leader, elector)
}

/// One translation pass: translate, write the files, publish, hand over to the writer.
struct Pass<'a> {
    settings: &'a Settings,
    shared: &'a store::Shared,
    translate: &'a TranslateFn,
    tx: &'a watch::Sender<State>,
    work: &'a watch::Sender<Option<Arc<Work>>>,
    /// Counts changes of the materialised files (the snapshot's `revision`).
    revision: u64,
    first: bool,
}

impl Pass<'_> {
    fn run(&mut self, extra: &[Diagnostic], degraded: Option<String>) {
        let (inventory, managed) = {
            let stores = self.shared.lock();
            (stores.inventory(), stores.managed_by_name())
        };
        let translation = (self.translate)(&inventory, self.settings);
        if self.first {
            self.first = false;
            tracing::info!(
                provider = PROVIDER,
                gateway_classes = inventory.gateway_classes.len(),
                gateways = inventory.gateways.len(),
                http_routes = inventory.http_routes.len(),
                services = inventory.services.len(),
                ingresses = inventory.ingresses.len(),
                missing_kinds = ?inventory.missing_kinds,
                crd_bundle_version = inventory.crd_bundle_version.as_deref().unwrap_or("unknown"),
                "first sync complete"
            );
        }

        // (a) Files, before the snapshot that names them.
        let wanted = {
            let stores = self.shared.lock();
            let secrets = translation.secrets.iter().filter_map(|key| {
                let s = stores.secrets.get(key)?;
                s.info.valid.as_ref().ok()?;
                Some((key, s.crt.as_deref()?, s.key.as_deref()?))
            });
            let config_maps = translation.config_maps.iter().filter_map(|key| {
                let c = stores.config_maps.get(key)?;
                Some((key, c.ca.as_deref()?))
            });
            files::wanted(&self.settings.data_dir, secrets, config_maps)
        };
        match files::materialise(&self.settings.data_dir, &wanted) {
            Ok(true) => self.revision += 1,
            Ok(false) => {}
            Err(err) => tracing::warn!(provider = PROVIDER, error = %err,
            "cannot write the Secret files; the previous ones stay in use"),
        }

        // (b) The snapshot.
        let mut diagnostics = translation.diagnostics.clone();
        diagnostics.extend(extra.iter().cloned());
        let snapshot = Snapshot {
            provider: PROVIDER.to_owned(),
            fragment: translation.fragment.clone(),
            diagnostics,
            revision: (!wanted.is_empty()).then(|| self.revision.to_string()),
        };
        let reason = degraded;
        self.tx.send_if_modified(|state| {
            let mut changed = state.publish(snapshot);
            if state.degraded != reason {
                state.degraded = reason;
                changed = true;
            }
            changed
        });

        // (c) The writer (it acts only while this replica leads).
        self.work.send_replace(Some(Arc::new(Work {
            inventory: Arc::new(inventory),
            status: translation.status,
            services: translation.services,
            managed,
        })));
    }
}

/// Writes Services and status for the latest translation while this replica leads.
async fn writer(
    client: Client,
    settings: Settings,
    mut work: watch::Receiver<Option<Arc<Work>>>,
    mut leader: watch::Receiver<bool>,
    extra: watch::Sender<Vec<Diagnostic>>,
) {
    let mut errors = status::ErrorLog::default();
    let services: kube::Api<Service> =
        kube::Api::namespaced(client.clone(), settings.service_namespace());
    loop {
        let retry = errors.next_due();
        tokio::select! {
            r = work.changed() => if r.is_err() { return },
            r = leader.changed() => if r.is_err() { return },
            () = async {
                match retry {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            } => {}
        }
        if !*leader.borrow_and_update() {
            continue;
        }
        let Some(item) = work.borrow_and_update().clone() else {
            continue;
        };
        if settings.provider.gateway.enabled {
            let outcome = services::reconcile(
                &services,
                &settings,
                &item.managed,
                &item.services,
                &mut errors,
            )
            .await;
            extra.send_if_modified(|current| {
                let changed = *current != outcome.diagnostics;
                if changed {
                    current.clone_from(&outcome.diagnostics);
                }
                changed
            });
        }
        if !*leader.borrow() {
            continue;
        }
        let mut writer = status::Writer {
            client: &client,
            controller: &settings.provider.controller_name,
            errors: &mut errors,
            writes: 0,
        };
        writer.write(&item.inventory, &item.status).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_come_from_the_context() {
        let context = RunContext {
            data_dir: PathBuf::from("/var/lib/rdock"),
            pod_namespace: "rdock-system".to_owned(),
            pod_name: "rdock-0".to_owned(),
        };
        let settings = context.settings(&KubernetesProvider::default());
        assert_eq!(settings.controller_namespace, "rdock-system");
        assert_eq!(settings.data_dir, PathBuf::from("/var/lib/rdock"));
    }

    #[tokio::test]
    async fn an_empty_pod_selector_is_a_configuration_error() {
        let (tx, mut rx) = watch::channel(State::default());
        let (stop, stop_rx) = watch::channel(false);
        let context = RunContext::from_env(PathBuf::from("/tmp/rdock-test"));
        let task = tokio::spawn(run(KubernetesProvider::default(), context, tx, stop_rx));
        rx.changed().await.unwrap();
        let reason = rx.borrow().degraded.clone().unwrap();
        assert!(
            reason.contains("providers.kubernetes.gateway.pod_selector"),
            "{reason}"
        );
        assert!(rx.borrow().snapshot.is_none());
        stop.send(true).unwrap();
        task.await.unwrap();
    }
}
