//! The certificate manager: a background task that keeps a certificate for every requested set
//! of names, and publishes them to the data plane's resolver (ADR-0020). The data plane never
//! waits for it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rcgen::KeyPair;
use rdock_cluster::{ClusterStore, Lease, StoreError};
use rustls_pki_types::pem::PemObject;

use instant_acme::{Account, ChallengeType};
use rdock_model::acme::{Acme, Challenge};
use rdock_observability::Metrics;
use rdock_tls::{CertIndex, CertRequest, Challenges, LoadedCert, SniResolver};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::account::{Accounts, choose_profile};
use crate::cluster::ClusterAcme;
use crate::directory::{directory_url, staging_for};
use crate::dns::{DnsProviders, Lookup};
use crate::issue::{AnswerSink, DnsChallenge, IssueError, OrderSpec, complete, new_order};
use crate::state::{CertState, CertStatus, spread};
use crate::storage::{
    AriWindow, CertMeta, OrderJournal, Storage, StorageError, StorageLock, StoredCert, cert_lease,
};

/// Orders running at once against one CA.
const MAX_CONCURRENT_ORDERS: usize = 4;
/// The longest the task sleeps; it also refreshes the storage lock and looks for certificates
/// other instances stored this often.
const MAX_SLEEP: Duration = Duration::from_secs(10);
/// How soon to look again while another instance holds the lease on a certificate.
const BUSY_RECHECK: Duration = Duration::from_secs(2);
/// The lease on a certificate of a single instance (its own directory).
const LOCAL_LEASE: Duration = Duration::from_secs(60);

/// What the configuration asks of the manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// ACME settings in effect.
    pub acme: Acme,
    /// Certificates to keep.
    pub requests: Vec<CertRequest>,
    /// Whether a plain-HTTP listener can answer HTTP-01 challenges.
    pub http01: bool,
    /// Whether a TLS listener can answer TLS-ALPN-01 challenges.
    pub tls_alpn01: bool,
}

impl Plan {
    /// The challenge types that can work, in the configured order of preference.
    fn challenge_types(&self) -> Vec<ChallengeType> {
        self.acme
            .challenges
            .iter()
            .filter_map(|c| match c {
                Challenge::Http01 if self.http01 => Some(ChallengeType::Http01),
                Challenge::TlsAlpn01 if self.tls_alpn01 => Some(ChallengeType::TlsAlpn01),
                _ => None,
            })
            .collect()
    }
}

/// What the manager needs from the rest of the process.
#[derive(Debug, Clone)]
pub struct Services {
    /// Used unless `acme.storage` is set.
    pub default_storage: PathBuf,
    /// Receives issued certificates.
    pub resolver: Arc<SniResolver>,
    /// Receives challenge answers.
    pub challenges: Arc<Challenges>,
    /// Certificate expiry, renewal failures and orders.
    pub metrics: Metrics,
    /// Builds DNS-01 solvers from `acme.dns_providers`.
    pub dns: Arc<dyn DnsProviders>,
    /// The cluster's store, when this instance is a member of one (ADR-0031): certificates,
    /// the account, leases and challenge answers are shared through it instead of
    /// `acme.storage`.
    pub cluster: Option<ClusterAcme>,
}

/// Handle to the manager task.
#[derive(Debug)]
pub struct Manager {
    plans: watch::Sender<Option<Arc<Plan>>>,
    status: Arc<Mutex<Vec<CertStatus>>>,
    renewals: tokio::sync::mpsc::Sender<String>,
}

impl Manager {
    /// Starts the manager.
    #[must_use]
    pub fn spawn(services: Services) -> Self {
        let (plans, rx) = watch::channel(None);
        let (renewals, renew_rx) = tokio::sync::mpsc::channel(16);
        let status = Arc::new(Mutex::new(Vec::new()));
        let worker = Worker {
            services,
            accounts: Accounts::default(),
            certs: BTreeMap::new(),
            lock: None,
            status: status.clone(),
            holder: String::new(),
        };
        tokio::spawn(worker.run(rx, renew_rx));
        Self {
            plans,
            status,
            renewals,
        }
    }

    /// Asks for the certificate that covers `name` to be renewed now, within the usual
    /// back-off after failures. Returns `false` when no automatic certificate covers it.
    pub fn renew(&self, name: &str) -> bool {
        let known = self
            .status()
            .iter()
            .any(|s| s.names.iter().any(|n| n == name));
        known && self.renewals.try_send(name.to_owned()).is_ok()
    }

    /// Replaces the plan; the manager starts working on it at once. An unchanged plan is
    /// ignored.
    pub fn update(&self, mut plan: Plan) {
        // Two requests with one first name would share a store entry and a lease.
        plan.requests = CertRequest::merge_shared_first_names(std::mem::take(&mut plan.requests));
        self.plans.send_if_modified(|current| {
            if current.as_deref() == Some(&plan) {
                return false;
            }
            *current = Some(Arc::new(plan));
            true
        });
    }

    /// The state of every automatic certificate.
    #[must_use]
    pub fn status(&self) -> Vec<CertStatus> {
        self.status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

struct Worker {
    services: Services,
    accounts: Accounts,
    certs: BTreeMap<Vec<String>, CertState>,
    lock: Option<StorageLock>,
    status: Arc<Mutex<Vec<CertStatus>>>,
    /// The holder name in leases: the cluster instance, or `local-<pid>`.
    holder: String,
}

/// How one certificate's turn ended.
enum Outcome {
    /// This instance issued and stored it.
    Issued(StoredCert),
    /// Another instance had stored a current one; it is used instead.
    Adopted(StoredCert),
    /// Another instance holds the lease and is working on it.
    Busy(String),
    /// The attempt failed.
    Failed(String),
}

impl Worker {
    async fn run(
        mut self,
        mut plans: watch::Receiver<Option<Arc<Plan>>>,
        mut renewals: tokio::sync::mpsc::Receiver<String>,
    ) {
        self.holder = self.services.cluster.as_ref().map_or_else(
            || format!("local-{}", std::process::id()),
            ClusterAcme::lease_holder,
        );
        if let Some(cluster) = &self.services.cluster {
            cluster.start_replication(self.services.challenges.clone());
        }
        loop {
            let plan = plans.borrow_and_update().clone();
            let wake = match &plan {
                Some(plan) => self.step(plan).await,
                None => Instant::now() + MAX_SLEEP,
            };
            tokio::select! {
                changed = plans.changed() => if changed.is_err() { return },
                Some(name) = renewals.recv() => {
                    for (names, state) in &mut self.certs {
                        if names.contains(&name) {
                            state.renewal_requested = Some(Instant::now());
                            tracing::info!(certificate = %name, "renewal requested through the admin API");
                        }
                    }
                }
                () = tokio::time::sleep_until(wake.into()) => {}
            }
        }
    }

    fn storage(&self, plan: &Plan) -> Storage {
        match &self.services.cluster {
            Some(cluster) => Storage::cluster(cluster.store.clone()),
            None => Storage::new(
                plan.acme
                    .storage
                    .clone()
                    .unwrap_or_else(|| self.services.default_storage.clone()),
            ),
        }
    }

    fn lease_ttl(&self) -> Duration {
        self.services
            .cluster
            .as_ref()
            .map_or(LOCAL_LEASE, |c| c.lease_ttl)
    }

    /// Loads, checks, issues and publishes what `plan` needs; returns when to look again.
    async fn step(&mut self, plan: &Plan) -> Instant {
        let next_look = Instant::now() + MAX_SLEEP;
        let storage = self.storage(plan);
        if plan.requests.is_empty() {
            self.certs.clear();
            self.lock = None;
            self.publish();
            return next_look;
        }
        if storage.is_local() && !self.hold_lock(&storage) {
            return next_look;
        }
        self.load(plan, &storage).await;
        self.check_renewal_info(plan, &storage).await;
        let now = unix_now();
        let due: Vec<CertRequest> = plan
            .requests
            .iter()
            .filter(|r| self.certs.get(&r.names).is_some_and(|s| s.due(now)))
            .cloned()
            .collect();
        if !due.is_empty() {
            self.issue_all(plan, &storage, due).await;
            self.publish();
        }
        self.alert();
        let now = unix_now();
        self.certs
            .values()
            .map(|s| s.wake_at(now))
            .fold(next_look, Instant::min)
    }

    /// Forgets certificates no longer asked for and (re)loads stored ones whenever their
    /// metadata changed: the first time, and after another instance stored a new one.
    async fn load(&mut self, plan: &Plan, storage: &Storage) {
        self.certs
            .retain(|names, _| plan.requests.iter().any(|r| &r.names == names));
        for request in &plan.requests {
            let Some(first) = request.names.first() else {
                continue;
            };
            let version = match storage.meta_version(first).await {
                Ok(version) => version,
                Err(e) => {
                    warn!(names = ?request.names, error = %e, "cannot read the certificate store");
                    continue;
                }
            };
            let state = self.certs.entry(request.names.clone()).or_default();
            if state.loaded_from_disk && state.meta_version == version {
                continue;
            }
            state.loaded_from_disk = true;
            state.meta_version = version;
            if version == 0 {
                continue;
            }
            match storage.load_cert(first).await {
                Ok(Some(stored)) if stored.meta.names == request.names => {
                    let same = state
                        .cert
                        .as_ref()
                        .is_some_and(|c| c.key.cert.first() == stored.cert.key.cert.first());
                    if !same {
                        if state.cert.is_some() {
                            info!(names = ?request.names, by = ?stored.meta.issued_by, "using the certificate another instance stored");
                        }
                        state.set_cert(stored.cert.clone());
                    }
                    state.adopt_meta(&stored.meta);
                }
                Ok(Some(_)) => {}
                Ok(None) => state.meta_version = 0,
                Err(e) => {
                    warn!(names = ?request.names, error = %e, "ignoring an unreadable stored certificate");
                }
            }
        }
        self.publish();
    }

    /// Takes or refreshes the storage lock; false while another process holds it.
    fn hold_lock(&mut self, storage: &Storage) -> bool {
        if let Some(lock) = &self.lock
            && lock.refresh().is_ok()
        {
            return true;
        }
        self.lock = None;
        match storage.lock() {
            Ok(Some(lock)) => {
                self.lock = Some(lock);
                true
            }
            Ok(None) => {
                warn!("another rdock process holds the ACME storage lock; waiting for it");
                false
            }
            Err(e) => {
                warn!(error = %e, "cannot take the ACME storage lock");
                false
            }
        }
    }

    /// Fetches the CA's suggested renewal window for certificates whose check is due. The
    /// moment chosen inside a window is stored with the certificate, so every instance of a
    /// cluster uses the one that was chosen first.
    async fn check_renewal_info(&mut self, plan: &Plan, storage: &Storage) {
        if !self.certs.values().any(CertState::wants_ari) {
            return;
        }
        let Ok(account) = self.accounts.get(&plan.acme, storage, &self.holder).await else {
            return;
        };
        for (names, state) in self.certs.iter_mut().filter(|(_, s)| s.wants_ari()) {
            let Some(id) = &state.cert_id else { continue };
            match account.renewal_info(id).await {
                Ok((info, retry_after)) => {
                    let window = info.suggested_window;
                    let (start, end) = (window.start.unix_timestamp(), window.end.unix_timestamp());
                    state.apply_window(start, end, retry_after, spread());
                    if let Some(first) = names.first() {
                        share_window(storage, first, state, start, end, &self.holder).await;
                    }
                }
                Err(instant_acme::Error::Unsupported(_)) => state.ari_failed(true),
                Err(e) => {
                    warn!(error = %e, "cannot fetch ACME renewal information; using the certificate lifetime meanwhile");
                    state.ari_failed(false);
                }
            }
        }
    }

    async fn issue_all(&mut self, plan: &Plan, storage: &Storage, due: Vec<CertRequest>) {
        let types = plan.challenge_types();
        let (due, unusable): (Vec<CertRequest>, Vec<CertRequest>) = due
            .into_iter()
            .partition(|r| r.dns_provider.is_some() || !types.is_empty());
        for request in unusable {
            let why = "no usable challenge: http-01 needs a plain-HTTP listener, tls-alpn-01 a TLS listener, each listed in acme.challenges";
            self.failed(&request.names, why.to_owned());
        }
        if due.is_empty() {
            return;
        }
        let account = match self.accounts.get(&plan.acme, storage, &self.holder).await {
            Ok(account) => account,
            Err(crate::account::AccountError::Busy) => return,
            Err(e) => {
                for request in &due {
                    self.failed(&request.names, format!("ACME account: {e}"));
                }
                return;
            }
        };
        let directory = directory_url(&plan.acme).unwrap_or_default();
        let staging = self.staging_account(plan, storage, &directory).await;
        let dns = self.dns_challenges(plan, &due);
        let profile = choose_profile(&account, plan.acme.profile);
        let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_ORDERS));
        let mut orders = JoinSet::new();
        for request in due {
            let state = self.certs.get(&request.names);
            let dns = request
                .dns_provider
                .as_ref()
                .and_then(|name| dns.get(name).cloned());
            let job = Job {
                types: if request.dns_provider.is_some() {
                    vec![ChallengeType::Dns01]
                } else {
                    rotated(&types, state.map_or(0, |s| s.failures))
                },
                dns,
                replaces: state
                    .filter(|s| s.ari_known)
                    .and_then(|s| s.cert_id.clone()),
                // After a failure against Let's Encrypt, prove the setup on staging first.
                staging: staging
                    .clone()
                    .filter(|_| state.is_some_and(|s| s.failures > 0)),
                profile: profile.clone(),
                account: account.clone(),
                answers: self.answer_sinks(),
                limit: limit.clone(),
                storage: storage.clone(),
                holder: self.holder.clone(),
                lease_ttl: self.lease_ttl(),
                directory: directory.clone(),
                known_version: state.map_or(0, |s| s.meta_version),
                forced: state.is_some_and(|s| s.renewal_requested.is_some()),
                metrics: self.services.metrics.clone(),
            };
            orders.spawn(async move {
                let result = job.run(&request.names).await;
                (request, result)
            });
        }
        let ca = host_of(&directory);
        while let Some(joined) = orders.join_next().await {
            let Ok((request, outcome)) = joined else {
                continue;
            };
            let label = match &outcome {
                Outcome::Issued(_) => Some("issued"),
                Outcome::Failed(_) => Some("failed"),
                Outcome::Adopted(_) | Outcome::Busy(_) => None,
            };
            if let Some(label) = label {
                self.services
                    .metrics
                    .acme_orders
                    .with_label_values(&[ca.as_str(), label])
                    .inc();
            }
            match outcome {
                Outcome::Issued(stored) | Outcome::Adopted(stored) => {
                    info!(names = ?request.names, not_after = stored.cert.not_after, by = ?stored.meta.issued_by, "certificate issued");
                    let state = self.certs.entry(request.names.clone()).or_default();
                    state.set_cert(stored.cert);
                    state.adopt_meta(&stored.meta);
                    state.meta_version = stored.version;
                }
                Outcome::Busy(holder) => {
                    let state = self.certs.entry(request.names.clone()).or_default();
                    state.wait_for(&holder, BUSY_RECHECK);
                }
                Outcome::Failed(e) => self.failed(&request.names, e),
            }
        }
    }

    /// Where this instance's orders publish challenge answers.
    fn answer_sinks(&self) -> Sinks {
        Sinks {
            cluster: self.services.cluster.clone(),
            challenges: self.services.challenges.clone(),
        }
    }

    /// A DNS-01 solver for every provider the due requests name. A provider that cannot be
    /// built fails its requests when they run.
    fn dns_challenges(&self, plan: &Plan, due: &[CertRequest]) -> BTreeMap<String, DnsChallenge> {
        let lookup = if plan.acme.dns_resolvers.is_empty() {
            Lookup::Authoritative
        } else {
            Lookup::Resolvers(
                plan.acme
                    .dns_resolvers
                    .iter()
                    .filter_map(|r| rdock_model::acme::parse_resolver(r))
                    .collect(),
            )
        };
        let mut built = BTreeMap::new();
        for name in due.iter().filter_map(|r| r.dns_provider.as_ref()) {
            if built.contains_key(name) {
                continue;
            }
            let Some(config) = plan.acme.dns_providers.get(name) else {
                continue;
            };
            match self.services.dns.build(config) {
                Ok(solver) => {
                    built.insert(
                        name.clone(),
                        DnsChallenge {
                            solver,
                            lookup: lookup.clone(),
                            timeout: plan.acme.dns_propagation_timeout.as_std(),
                        },
                    );
                }
                Err(e) => warn!(provider = %name, error = %e, "cannot use the DNS provider"),
            }
        }
        built
    }

    /// The Let's Encrypt staging account, when the configured CA is Let's Encrypt production.
    async fn staging_account(
        &mut self,
        plan: &Plan,
        storage: &Storage,
        directory: &str,
    ) -> Option<Account> {
        staging_for(directory)?;
        if !self.certs.values().any(|s| s.failures > 0) {
            return None;
        }
        let mut acme = plan.acme.clone();
        acme.staging = true;
        self.accounts.get(&acme, storage, &self.holder).await.ok()
    }

    fn failed(&mut self, names: &[String], error: String) {
        warn!(names = ?names, error = %error, "certificate order failed");
        let name = names.first().map_or("", String::as_str);
        self.services
            .metrics
            .cert_renewal_failures
            .with_label_values(&[name])
            .inc();
        self.certs.entry(names.to_vec()).or_default().fail(error);
    }

    /// Serves every certificate the manager holds and updates metrics and status.
    fn publish(&self) {
        let certs: Vec<LoadedCert> = self.certs.values().filter_map(|s| s.cert.clone()).collect();
        for cert in &certs {
            self.services
                .metrics
                .cert_expiry
                .with_label_values(&[&cert.name])
                .set(cert.not_after);
        }
        self.services
            .resolver
            .swap_managed(CertIndex::build(&certs, None));
        let status = self
            .certs
            .iter()
            .map(|(names, state)| state.status(names))
            .collect();
        *self.status.lock().unwrap_or_else(PoisonError::into_inner) = status;
    }

    /// Reports certificates that keep failing or are about to expire.
    fn alert(&mut self) {
        let now = unix_now();
        let alerts: Vec<(Vec<String>, serde_json::Value)> = self
            .certs
            .iter()
            .filter_map(|(names, state)| {
                crate::alerts::due(state, names, now).map(|a| (names.clone(), a))
            })
            .collect();
        for (names, alert) in alerts {
            warn!(names = ?names, alert = %alert, "certificate alert");
            let summary = match alert["event"].as_str() {
                Some("certificate_renewal_failing") => format!(
                    "Renewal of the certificate for {} keeps failing: {}",
                    names.join(", "),
                    alert["error"].as_str().unwrap_or("unknown error")
                ),
                _ => format!(
                    "The certificate for {} expires within 7 days",
                    names.join(", ")
                ),
            };
            self.services
                .metrics
                .feeds
                .alerts
                .raise(rdock_observability::alerts::Alert::firing(
                    rdock_model::settings::AlertRule::Certificates,
                    format!("certificate:{}", names.join(",")),
                    summary,
                    alert,
                ));
            if let Some(state) = self.certs.get_mut(&names) {
                crate::alerts::sent(state);
            }
        }
        self.publish();
    }
}

/// Stores the renewal moment chosen inside a window with the certificate, unless another
/// instance chose one for the same window first: then that one is used. The write is made
/// under the certificate's lease, like every write of a certificate's files (a control plane's
/// store refuses it otherwise); while another instance holds the lease the moment is not
/// shared this time.
async fn share_window(
    storage: &Storage,
    first: &str,
    state: &mut CertState,
    start: i64,
    end: i64,
    holder: &str,
) {
    if state.ari_renew_at.is_none() {
        return;
    }
    let store = storage.store().clone();
    let lease = match store
        .acquire(&cert_lease(first), holder, Duration::from_secs(30))
        .await
    {
        Ok(Some(lease)) => lease,
        Ok(None) => return,
        Err(e) => {
            warn!(certificate = %first, error = %e, "cannot share the renewal time");
            return;
        }
    };
    share_window_under(storage, first, state, start, end, &lease).await;
    if let Err(e) = store.release(&lease).await {
        warn!(certificate = %first, error = %e, "cannot release the certificate lease");
    }
}

async fn share_window_under(
    storage: &Storage,
    first: &str,
    state: &mut CertState,
    start: i64,
    end: i64,
    lease: &Lease,
) {
    let Some(mine) = state.ari_renew_at else {
        return;
    };
    for _ in 0..3 {
        let Ok(Some(stored)) = storage.load_cert(first).await else {
            return;
        };
        let ours = state
            .cert
            .as_ref()
            .is_some_and(|c| c.key.cert.first() == stored.cert.key.cert.first());
        if !ours {
            return;
        }
        if let Some(window) = stored.meta.ari
            && window.start == start
            && window.end == end
        {
            state.ari_renew_at = Some(window.renew_at);
            state.meta_version = stored.version;
            return;
        }
        let mut meta = stored.meta.clone();
        meta.ari = Some(AriWindow {
            start,
            end,
            renew_at: mine,
        });
        match storage
            .save_meta(first, &meta, stored.version, Some(lease))
            .await
        {
            Ok(version) => {
                state.meta_version = version;
                return;
            }
            Err(StorageError::Store(StoreError::Conflict { .. })) => {}
            Err(e) => {
                warn!(certificate = %first, error = %e, "cannot share the renewal time");
                return;
            }
        }
    }
}

/// Renews `lease` every third of `ttl` until dropped; `lost` turns true when a renewal fails.
struct LeaseKeeper {
    task: tokio::task::JoinHandle<()>,
    lost: watch::Receiver<bool>,
}

impl LeaseKeeper {
    fn start(store: Arc<dyn ClusterStore>, lease: Lease, ttl: Duration) -> Self {
        let (tx, lost) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut current = lease;
            loop {
                tokio::time::sleep(ttl / 3).await;
                match store.renew(&current, ttl).await {
                    Ok(renewed) => current = renewed,
                    Err(StoreError::Unavailable(e)) => {
                        warn!(lease = %current.name, error = %e, "cannot renew the certificate lease; trying again");
                    }
                    Err(e) => {
                        warn!(lease = %current.name, error = %e, "lost the certificate lease");
                        let _ = tx.send(true);
                        return;
                    }
                }
            }
        });
        Self { task, lost }
    }

    fn lost(&self) -> bool {
        *self.lost.borrow()
    }
}

impl Drop for LeaseKeeper {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Makes the answer sink of an order once its lease is held.
struct Sinks {
    cluster: Option<ClusterAcme>,
    challenges: Arc<Challenges>,
}

impl Sinks {
    fn sink(&self, lease: &Lease) -> Arc<dyn AnswerSink> {
        match &self.cluster {
            Some(cluster) => cluster.answers(self.challenges.clone(), lease.clone()),
            None => Arc::new(crate::issue::LocalAnswers::new(self.challenges.clone())),
        }
    }
}

/// One order, run on its own task.
struct Job {
    types: Vec<ChallengeType>,
    dns: Option<DnsChallenge>,
    replaces: Option<instant_acme::CertificateIdentifier<'static>>,
    staging: Option<Account>,
    profile: Option<String>,
    account: Account,
    answers: Sinks,
    limit: Arc<Semaphore>,
    storage: Storage,
    holder: String,
    lease_ttl: Duration,
    directory: String,
    /// The version of the stored metadata this instance last loaded (`0`: none).
    known_version: u64,
    /// Renewal was asked for through the admin API.
    forced: bool,
    metrics: Metrics,
}

impl Job {
    /// Takes the lease on the name, re-checks the store, resumes a journalled order or orders,
    /// stores the certificate and gives the lease up (ADR-0031).
    async fn run(self, names: &[String]) -> Outcome {
        let _permit = self.limit.clone().acquire_owned().await;
        let Some(first) = names.first() else {
            return Outcome::Failed("a certificate without names".to_owned());
        };
        let store = self.storage.store().clone();
        let lease_name = cert_lease(first);
        let count = |result: &str| {
            self.metrics
                .cluster_leases
                .with_label_values(&[result])
                .inc();
        };
        let lease = match store
            .acquire(&lease_name, &self.holder, self.lease_ttl)
            .await
        {
            Ok(Some(lease)) => {
                count("acquired");
                lease
            }
            Ok(None) => {
                count("busy");
                let holder = store
                    .lease(&lease_name)
                    .await
                    .ok()
                    .flatten()
                    .map_or_else(|| "another instance".to_owned(), |l| l.holder);
                return Outcome::Busy(holder);
            }
            Err(e) => {
                count("error");
                return Outcome::Failed(format!("cannot take the certificate lease: {e}"));
            }
        };
        let keeper = LeaseKeeper::start(store.clone(), lease.clone(), self.lease_ttl);
        if let Some(cluster) = &self.answers.cluster {
            // What an earlier holder of this name left is withdrawn first (review finding M2).
            cluster.withdraw_leftovers(&lease).await;
        }
        let answers = self.answers.sink(&lease);
        let outcome = self
            .under_lease(names, first, &lease, &keeper, &answers)
            .await;
        if keeper.lost() {
            count("lost");
        }
        drop(keeper);
        if let Err(e) = store.release(&lease).await {
            warn!(lease = %lease_name, error = %e, "cannot release the certificate lease");
        }
        outcome
    }

    async fn under_lease(
        &self,
        names: &[String],
        first: &str,
        lease: &Lease,
        keeper: &LeaseKeeper,
        answers: &Arc<dyn AnswerSink>,
    ) -> Outcome {
        // Someone may have stored a certificate while this instance waited for the lease. The
        // compare-and-swap below is against the version of `meta.json` read here, whatever it
        // describes (other names, a chain stored nowhere): such a file is replaced, never a
        // reason to fail (review finding H1).
        let (meta_version, stored) = match self.storage.read_cert(first).await {
            Ok((version, stored)) => (version, stored.filter(|s| s.meta.names == names)),
            Err(e) => return Outcome::Failed(format!("cannot read the certificate store: {e}")),
        };
        if let Some(stored) = stored {
            // Another instance stored a certificate this one has not loaded, or the stored one
            // is not due by the shared renewal time: use it. Only an operator's renewal of the
            // very certificate this instance holds goes ahead.
            let newer = stored.version != self.known_version;
            let current = !stored_due(&stored, unix_now());
            if current && (newer || !self.forced) {
                return Outcome::Adopted(stored);
            }
        }
        if let Some(staging) = &self.staging {
            let rehearsal = OrderSpec {
                names,
                profile: None,
                challenge_types: &self.types,
                replaces: None,
                dns: self.dns.as_ref(),
            };
            let challenges = answers.clone();
            let key = match KeyPair::generate() {
                Ok(key) => key,
                Err(e) => return Outcome::Failed(e.to_string()),
            };
            let result = async {
                let mut order = new_order(staging, rehearsal).await?;
                complete(&mut order, rehearsal, challenges.as_ref(), &key).await
            }
            .await;
            if let Err(e) = result {
                return Outcome::Failed(e.to_string());
            }
            info!(names = ?names, "staging order succeeded; ordering from production");
        }
        let spec = OrderSpec {
            names,
            profile: self.profile.as_deref(),
            challenge_types: &self.types,
            replaces: self.replaces.as_ref(),
            dns: self.dns.as_ref(),
        };
        let (chain_pem, key_pem) = match self.order(names, first, spec, lease, answers).await {
            Ok(issued) => issued,
            Err(e) => return Outcome::Failed(e),
        };
        if keeper.lost() {
            return Outcome::Failed("lost the certificate lease before storing the certificate; the order stays journalled for the next holder".to_owned());
        }
        let meta = issued_meta(
            names,
            &self.directory,
            self.profile.clone(),
            &chain_pem,
            &self.holder,
        );
        match self
            .storage
            .save_cert(
                first,
                &chain_pem,
                &key_pem,
                &meta,
                meta_version,
                Some(lease),
            )
            .await
        {
            Ok(_) => {}
            Err(StorageError::Store(StoreError::Conflict { .. })) => {
                // Only possible when the store's fencing is best effort: another writer won.
                if let Ok(Some(stored)) = self.storage.load_cert(first).await
                    && stored.meta.names == names
                {
                    return Outcome::Adopted(stored);
                }
                return Outcome::Failed(
                    "another instance stored the certificate at the same time".to_owned(),
                );
            }
            Err(e) => return Outcome::Failed(format!("cannot store the certificate: {e}")),
        }
        if let Err(e) = self.storage.delete_order(first, Some(lease)).await {
            warn!(names = ?names, error = %e, "cannot remove the order journal");
        }
        match self.storage.load_cert(first).await {
            Ok(Some(stored)) => Outcome::Issued(stored),
            Ok(None) => {
                Outcome::Failed("the certificate is missing after it was stored".to_owned())
            }
            Err(e) => Outcome::Failed(format!("cannot read the stored certificate: {e}")),
        }
    }

    /// Finishes the journalled order if there is one the CA still knows, else creates an order
    /// and journals it before answering any challenge. Returns the chain and the key.
    async fn order(
        &self,
        names: &[String],
        first: &str,
        spec: OrderSpec<'_>,
        lease: &Lease,
        answers: &Arc<dyn AnswerSink>,
    ) -> Result<(String, String), String> {
        match self.storage.load_order(first).await {
            Ok(Some(journal)) if journal.directory == self.directory && journal.names == names => {
                match self.resume(&journal, spec, answers.as_ref()).await {
                    Resumed::Done(chain) => return Ok((chain, journal.key_pem)),
                    Resumed::Retry(e) => return Err(e),
                    Resumed::Abandon(reason) => {
                        info!(names = ?names, url = %journal.url, %reason, "abandoning the journalled order");
                        self.storage
                            .delete_order(first, Some(lease))
                            .await
                            .map_err(|e| format!("cannot remove the order journal: {e}"))?;
                    }
                }
            }
            Ok(Some(_)) => {
                self.storage
                    .delete_order(first, Some(lease))
                    .await
                    .map_err(|e| format!("cannot remove the order journal: {e}"))?;
            }
            Ok(None) => {}
            Err(e) => return Err(format!("cannot read the order journal: {e}")),
        }
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut order = new_order(&self.account, spec)
            .await
            .map_err(|e| e.to_string())?;
        let journal = OrderJournal {
            url: order.url().to_owned(),
            directory: self.directory.clone(),
            names: names.to_vec(),
            key_pem: key.serialize_pem(),
            created_by: self.holder.clone(),
            created_at: unix_now(),
        };
        self.storage
            .save_order(first, &journal, Some(lease))
            .await
            .map_err(|e| format!("cannot journal the order: {e}"))?;
        match complete(&mut order, spec, answers.as_ref(), &key).await {
            Ok(chain) => Ok((chain, journal.key_pem)),
            Err(e @ IssueError::Invalid(_)) => {
                let _ = self.storage.delete_order(first, Some(lease)).await;
                Err(e.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    async fn resume(
        &self,
        journal: &OrderJournal,
        spec: OrderSpec<'_>,
        answers: &dyn AnswerSink,
    ) -> Resumed {
        let key = match KeyPair::from_pem(&journal.key_pem) {
            Ok(key) => key,
            Err(e) => return Resumed::Abandon(format!("the journalled key is unusable: {e}")),
        };
        let mut order = match self.account.order(journal.url.clone()).await {
            Ok(order) => order,
            Err(instant_acme::Error::Api(problem)) => {
                return Resumed::Abandon(format!("the CA no longer has it: {problem}"));
            }
            Err(e) => return Resumed::Retry(format!("cannot fetch the journalled order: {e}")),
        };
        info!(names = ?journal.names, url = %journal.url, by = %journal.created_by, "resuming the journalled order");
        match complete(&mut order, spec, answers, &key).await {
            Ok(chain) => Resumed::Done(chain),
            Err(IssueError::Invalid(reason)) => Resumed::Abandon(reason),
            Err(e) => Resumed::Retry(e.to_string()),
        }
    }
}

/// How finishing a journalled order went.
enum Resumed {
    Done(String),
    /// A failure worth trying again with the same order.
    Retry(String),
    /// The order cannot be finished; a new one is created.
    Abandon(String),
}

/// Whether a stored certificate is due for renewal by its shared metadata: the chosen moment in
/// the CA's window, else a third of its lifetime before expiry.
fn stored_due(stored: &StoredCert, now: i64) -> bool {
    let renew_at = stored.meta.ari.map_or_else(
        || {
            let lifetime = stored.cert.not_after - stored.cert.not_before;
            stored.cert.not_after - lifetime / 3
        },
        |w| w.renew_at,
    );
    now >= renew_at
}

/// The metadata of a certificate this instance just issued.
fn issued_meta(
    names: &[String],
    directory: &str,
    profile: Option<String>,
    chain_pem: &str,
    holder: &str,
) -> CertMeta {
    let mut meta = CertMeta {
        names: names.to_vec(),
        directory: directory.to_owned(),
        profile,
        issued_by: Some(holder.to_owned()),
        issued_at: Some(unix_now()),
        ..CertMeta::default()
    };
    if let Some(der) = rustls_pki_types::CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()
        .and_then(Result::ok)
        && let Ok((_, leaf)) = x509_parser::parse_x509_certificate(der.as_ref())
    {
        meta.issuer = Some(leaf.issuer().to_string());
        meta.serial = Some(leaf.raw_serial_as_string().replace(':', ""));
        meta.not_before = Some(leaf.validity().not_before.timestamp());
        meta.not_after = Some(leaf.validity().not_after.timestamp());
    }
    meta
}
/// After a failure the next attempt starts with the next challenge type (ADR-0020).
fn rotated(types: &[ChallengeType], failures: u32) -> Vec<ChallengeType> {
    let mut types = types.to_vec();
    if !types.is_empty() {
        let shift = usize::try_from(failures).unwrap_or(0) % types.len();
        types.rotate_left(shift);
    }
    types
}

/// The host of a directory URL, as the `ca` metric label.
fn host_of(directory: &str) -> String {
    directory
        .trim_start_matches("https://")
        .split(['/', ':'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_moves_to_the_next_challenge() {
        let types = [ChallengeType::Http01, ChallengeType::TlsAlpn01];
        assert_eq!(rotated(&types, 0), types);
        assert_eq!(
            rotated(&types, 1),
            [ChallengeType::TlsAlpn01, ChallengeType::Http01]
        );
        assert_eq!(rotated(&types, 2), types);
        assert_eq!(rotated(&[], 3), []);
    }

    #[test]
    fn labels_orders_by_ca_host() {
        assert_eq!(
            host_of("https://acme-v02.api.letsencrypt.org/directory"),
            "acme-v02.api.letsencrypt.org"
        );
        assert_eq!(host_of("https://localhost:14000/dir"), "localhost");
    }
}
