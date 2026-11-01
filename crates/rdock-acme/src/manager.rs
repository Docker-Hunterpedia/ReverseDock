//! The certificate manager: a background task that keeps a certificate for every requested set
//! of names, and publishes them to the data plane's resolver (ADR-0020). The data plane never
//! waits for it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use instant_acme::{Account, ChallengeType};
use rdock_model::acme::{Acme, Challenge, Webhook};
use rdock_observability::Metrics;
use rdock_tls::{CertIndex, CertRequest, Challenges, LoadedCert, SniResolver};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::account::{Accounts, choose_profile};
use crate::directory::{directory_url, staging_for};
use crate::dns::{DnsProviders, Lookup};
use crate::http::WebhookClient;
use crate::issue::{DnsChallenge, IssueError, Issued, OrderSpec, issue};
use crate::state::{CertState, CertStatus, spread};
use crate::storage::{CertMeta, Storage, StorageLock};

/// Orders running at once against one CA.
const MAX_CONCURRENT_ORDERS: usize = 4;
/// The longest the task sleeps; it also refreshes the storage lock this often.
const MAX_SLEEP: Duration = Duration::from_secs(10);

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
    /// Where alerts go besides the log.
    pub alerts: Option<Webhook>,
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
            webhook: None,
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
    pub fn update(&self, plan: Plan) {
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
    webhook: Option<WebhookClient>,
}

impl Worker {
    async fn run(
        mut self,
        mut plans: watch::Receiver<Option<Arc<Plan>>>,
        mut renewals: tokio::sync::mpsc::Receiver<String>,
    ) {
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

    /// Loads, checks, issues and publishes what `plan` needs; returns when to look again.
    async fn step(&mut self, plan: &Plan) -> Instant {
        let next_look = Instant::now() + MAX_SLEEP;
        let storage = Storage::new(
            plan.acme
                .storage
                .clone()
                .unwrap_or_else(|| self.services.default_storage.clone()),
        );
        if plan.requests.is_empty() {
            self.certs.clear();
            self.lock = None;
            self.publish();
            return next_look;
        }
        if !self.hold_lock(&storage) {
            return next_look;
        }
        self.load(plan, &storage);
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
        self.alert(plan).await;
        let now = unix_now();
        self.certs
            .values()
            .map(|s| s.wake_at(now))
            .fold(next_look, Instant::min)
    }

    /// Forgets certificates no longer asked for and loads stored ones the first time.
    fn load(&mut self, plan: &Plan, storage: &Storage) {
        self.certs
            .retain(|names, _| plan.requests.iter().any(|r| &r.names == names));
        for request in &plan.requests {
            let state = self.certs.entry(request.names.clone()).or_default();
            if !state.loaded_from_disk {
                state.loaded_from_disk = true;
                if let Some(cert) = load_stored(storage, &request.names) {
                    state.set_cert(cert);
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

    /// Fetches the CA's suggested renewal window for certificates whose check is due.
    async fn check_renewal_info(&mut self, plan: &Plan, storage: &Storage) {
        if !self.certs.values().any(CertState::wants_ari) {
            return;
        }
        let Ok(account) = self.accounts.get(&plan.acme, storage).await else {
            return;
        };
        for state in self.certs.values_mut().filter(|s| s.wants_ari()) {
            let Some(id) = &state.cert_id else { continue };
            match account.renewal_info(id).await {
                Ok((info, retry_after)) => {
                    let window = info.suggested_window;
                    state.apply_window(
                        window.start.unix_timestamp(),
                        window.end.unix_timestamp(),
                        retry_after,
                        spread(),
                    );
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
        let account = match self.accounts.get(&plan.acme, storage).await {
            Ok(account) => account,
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
                challenges: self.services.challenges.clone(),
                limit: limit.clone(),
            };
            orders.spawn(async move {
                let result = job.run(&request.names).await;
                (request, result)
            });
        }
        let ca = host_of(&directory);
        while let Some(joined) = orders.join_next().await {
            let Ok((request, result)) = joined else {
                continue;
            };
            let outcome = if result.is_ok() { "issued" } else { "failed" };
            self.services
                .metrics
                .acme_orders
                .with_label_values(&[ca.as_str(), outcome])
                .inc();
            match result {
                Ok(issued) => {
                    let meta = CertMeta {
                        names: request.names.clone(),
                        directory: directory.clone(),
                        profile: profile.clone(),
                    };
                    self.store(storage, &request.names, &issued, &meta);
                }
                Err(e) => self.failed(&request.names, e.to_string()),
            }
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
        self.accounts.get(&acme, storage).await.ok()
    }

    fn store(&mut self, storage: &Storage, names: &[String], issued: &Issued, meta: &CertMeta) {
        let first = names.first().map_or("", String::as_str);
        let saved = storage
            .save_cert(first, &issued.chain_pem, &issued.key_pem, meta)
            .and_then(|()| {
                storage
                    .load_cert(first)
                    .and_then(|c| c.ok_or_else(|| std::io::Error::other("missing after write")))
            });
        match saved {
            Ok((cert, _)) => {
                info!(names = ?names, not_after = cert.not_after, "certificate issued");
                let state = self.certs.entry(names.to_vec()).or_default();
                state.set_cert(cert);
            }
            Err(e) => self.failed(names, format!("cannot store the certificate: {e}")),
        }
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
    async fn alert(&mut self, plan: &Plan) {
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
            if let Some(webhook) = &plan.alerts {
                self.send(webhook, &alert).await;
            }
            if let Some(state) = self.certs.get_mut(&names) {
                crate::alerts::sent(state);
            }
        }
        self.publish();
    }

    async fn send(&mut self, webhook: &Webhook, alert: &serde_json::Value) {
        if self.webhook.is_none() {
            match WebhookClient::new() {
                Ok(client) => self.webhook = Some(client),
                Err(e) => {
                    warn!(error = %e, "cannot create the alert webhook client");
                    return;
                }
            }
        }
        if let Some(client) = &self.webhook
            && let Err(e) = client.post(webhook, alert).await
        {
            warn!(error = %e, "alert webhook failed");
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
    challenges: Arc<Challenges>,
    limit: Arc<Semaphore>,
}

impl Job {
    async fn run(self, names: &[String]) -> Result<Issued, IssueError> {
        let _permit = self.limit.acquire_owned().await;
        if let Some(staging) = &self.staging {
            let rehearsal = OrderSpec {
                names,
                profile: None,
                challenge_types: &self.types,
                replaces: None,
                dns: self.dns.as_ref(),
            };
            issue(staging, rehearsal, &self.challenges).await?;
            info!(names = ?names, "staging order succeeded; ordering from production");
        }
        let spec = OrderSpec {
            names,
            profile: self.profile.as_deref(),
            challenge_types: &self.types,
            replaces: self.replaces.as_ref(),
            dns: self.dns.as_ref(),
        };
        issue(&self.account, spec, &self.challenges).await
    }
}

fn load_stored(storage: &Storage, names: &[String]) -> Option<LoadedCert> {
    let first = names.first()?;
    match storage.load_cert(first) {
        Ok(Some((cert, meta))) if meta.names == names => Some(cert),
        Ok(_) => None,
        Err(e) => {
            warn!(names = ?names, error = %e, "ignoring an unreadable stored certificate");
            None
        }
    }
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
