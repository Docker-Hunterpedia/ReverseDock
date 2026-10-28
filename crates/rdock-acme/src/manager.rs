//! The certificate manager: a background task that keeps a certificate for every requested set
//! of names, and publishes them to the data plane's resolver (ADR-0020). The data plane never
//! waits for it.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use instant_acme::{Account, ExternalAccountKey, NewAccount};
use rdock_model::acme::{Acme, AcmeProfile, Challenge};
use rdock_tls::{CertIndex, CertRequest, Challenges, LoadedCert, SniResolver};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::directory::directory_url;
use crate::issue::issue;
use crate::storage::{CertMeta, Storage, StorageLock};

/// Orders running at once against one CA.
const MAX_CONCURRENT_ORDERS: usize = 4;
/// The longest the task sleeps; it also refreshes the storage lock this often.
const MAX_SLEEP: Duration = Duration::from_secs(10);
/// Backoff after the first failure, doubled after each further one.
const FIRST_RETRY: Duration = Duration::from_secs(60);
/// Longest backoff between attempts.
const MAX_RETRY: Duration = Duration::from_secs(24 * 3600);

/// What the configuration asks of the manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// ACME settings in effect.
    pub acme: Acme,
    /// Certificates to keep.
    pub requests: Vec<CertRequest>,
    /// Whether a plain-HTTP listener can answer HTTP-01 challenges.
    pub http01: bool,
}

/// Handle to the manager task.
#[derive(Debug)]
pub struct Manager {
    plans: watch::Sender<Option<Arc<Plan>>>,
}

impl Manager {
    /// Starts the manager. `default_storage` is used unless `acme.storage` is set; issued
    /// certificates go to `resolver`, HTTP-01 answers to `challenges`.
    #[must_use]
    pub fn spawn(
        default_storage: PathBuf,
        resolver: Arc<SniResolver>,
        challenges: Arc<Challenges>,
    ) -> Self {
        let (plans, rx) = watch::channel(None);
        let worker = Worker {
            default_storage,
            resolver,
            challenges,
            accounts: HashMap::new(),
            certs: BTreeMap::new(),
            lock: None,
        };
        tokio::spawn(worker.run(rx));
        Self { plans }
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
}

/// What the manager knows about one requested certificate.
#[derive(Debug, Default)]
struct CertState {
    cert: Option<LoadedCert>,
    loaded_from_disk: bool,
    failures: u32,
    retry_at: Option<Instant>,
}

impl CertState {
    /// When the certificate should be renewed: with a third of its lifetime left.
    fn renew_at(&self) -> Option<i64> {
        let cert = self.cert.as_ref()?;
        let lifetime = cert.not_after - cert.not_before;
        Some(cert.not_after - lifetime / 3)
    }

    fn due(&self, now: i64) -> bool {
        let waiting = self.retry_at.is_some_and(|at| at > Instant::now());
        !waiting && self.renew_at().is_none_or(|at| now >= at)
    }

    /// When this certificate next needs attention.
    fn wake_at(&self, now: i64) -> Instant {
        if let Some(at) = self.retry_at {
            return at;
        }
        let secs = self.renew_at().map_or(0, |at| at - now);
        Instant::now() + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
    }
}

struct Worker {
    default_storage: PathBuf,
    resolver: Arc<SniResolver>,
    challenges: Arc<Challenges>,
    accounts: HashMap<String, Account>,
    certs: BTreeMap<Vec<String>, CertState>,
    lock: Option<StorageLock>,
}

impl Worker {
    async fn run(mut self, mut plans: watch::Receiver<Option<Arc<Plan>>>) {
        loop {
            let plan = plans.borrow_and_update().clone();
            let wake = match &plan {
                Some(plan) => self.step(plan).await,
                None => Instant::now() + MAX_SLEEP,
            };
            tokio::select! {
                changed = plans.changed() => if changed.is_err() { return },
                () = tokio::time::sleep_until(wake.into()) => {}
            }
        }
    }

    /// Loads, issues and publishes what `plan` needs; returns when to look again.
    async fn step(&mut self, plan: &Plan) -> Instant {
        let next_look = Instant::now() + MAX_SLEEP;
        let storage = Storage::new(
            plan.acme
                .storage
                .clone()
                .unwrap_or_else(|| self.default_storage.clone()),
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
        let now = unix_now();
        self.certs
            .retain(|names, _| plan.requests.iter().any(|r| &r.names == names));
        for request in &plan.requests {
            let state = self.certs.entry(request.names.clone()).or_default();
            if !state.loaded_from_disk {
                state.loaded_from_disk = true;
                state.cert = load_stored(&storage, &request.names);
            }
        }
        self.publish();
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
        let now = unix_now();
        self.certs
            .values()
            .map(|s| s.wake_at(now))
            .fold(next_look, Instant::min)
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

    async fn issue_all(&mut self, plan: &Plan, storage: &Storage, due: Vec<CertRequest>) {
        if !plan.http01 || !plan.acme.challenges.contains(&Challenge::Http01) {
            for request in &due {
                warn!(names = ?request.names, "no usable ACME challenge: HTTP-01 needs a plain-HTTP listener and `http-01` in acme.challenges");
                self.failed(&request.names);
            }
            return;
        }
        let account = match self.account(&plan.acme, storage).await {
            Ok(account) => account,
            Err(e) => {
                warn!(error = %e, "cannot use the ACME account");
                for request in &due {
                    self.failed(&request.names);
                }
                return;
            }
        };
        let profile = choose_profile(&account, plan.acme.profile);
        let directory = directory_url(&plan.acme).unwrap_or_default();
        let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_ORDERS));
        let mut orders = JoinSet::new();
        for request in due {
            let (account, challenges, limit, profile) = (
                account.clone(),
                self.challenges.clone(),
                limit.clone(),
                profile.clone(),
            );
            orders.spawn(async move {
                let _permit = limit.acquire_owned().await;
                let result = issue(&account, &request.names, profile.as_deref(), &challenges).await;
                (request, result)
            });
        }
        while let Some(joined) = orders.join_next().await {
            let Ok((request, result)) = joined else {
                continue;
            };
            match result {
                Ok(issued) => {
                    let meta = CertMeta {
                        names: request.names.clone(),
                        directory: directory.clone(),
                        profile: profile.clone(),
                    };
                    self.store(storage, &request.names, &issued, &meta);
                }
                Err(e) => {
                    warn!(names = ?request.names, error = %e, "certificate order failed");
                    self.failed(&request.names);
                }
            }
        }
    }

    fn store(
        &mut self,
        storage: &Storage,
        names: &[String],
        issued: &crate::Issued,
        meta: &CertMeta,
    ) {
        let first = names.first().map_or("", String::as_str);
        let saved = storage
            .save_cert(first, &issued.chain_pem, &issued.key_pem, meta)
            .and_then(|()| {
                storage
                    .load_cert(first)
                    .and_then(|c| c.ok_or_else(|| std::io::Error::other("missing after write")))
            });
        let state = self.certs.entry(names.to_vec()).or_default();
        match saved {
            Ok((cert, _)) => {
                info!(names = ?names, not_after = cert.not_after, "certificate issued");
                *state = CertState {
                    cert: Some(cert),
                    loaded_from_disk: true,
                    ..CertState::default()
                };
            }
            Err(e) => {
                warn!(names = ?names, error = %e, "cannot store the issued certificate");
                self.failed(names);
            }
        }
    }

    fn failed(&mut self, names: &[String]) {
        let state = self.certs.entry(names.to_vec()).or_default();
        state.failures += 1;
        state.retry_at = Some(Instant::now() + backoff(state.failures));
    }

    /// Serves every certificate the manager holds.
    fn publish(&self) {
        let certs: Vec<LoadedCert> = self.certs.values().filter_map(|s| s.cert.clone()).collect();
        self.resolver.swap_managed(CertIndex::build(&certs, None));
    }

    async fn account(&mut self, acme: &Acme, storage: &Storage) -> Result<Account, AccountError> {
        let directory = directory_url(acme)?;
        if let Some(account) = self.accounts.get(&directory) {
            return Ok(account.clone());
        }
        let builder = match &acme.ca_root {
            Some(root) => Account::builder_with_root(root)?,
            None => Account::builder()?,
        };
        let account = if let Some(credentials) = storage.load_account(&directory)? {
            builder.from_credentials(credentials).await?
        } else {
            let contact = acme.email.as_ref().map(|e| format!("mailto:{e}"));
            let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
            let eab = external_account_key(acme)?;
            let (account, credentials) = builder
                .create(
                    &NewAccount {
                        contact: &contacts,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    directory.clone(),
                    eab.as_ref(),
                )
                .await?;
            storage.save_account(&directory, &credentials)?;
            info!(directory = %directory, "created an ACME account, which accepts the CA's terms of service");
            account
        };
        self.accounts.insert(directory, account.clone());
        Ok(account)
    }
}

/// Why the ACME account cannot be used.
#[derive(Debug, thiserror::Error)]
enum AccountError {
    #[error(transparent)]
    Directory(#[from] crate::directory::DirectoryError),
    #[error(transparent)]
    Acme(#[from] instant_acme::Error),
    #[error("account storage: {0}")]
    Storage(#[from] std::io::Error),
    #[error("acme.eab.hmac_key: {0}")]
    Eab(String),
}

fn external_account_key(acme: &Acme) -> Result<Option<ExternalAccountKey>, AccountError> {
    let Some(eab) = &acme.eab else {
        return Ok(None);
    };
    let encoded = rdock_config::interpolate::expand(&eab.hmac_key, &rdock_config::System)
        .map_err(|e| AccountError::Eab(e.to_string()))?;
    let key = URL_SAFE_NO_PAD
        .decode(encoded.trim().trim_end_matches('='))
        .map_err(|e| AccountError::Eab(format!("not base64url: {e}")))?;
    Ok(Some(ExternalAccountKey::new(eab.key_id.clone(), &key)))
}

/// The profile to order: the configured one, else `tlsserver` when the CA offers it (ADR-0020),
/// else none.
fn choose_profile(account: &Account, configured: Option<AcmeProfile>) -> Option<String> {
    let name = |p: AcmeProfile| match p {
        AcmeProfile::Classic => "classic",
        AcmeProfile::Tlsserver => "tlsserver",
        AcmeProfile::Shortlived => "shortlived",
    };
    match configured {
        Some(profile) => Some(name(profile).to_owned()),
        None => account
            .profiles()
            .any(|p| p.name == "tlsserver")
            .then(|| "tlsserver".to_owned()),
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

/// Exponential backoff with up to 10 % jitter: 1 minute, 2, 4, … at most 24 hours.
fn backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(16);
    let base = FIRST_RETRY.saturating_mul(1 << exponent).min(MAX_RETRY);
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos())
        % 100;
    base + base / 1000 * jitter
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_a_day() {
        assert!(backoff(1) >= FIRST_RETRY && backoff(1) < FIRST_RETRY * 11 / 10);
        assert!(backoff(2) >= FIRST_RETRY * 2);
        assert!(backoff(30) >= MAX_RETRY && backoff(30) <= MAX_RETRY * 11 / 10);
    }

    #[test]
    fn a_missing_certificate_is_due_at_once() {
        let state = CertState::default();
        assert!(state.due(0));
        assert_eq!(state.renew_at(), None);
    }
}
