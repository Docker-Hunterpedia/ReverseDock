//! The control plane's state and operations: tokens, enrolment, the registry, publication and
//! the store, behind one lock. The cluster listener (`server`) and the binary's operator API
//! both call into it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rdock_cluster::protocol::{
    Bundle, EnrollRequest, EnrollResponse, Report, StoreRequest, StoreResponse, Verdict,
};
use rdock_cluster::{ClusterStore, DirStore};
use rdock_credentials::Secret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{info, warn};

use crate::bundles::History;
use crate::ca::ClusterCa;
use crate::registry::{Instance, LastReport, Registry};
use crate::rollout::{self, Refusal, Rollout};
use crate::tokens::{TokenRecord, TokenUse, Tokens};

/// How long the certificate a renewal replaced keeps working, so calls in flight finish.
const RENEWAL_GRACE: i64 = 600;
/// How often the control plane removes left-over records from its store.
const TIDY: Duration = Duration::from_secs(60);
use crate::{Error, unix_now};

/// `<data>/control/cluster.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClusterFile {
    id: String,
    created_at: i64,
}

struct Mutable {
    tokens: Tokens,
    registry: Registry,
    history: History,
    rollout: Rollout,
    /// When each instance last called (Unix seconds); kept in memory, written with reports.
    seen: BTreeMap<String, i64>,
}

/// The control plane.
pub struct ControlPlane {
    settings: rdock_model::cluster::ControlPlane,
    cluster_id: String,
    ca: ClusterCa,
    state: Mutex<Mutable>,
    /// Bumped on every change that can alter which revision an instance is given (a
    /// publication, a rollout step), to wake long polls.
    changes: watch::Sender<u64>,
    /// Rollout events for the audit log: unbounded, so none is ever dropped (they come one or
    /// two per publication; review finding L8).
    events: mpsc::UnboundedSender<rollout::Event>,
    events_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<rollout::Event>>>,
    store: DirStore,
    root: PathBuf,
}

impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane")
            .field("cluster_id", &self.cluster_id)
            .finish_non_exhaustive()
    }
}

/// How an instance stands, in the status words of Envoy's CSDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceState {
    /// Serves the newest revision.
    Synced,
    /// Serves an older revision and has not refused the newest (a running rollout may be
    /// holding it on the stable revision).
    Behind,
    /// Refused the newest revision (NACK).
    Error,
    /// Has not called for longer than `control.offline_after`.
    Offline,
    /// Revoked.
    Revoked,
}

impl InstanceState {
    /// The label value of `rdock_control_instances`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Behind => "behind",
            Self::Error => "error",
            Self::Offline => "offline",
            Self::Revoked => "revoked",
        }
    }
}

impl ControlPlane {
    /// Opens (or creates) the control plane's state in `<data_dir>/control`.
    pub fn open(
        data_dir: &Path,
        settings: rdock_model::cluster::ControlPlane,
    ) -> Result<Arc<Self>, Error> {
        let root = data_dir.join("control");
        rdock_cluster::dir::create_dir(&root)
            .map_err(|e| Error::State(format!("{}: {e}", root.display())))?;
        let cluster_path = root.join("cluster.json");
        let cluster: ClusterFile = match std::fs::read(&cluster_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::State(format!("{}: {e}", cluster_path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = format!(
                    "c{}",
                    rdock_credentials::random_base62(12)
                        .ok_or_else(|| Error::State(
                            "the system random generator failed".to_owned()
                        ))?
                        .to_ascii_lowercase()
                );
                let file = ClusterFile {
                    id,
                    created_at: unix_now(),
                };
                let json =
                    serde_json::to_vec_pretty(&file).map_err(|e| Error::State(e.to_string()))?;
                rdock_cluster::dir::write_private(&cluster_path, &json)
                    .map_err(|e| Error::State(format!("{}: {e}", cluster_path.display())))?;
                info!(cluster = %file.id, "created a new cluster");
                file
            }
            Err(e) => return Err(Error::State(format!("{}: {e}", cluster_path.display()))),
        };
        let ca = ClusterCa::load_or_create(&root.join("ca"), &cluster.id)?;
        let history = History::load(
            &root.join("bundles"),
            usize::try_from(settings.history).unwrap_or(50),
        )?;
        let rollout = Rollout::load(&root, settings.rollout.clone(), history.latest_revision())?;
        let (changes, _) = watch::channel(0);
        let (events, events_rx) = mpsc::unbounded_channel();
        let plane = Self {
            cluster_id: cluster.id,
            ca,
            state: Mutex::new(Mutable {
                tokens: Tokens::load(&root)?,
                registry: Registry::load(&root)?,
                history,
                rollout,
                seen: BTreeMap::new(),
            }),
            changes,
            events,
            events_rx: std::sync::Mutex::new(Some(events_rx)),
            store: DirStore::exclusive(root.join("store")),
            root,
            settings,
        };
        Ok(Arc::new(plane))
    }

    /// The cluster's id.
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    /// The cluster CA.
    #[must_use]
    pub fn ca(&self) -> &ClusterCa {
        &self.ca
    }

    /// The settings the control plane runs with.
    #[must_use]
    pub fn settings(&self) -> &rdock_model::cluster::ControlPlane {
        &self.settings
    }

    /// The directory of the control plane's state.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The store the control plane serves to its members (fencing enforced: one process, one
    /// lock, one clock).
    #[must_use]
    pub fn store(&self) -> &DirStore {
        &self.store
    }

    /// Creates a join token valid for `ttl` (default `control.join_token_ttl`).
    pub async fn create_token(
        &self,
        ttl: Option<Duration>,
        created_by: Option<String>,
    ) -> Result<(Secret, TokenRecord), Error> {
        let ttl = ttl.unwrap_or_else(|| self.settings.join_token_ttl.as_std());
        let mut state = self.state.lock().await;
        let created = state.tokens.create(ttl, created_by)?;
        info!(token = %created.1.id, expires_at = created.1.expires_at, "created a join token");
        Ok(created)
    }

    /// Join tokens, newest first, without secrets.
    pub async fn tokens(&self) -> Vec<TokenRecord> {
        self.state.lock().await.tokens.list()
    }

    /// Enrols a data plane that presents a valid join token. `presented` is the identity of
    /// the client certificate the caller presented, if any (instance and serial).
    ///
    /// - A name that is enrolled and not revoked is refused, unless the caller presents that
    ///   instance's current client certificate (it enrols again). Two machines can therefore
    ///   never share an instance name; a lost instance is replaced by revoking it first
    ///   (review finding H2).
    /// - A revoked name may be enrolled again with a new token: the new certificate replaces
    ///   the old one, whose serial no longer matches, so the old machine stays shut out.
    /// - A request with a token already used by the same key, while the token is valid, is
    ///   answered again with a new certificate for the instance it enrolled: a lost answer
    ///   does not spend the token (review finding L2).
    pub async fn enroll(
        &self,
        request: &EnrollRequest,
        presented: Option<(&str, &str)>,
    ) -> Result<EnrollResponse, Error> {
        let key = crate::ca::csr_key_digest(&request.csr_pem)?;
        let mut state = self.state.lock().await;
        let now = unix_now();
        let requested = match &request.name {
            Some(name) if rdock_model::cluster::is_instance_name(name) => Some(name.to_owned()),
            Some(_) => return Err(Error::Refused("the instance name is not valid".to_owned())),
            None => None,
        };
        let (token_id, name, fresh) = match state.tokens.check(&request.token, &key)? {
            TokenUse::Retry { id, instance } => {
                if requested.as_ref().is_some_and(|r| *r != instance) {
                    return Err(Error::Refused(
                        "the join token is not valid (unknown, expired or already used)".to_owned(),
                    ));
                }
                let current = state
                    .registry
                    .get(&instance)
                    .is_some_and(|i| !i.revoked && i.token_id == id);
                if !current {
                    return Err(Error::Refused(
                        "the join token is not valid (unknown, expired or already used)".to_owned(),
                    ));
                }
                info!(%instance, token = %id, "answering an enrolment again (the first answer was lost)");
                (id, instance, false)
            }
            TokenUse::Fresh(id) => {
                let name = match requested {
                    Some(name) => name,
                    None => format!(
                        "dp-{}",
                        rdock_credentials::random_base62(8)
                            .ok_or_else(|| Error::State(
                                "the system random generator failed".to_owned()
                            ))?
                            .to_ascii_lowercase()
                    ),
                };
                if let Some(existing) = state.registry.get(&name)
                    && !existing.revoked
                {
                    let holder = presented.is_some_and(|(instance, serial)| {
                        instance == name && state.registry.admits(&name, serial, now)
                    });
                    if !holder {
                        return Err(Error::Refused(format!(
                            "the instance name `{name}` is already enrolled; to replace a lost instance, revoke it first (`rdock control revoke {name}`) and enrol again with a new token, or choose another name"
                        )));
                    }
                }
                (id, name, true)
            }
        };
        let lifetime = self.settings.identity_lifetime.as_std();
        let (certificate_pem, serial, not_after) =
            self.ca
                .client_certificate(&request.csr_pem, &self.cluster_id, &name, lifetime)?;
        if fresh {
            state.tokens.mark_used(&token_id, &name, &key)?;
        }
        let rollout_state = state
            .registry
            .get(&name)
            .filter(|i| !i.revoked)
            .map(|i| (i.serving, i.last_report.clone()));
        let (serving, last_report) = rollout_state.unwrap_or((0, None));
        state.registry.insert(Instance {
            name: name.clone(),
            enrolled_at: now,
            token_id: token_id.clone(),
            certificate_serial: serial,
            certificate_not_after: not_after,
            previous_serial: None,
            previous_until: None,
            revoked: false,
            last_seen: Some(now),
            version: Some(request.version.clone()),
            serving,
            last_report,
        });
        state.registry.save()?;
        state.seen.insert(name.clone(), now);
        info!(instance = %name, token = %token_id, "enrolled a data plane");
        Ok(EnrollResponse {
            cluster_id: self.cluster_id.clone(),
            instance: name,
            certificate_pem,
            ca_pem: self.ca.pem().to_owned(),
            not_after,
        })
    }

    /// Issues an enrolled instance a new certificate. The one it replaces keeps working for a
    /// few minutes, so calls in flight finish; then only the new one does.
    pub async fn renew(&self, instance: &str, csr_pem: &str) -> Result<EnrollResponse, Error> {
        let mut state = self.state.lock().await;
        if !state.registry.allowed(instance) {
            return Err(Error::Forbidden);
        }
        let lifetime = self.settings.identity_lifetime.as_std();
        let (certificate_pem, serial, not_after) =
            self.ca
                .client_certificate(csr_pem, &self.cluster_id, instance, lifetime)?;
        if let Some(entry) = state.registry.get_mut(instance) {
            let previous = std::mem::replace(&mut entry.certificate_serial, serial);
            entry.previous_serial = Some(previous);
            entry.previous_until = Some(unix_now() + RENEWAL_GRACE);
            entry.certificate_not_after = not_after;
        }
        state.registry.save()?;
        info!(%instance, not_after, "renewed a data plane's certificate");
        Ok(EnrollResponse {
            cluster_id: self.cluster_id.clone(),
            instance: instance.to_owned(),
            certificate_pem,
            ca_pem: self.ca.pem().to_owned(),
            not_after,
        })
    }

    /// Whether the certificate with `serial` may call as `instance` (enrolled, not revoked, the
    /// newest certificate issued to it); records that it called.
    pub async fn admit(&self, instance: &str, serial: &str) -> bool {
        let mut state = self.state.lock().await;
        let allowed = state.registry.admits(instance, serial, unix_now());
        if allowed {
            state.seen.insert(instance.to_owned(), unix_now());
        }
        allowed
    }

    /// The compressed bundle `instance` is to take when its revision is above `after` (the
    /// rollout decides which: the newest, or the stable one while a canary runs), waiting up
    /// to `wait` for one; `None` when none came.
    pub async fn bundle_after(
        &self,
        instance: &str,
        after: u64,
        wait: Duration,
    ) -> Option<Vec<u8>> {
        let mut changes = self.changes.subscribe();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            {
                let mut state = self.state.lock().await;
                let target = state.rollout.target(instance);
                if target > after {
                    match state.history.bytes(target) {
                        Ok(Some(bytes)) => {
                            if state.rollout.offered(instance, target)
                                && let Err(e) = state.rollout.save()
                            {
                                warn!(error = %e, "cannot write the rollout state");
                            }
                            return Some(bytes);
                        }
                        Ok(None) => {
                            warn!(%instance, revision = target, "the revision to serve is no longer kept");
                        }
                        Err(e) => warn!(error = %e, "cannot read a published bundle"),
                    }
                }
            }
            match tokio::time::timeout_at(deadline, changes.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return None,
            }
        }
    }

    /// Takes the stream of rollout events (canary chosen, soaking, complete, halted), for the
    /// audit log; `None` once taken. Every event is delivered (the channel is unbounded and
    /// events are rare).
    #[must_use]
    pub fn take_events(&self) -> Option<mpsc::UnboundedReceiver<rollout::Event>> {
        self.events_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn announce(&self, events: Vec<rollout::Event>) {
        if events.is_empty() {
            return;
        }
        for event in events {
            match &event {
                rollout::Event::CanaryChosen {
                    revision,
                    canary,
                    instead_of,
                } => {
                    if let Some(wanted) = instead_of {
                        warn!(revision, %canary, configured = %wanted, "the configured canary is offline; another instance takes the revision first");
                    } else {
                        info!(revision, %canary, "the canary takes the revision first");
                    }
                }
                rollout::Event::Soaking { revision } => {
                    info!(
                        revision,
                        "the canary took the revision; the rest follow after the soak time"
                    );
                }
                rollout::Event::Completed { revision } => {
                    info!(revision, "every instance is given the revision");
                }
                rollout::Event::Halted { revision, halt } => {
                    warn!(revision, reason = %halt.reason, "the rollout halted; instances not given the revision stay on the stable one");
                }
            }
            let _ = self.events.send(event);
        }
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// The online, unrevoked instances by name (for choosing a canary).
    fn online(&self, state: &Mutable, now: i64) -> Vec<String> {
        let offline_after =
            i64::try_from(self.settings.offline_after.as_std().as_secs()).unwrap_or(90);
        state
            .registry
            .all()
            .filter(|i| !i.revoked)
            .filter(|i| {
                state
                    .seen
                    .get(&i.name)
                    .copied()
                    .or(i.last_seen)
                    .is_some_and(|s| now - s <= offline_after)
            })
            .map(|i| i.name.clone())
            .collect()
    }

    /// Moves rollouts on with time (a canary coming online, a silent canary, the end of the
    /// soak time) until `stop` turns true.
    pub async fn drive(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_tidy: Option<std::time::Instant> = None;
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                _ = tick.tick() => {}
            }
            if last_tidy.is_none_or(|at| at.elapsed() >= TIDY) {
                last_tidy = Some(std::time::Instant::now());
                self.tidy().await;
            }
            let events = {
                let mut state = self.state.lock().await;
                let now = unix_now();
                let online = self.online(&state, now);
                let events = state.rollout.tick(&online, now);
                if !events.is_empty()
                    && let Err(e) = state.rollout.save()
                {
                    warn!(error = %e, "cannot write the rollout state");
                }
                events
            };
            self.announce(events);
        }
    }

    /// Removes left-over records from the store by this process's clock, which is the
    /// store's: ended limit windows, answers of orders whose holder died, confirmations of
    /// answers that are gone and heartbeats of members that left (review findings L9, M3, M6).
    pub async fn tidy(&self) {
        let now = rdock_cluster::Clock::now_ms(&rdock_cluster::SystemClock);
        if let Err(e) = rdock_cluster::janitor::tidy(&self.store, now).await {
            warn!(error = %e, "cannot remove left-over records from the cluster store");
        }
        if let Err(e) = rdock_cluster::janitor::tidy_all_limits(&self.store, now).await {
            warn!(error = %e, "cannot remove ended limit windows from the cluster store");
        }
    }

    /// The rollout's state, for the API.
    pub async fn rollout(&self) -> Value {
        self.state.lock().await.rollout.view()
    }

    /// An operator lets a halted or soaking rollout go on to every instance.
    pub async fn resume(&self, by: &str) -> Result<Value, Error> {
        let (events, view) = {
            let mut state = self.state.lock().await;
            let events = state
                .rollout
                .resume(by, unix_now())
                .map_err(|Refusal::Conflict(m)| Error::Conflict(m))?;
            state.rollout.save()?;
            (events, state.rollout.view())
        };
        info!(by, "the rollout was resumed");
        self.announce(events);
        Ok(view)
    }

    /// An operator abandons a halted or running rollout: the stable revision's document is
    /// published again as a new revision, which every instance takes at once (the instances
    /// already given the abandoned revision are sent back). Choosing the target, marking the
    /// rollout abandoned and publishing happen under one lock, so a publication in between
    /// cannot be marked abandoned in its place (review finding L6).
    pub async fn abandon(&self, by: &str) -> Result<Bundle, Error> {
        let mut state = self.state.lock().await;
        let stable = state
            .rollout
            .abandon_target()
            .map_err(|Refusal::Conflict(m)| Error::Conflict(m))?;
        let document = state
            .history
            .get(stable)?
            .map(|b| b.document)
            .ok_or_else(|| Error::Conflict(format!("revision {stable} is no longer kept")))?;
        Self::check_publishable(&document)?;
        state.rollout.abandoned(by, unix_now());
        state.rollout.save()?;
        info!(by, stable, "the rollout was abandoned");
        let (bundle, events) =
            self.publish_locked(&mut state, document, Some(stable), Some(by.to_owned()))?;
        drop(state);
        self.announce(events);
        Ok(bundle)
    }

    /// Records a data plane's report on a bundle.
    pub async fn report(&self, instance: &str, report: Report) -> Result<(), Error> {
        let mut state = self.state.lock().await;
        let now = unix_now();
        let Some(entry) = state.registry.get_mut(instance) else {
            return Err(Error::Forbidden);
        };
        if entry.revoked {
            return Err(Error::Forbidden);
        }
        entry.serving = report.serving;
        entry.version = Some(report.version.clone());
        entry.last_seen = Some(now);
        if report.verdict == Verdict::Nack {
            tracing::warn!(%instance, revision = report.revision, "a data plane refused a bundle");
        } else {
            info!(%instance, revision = report.revision, "a data plane applied a bundle");
        }
        let reason = report
            .diagnostics
            .first()
            .and_then(|d| d["message"].as_str())
            .map(str::to_owned);
        entry.last_report = Some(LastReport {
            revision: report.revision,
            verdict: report.verdict,
            diagnostics: report.diagnostics,
            at: now,
        });
        state.seen.insert(instance.to_owned(), now);
        state.registry.save()?;
        let events = state.rollout.report(
            instance,
            report.revision,
            report.verdict,
            reason.as_deref(),
            now,
        );
        if !events.is_empty() {
            state.rollout.save()?;
        }
        drop(state);
        self.announce(events);
        Ok(())
    }

    /// Publishes `document` (already validated by the caller) as the next revision.
    /// `rollback_of` names the revision it republishes. Refused: an empty document, a document
    /// that is not an object, one that carries `cluster` or `control`.
    pub async fn publish(
        &self,
        document: Value,
        rollback_of: Option<u64>,
        published_by: Option<String>,
    ) -> Result<Bundle, Error> {
        Self::check_publishable(&document)?;
        let mut state = self.state.lock().await;
        let (bundle, events) =
            self.publish_locked(&mut state, document, rollback_of, published_by)?;
        drop(state);
        self.announce(events);
        Ok(bundle)
    }

    fn check_publishable(document: &Value) -> Result<(), Error> {
        let problems = rdock_model::cluster::bundle_diagnostics(document);
        if let Some(problem) = problems.first() {
            return Err(Error::Refused(format!(
                "{}: {}",
                problem.path, problem.message
            )));
        }
        if document.as_object().is_none_or(serde_json::Map::is_empty) {
            return Err(Error::Refused(
                "an empty configuration is never published".to_owned(),
            ));
        }
        Ok(())
    }

    fn publish_locked(
        &self,
        state: &mut Mutable,
        document: Value,
        rollback_of: Option<u64>,
        published_by: Option<String>,
    ) -> Result<(Bundle, Vec<rollout::Event>), Error> {
        let revision = state.history.latest_revision() + 1;
        let bundle = Bundle {
            format: rdock_cluster::protocol::VERSION,
            cluster_id: self.cluster_id.clone(),
            revision,
            sha256: Bundle::digest(&document),
            published_at: rfc3339(unix_now()),
            published_by,
            rollback_of,
            document,
        };
        // The revision that is stable once this one is published: never evicted (review
        // finding L1; the stable revision recorded before a rollout that completed at once is
        // older than the one instances fall back to).
        let pinned = state.rollout.next_stable();
        state.history.add(bundle.clone(), pinned)?;
        let now = unix_now();
        let online = self.online(state, now);
        let events = state
            .rollout
            .start(revision, rollback_of.is_some(), &online, now);
        state.rollout.save()?;
        info!(revision, sha256 = %bundle.sha256, rollback_of, "published a bundle");
        Ok((bundle, events))
    }

    /// The document of a kept revision.
    pub async fn document(&self, revision: u64) -> Result<Option<Value>, Error> {
        let state = self.state.lock().await;
        Ok(state.history.get(revision)?.map(|b| b.document))
    }

    /// The newest revision (`0` before the first publication).
    pub async fn latest_revision(&self) -> u64 {
        self.state.lock().await.history.latest_revision()
    }

    /// Kept revisions, newest first: revision, hash, when, who, rollback, and which instances
    /// refused it.
    pub async fn revisions(&self) -> Result<Value, Error> {
        let state = self.state.lock().await;
        let mut out = Vec::new();
        for bundle in state.history.list()? {
            let refused: Vec<Value> = state
                .registry
                .all()
                .filter_map(|i| {
                    i.last_report
                        .as_ref()
                        .filter(|r| r.revision == bundle.revision && r.verdict == Verdict::Nack)
                        .map(|r| json!({ "instance": i.name, "diagnostics": r.diagnostics }))
                })
                .collect();
            out.push(json!({
                "revision": bundle.revision,
                "sha256": bundle.sha256,
                "published_at": bundle.published_at,
                "published_by": bundle.published_by,
                "rollback_of": bundle.rollback_of,
                "refused_by": refused,
                "rollout": state.rollout.outcome_of(bundle.revision),
            }));
        }
        Ok(json!({
            "cluster_id": self.cluster_id,
            "latest": state.history.latest_revision(),
            "rollout": state.rollout.view(),
            "revisions": out,
        }))
    }

    /// Revokes `instance`: it can no longer fetch bundles or use the store. `false` when
    /// there is no such instance.
    pub async fn revoke(&self, instance: &str) -> Result<bool, Error> {
        let mut state = self.state.lock().await;
        let Some(entry) = state.registry.get_mut(instance) else {
            return Ok(false);
        };
        entry.revoked = true;
        state.registry.save()?;
        info!(%instance, "revoked a data plane");
        Ok(true)
    }

    /// Every instance with its state.
    pub async fn instances(&self) -> Value {
        let state = self.state.lock().await;
        let latest = state.history.latest_revision();
        let now = unix_now();
        let away_after =
            i64::try_from(self.settings.offline_after.as_std().as_secs()).unwrap_or(90);
        let list: Vec<Value> = state
            .registry
            .all()
            .map(|i| {
                let seen = state.seen.get(&i.name).copied().or(i.last_seen);
                let status = instance_state(i, seen, latest, now, away_after);
                let last_error = i
                    .last_report
                    .as_ref()
                    .filter(|r| r.verdict == Verdict::Nack)
                    .map(|r| {
                        let message = r
                            .diagnostics
                            .first()
                            .and_then(|d| d["message"].as_str())
                            .unwrap_or("refused");
                        format!("revision {}: {message}", r.revision)
                    });
                json!({
                    "name": i.name,
                    "state": status,
                    "serving": i.serving,
                    "target": state.rollout.target(&i.name),
                    "latest": latest,
                    "last_error": last_error,
                    "version": i.version,
                    "enrolled_at": rfc3339(i.enrolled_at),
                    "last_seen": seen.map(rfc3339),
                    "certificate_not_after": rfc3339(i.certificate_not_after),
                    "revoked": i.revoked,
                    "last_report": i.last_report.as_ref().map(|r| json!({
                        "revision": r.revision,
                        "verdict": r.verdict,
                        "diagnostics": r.diagnostics,
                        "at": rfc3339(r.at),
                    })),
                })
            })
            .collect();
        json!({
            "cluster_id": self.cluster_id,
            "name": self.settings.name,
            "latest": latest,
            "rollout": state.rollout.view(),
            "instances": list,
        })
    }

    /// How many instances are in each state, for `rdock_control_instances`.
    pub async fn census(&self) -> BTreeMap<&'static str, i64> {
        let state = self.state.lock().await;
        let latest = state.history.latest_revision();
        let now = unix_now();
        let away_after =
            i64::try_from(self.settings.offline_after.as_std().as_secs()).unwrap_or(90);
        let mut out: BTreeMap<&'static str, i64> =
            ["synced", "behind", "error", "offline", "revoked"]
                .into_iter()
                .map(|s| (s, 0))
                .collect();
        for i in state.registry.all() {
            let seen = state.seen.get(&i.name).copied().or(i.last_seen);
            *out.entry(instance_state(i, seen, latest, now, away_after).as_str())
                .or_default() += 1;
        }
        out
    }

    /// One store operation on behalf of `instance` (which must be admitted). The holder of a
    /// lease is always the calling instance.
    pub async fn store_op(&self, instance: &str, request: StoreRequest) -> StoreResponse {
        crate::store::serve(&self.store, instance, request).await
    }
}

fn instance_state(
    i: &Instance,
    seen: Option<i64>,
    latest: u64,
    now: i64,
    away_after: i64,
) -> InstanceState {
    if i.revoked {
        InstanceState::Revoked
    } else if seen.is_none_or(|s| now - s > away_after) {
        InstanceState::Offline
    } else if i
        .last_report
        .as_ref()
        .is_some_and(|r| r.revision == latest && r.verdict == Verdict::Nack)
    {
        InstanceState::Error
    } else if i.serving >= latest {
        InstanceState::Synced
    } else {
        InstanceState::Behind
    }
}

/// RFC 3339 in UTC for Unix seconds.
#[must_use]
pub fn rfc3339(unix: i64) -> String {
    let at = std::time::UNIX_EPOCH + Duration::from_secs(u64::try_from(unix).unwrap_or(0));
    rdock_observability::rfc3339(at)
}

impl ControlPlane {
    /// The store as a trait object (tests and the binary's own use).
    #[must_use]
    pub fn shared_store(&self) -> Arc<dyn ClusterStore> {
        Arc::new(self.store.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csr() -> (String, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        (csr, key)
    }

    fn request(token: &Secret, csr: &str, name: Option<&str>) -> EnrollRequest {
        EnrollRequest {
            token: token.expose().to_owned(),
            csr_pem: csr.to_owned(),
            name: name.map(str::to_owned),
            version: "test".into(),
        }
    }

    fn serial_of(answer: &EnrollResponse) -> String {
        use rustls_pki_types::pem::PemObject;
        let der =
            rustls_pki_types::CertificateDer::from_pem_slice(answer.certificate_pem.as_bytes())
                .unwrap();
        crate::ca::identity_of(&der, &answer.cluster_id).unwrap().1
    }

    fn plane(
        settings: rdock_model::cluster::ControlPlane,
    ) -> (tempfile::TempDir, Arc<ControlPlane>) {
        let dir = tempfile::tempdir().unwrap();
        let plane = ControlPlane::open(dir.path(), settings).unwrap();
        (dir, plane)
    }

    /// Review finding H2: a second machine cannot enrol under a live instance's name; the
    /// holder of the name's current certificate can; a revoked name can be enrolled again and
    /// the old certificate stays shut out.
    #[tokio::test]
    async fn an_enrolled_name_is_not_given_to_another_machine() {
        let (_dir, plane) = plane(rdock_model::cluster::ControlPlane::default());
        let (token_a, _) = plane.create_token(None, None).await.unwrap();
        let (csr_a, _) = csr();
        let first = plane
            .enroll(&request(&token_a, &csr_a, Some("edge-1")), None)
            .await
            .unwrap();
        let first_serial = serial_of(&first);
        assert!(plane.admit("edge-1", &first_serial).await);
        // Another machine with another token and the same name: refused.
        let (token_b, _) = plane.create_token(None, None).await.unwrap();
        let (csr_b, _) = csr();
        let refused = plane
            .enroll(&request(&token_b, &csr_b, Some("edge-1")), None)
            .await
            .unwrap_err();
        assert!(refused.to_string().contains("revoke it first"), "{refused}");
        assert!(
            plane.admit("edge-1", &first_serial).await,
            "the first one is untouched"
        );
        // The holder of the current certificate may enrol again (with a token).
        let again = plane
            .enroll(
                &request(&token_b, &csr_b, Some("edge-1")),
                Some(("edge-1", &first_serial)),
            )
            .await
            .unwrap();
        let second_serial = serial_of(&again);
        assert!(!plane.admit("edge-1", &first_serial).await, "replaced");
        assert!(plane.admit("edge-1", &second_serial).await);
        // A revoked name may be enrolled again; the old certificate stays refused.
        assert!(plane.revoke("edge-1").await.unwrap());
        let (token_c, _) = plane.create_token(None, None).await.unwrap();
        let (csr_c, _) = csr();
        let replaced = plane
            .enroll(&request(&token_c, &csr_c, Some("edge-1")), None)
            .await
            .unwrap();
        assert!(plane.admit("edge-1", &serial_of(&replaced)).await);
        assert!(!plane.admit("edge-1", &second_serial).await);
        // A certificate of another instance's name does not count as the holder.
        let (token_d, _) = plane.create_token(None, None).await.unwrap();
        let (csr_d, _) = csr();
        let other = plane
            .enroll(&request(&token_d, &csr_d, Some("edge-2")), None)
            .await
            .unwrap();
        let (token_e, _) = plane.create_token(None, None).await.unwrap();
        assert!(
            plane
                .enroll(
                    &request(&token_e, &csr_d, Some("edge-1")),
                    Some(("edge-2", &serial_of(&other)))
                )
                .await
                .is_err()
        );
    }

    /// Review finding L2: a lost answer does not spend the token; the same key asks again and
    /// gets a certificate for the same instance; another key with that token does not.
    #[tokio::test]
    async fn a_retry_with_the_same_key_is_answered_again() {
        let (_dir, plane) = plane(rdock_model::cluster::ControlPlane::default());
        let (token, _) = plane.create_token(None, None).await.unwrap();
        let (csr_a, key) = csr();
        let first = plane
            .enroll(&request(&token, &csr_a, None), None)
            .await
            .unwrap();
        // The answer was lost; the data plane asks again with the same key (a new request).
        let csr_again = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let again = plane
            .enroll(&request(&token, &csr_again, None), None)
            .await
            .unwrap();
        assert_eq!(again.instance, first.instance, "a generated name is kept");
        assert!(plane.admit(&again.instance, &serial_of(&again)).await);
        let (csr_other, _) = csr();
        assert!(
            plane
                .enroll(&request(&token, &csr_other, None), None)
                .await
                .is_err()
        );
    }

    /// Review finding L3: after a renewal the old certificate works only for the grace time.
    #[tokio::test]
    async fn a_renewed_away_certificate_stops_working() {
        let (_dir, plane) = plane(rdock_model::cluster::ControlPlane::default());
        let (token, _) = plane.create_token(None, None).await.unwrap();
        let (csr_a, _) = csr();
        let first = plane
            .enroll(&request(&token, &csr_a, Some("edge-1")), None)
            .await
            .unwrap();
        let (csr_b, _) = csr();
        let renewed = plane.renew("edge-1", &csr_b).await.unwrap();
        assert!(plane.admit("edge-1", &serial_of(&renewed)).await);
        assert!(
            plane.admit("edge-1", &serial_of(&first)).await,
            "grace time"
        );
        {
            let mut state = plane.state.lock().await;
            let entry = state.registry.get_mut("edge-1").unwrap();
            entry.previous_until = Some(unix_now() - 1);
        }
        assert!(!plane.admit("edge-1", &serial_of(&first)).await);
        assert!(plane.admit("edge-1", &serial_of(&renewed)).await);
    }

    /// Review finding L1: with a short history, a rollout that completed at once (the first
    /// revision, a rollback) followed by a canary publication keeps the revision instances fall
    /// back to.
    #[tokio::test]
    async fn the_stable_revision_is_never_pruned() {
        let settings = rdock_model::cluster::ControlPlane {
            history: 2,
            ..rdock_model::cluster::ControlPlane::default()
        };
        let (_dir, plane) = plane(settings);
        let doc =
            |n: u64| json!({ "services": { format!("s{n}"): { "url": "http://127.0.0.1:1" } } });
        plane.publish(doc(1), None, None).await.unwrap();
        plane.publish(doc(1), Some(1), None).await.unwrap();
        plane.publish(doc(3), None, None).await.unwrap();
        let state = plane.state.lock().await;
        let stable = state.rollout.state().stable;
        assert_eq!(stable, 2);
        assert!(
            state.history.get(stable).unwrap().is_some(),
            "revision {stable} was evicted"
        );
    }
}
