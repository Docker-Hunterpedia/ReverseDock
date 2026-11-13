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
use tokio::sync::{Mutex, broadcast, watch};
use tracing::{info, warn};

use crate::bundles::History;
use crate::ca::ClusterCa;
use crate::registry::{Instance, LastReport, Registry};
use crate::rollout::{self, Refusal, Rollout};
use crate::tokens::{TokenRecord, Tokens};
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
    events: broadcast::Sender<rollout::Event>,
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
        let (events, _) = broadcast::channel(64);
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

    /// Enrols a data plane that presents a valid join token.
    pub async fn enroll(&self, request: &EnrollRequest) -> Result<EnrollResponse, Error> {
        let mut state = self.state.lock().await;
        let name = match &request.name {
            Some(name) if rdock_model::cluster::is_instance_name(name) => name.to_owned(),
            Some(_) => return Err(Error::Refused("the instance name is not valid".to_owned())),
            None => format!(
                "dp-{}",
                rdock_credentials::random_base62(8)
                    .ok_or_else(|| Error::State("the system random generator failed".to_owned()))?
                    .to_ascii_lowercase()
            ),
        };
        if state.registry.get(&name).is_some_and(|i| i.revoked) {
            return Err(Error::Refused(format!(
                "the instance `{name}` was revoked; enrol it under another name"
            )));
        }
        let token_id = state.tokens.consume(&request.token, &name)?;
        let lifetime = self.settings.identity_lifetime.as_std();
        let (certificate_pem, serial, not_after) =
            self.ca
                .client_certificate(&request.csr_pem, &self.cluster_id, &name, lifetime)?;
        state.registry.insert(Instance {
            name: name.clone(),
            enrolled_at: unix_now(),
            token_id: token_id.clone(),
            certificate_serial: serial,
            certificate_not_after: not_after,
            revoked: false,
            last_seen: Some(unix_now()),
            version: Some(request.version.clone()),
            serving: 0,
            last_report: None,
        });
        state.registry.save()?;
        state.seen.insert(name.clone(), unix_now());
        info!(instance = %name, token = %token_id, "enrolled a data plane");
        Ok(EnrollResponse {
            cluster_id: self.cluster_id.clone(),
            instance: name,
            certificate_pem,
            ca_pem: self.ca.pem().to_owned(),
            not_after,
        })
    }

    /// Issues an enrolled instance a new certificate.
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
            entry.certificate_serial = serial;
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

    /// Whether `instance` may call (enrolled, not revoked); records that it called.
    pub async fn admit(&self, instance: &str) -> bool {
        let mut state = self.state.lock().await;
        let allowed = state.registry.allowed(instance);
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

    /// Subscribes to rollout events (canary chosen, soaking, complete, halted), for the audit
    /// log.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<rollout::Event> {
        self.events.subscribe()
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
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                _ = tick.tick() => {}
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
    /// already given the abandoned revision are sent back).
    pub async fn abandon(&self, by: &str) -> Result<Bundle, Error> {
        let (stable, document) = {
            let state = self.state.lock().await;
            let stable = state
                .rollout
                .abandon_target()
                .map_err(|Refusal::Conflict(m)| Error::Conflict(m))?;
            let document = state
                .history
                .get(stable)?
                .map(|b| b.document)
                .ok_or_else(|| Error::Conflict(format!("revision {stable} is no longer kept")))?;
            (stable, document)
        };
        {
            let mut state = self.state.lock().await;
            state.rollout.abandoned(by, unix_now());
            state.rollout.save()?;
        }
        info!(by, stable, "the rollout was abandoned");
        self.publish(document, Some(stable), Some(by.to_owned()))
            .await
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
        let problems = rdock_model::cluster::bundle_diagnostics(&document);
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
        let mut state = self.state.lock().await;
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
        let pinned = state.rollout.state().stable;
        state.history.add(bundle.clone(), pinned)?;
        let now = unix_now();
        let online = self.online(&state, now);
        let events = state
            .rollout
            .start(revision, rollback_of.is_some(), &online, now);
        state.rollout.save()?;
        drop(state);
        info!(revision, sha256 = %bundle.sha256, rollback_of, "published a bundle");
        self.announce(events);
        Ok(bundle)
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
