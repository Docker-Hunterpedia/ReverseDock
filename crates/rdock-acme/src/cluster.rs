//! Certificates in a cluster (ADR-0031): challenge answers replicated to every member through
//! the cluster store, with a barrier before the CA is told to validate.
//!
//! - Every member writes `members/<instance>` every few seconds (its heartbeat) and polls
//!   `challenges/` in the background, copying each answer into its own lock-free maps (the data
//!   plane never reads the store on the request path, ADR-0020) and confirming it with
//!   `challenge-acks/<id>/<instance>`. An answer whose stored version changed (republished by
//!   a successor resuming the order) is applied and confirmed again.
//! - The member that orders writes its answers to `challenges/<id>` under the certificate's
//!   lease and waits until every live member (a heartbeat that changed within [`MEMBER_TTL`])
//!   confirmed each one, or until the barrier timeout. Members that have not confirmed by then
//!   cannot answer; validation goes ahead, because a member that is away should not stop every
//!   other member from getting a certificate. A member cut off from the store that still
//!   receives public traffic is the case DNS-01 avoids, which is why validation recommends
//!   DNS-01 for clusters.
//! - Answer ids are unique per order (`http-<token>`, `alpn-<name>-<digest>`), so a member
//!   never keeps a stale TLS-ALPN-01 certificate or confirms an answer it does not hold (review
//!   finding M2). A new holder of a name's lease first withdraws what an earlier holder of that
//!   name left; anything else left over is removed after [`rdock_cluster::janitor::ANSWER_MAX_AGE`].
//!
//! For TLS-ALPN-01 only the name and the digest of the key authorization travel; each member
//! builds its own validation certificate from them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rdock_cluster::store::segment;
use rdock_cluster::{Clock, ClusterStore, Expect, Lease, StoreError, SystemClock};
use rdock_observability::Metrics;
use rdock_tls::Challenges;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::issue::{AnswerSink, IssueError, validation_certificate};

/// How often members poll for answers and how often the barrier looks for confirmations.
const POLL: Duration = Duration::from_millis(250);
/// How often a member writes its heartbeat.
const HEARTBEAT: Duration = Duration::from_secs(5);
/// How often a member removes left-over records ([`rdock_cluster::janitor`]).
const TIDY: Duration = Duration::from_secs(60);
/// A member whose heartbeat has not changed for this long is away: barriers do not wait for it.
pub const MEMBER_TTL: Duration = Duration::from_secs(20);

/// What a member of a cluster needs to issue certificates with the others.
#[derive(Debug, Clone)]
pub struct ClusterAcme {
    /// The shared store.
    pub store: Arc<dyn ClusterStore>,
    /// This instance's name in heartbeats and confirmations.
    pub instance: String,
    /// The lease on a certificate name (`cluster.store.lease_ttl`).
    pub lease_ttl: Duration,
    /// How long the barrier waits (`cluster.store.barrier_timeout`).
    pub barrier_timeout: Duration,
    /// Barrier and lease counters.
    pub metrics: Option<Metrics>,
}

/// A replicated answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum Answer {
    Http01 {
        token: String,
        key_authorization: String,
    },
    TlsAlpn01 {
        name: String,
        /// SHA-256 of the key authorization, lower-case hex.
        digest: String,
    },
}

/// What `challenges/<id>` holds: the answer, the lease of the order it belongs to, and when it
/// was published (by the publisher's clock), so left-overs can be withdrawn.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Published {
    #[serde(flatten)]
    answer: Answer,
    /// The lease the order runs under (`cert/<first name>`).
    #[serde(default)]
    owner: String,
    /// Milliseconds since the Unix epoch.
    #[serde(default)]
    created_at_ms: u64,
}

/// A heartbeat (`members/<instance>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Heartbeat {
    instance: String,
    /// By the member's clock, in milliseconds since the Unix epoch.
    at_ms: u64,
    /// A random tag of the process, which tells two processes with one name apart.
    #[serde(default)]
    tag: String,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn http01_id(token: &str) -> String {
    format!("http-{}", segment(token))
}

/// Unique per order: the digest differs with every challenge token.
fn tls_alpn01_id(name: &str, digest_hex: &str) -> String {
    let short = digest_hex.get(..16).unwrap_or(digest_hex);
    format!("alpn-{}-{short}", segment(name))
}

/// A random tag for this process, so two processes that were given the same instance name
/// neither share a lease on a shared directory nor go unnoticed (review finding H2).
fn process_tag() -> &'static str {
    static TAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TAG.get_or_init(|| {
        let mut bytes = [0u8; 6];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes);
        hex(&bytes)
    })
}

/// What a member's replication remembers between rounds.
#[derive(Default)]
struct Replica {
    /// Applied answers by id, with the stored version they were applied at.
    applied: BTreeMap<String, (u64, Answer)>,
    last_beat: Option<Instant>,
    /// The heartbeat this process wrote last.
    written: Option<Vec<u8>>,
    warned_duplicate: bool,
    last_tidy: Option<Instant>,
    failing: bool,
}

/// Heartbeats as this member saw them: the value and when it last changed, by this member's
/// monotonic clock.
type Seen = BTreeMap<String, (u64, Instant)>;

impl ClusterAcme {
    /// The holder named in this process's leases. On the control plane's store the control
    /// plane names the holder after the instance its client certificate names, whatever is
    /// asked for; on a shared directory, which cannot authenticate anyone, the holder is the
    /// instance name and a random tag of this process, so two processes given the same
    /// `cluster.instance` never hold one lease together.
    #[must_use]
    pub fn lease_holder(&self) -> String {
        match self.store.fencing() {
            rdock_cluster::Fencing::Enforced => self.instance.clone(),
            rdock_cluster::Fencing::BestEffort => format!("{}@{}", self.instance, process_tag()),
        }
    }

    /// The answer sink of one order, which runs under `lease` (`cert/<first name>`).
    #[must_use]
    pub fn answers(&self, challenges: Arc<Challenges>, lease: Lease) -> Arc<dyn AnswerSink> {
        Arc::new(ClusterAnswers {
            cluster: self.clone(),
            local: crate::issue::LocalAnswers::new(challenges),
            lease,
            ids: Mutex::new(BTreeSet::new()),
        })
    }

    /// Withdraws the answers an earlier holder of `lease` left in the store (it died before it
    /// withdrew them). Called by a new holder before it orders.
    pub async fn withdraw_leftovers(&self, lease: &Lease) {
        let Ok(keys) = self.store.list("challenges").await else {
            return;
        };
        for key in keys {
            let Ok(Some(entry)) = self.store.get(&key).await else {
                continue;
            };
            let owned = serde_json::from_slice::<Published>(&entry.value)
                .is_ok_and(|p| p.owner == lease.name);
            if !owned {
                continue;
            }
            if let Some(id) = key.strip_prefix("challenges/") {
                debug!(%id, "withdrawing an answer an earlier holder left");
                withdraw(self.store.as_ref(), id, Some(lease)).await;
            }
        }
    }

    /// Starts the heartbeat and the background copy of other members' answers into
    /// `challenges`; runs until the process ends.
    pub fn start_replication(&self, challenges: Arc<Challenges>) {
        let cluster = self.clone();
        tokio::spawn(async move {
            let mut replica = Replica::default();
            loop {
                cluster.round(&challenges, &mut replica).await;
                tokio::time::sleep(POLL).await;
            }
        });
    }

    /// One bounded first synchronisation before the listeners accept: the heartbeat is written
    /// and the answers in the store are copied and confirmed, so a member that has just started
    /// can answer a validation already in progress. Gives up after `within` (the store is
    /// away); returns whether it finished.
    pub async fn prime(&self, challenges: &Arc<Challenges>, within: Duration) -> bool {
        let mut replica = Replica::default();
        let done = tokio::time::timeout(within, async {
            self.heartbeat(&mut replica).await.is_ok()
                && self.sync_answers(challenges, &mut replica).await.is_ok()
        })
        .await;
        matches!(done, Ok(true))
    }

    async fn round(&self, challenges: &Arc<Challenges>, replica: &mut Replica) {
        if replica.last_beat.is_none_or(|at| at.elapsed() >= HEARTBEAT) {
            match self.heartbeat(replica).await {
                Ok(()) => replica.last_beat = Some(Instant::now()),
                Err(e) => debug!(error = %e, "cannot write the cluster heartbeat"),
            }
        }
        match self.sync_answers(challenges, replica).await {
            Ok(()) => {
                if replica.failing {
                    info!("the cluster store answers again; challenge answers are replicated");
                }
                replica.failing = false;
            }
            Err(e) => {
                if !replica.failing {
                    warn!(error = %e, "cannot read challenge answers from the cluster store");
                }
                replica.failing = true;
            }
        }
        if replica.last_tidy.is_none_or(|at| at.elapsed() >= TIDY) {
            replica.last_tidy = Some(Instant::now());
            if let Err(e) =
                rdock_cluster::janitor::tidy(self.store.as_ref(), SystemClock.now_ms()).await
            {
                debug!(error = %e, "cannot remove left-over records from the cluster store");
            }
        }
    }

    /// Writes the heartbeat, after checking that the last one this process wrote is still
    /// there: when another process replaced it, two processes share this instance name.
    async fn heartbeat(&self, replica: &mut Replica) -> Result<(), StoreError> {
        let key = format!("members/{}", self.instance);
        if let Some(written) = &replica.written
            && !replica.warned_duplicate
            && let Some(entry) = self.store.get(&key).await?
            && entry.value != *written
            && serde_json::from_slice::<Heartbeat>(&entry.value)
                .is_ok_and(|b| b.tag != process_tag())
        {
            warn!(instance = %self.instance, "another process writes the heartbeat of this instance name: two instances share one name, so leases, the barrier and member counts treat them as one; give each instance its own `cluster.instance` (or none, for a generated one)");
            replica.warned_duplicate = true;
        }
        let beat = Heartbeat {
            instance: self.instance.clone(),
            at_ms: SystemClock.now_ms(),
            tag: process_tag().to_owned(),
        };
        let json = serde_json::to_vec(&beat).map_err(|e| StoreError::Backend(e.to_string()))?;
        self.store
            .put(&key, json.clone(), Expect::Any, None)
            .await?;
        replica.written = Some(json);
        Ok(())
    }

    /// Copies new and republished answers into `challenges`, confirms them, and removes
    /// withdrawn ones.
    async fn sync_answers(
        &self,
        challenges: &Challenges,
        replica: &mut Replica,
    ) -> Result<(), StoreError> {
        let applied = &mut replica.applied;
        let keys = self.store.list("challenges").await?;
        let ids: BTreeSet<String> = keys
            .iter()
            .filter_map(|k| k.strip_prefix("challenges/"))
            .filter(|id| !id.contains('/'))
            .map(str::to_owned)
            .collect();
        for id in &ids {
            let Some(entry) = self.store.get(&format!("challenges/{id}")).await? else {
                continue;
            };
            if applied.get(id).is_some_and(|(v, _)| *v == entry.version) {
                continue;
            }
            let Ok(published) = serde_json::from_slice::<Published>(&entry.value) else {
                warn!(%id, "ignoring an unreadable challenge answer in the cluster store");
                continue;
            };
            let answer = published.answer;
            match &answer {
                Answer::Http01 {
                    token,
                    key_authorization,
                } => challenges.add_http01(token, key_authorization),
                Answer::TlsAlpn01 { name, digest } => {
                    let Some(digest) = unhex(digest) else {
                        continue;
                    };
                    match validation_certificate(name, &digest) {
                        Ok(certificate) => challenges.add_tls_alpn01(name, &certificate),
                        Err(e) => {
                            warn!(%name, error = %e, "cannot build a TLS-ALPN-01 validation certificate");
                            continue;
                        }
                    }
                }
            }
            self.store
                .put(
                    &format!("challenge-acks/{id}/{}", self.instance),
                    Vec::new(),
                    Expect::Any,
                    None,
                )
                .await?;
            debug!(%id, "holding a replicated challenge answer");
            applied.insert(id.clone(), (entry.version, answer));
        }
        let gone: Vec<String> = applied
            .keys()
            .filter(|id| !ids.contains(*id))
            .cloned()
            .collect();
        for id in gone {
            match applied.remove(&id) {
                Some((_, Answer::Http01 { token, .. })) => challenges.remove_http01(&token),
                Some((_, Answer::TlsAlpn01 { name, .. })) => {
                    // A newer order's answer for the same name stays.
                    let newer = applied.values().any(|(_, a)| {
                        matches!(a, Answer::TlsAlpn01 { name: other, .. } if other.eq_ignore_ascii_case(&name))
                    });
                    if !newer {
                        challenges.remove_tls_alpn01(&name);
                    }
                }
                None => {}
            }
        }
        Ok(())
    }

    /// The members whose heartbeat changed within [`MEMBER_TTL`] by this member's monotonic
    /// clock, so a member whose wall clock is off neither counts the others away nor a dead
    /// member live (review finding M6). A heartbeat seen for the first time counts when its
    /// time is within [`MEMBER_TTL`] of this member's clock.
    async fn live_members(&self, seen: &mut Seen) -> Result<BTreeSet<String>, StoreError> {
        let now = SystemClock.now_ms();
        let ttl = u64::try_from(MEMBER_TTL.as_millis()).unwrap_or(u64::MAX);
        let mut live = BTreeSet::new();
        for key in self.store.list("members").await? {
            let Some(entry) = self.store.get(&key).await? else {
                continue;
            };
            let Ok(beat) = serde_json::from_slice::<Heartbeat>(&entry.value) else {
                continue;
            };
            let fresh = match seen.get(&key) {
                Some((at, changed)) if *at == beat.at_ms => changed.elapsed() < MEMBER_TTL,
                Some(_) => {
                    seen.insert(key.clone(), (beat.at_ms, Instant::now()));
                    true
                }
                None => {
                    let close = now.abs_diff(beat.at_ms) < ttl;
                    let changed = if close {
                        Instant::now()
                    } else {
                        Instant::now()
                            .checked_sub(MEMBER_TTL)
                            .unwrap_or_else(Instant::now)
                    };
                    seen.insert(key.clone(), (beat.at_ms, changed));
                    close
                }
            };
            if fresh {
                live.insert(beat.instance);
            }
        }
        live.insert(self.instance.clone());
        Ok(live)
    }

    fn count_barrier(&self, result: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.cluster_barriers.with_label_values(&[result]).inc();
        }
    }
}

/// Removes the answer `id` and then its confirmations.
async fn withdraw(store: &dyn ClusterStore, id: &str, fence: Option<&Lease>) {
    if let Err(e) = store
        .delete(&format!("challenges/{id}"), Expect::Any, fence)
        .await
    {
        warn!(%id, error = %e, "cannot withdraw a challenge answer from the cluster store");
        return;
    }
    for key in store
        .list(&format!("challenge-acks/{id}"))
        .await
        .unwrap_or_default()
    {
        let _ = store.delete(&key, Expect::Any, None).await;
    }
}

/// The answers of one order: local maps at once, the store for the others.
struct ClusterAnswers {
    cluster: ClusterAcme,
    local: crate::issue::LocalAnswers,
    lease: Lease,
    ids: Mutex<BTreeSet<String>>,
}

impl ClusterAnswers {
    async fn publish(&self, id: String, answer: Answer) -> Result<(), IssueError> {
        let published = Published {
            answer,
            owner: self.lease.name.clone(),
            created_at_ms: SystemClock.now_ms(),
        };
        let json = serde_json::to_vec(&published)
            .map_err(|e| IssueError::Cluster(format!("cannot encode the answer: {e}")))?;
        self.cluster
            .store
            .put(
                &format!("challenges/{id}"),
                json,
                Expect::Any,
                Some(&self.lease),
            )
            .await
            .map_err(|e| IssueError::Cluster(format!("cannot share the challenge answer: {e}")))?;
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id);
        Ok(())
    }

    fn ids(&self) -> Vec<String> {
        self.ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }
}

#[async_trait]
impl AnswerSink for ClusterAnswers {
    async fn add_http01(&self, token: &str, key_authorization: &str) -> Result<(), IssueError> {
        self.local.add_http01(token, key_authorization).await?;
        let answer = Answer::Http01 {
            token: token.to_owned(),
            key_authorization: key_authorization.to_owned(),
        };
        self.publish(http01_id(token), answer).await
    }

    async fn add_tls_alpn01(&self, name: &str, digest: &[u8]) -> Result<(), IssueError> {
        self.local.add_tls_alpn01(name, digest).await?;
        let digest = hex(digest);
        let id = tls_alpn01_id(name, &digest);
        let answer = Answer::TlsAlpn01 {
            name: name.to_owned(),
            digest,
        };
        self.publish(id, answer).await
    }

    /// The barrier: waits until every live member confirmed every answer of this order, or
    /// until the timeout.
    async fn ready(&self) -> Result<(), IssueError> {
        let ids = self.ids();
        if ids.is_empty() {
            return Ok(());
        }
        let deadline = Instant::now() + self.cluster.barrier_timeout;
        let mut seen = Seen::new();
        loop {
            let live = self
                .cluster
                .live_members(&mut seen)
                .await
                .unwrap_or_default();
            let mut missing: BTreeSet<String> = BTreeSet::new();
            for id in &ids {
                let acked: BTreeSet<String> = self
                    .cluster
                    .store
                    .list(&format!("challenge-acks/{id}"))
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|k| k.rsplit('/').next().map(str::to_owned))
                    .collect();
                missing.extend(live.iter().filter(|m| !acked.contains(*m)).cloned());
            }
            if missing.is_empty() {
                debug!(
                    members = live.len(),
                    "every live member holds the challenge answers"
                );
                self.cluster.count_barrier("complete");
                return Ok(());
            }
            if Instant::now() >= deadline {
                warn!(
                    missing = %missing.into_iter().collect::<Vec<_>>().join(", "),
                    "members did not confirm the challenge answers in time; they cannot answer this validation, which goes ahead"
                );
                self.cluster.count_barrier("timeout");
                return Ok(());
            }
            tokio::time::sleep(POLL).await;
        }
    }

    async fn clear(&self) {
        let ids = std::mem::take(&mut *self.ids.lock().unwrap_or_else(PoisonError::into_inner));
        for id in ids {
            withdraw(self.cluster.store.as_ref(), &id, Some(&self.lease)).await;
        }
        self.local.clear().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holds(challenges: &Challenges, name: &str, digest: &[u8]) -> bool {
        challenges.tls_alpn01(name).is_some_and(|key| {
            key.cert[0]
                .as_ref()
                .windows(digest.len())
                .any(|w| w == digest)
        })
    }

    /// Review finding M2: a TLS-ALPN-01 answer withdrawn and published again for the same name
    /// within one poll (the staging rehearsal followed at once by the production order) reaches
    /// every member, and the barrier waits for fresh confirmations instead of timing out on
    /// stale ones. Leftovers of an earlier holder are withdrawn by the next one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_republished_tls_alpn01_answer_replaces_the_old_one() {
        let store: Arc<dyn ClusterStore> = Arc::new(rdock_cluster::MemoryStore::new());
        let member = |name: &str| ClusterAcme {
            store: store.clone(),
            instance: name.to_owned(),
            lease_ttl: Duration::from_secs(30),
            barrier_timeout: Duration::from_secs(5),
            metrics: None,
        };
        let (a, b) = (member("edge-a"), member("edge-b"));
        let (on_a, on_b) = (
            Arc::new(Challenges::default()),
            Arc::new(Challenges::default()),
        );
        a.start_replication(on_a.clone());
        b.start_replication(on_b.clone());
        let deadline = Instant::now() + Duration::from_secs(10);
        while store.list("members").await.unwrap().len() < 2 {
            assert!(Instant::now() < deadline, "no heartbeats");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let lease = store
            .acquire("cert/x.example", "edge-a", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();
        let first = a.answers(on_a.clone(), lease.clone());
        first.add_tls_alpn01("x.example", &[1; 32]).await.unwrap();
        first.ready().await.unwrap();
        assert!(holds(&on_b, "x.example", &[1; 32]));
        first.clear().await;
        let second = a.answers(on_a.clone(), lease.clone());
        second.add_tls_alpn01("x.example", &[2; 32]).await.unwrap();
        let started = Instant::now();
        second.ready().await.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the barrier timed out: {:?}",
            started.elapsed()
        );
        assert!(
            holds(&on_b, "x.example", &[2; 32]),
            "edge-b kept the old answer"
        );
        assert!(holds(&on_a, "x.example", &[2; 32]));
        // The holder dies without withdrawing; the next holder withdraws what it left first.
        assert_eq!(store.list("challenges").await.unwrap().len(), 1);
        b.withdraw_leftovers(&lease).await;
        assert_eq!(store.list("challenges").await.unwrap().len(), 0);
        assert_eq!(store.list("challenge-acks").await.unwrap().len(), 0);
    }

    #[test]
    fn digests_travel_as_hex() {
        let digest = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&digest)).unwrap(), digest);
        assert!(unhex("abc").is_none());
        assert_eq!(http01_id("aB-_9"), "http-aB--9");
        assert_eq!(
            tls_alpn01_id("*.example.com", "0123456789abcdef0123"),
            "alpn-_.example.com-0123456789abcdef"
        );
    }
}
