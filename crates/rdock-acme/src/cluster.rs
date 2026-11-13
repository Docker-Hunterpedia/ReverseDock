//! Certificates in a cluster (ADR-0031): challenge answers replicated to every member through
//! the cluster store, with a barrier before the CA is told to validate.
//!
//! - Every member writes `members/<instance>` every few seconds (its heartbeat) and polls
//!   `challenges/` in the background, copying each answer into its own lock-free maps (the data
//!   plane never reads the store on the request path, ADR-0020) and confirming it with
//!   `challenge-acks/<id>/<instance>`.
//! - The member that orders writes its answers to `challenges/<id>` and waits until every live
//!   member (a heartbeat younger than [`MEMBER_TTL`]) confirmed each one, or until the barrier
//!   timeout. Members that have not confirmed by then cannot answer; validation goes ahead,
//!   because a member that is away should not stop every other member from getting a
//!   certificate. A member cut off from the store that still receives public traffic is the
//!   case DNS-01 avoids, which is why validation recommends DNS-01 for clusters.
//!
//! For TLS-ALPN-01 only the name and the digest of the key authorization travel; each member
//! builds its own validation certificate from them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rdock_cluster::store::segment;
use rdock_cluster::{Clock, ClusterStore, Expect, SystemClock};
use rdock_observability::Metrics;
use rdock_tls::Challenges;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::issue::{AnswerSink, IssueError, validation_certificate};

/// How often members poll for answers and how often the barrier looks for confirmations.
const POLL: Duration = Duration::from_millis(250);
/// How often a member writes its heartbeat.
const HEARTBEAT: Duration = Duration::from_secs(5);
/// A member whose heartbeat is older than this is away: barriers do not wait for it.
pub const MEMBER_TTL: Duration = Duration::from_secs(20);

/// What a member of a cluster needs to issue certificates with the others.
#[derive(Debug, Clone)]
pub struct ClusterAcme {
    /// The shared store.
    pub store: Arc<dyn ClusterStore>,
    /// This instance's name in leases, heartbeats and confirmations.
    pub instance: String,
    /// The lease on a certificate name (`cluster.store.lease_ttl`).
    pub lease_ttl: Duration,
    /// How long the barrier waits (`cluster.store.barrier_timeout`).
    pub barrier_timeout: Duration,
    /// Barrier and lease counters.
    pub metrics: Option<Metrics>,
}

/// A replicated answer (`challenges/<id>`).
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

/// A heartbeat (`members/<instance>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Heartbeat {
    instance: String,
    /// By the member's clock, in milliseconds since the Unix epoch.
    at_ms: u64,
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

fn tls_alpn01_id(name: &str) -> String {
    format!("alpn-{}", segment(name))
}

impl ClusterAcme {
    /// The answer sink of one order.
    #[must_use]
    pub fn answers(&self, challenges: Arc<Challenges>) -> Arc<dyn AnswerSink> {
        Arc::new(ClusterAnswers {
            cluster: self.clone(),
            local: crate::issue::LocalAnswers::new(challenges),
            ids: Mutex::new(BTreeSet::new()),
        })
    }

    /// Starts the heartbeat and the background copy of other members' answers into
    /// `challenges`; runs until the process ends.
    pub fn start_replication(&self, challenges: Arc<Challenges>) {
        let cluster = self.clone();
        tokio::spawn(async move { cluster.replicate(challenges).await });
    }

    async fn replicate(self, challenges: Arc<Challenges>) {
        let clock = SystemClock;
        let mut applied: BTreeMap<String, Answer> = BTreeMap::new();
        let mut last_beat: Option<Instant> = None;
        let mut failing = false;
        loop {
            if last_beat.is_none_or(|at| at.elapsed() >= HEARTBEAT) {
                let beat = Heartbeat {
                    instance: self.instance.clone(),
                    at_ms: clock.now_ms(),
                };
                if let Ok(json) = serde_json::to_vec(&beat) {
                    match self
                        .store
                        .put(
                            &format!("members/{}", self.instance),
                            json,
                            Expect::Any,
                            None,
                        )
                        .await
                    {
                        Ok(_) => last_beat = Some(Instant::now()),
                        Err(e) => debug!(error = %e, "cannot write the cluster heartbeat"),
                    }
                }
            }
            match self.sync_answers(&challenges, &mut applied).await {
                Ok(()) => {
                    if failing {
                        info!("the cluster store answers again; challenge answers are replicated");
                    }
                    failing = false;
                }
                Err(e) => {
                    if !failing {
                        warn!(error = %e, "cannot read challenge answers from the cluster store");
                    }
                    failing = true;
                }
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Copies new answers into `challenges`, confirms them, and removes withdrawn ones.
    async fn sync_answers(
        &self,
        challenges: &Challenges,
        applied: &mut BTreeMap<String, Answer>,
    ) -> Result<(), rdock_cluster::StoreError> {
        let keys = self.store.list("challenges").await?;
        let ids: BTreeSet<String> = keys
            .iter()
            .filter_map(|k| k.strip_prefix("challenges/"))
            .filter(|id| !id.contains('/'))
            .map(str::to_owned)
            .collect();
        let new: Vec<String> = ids
            .iter()
            .filter(|id| !applied.contains_key(*id))
            .cloned()
            .collect();
        for id in &new {
            let Some(entry) = self.store.get(&format!("challenges/{id}")).await? else {
                continue;
            };
            let Ok(answer) = serde_json::from_slice::<Answer>(&entry.value) else {
                warn!(%id, "ignoring an unreadable challenge answer in the cluster store");
                continue;
            };
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
            applied.insert(id.clone(), answer);
        }
        let gone: Vec<String> = applied
            .keys()
            .filter(|id| !ids.contains(*id))
            .cloned()
            .collect();
        for id in gone {
            match applied.remove(&id) {
                Some(Answer::Http01 { token, .. }) => challenges.remove_http01(&token),
                Some(Answer::TlsAlpn01 { name, .. }) => challenges.remove_tls_alpn01(&name),
                None => {}
            }
        }
        Ok(())
    }

    /// The members whose heartbeat is younger than [`MEMBER_TTL`], by this instance's clock.
    async fn live_members(&self) -> Result<BTreeSet<String>, rdock_cluster::StoreError> {
        let now = SystemClock.now_ms();
        let ttl = u64::try_from(MEMBER_TTL.as_millis()).unwrap_or(u64::MAX);
        let mut live = BTreeSet::new();
        for key in self.store.list("members").await? {
            let Some(entry) = self.store.get(&key).await? else {
                continue;
            };
            if let Ok(beat) = serde_json::from_slice::<Heartbeat>(&entry.value)
                && now.saturating_sub(beat.at_ms) < ttl
            {
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

/// The answers of one order: local maps at once, the store for the others.
struct ClusterAnswers {
    cluster: ClusterAcme,
    local: crate::issue::LocalAnswers,
    ids: Mutex<BTreeSet<String>>,
}

impl ClusterAnswers {
    async fn publish(&self, id: String, answer: &Answer) -> Result<(), IssueError> {
        let json = serde_json::to_vec(answer)
            .map_err(|e| IssueError::Cluster(format!("cannot encode the answer: {e}")))?;
        self.cluster
            .store
            .put(&format!("challenges/{id}"), json, Expect::Any, None)
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
        self.publish(http01_id(token), &answer).await
    }

    async fn add_tls_alpn01(&self, name: &str, digest: &[u8]) -> Result<(), IssueError> {
        self.local.add_tls_alpn01(name, digest).await?;
        let answer = Answer::TlsAlpn01 {
            name: name.to_owned(),
            digest: hex(digest),
        };
        self.publish(tls_alpn01_id(name), &answer).await
    }

    /// The barrier: waits until every live member confirmed every answer of this order, or
    /// until the timeout.
    async fn ready(&self) -> Result<(), IssueError> {
        let ids = self.ids();
        if ids.is_empty() {
            return Ok(());
        }
        let deadline = Instant::now() + self.cluster.barrier_timeout;
        loop {
            let live = self.cluster.live_members().await.unwrap_or_default();
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
            let store = &self.cluster.store;
            if let Err(e) = store
                .delete(&format!("challenges/{id}"), Expect::Any, None)
                .await
            {
                warn!(%id, error = %e, "cannot withdraw a challenge answer from the cluster store");
            }
            for key in store
                .list(&format!("challenge-acks/{id}"))
                .await
                .unwrap_or_default()
            {
                let _ = store.delete(&key, Expect::Any, None).await;
            }
        }
        self.local.clear().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_travel_as_hex() {
        let digest = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&digest)).unwrap(), digest);
        assert!(unhex("abc").is_none());
        assert_eq!(http01_id("aB-_9"), "http-aB--9");
        assert_eq!(tls_alpn01_id("*.example.com"), "alpn-_.example.com");
    }
}
