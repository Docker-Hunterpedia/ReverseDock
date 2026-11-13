//! Cluster-scoped limits (ADR-0031), on the store's side: the backends that hold each key's
//! claimed total (the [`ClusterStore`] or a Redis-compatible server) and the background task
//! that sends the claims [`SharedLimits`] queues, keeps the member count and notices when the
//! store goes away and comes back. The request path never waits on any of it.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rdock_limits::shared::{Claim, SharedLimits};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::clock::{Clock, SystemClock};
use crate::resp::{RespClient, RespError};
use crate::store::{ClusterStore, Expect, StoreError, segment};

/// A member whose heartbeat has not changed for this long no longer counts.
pub const MEMBER_TTL: Duration = Duration::from_secs(15);

/// Claims sent at once by the background task.
const CONCURRENT_CLAIMS: usize = 16;

/// How often the heartbeat is written and the members counted.
const HEARTBEAT: Duration = Duration::from_secs(3);

/// How often records of past windows are removed from a cluster store.
const CLEANUP: Duration = Duration::from_secs(60);

/// Where claimed totals are kept.
#[async_trait]
pub trait ShareBackend: Send + Sync + fmt::Debug {
    /// Adds up to `amount` to the total of `key` in `budget`'s window `window` (start and end,
    /// Unix milliseconds), without passing `limit` (exactly `amount` when `forced`). Returns
    /// what was granted and the total after it.
    async fn claim(
        &self,
        budget: &str,
        window: (u64, u64),
        key: &str,
        amount: u64,
        limit: u64,
        forced: bool,
    ) -> Result<(u64, u64), StoreError>;

    /// Writes this instance's heartbeat and returns how many members are live (at least 1).
    async fn heartbeat(&self, instance: &str) -> Result<u64, StoreError>;

    /// Removes the records of `budget`'s windows that ended more than
    /// [`crate::janitor::WINDOW_MARGIN`] before `now_ms`, so a member whose clock runs behind
    /// still finds the window it is in (review finding M6).
    async fn cleanup(&self, budget: &str, now_ms: u64) -> Result<(), StoreError> {
        let _ = (budget, now_ms);
        Ok(())
    }
}

/// The store key of a limit key: the first 128 bits of its SHA-256, in hex (keys may hold
/// IP addresses, consumer names or header values, which are neither key-safe nor needed in the
/// store).
#[must_use]
pub fn digest(key: &str) -> String {
    use std::fmt::Write as _;
    let hash = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
    hash.as_ref()[..16]
        .iter()
        .fold(String::with_capacity(32), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

#[derive(Serialize, Deserialize)]
struct Total {
    total: u64,
}

#[derive(Serialize, Deserialize)]
struct Beat {
    at_ms: u64,
}

/// Totals in a [`ClusterStore`] (`limits/<budget>/<window end>-<key digest>`, see
/// [`crate::janitor::limit_key`]), updated with compare-and-swap; heartbeats in
/// `limits/members/<instance>`.
#[derive(Debug, Clone)]
pub struct StoreShares {
    store: Arc<dyn ClusterStore>,
    clock: Arc<dyn Clock>,
    /// Each heartbeat as last read and when it last changed, by this instance's monotonic
    /// clock: a member counts while its heartbeat keeps changing, whatever the clocks say.
    seen: Arc<Mutex<HashMap<String, (u64, Instant)>>>,
}

impl StoreShares {
    /// Totals in `store`.
    #[must_use]
    pub fn new(store: Arc<dyn ClusterStore>) -> Self {
        Self::with_clock(store, Arc::new(SystemClock))
    }

    /// Totals in `store`, with `clock` for heartbeats and window ends (tests skew it).
    #[must_use]
    pub fn with_clock(store: Arc<dyn ClusterStore>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            clock,
            seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Whether the heartbeat `key` read as `at_ms` counts as live: it changed within
    /// [`MEMBER_TTL`] by this instance's monotonic clock; one seen for the first time counts
    /// when its time is within [`MEMBER_TTL`] of this instance's clock (review finding M6).
    fn live(&self, key: &str, at_ms: u64, now_ms: u64) -> bool {
        let ttl = u64::try_from(MEMBER_TTL.as_millis()).unwrap_or(u64::MAX);
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        match seen.get(key) {
            Some((at, changed)) if *at == at_ms => changed.elapsed() <= MEMBER_TTL,
            Some(_) => {
                seen.insert(key.to_owned(), (at_ms, Instant::now()));
                true
            }
            None => {
                let close = now_ms.abs_diff(at_ms) <= ttl;
                let changed = if close {
                    Instant::now()
                } else {
                    Instant::now()
                        .checked_sub(MEMBER_TTL + Duration::from_millis(1))
                        .unwrap_or_else(Instant::now)
                };
                seen.insert(key.to_owned(), (at_ms, changed));
                close
            }
        }
    }
}

#[async_trait]
impl ShareBackend for StoreShares {
    async fn claim(
        &self,
        budget: &str,
        window: (u64, u64),
        key: &str,
        amount: u64,
        limit: u64,
        forced: bool,
    ) -> Result<(u64, u64), StoreError> {
        let path = crate::janitor::limit_key(budget, window.1, key);
        let mut seen = 0;
        for _ in 0..16 {
            let current = self.store.get(&path).await?;
            let (total, expect) = match &current {
                Some(entry) => (
                    serde_json::from_slice::<Total>(&entry.value).map_or(0, |t| t.total),
                    Expect::Version(entry.version),
                ),
                None => (0, Expect::Absent),
            };
            seen = total;
            let grant = if forced {
                amount
            } else {
                amount.min(limit.saturating_sub(total))
            };
            if grant == 0 {
                return Ok((0, total));
            }
            let after = total.saturating_add(grant);
            let value = serde_json::to_vec(&Total { total: after })
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            match self.store.put(&path, value, expect, None).await {
                Ok(_) => return Ok((grant, after)),
                Err(StoreError::Conflict { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        // Too much contention: grant nothing this time; the claim is asked again.
        Ok((0, seen))
    }

    async fn heartbeat(&self, instance: &str) -> Result<u64, StoreError> {
        let now = self.clock.now_ms();
        let beat = serde_json::to_vec(&Beat { at_ms: now })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        self.store
            .put(
                &format!("limits/members/{}", segment(instance)),
                beat,
                Expect::Any,
                None,
            )
            .await?;
        let own = format!("limits/members/{}", segment(instance));
        let mut live = 0u64;
        for key in self.store.list("limits/members").await? {
            if key == own {
                live += 1;
                continue;
            }
            if let Some(entry) = self.store.get(&key).await?
                && let Ok(beat) = serde_json::from_slice::<Beat>(&entry.value)
                && self.live(&key, beat.at_ms, now)
            {
                live += 1;
            }
        }
        Ok(live.max(1))
    }

    async fn cleanup(&self, budget: &str, now_ms: u64) -> Result<(), StoreError> {
        crate::janitor::tidy_limits(self.store.as_ref(), budget, now_ms).await
    }
}

/// Totals in a Redis-compatible server: `INCRBY`, then `DECRBY` of what passed the limit, so
/// concurrent claims never grant more than the limit in total; each key expires a minute
/// after its window. Members are a sorted set scored by heartbeat time.
#[derive(Debug)]
pub struct RedisShares {
    client: RespClient,
    prefix: String,
    clock: Arc<dyn Clock>,
}

impl RedisShares {
    /// Totals through `client`, under `prefix`.
    #[must_use]
    pub fn new(client: RespClient, prefix: &str) -> Self {
        Self {
            client,
            prefix: prefix.to_owned(),
            clock: Arc::new(SystemClock),
        }
    }
}

fn unavailable(e: &RespError) -> StoreError {
    StoreError::Unavailable(e.to_string())
}

#[async_trait]
impl ShareBackend for RedisShares {
    async fn claim(
        &self,
        budget: &str,
        window: (u64, u64),
        key: &str,
        amount: u64,
        limit: u64,
        forced: bool,
    ) -> Result<(u64, u64), StoreError> {
        let path = format!("{}limits:{budget}:{}:{key}", self.prefix, window.0);
        let amount_text = amount.to_string();
        let after = self
            .client
            .command(&[b"INCRBY", path.as_bytes(), amount_text.as_bytes()])
            .await
            .and_then(|r| r.integer())
            .map_err(|e| unavailable(&e))?;
        let after = u64::try_from(after).unwrap_or(0);
        let excess = if forced {
            0
        } else {
            amount.min(after.saturating_sub(limit))
        };
        if excess > 0 {
            let text = excess.to_string();
            self.client
                .command(&[b"DECRBY", path.as_bytes(), text.as_bytes()])
                .await
                .map_err(|e| unavailable(&e))?;
        }
        let expire = window.1.saturating_add(60_000).to_string();
        self.client
            .command(&[b"PEXPIREAT", path.as_bytes(), expire.as_bytes()])
            .await
            .map_err(|e| unavailable(&e))?;
        Ok((amount - excess, after - excess))
    }

    /// Scored and pruned by the server's clock (`TIME`), so members whose clocks disagree
    /// still count each other (review finding M6); a server without `TIME` falls back to this
    /// instance's clock.
    async fn heartbeat(&self, instance: &str) -> Result<u64, StoreError> {
        let set = format!("{}members", self.prefix);
        let now = match self.client.command(&[b"TIME"]).await {
            Ok(reply) => reply.time_ms().map_err(|e| unavailable(&e))?,
            Err(RespError::Refused(_)) => self.clock.now_ms(),
            Err(e) => return Err(unavailable(&e)),
        };
        let score = now.to_string();
        self.client
            .command(&[
                b"ZADD",
                set.as_bytes(),
                score.as_bytes(),
                instance.as_bytes(),
            ])
            .await
            .map_err(|e| unavailable(&e))?;
        let oldest = now
            .saturating_sub(u64::try_from(MEMBER_TTL.as_millis()).unwrap_or(0))
            .to_string();
        self.client
            .command(&[
                b"ZREMRANGEBYSCORE",
                set.as_bytes(),
                b"-inf",
                format!("({oldest}").as_bytes(),
            ])
            .await
            .map_err(|e| unavailable(&e))?;
        let count = self
            .client
            .command(&[b"ZCARD", set.as_bytes()])
            .await
            .and_then(|r| r.integer())
            .map_err(|e| unavailable(&e))?;
        Ok(u64::try_from(count).unwrap_or(1).max(1))
    }
}

/// What the background task reports, for metrics.
pub trait Observer: Send + Sync {
    /// The store answers (`true`) or not.
    fn store(&self, up: bool);
    /// A claim ended: `granted`, `exhausted` (nothing left), `forced` or `failed`.
    fn claim(&self, outcome: &'static str);
    /// The number of live members.
    fn members(&self, count: u64);
}

/// The background task of cluster-scoped limits.
pub struct LimitsDriver {
    /// The budgets of this process.
    pub limits: SharedLimits,
    /// Where totals are kept.
    pub backend: Arc<dyn ShareBackend>,
    /// This instance's name.
    pub instance: String,
    /// How often membership and recovery are attended to.
    pub sync_interval: Duration,
    /// Metrics.
    pub observer: Arc<dyn Observer>,
    /// Name of the store in log lines (`cluster store`, `redis`).
    pub store_name: &'static str,
}

impl LimitsDriver {
    /// Runs until `stop` turns true.
    pub async fn run(self, mut stop: tokio::sync::watch::Receiver<bool>) {
        self.limits.attach();
        let mut tick = tokio::time::interval(self.sync_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_beat: Option<Instant> = None;
        let mut last_cleanup = Instant::now();
        let mut reported: Option<bool> = None;
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                _ = tick.tick() => {}
                () = self.limits.wanted() => {}
            }
            let up = self.limits.store_up();
            if !up || last_beat.is_none_or(|at| at.elapsed() >= HEARTBEAT) {
                match self.backend.heartbeat(&self.instance).await {
                    Ok(members) => {
                        last_beat = Some(Instant::now());
                        self.limits.set_members(members);
                        self.observer.members(members);
                        self.set_up(true, None, &mut reported);
                    }
                    Err(e) => {
                        self.set_up(false, Some(&e), &mut reported);
                        for claim in self.limits.drain() {
                            claim.budget.failed(&claim.key, claim.window);
                        }
                        continue;
                    }
                }
            }
            self.send_claims(&mut reported).await;
            if self.limits.store_up() && last_cleanup.elapsed() >= CLEANUP {
                last_cleanup = Instant::now();
                let now = SystemClock.now_ms();
                for budget in self.limits.budgets() {
                    if let Err(e) = self.backend.cleanup(budget.id(), now).await {
                        tracing::debug!(error = %e, budget = budget.id(), "cannot remove past limit windows");
                    }
                }
            }
        }
    }

    /// Sends the queued claims, up to [`CONCURRENT_CLAIMS`] at once, so a burst of new keys
    /// is not answered one store round trip after another (review finding M4). The first
    /// failure marks the store away; claims not answered yet are failed (asked again later).
    async fn send_claims(&self, reported: &mut Option<bool>) {
        let mut queue: std::collections::VecDeque<Claim> = self.limits.drain().into();
        let mut running = tokio::task::JoinSet::new();
        let mut failure: Option<StoreError> = None;
        loop {
            while failure.is_none() && running.len() < CONCURRENT_CLAIMS {
                let Some(claim) = queue.pop_front() else {
                    break;
                };
                let backend = self.backend.clone();
                running.spawn(async move {
                    let result = backend
                        .claim(
                            claim.budget.id(),
                            claim.window,
                            &digest(&claim.key),
                            claim.amount,
                            claim.limit,
                            claim.forced,
                        )
                        .await;
                    (claim, result)
                });
            }
            let Some(joined) = running.join_next().await else {
                break;
            };
            let Ok((claim, result)) = joined else {
                continue;
            };
            match result {
                Ok((granted, total)) => {
                    claim.budget.granted(
                        &claim.key,
                        claim.window,
                        granted,
                        total,
                        claim.amount,
                        claim.forced,
                    );
                    self.observer.claim(if claim.forced {
                        "forced"
                    } else if granted < claim.amount {
                        "exhausted"
                    } else {
                        "granted"
                    });
                }
                Err(e) => {
                    self.observer.claim("failed");
                    claim.budget.failed(&claim.key, claim.window);
                    failure.get_or_insert(e);
                }
            }
            if failure.is_none() && queue.is_empty() {
                queue.extend(self.limits.drain());
            }
        }
        if let Some(e) = failure {
            for rest in queue.drain(..) {
                rest.budget.failed(&rest.key, rest.window);
            }
            self.set_up(false, Some(&e), reported);
        }
    }

    fn set_up(&self, up: bool, error: Option<&StoreError>, reported: &mut Option<bool>) {
        if *reported != Some(up) {
            match (up, error) {
                (true, _) if reported.is_some() => {
                    info!(
                        store = self.store_name,
                        "the limit store answers again; cluster-scoped limits are shared again"
                    );
                }
                (true, _) => {
                    info!(
                        store = self.store_name,
                        "cluster-scoped limits are shared through the store"
                    );
                }
                (false, Some(e)) => {
                    warn!(store = self.store_name, error = %e, "the limit store is away; cluster-scoped limits fall back to each instance's share");
                }
                (false, None) => {
                    warn!(
                        store = self.store_name,
                        "the limit store is away; cluster-scoped limits fall back to each instance's share"
                    );
                }
            }
            *reported = Some(up);
            self.observer.store(up);
        }
        self.limits.set_store_up(up);
    }
}

#[cfg(test)]
mod tests {
    use rdock_limits::shared::{Take, WindowKind, bound};

    use super::*;
    use crate::MemoryStore;

    struct Quiet;

    impl Observer for Quiet {
        fn store(&self, _: bool) {}
        fn claim(&self, _: &'static str) {}
        fn members(&self, _: u64) {}
    }

    #[tokio::test]
    async fn claims_never_pass_the_limit_and_forced_claims_count() {
        let shares = StoreShares::new(Arc::new(MemoryStore::new()));
        let window = (0, 60_000);
        assert_eq!(
            shares.claim("b", window, "k", 6, 10, false).await.unwrap(),
            (6, 6)
        );
        assert_eq!(
            shares.claim("b", window, "k", 6, 10, false).await.unwrap(),
            (4, 10)
        );
        assert_eq!(
            shares.claim("b", window, "k", 1, 10, false).await.unwrap(),
            (0, 10)
        );
        assert_eq!(
            shares.claim("b", window, "k", 3, 10, true).await.unwrap(),
            (3, 13)
        );
        // Another window starts from zero; the old one is cleaned up.
        assert_eq!(
            shares
                .claim("b", (60_000, 120_000), "k", 2, 10, false)
                .await
                .unwrap(),
            (2, 2)
        );
        // A window's total is removed a minute after the window ended, not before.
        shares.cleanup("b", 119_999).await.unwrap();
        assert_eq!(shares.store.list("limits/b").await.unwrap().len(), 2);
        shares.cleanup("b", 120_000).await.unwrap();
        assert_eq!(
            shares.store.list("limits/b").await.unwrap(),
            vec!["limits/b/120000-k"]
        );
        assert_eq!(shares.heartbeat("edge-1").await.unwrap(), 1);
        assert_eq!(shares.heartbeat("edge-2").await.unwrap(), 2);
        assert_eq!(digest("ip:192.0.2.1").len(), 32);
    }

    /// Review finding M6: an instance whose clock runs ahead cleans up when its own window has
    /// moved on while another instance still claims in the previous one; the previous window's
    /// total survives, so the other's claims are still capped by what was granted.
    #[tokio::test]
    async fn a_clock_ahead_does_not_remove_a_window_still_in_use() {
        let store: Arc<dyn ClusterStore> = Arc::new(MemoryStore::new());
        let start = 1_800_000_000_000u64;
        let clock = crate::ManualClock::new(start);
        let ahead = StoreShares::with_clock(store.clone(), Arc::new(clock.skewed(100)));
        let behind = StoreShares::with_clock(store.clone(), Arc::new(clock.clone()));
        let window = (start - 1_000, start);
        assert_eq!(
            behind.claim("b", window, "k", 10, 10, false).await.unwrap(),
            (10, 10)
        );
        // `ahead` is 100 ms into the next window and tidies up.
        ahead.cleanup("b", start + 100).await.unwrap();
        // `behind` is still in the old window: nothing is left there.
        assert_eq!(
            behind.claim("b", window, "k", 5, 10, false).await.unwrap(),
            (0, 10)
        );
    }

    /// Members count while their heartbeat changes, whatever their clocks say: an instance
    /// whose clock runs 20 s ahead still counts the others, and a member whose heartbeat stops
    /// changing stops counting once it has not changed for the TTL.
    #[tokio::test]
    async fn members_count_by_change_not_by_clock() {
        let store: Arc<dyn ClusterStore> = Arc::new(MemoryStore::new());
        let clock = crate::ManualClock::new(1_800_000_000_000);
        let ahead = StoreShares::with_clock(store.clone(), Arc::new(clock.skewed(20_000)));
        let other = StoreShares::with_clock(store.clone(), Arc::new(clock.clone()));
        assert_eq!(other.heartbeat("edge-2").await.unwrap(), 1);
        // Seen for the first time, 20 s off: not counted yet.
        assert_eq!(ahead.heartbeat("edge-1").await.unwrap(), 1);
        clock.advance(3_000);
        // `other` sees `edge-1` for the first time, 20 s ahead of its own clock: not yet.
        assert_eq!(other.heartbeat("edge-2").await.unwrap(), 1);
        // `edge-2`'s heartbeat changed: counted, though by `ahead`'s clock it is 17 s old.
        assert_eq!(ahead.heartbeat("edge-1").await.unwrap(), 2);
        clock.advance(3_000);
        assert_eq!(other.heartbeat("edge-2").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn claims_on_a_directory_store() {
        let dir = tempfile::tempdir().unwrap();
        let shares = StoreShares::new(Arc::new(crate::DirStore::exclusive(dir.path())));
        for i in 0..5u64 {
            let started = Instant::now();
            assert_eq!(
                shares
                    .claim("rl-x", (0, 60_000), "k", 2, 30, false)
                    .await
                    .unwrap(),
                (2, 2 * (i + 1))
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{:?}",
                started.elapsed()
            );
        }
    }

    /// Three instances' drivers on one store: the total admitted stays within the bound, and
    /// without the store each admits its share.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_drivers_share_one_budget() {
        let store: Arc<dyn ClusterStore> = Arc::new(MemoryStore::new());
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let mut budgets = Vec::new();
        for i in 0..3 {
            let limits = SharedLimits::default();
            limits.configure(10, false);
            let driver = LimitsDriver {
                limits: limits.clone(),
                backend: Arc::new(StoreShares::new(store.clone())),
                instance: format!("edge-{i}"),
                sync_interval: Duration::from_millis(100),
                observer: Arc::new(Quiet),
                store_name: "cluster store",
            };
            tokio::spawn(driver.run(stop_rx.clone()));
            budgets.push((
                limits.clone(),
                limits.budget("q-test", WindowKind::Fixed(Duration::from_secs(3600))),
            ));
        }
        // Wait for every driver to see three members.
        let deadline = Instant::now() + Duration::from_secs(20);
        while budgets
            .iter()
            .any(|(l, _)| l.members() != 3 || !l.store_up())
        {
            assert!(
                Instant::now() < deadline,
                "the drivers did not count three members"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let limit = 60;
        let mut admitted = 0u64;
        for _ in 0..200 {
            for (_, budget) in &budgets {
                if matches!(budget.take("k", limit), Take::Allowed { .. }) {
                    admitted += 1;
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(admitted <= bound(limit, 10, 3), "admitted {admitted}");
        assert!(admitted >= limit - 3, "admitted only {admitted}");
        let _ = stop.send(true);
    }
}
