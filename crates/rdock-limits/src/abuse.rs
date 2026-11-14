//! Abuse counters and bans (H-SEC-01, ADR-0031): events per key in a fixed window, and a ban
//! list with expiry, per `abuse` middleware.
//!
//! The counter table and the ban list are separate and both bounded. Counters may be dropped
//! (the oldest window first) when the table is full; a ban is never dropped before it ends: a
//! full ban list refuses new bans instead, so an attacker who churns keys cannot lift an
//! existing ban. Bans are written to `<data dir>/abuse/<middleware>.json` (`0600`) and read
//! back at start, so a restart or a binary upgrade keeps them. Counts and bans are per
//! instance; [`BanStore`] is the seam a cluster store will implement.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::quota::{Clock, SystemClock};

/// How many counters a full table looks at to find one to drop.
const EVICTION_SAMPLE: usize = 32;

/// One ban.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ban {
    /// The banned key (`ip:192.0.2.1`, `ip:2001:db8:1:2::/64`, `consumer:…`, `ja4:…`,
    /// `header:…`).
    pub key: String,
    /// When it started (Unix seconds).
    pub since: i64,
    /// When it ends (Unix seconds).
    pub until: i64,
}

/// What [`Abuse::record`] did with an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// Counted, below the threshold.
    Counted,
    /// The threshold was reached: the key is banned now.
    Banned,
    /// The threshold was reached but the ban list is full.
    Refused,
}

/// Where bans live: in memory with a file per middleware today; a cluster store later.
pub trait BanStore: Send + Sync + std::fmt::Debug {
    /// The ban of `key`, if one is in force at `now`.
    fn get(&self, key: &str, now: i64) -> Option<Ban>;
    /// Starts a ban; `false` when the list is full.
    fn insert(&self, ban: Ban, now: i64) -> bool;
    /// Lifts the ban of `key`; whether there was one.
    fn remove(&self, key: &str) -> bool;
    /// Every ban in force at `now`, by key.
    fn list(&self, now: i64) -> Vec<Ban>;
}

/// The bans of one middleware, in memory, written to a file when they change.
#[derive(Debug)]
pub struct LocalBans {
    bans: Mutex<HashMap<String, Ban>>,
    max: usize,
    path: Option<PathBuf>,
    dirty: AtomicBool,
}

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    bans: Vec<Ban>,
}

impl LocalBans {
    /// Bans of at most `max` keys, read from `path` when it exists (bans already over are
    /// dropped).
    #[must_use]
    pub fn open(max: usize, path: Option<PathBuf>, now: i64) -> Self {
        let mut bans = HashMap::new();
        if let Some(file) = path.as_ref().and_then(|p| read(p)) {
            for ban in file.bans.into_iter().filter(|b| b.until > now) {
                if bans.len() < max {
                    bans.insert(ban.key.clone(), ban);
                }
            }
        }
        Self {
            bans: Mutex::new(bans),
            max,
            path,
            dirty: AtomicBool::new(false),
        }
    }

    /// Writes the bans if they changed since the last write.
    pub fn flush(&self, now: i64) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        let mut bans = self.list(now);
        bans.sort_by(|a, b| a.key.cmp(&b.key));
        let bytes = serde_json::to_vec(&File { version: 1, bans }).map_err(io::Error::other)?;
        crate::quota::write_atomic(path, &bytes).inspect_err(|_| {
            self.dirty.store(true, Ordering::SeqCst);
        })
    }

    /// Reads the file again (after another process wrote it, in a binary upgrade), keeping
    /// bans of this process that the file does not have.
    pub fn reread(&self, now: i64) {
        let Some(file) = self.path.as_ref().and_then(|p| read(p)) else {
            return;
        };
        let mut bans = self.bans.lock().unwrap_or_else(PoisonError::into_inner);
        for ban in file.bans.into_iter().filter(|b| b.until > now) {
            if bans.len() < self.max || bans.contains_key(&ban.key) {
                bans.insert(ban.key.clone(), ban);
            }
        }
    }

    fn purge(bans: &mut HashMap<String, Ban>, now: i64) {
        bans.retain(|_, b| b.until > now);
    }
}

fn read(path: &std::path::Path) -> Option<File> {
    let bytes = std::fs::read(path).ok()?;
    let file: File = serde_json::from_slice(&bytes).ok()?;
    (file.version == 1).then_some(file)
}

impl BanStore for LocalBans {
    fn get(&self, key: &str, now: i64) -> Option<Ban> {
        let bans = self.bans.lock().unwrap_or_else(PoisonError::into_inner);
        bans.get(key).filter(|b| b.until > now).cloned()
    }

    fn insert(&self, ban: Ban, now: i64) -> bool {
        let mut bans = self.bans.lock().unwrap_or_else(PoisonError::into_inner);
        if bans.len() >= self.max && !bans.contains_key(&ban.key) {
            Self::purge(&mut bans, now);
            if bans.len() >= self.max {
                return false;
            }
        }
        bans.insert(ban.key.clone(), ban);
        self.dirty.store(true, Ordering::SeqCst);
        true
    }

    fn remove(&self, key: &str) -> bool {
        let removed = self
            .bans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key)
            .is_some();
        if removed {
            self.dirty.store(true, Ordering::SeqCst);
        }
        removed
    }

    fn list(&self, now: i64) -> Vec<Ban> {
        let bans = self.bans.lock().unwrap_or_else(PoisonError::into_inner);
        bans.values().filter(|b| b.until > now).cloned().collect()
    }
}

/// Settings of one middleware's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Events within a window that start a ban.
    pub threshold: u32,
    /// Window length in seconds.
    pub window: i64,
    /// Ban length in seconds.
    pub ban: i64,
    /// Counters kept at once.
    pub max_keys: usize,
    /// Bans kept at once.
    pub max_bans: usize,
}

#[derive(Debug, Clone, Copy)]
struct Count {
    start: i64,
    events: u32,
}

/// One `abuse` middleware's counters and bans.
#[derive(Debug)]
pub struct Abuse {
    policy: Policy,
    counters: Mutex<HashMap<String, Count>>,
    bans: Arc<dyn BanStore>,
    clock: Arc<dyn Clock>,
}

impl Abuse {
    /// Counters for `policy` over `bans`.
    #[must_use]
    pub fn new(policy: Policy, bans: Arc<dyn BanStore>, clock: Arc<dyn Clock>) -> Self {
        Self {
            policy,
            counters: Mutex::new(HashMap::new()),
            bans,
            clock,
        }
    }

    /// The settings.
    #[must_use]
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// The ban of `key` in force now, if any.
    #[must_use]
    pub fn banned(&self, key: &str) -> Option<Ban> {
        self.bans.get(key, self.clock.now())
    }

    /// Counts one event for `key`; bans it when the window's count reaches the threshold.
    pub fn record(&self, key: &str) -> Recorded {
        let now = self.clock.now();
        let reached = {
            let mut counters = self.counters.lock().unwrap_or_else(PoisonError::into_inner);
            if !counters.contains_key(key) && counters.len() >= self.policy.max_keys {
                evict(&mut counters, now, self.policy.window);
            }
            let count = counters.entry(key.to_owned()).or_insert(Count {
                start: now,
                events: 0,
            });
            if now - count.start >= self.policy.window {
                *count = Count {
                    start: now,
                    events: 0,
                };
            }
            count.events = count.events.saturating_add(1);
            let reached = count.events >= self.policy.threshold;
            if reached {
                counters.remove(key);
            }
            reached
        };
        if !reached {
            return Recorded::Counted;
        }
        let ban = Ban {
            key: key.to_owned(),
            since: now,
            until: now.saturating_add(self.policy.ban),
        };
        if self.bans.insert(ban, now) {
            Recorded::Banned
        } else {
            Recorded::Refused
        }
    }

    /// Counters held now.
    #[must_use]
    pub fn counters(&self) -> usize {
        self.counters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// The ban store.
    #[must_use]
    pub fn bans(&self) -> &Arc<dyn BanStore> {
        &self.bans
    }
}

/// Frees one slot in a full table: every expired window if there are any among a sample,
/// otherwise the oldest window of the sample.
fn evict(counters: &mut HashMap<String, Count>, now: i64, window: i64) {
    let mut oldest: Option<(String, i64)> = None;
    let mut expired = Vec::new();
    for (key, count) in counters.iter().take(EVICTION_SAMPLE) {
        if now - count.start >= window {
            expired.push(key.clone());
        } else if oldest
            .as_ref()
            .is_none_or(|(_, start)| count.start < *start)
        {
            oldest = Some((key.clone(), count.start));
        }
    }
    if expired.is_empty() {
        if let Some((key, _)) = oldest {
            counters.remove(&key);
        }
    } else {
        for key in expired {
            counters.remove(&key);
        }
    }
}

/// Every `abuse` middleware's counters and bans, by middleware name, for the life of the
/// process: a reload keeps them unless the policy changed (bans are kept even then).
#[derive(Debug)]
pub struct AbuseRegistry {
    dir: Mutex<Option<PathBuf>>,
    clock: Arc<dyn Clock>,
    sets: Mutex<HashMap<String, Arc<Abuse>>>,
    bans: Mutex<HashMap<String, Arc<LocalBans>>>,
}

impl Default for AbuseRegistry {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl AbuseRegistry {
    /// A registry on `clock`.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            dir: Mutex::new(None),
            clock,
            sets: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
        }
    }

    /// Where bans are written (`<data dir>/abuse`); none means memory only.
    pub fn set_dir(&self, dir: PathBuf) {
        *self.dir.lock().unwrap_or_else(PoisonError::into_inner) = Some(dir);
    }

    /// The counters of middleware `name` with `policy`, reused when they exist with the same
    /// policy. The bans of `name` are kept across policy changes.
    #[must_use]
    pub fn get(&self, name: &str, policy: Policy) -> Arc<Abuse> {
        let mut sets = self.sets.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = sets.get(name)
            && existing.policy == policy
        {
            return existing.clone();
        }
        let bans = {
            let mut all = self.bans.lock().unwrap_or_else(PoisonError::into_inner);
            match all.get(name) {
                Some(b) if b.max == policy.max_bans => b.clone(),
                _ => {
                    let path = self
                        .dir
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .as_ref()
                        .map(|dir| dir.join(crate::quota::file_name(name)));
                    let previous = all.get(name).map(|b| b.list(self.clock.now()));
                    let fresh = Arc::new(LocalBans::open(policy.max_bans, path, self.clock.now()));
                    for ban in previous.into_iter().flatten() {
                        let _ = fresh.insert(ban, self.clock.now());
                    }
                    all.insert(name.to_owned(), fresh.clone());
                    fresh
                }
            }
        };
        let set = Arc::new(Abuse::new(policy, bans, self.clock.clone()));
        sets.insert(name.to_owned(), set.clone());
        set
    }

    /// Every middleware's bans in force, as `(middleware, ban)`, by middleware then key.
    #[must_use]
    pub fn bans(&self) -> Vec<(String, Ban)> {
        let now = self.clock.now();
        let mut out: Vec<(String, Ban)> = self
            .bans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .flat_map(|(name, bans)| bans.list(now).into_iter().map(|b| (name.clone(), b)))
            .collect();
        out.sort_by(|a, b| (&a.0, &a.1.key).cmp(&(&b.0, &b.1.key)));
        out
    }

    /// Lifts the ban of `key` in every middleware, or only in `middleware`; how many were
    /// lifted.
    pub fn unban(&self, key: &str, middleware: Option<&str>) -> usize {
        let all = self.bans.lock().unwrap_or_else(PoisonError::into_inner);
        all.iter()
            .filter(|(name, _)| middleware.is_none_or(|m| m == name.as_str()))
            .filter(|(_, bans)| bans.remove(key))
            .count()
    }

    /// Bans in force, all middlewares together.
    #[must_use]
    pub fn count(&self) -> usize {
        let now = self.clock.now();
        self.bans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|b| b.list(now).len())
            .sum()
    }

    /// Writes every changed ban list.
    pub fn flush_all(&self) {
        let now = self.clock.now();
        let all: Vec<(String, Arc<LocalBans>)> = self
            .bans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(n, b)| (n.clone(), b.clone()))
            .collect();
        for (name, bans) in all {
            if let Err(err) = bans.flush(now) {
                tracing::warn!(abuse = %name, error = %err, "cannot write the ban list");
            }
        }
    }

    /// Reads every ban list file again (the next process of a binary upgrade, after the old
    /// one stopped writing).
    pub fn reread(&self) {
        let now = self.clock.now();
        for bans in self
            .bans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            bans.reread(now);
        }
    }
}

#[cfg(test)]
mod tests;
