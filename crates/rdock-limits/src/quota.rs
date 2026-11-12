//! Request quotas per calendar window (F-GW-02, ADR-0030): fixed-window counters per key,
//! windows aligned to the hour, the day or the month in UTC, kept across reloads in a
//! [`QuotaRegistry`] and written to a file so a restart keeps them.
//!
//! Counts are exact on one instance (one lock per counter set) and approximate across
//! restarts: a crash loses what was counted since the last flush.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Keys tracked per counter set; past this, new keys share one overflow counter.
pub const MAX_KEYS: usize = 100_000;
/// The key that keys past [`MAX_KEYS`] share.
pub const OVERFLOW_KEY: &str = "\u{0}overflow";

/// Seconds since the Unix epoch, from a clock tests can replace.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Now, in seconds since the Unix epoch.
    fn now(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}

/// A calendar window in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Window {
    /// From the start of each hour.
    Hour,
    /// From 00:00 UTC.
    Day,
    /// From 00:00 UTC on the 1st of the month.
    Month,
}

impl Window {
    /// Start and end (exclusive) of the window that holds `now`, in Unix seconds.
    #[must_use]
    pub fn bounds(self, now: i64) -> (i64, i64) {
        match self {
            Self::Hour => {
                let start = now.div_euclid(3600) * 3600;
                (start, start + 3600)
            }
            Self::Day => {
                let start = now.div_euclid(86_400) * 86_400;
                (start, start + 86_400)
            }
            Self::Month => {
                let (year, month, _) = civil_from_days(now.div_euclid(86_400));
                let start = days_from_civil(year, month, 1) * 86_400;
                let (ny, nm) = if month == 12 {
                    (year + 1, 1)
                } else {
                    (year, month + 1)
                };
                (start, days_from_civil(ny, nm, 1) * 86_400)
            }
        }
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// The answer of [`QuotaCounter::take`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taken {
    /// Counted; `remaining` requests are left in the window.
    Allowed {
        /// Requests left after this one.
        remaining: u64,
        /// Seconds until the window ends.
        reset: u64,
    },
    /// The quota is used up until the window ends; the request was not counted.
    Exceeded {
        /// Seconds until the window ends.
        reset: u64,
    },
}

/// One key's use in the current window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// The key (a consumer name, or `ip:<address>` for requests without one).
    pub key: String,
    /// Requests counted.
    pub used: u64,
    /// The limit applied to the last request.
    pub limit: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    start: i64,
    counts: HashMap<String, (u64, u64)>,
}

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    window: Window,
    start: i64,
    counts: HashMap<String, (u64, u64)>,
}

/// The counters of one `quota` middleware.
#[derive(Debug)]
pub struct QuotaCounter {
    window: Window,
    path: Option<PathBuf>,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
    dirty: AtomicBool,
    flush_every: Mutex<Duration>,
    flushed_at: Mutex<i64>,
}

impl QuotaCounter {
    /// Counters for `window`, read from `path` when it holds the current window's counts.
    #[must_use]
    pub fn open(window: Window, path: Option<PathBuf>, clock: Arc<dyn Clock>) -> Self {
        let now = clock.now();
        let (start, _) = window.bounds(now);
        let mut state = State {
            start,
            counts: HashMap::new(),
        };
        if let Some(file) = path.as_deref().and_then(read_file)
            && file.window == window
            && file.start == start
        {
            state.counts = file.counts;
        }
        Self {
            window,
            path,
            clock,
            state: Mutex::new(state),
            dirty: AtomicBool::new(false),
            flush_every: Mutex::new(Duration::from_secs(10)),
            flushed_at: Mutex::new(now),
        }
    }

    /// The window.
    #[must_use]
    pub fn window(&self) -> Window {
        self.window
    }

    /// Sets how often [`QuotaRegistry::flush_due`] writes this counter.
    pub fn set_flush_interval(&self, every: Duration) {
        *self
            .flush_every
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = every;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (start, _) = self.window.bounds(self.clock.now());
        if state.start != start {
            // A new window: everyone starts again.
            state.start = start;
            state.counts.clear();
            self.dirty.store(true, Ordering::Relaxed);
        }
        state
    }

    /// Counts one request for `key` against `limit`, unless the quota is used up.
    pub fn take(&self, key: &str, limit: u64) -> Taken {
        let now = self.clock.now();
        let (_, end) = self.window.bounds(now);
        let reset = u64::try_from(end - now).unwrap_or(0).max(1);
        let mut state = self.lock();
        let key = if state.counts.contains_key(key) || state.counts.len() < MAX_KEYS {
            key
        } else {
            OVERFLOW_KEY
        };
        let entry = state.counts.entry(key.to_owned()).or_insert((0, limit));
        entry.1 = limit;
        if entry.0 >= limit {
            return Taken::Exceeded { reset };
        }
        entry.0 += 1;
        let remaining = limit - entry.0;
        drop(state);
        self.dirty.store(true, Ordering::Relaxed);
        Taken::Allowed { remaining, reset }
    }

    /// The use of `key` in the current window.
    #[must_use]
    pub fn usage(&self, key: &str) -> Option<Usage> {
        self.lock().counts.get(key).map(|&(used, limit)| Usage {
            key: key.to_owned(),
            used,
            limit,
        })
    }

    /// Every key's use in the current window, by key.
    #[must_use]
    pub fn all(&self) -> Vec<Usage> {
        let mut out: Vec<Usage> = self
            .lock()
            .counts
            .iter()
            .map(|(key, &(used, limit))| Usage {
                key: key.clone(),
                used,
                limit,
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }

    /// Start and end of the current window, in Unix seconds.
    #[must_use]
    pub fn bounds(&self) -> (i64, i64) {
        self.window.bounds(self.clock.now())
    }

    /// Forgets `key`'s count; returns whether it had one.
    pub fn reset(&self, key: &str) -> bool {
        let removed = self.lock().counts.remove(key).is_some();
        if removed {
            self.dirty.store(true, Ordering::Relaxed);
        }
        removed
    }

    /// Writes the counters when they changed since the last write.
    ///
    /// # Errors
    ///
    /// When the file cannot be written; the counters stay marked as changed.
    pub fn flush(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        let bytes = {
            let state = self.lock();
            serde_json::to_vec(&File {
                version: 1,
                window: self.window,
                start: state.start,
                counts: state.counts.clone(),
            })
            .map_err(io::Error::other)?
        };
        let result = write_atomic(path, &bytes);
        if result.is_err() {
            self.dirty.store(true, Ordering::Relaxed);
        }
        *self
            .flushed_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = self.clock.now();
        result
    }

    fn due(&self) -> bool {
        let every = *self
            .flush_every
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let at = *self
            .flushed_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.dirty.load(Ordering::Relaxed)
            && self.clock.now() - at >= i64::try_from(every.as_secs()).unwrap_or(i64::MAX)
    }
}

fn read_file(path: &Path) -> Option<File> {
    let bytes = std::fs::read(path).ok()?;
    let file: File = serde_json::from_slice(&bytes).ok()?;
    (file.version == 1).then_some(file)
}

/// Writes `bytes` to a temporary file next to `path` and renames it over `path`, so a reader
/// (or a crash) never sees half a file.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Every `quota` middleware's counters, by middleware name, for the life of the process: a
/// reload keeps a middleware's counts unless its window changed.
#[derive(Debug)]
pub struct QuotaRegistry {
    dir: Mutex<Option<PathBuf>>,
    clock: Arc<dyn Clock>,
    counters: Mutex<HashMap<String, Arc<QuotaCounter>>>,
}

impl Default for QuotaRegistry {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl QuotaRegistry {
    /// A registry on `clock`.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            dir: Mutex::new(None),
            clock,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Where counters are written (`<data dir>/quota`); none means memory only.
    pub fn set_dir(&self, dir: PathBuf) {
        *self.dir.lock().unwrap_or_else(PoisonError::into_inner) = Some(dir);
    }

    /// The counters of middleware `name` with `window`, reused when they exist.
    #[must_use]
    pub fn counter(&self, name: &str, window: Window) -> Arc<QuotaCounter> {
        let mut counters = self.counters.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = counters.get(name)
            && existing.window == window
        {
            return existing.clone();
        }
        let path = self
            .dir
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|dir| dir.join(file_name(name)));
        let counter = Arc::new(QuotaCounter::open(window, path, self.clock.clone()));
        counters.insert(name.to_owned(), counter.clone());
        counter
    }

    /// Every middleware's counters, by name.
    #[must_use]
    pub fn counters(&self) -> Vec<(String, Arc<QuotaCounter>)> {
        let mut out: Vec<(String, Arc<QuotaCounter>)> = self
            .counters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(n, c)| (n.clone(), c.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Writes the counters whose flush interval has passed.
    pub fn flush_due(&self) {
        for (name, counter) in self.counters() {
            if counter.due()
                && let Err(err) = counter.flush()
            {
                warn_unwritten(&name, &err);
            }
        }
    }

    /// Writes every changed counter (at shutdown).
    pub fn flush_all(&self) {
        for (name, counter) in self.counters() {
            if let Err(err) = counter.flush() {
                warn_unwritten(&name, &err);
            }
        }
    }
}

fn warn_unwritten(name: &str, err: &io::Error) {
    tracing::warn!(quota = %name, error = %err, "cannot write the quota counters");
}

/// A file name for a middleware name (`name@provider` included): safe characters only, plus
/// a hash so two names never share a file.
fn file_name(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    // FNV-1a: stable across runs (unlike `DefaultHasher`'s random keys).
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{safe}-{hash:016x}.json")
}

#[cfg(test)]
mod tests;
