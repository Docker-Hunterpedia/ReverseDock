//! Request quotas per calendar window (F-GW-02, ADR-0030): fixed-window counters per key,
//! windows aligned to the hour, the day or the month in UTC, kept across reloads in a
//! [`QuotaRegistry`] and written to a file so a restart keeps them.
//!
//! Counts are exact on one instance (one lock per counter set) and approximate across
//! restarts: a crash loses what was counted since the last flush.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Anonymous keys (`ip:…`) tracked per counter set, and apart from them keys of consumers
/// asserted by a token issuer (`~…`); past this, new keys of the class share one overflow
/// counter of that class. Keys of consumers defined in `consumers` (bare names, bounded by
/// the configuration) never overflow (M2 of the v0.8 review).
pub const MAX_KEYS: usize = 100_000;
/// The counter anonymous keys past [`MAX_KEYS`] share.
pub const OVERFLOW_KEY: &str = "\u{0}overflow";
/// The counter token consumers past [`MAX_KEYS`] share.
pub const TOKEN_OVERFLOW_KEY: &str = "\u{0}overflow:token";

/// The kind of a counter key, each with its own budget of [`MAX_KEYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    /// A request without a consumer, counted per client address (`ip:…`).
    Anonymous,
    /// A consumer named by a token issuer (`oidc`, `jwt`, `cloudflare_access`).
    Token,
    /// A consumer defined in `consumers`; never overflows.
    Consumer,
    /// A consumer group (`key: group`, `group:<name>`); groups come from the configuration,
    /// so they never overflow.
    Group,
}

impl KeyClass {
    /// The class of `key`; `None` for the overflow counters themselves.
    #[must_use]
    pub fn of(key: &str) -> Option<Self> {
        if key.starts_with('\u{0}') {
            None
        } else if key.starts_with("ip:") {
            Some(Self::Anonymous)
        } else if key.starts_with('~') {
            Some(Self::Token)
        } else if key.starts_with(GROUP_PREFIX) {
            Some(Self::Group)
        } else {
            Some(Self::Consumer)
        }
    }

    /// The label of the class in metrics.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Token => "token",
            Self::Consumer => "consumer",
            Self::Group => "group",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Anonymous => 0,
            Self::Token => 1,
            Self::Consumer | Self::Group => 2,
        }
    }

    fn overflow(self) -> Option<&'static str> {
        match self {
            Self::Anonymous => Some(OVERFLOW_KEY),
            Self::Token => Some(TOKEN_OVERFLOW_KEY),
            Self::Consumer | Self::Group => None,
        }
    }
}

/// The start of a group's counter key. A configured consumer name cannot contain `:`, so a
/// group never shares a consumer's key.
pub const GROUP_PREFIX: &str = "group:";

/// The counter key of consumer group `name` (`key: group`).
#[must_use]
pub fn group_key(name: &str) -> String {
    format!("{GROUP_PREFIX}{name}")
}

/// The group of a counter key made by [`group_key`].
#[must_use]
pub fn key_group(key: &str) -> Option<&str> {
    key.strip_prefix(GROUP_PREFIX)
}

/// The counter key of a consumer: its name when `consumers` defines it (`issuer` is `None`),
/// otherwise `~<length of issuer>:<issuer><name>`. A configured name cannot contain `~` or
/// `:`, and the length makes the split unambiguous, so a token's consumer never shares a
/// configured consumer's key, nor one issuer's user another's.
#[must_use]
pub fn consumer_key<'a>(issuer: Option<&str>, name: &'a str) -> Cow<'a, str> {
    match issuer {
        None => Cow::Borrowed(name),
        Some(issuer) => Cow::Owned(format!("~{}:{issuer}{name}", issuer.len())),
    }
}

/// The consumer name in a counter key made by [`consumer_key`]; `None` for anonymous keys
/// and the overflow counters.
#[must_use]
pub fn key_consumer(key: &str) -> Option<&str> {
    match KeyClass::of(key)? {
        KeyClass::Anonymous | KeyClass::Group => None,
        KeyClass::Consumer => Some(key),
        KeyClass::Token => {
            let (len, rest) = key.strip_prefix('~')?.split_once(':')?;
            rest.get(len.parse::<usize>().ok()?..)
        }
    }
}

/// Whether counter `key` belongs to `name`: a consumer's own and its token users' counters,
/// or a group's counter asked for as `group:<name>`.
fn names(key: &str, name: &str) -> bool {
    key_consumer(key) == Some(name) || (key_group(key).is_some() && key == name)
}

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
    /// The key: a consumer name, a token consumer's [`consumer_key`], or `ip:<address>`
    /// (`ip:<prefix>/64` for IPv6) for requests without a consumer.
    pub key: String,
    /// Requests counted.
    pub used: u64,
    /// The limit applied to the last request.
    pub limit: u64,
}

#[derive(Debug, Default)]
struct State {
    start: i64,
    counts: HashMap<String, (u64, u64)>,
    /// Keys per [`KeyClass`], overflow counters not included.
    sizes: [usize; 3],
}

impl State {
    fn recount(&mut self) {
        self.sizes = [0; 3];
        for key in self.counts.keys() {
            if let Some(class) = KeyClass::of(key) {
                self.sizes[class.index()] += 1;
            }
        }
    }

    fn remove(&mut self, key: &str) -> bool {
        let removed = self.counts.remove(key).is_some();
        if removed && let Some(class) = KeyClass::of(key) {
            self.sizes[class.index()] -= 1;
        }
        removed
    }
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
            ..State::default()
        };
        if let Some(file) = path.as_deref().and_then(read_file)
            && file.window == window
            && file.start == start
        {
            state.counts = file.counts;
            state.recount();
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
            state.sizes = [0; 3];
            self.dirty.store(true, Ordering::Relaxed);
        }
        state
    }

    /// Counts one request for `key` against `limit`, unless the quota is used up.
    pub fn take(&self, key: &str, limit: u64) -> Taken {
        self.take_counted(key, limit).0
    }

    /// [`take`](Self::take), and the class whose overflow counter took the request when
    /// `key` is new and its class is full.
    pub fn take_counted(&self, key: &str, limit: u64) -> (Taken, Option<KeyClass>) {
        let now = self.clock.now();
        let (_, end) = self.window.bounds(now);
        let reset = u64::try_from(end - now).unwrap_or(0).max(1);
        let mut state = self.lock();
        let mut overflowed = None;
        let key = if state.counts.contains_key(key) {
            key
        } else {
            match KeyClass::of(key) {
                Some(class) => match class.overflow() {
                    Some(shared) if state.sizes[class.index()] >= MAX_KEYS => {
                        overflowed = Some(class);
                        shared
                    }
                    _ => {
                        state.sizes[class.index()] += 1;
                        key
                    }
                },
                None => key,
            }
        };
        let entry = state.counts.entry(key.to_owned()).or_insert((0, limit));
        entry.1 = limit;
        if entry.0 >= limit {
            return (Taken::Exceeded { reset }, overflowed);
        }
        entry.0 += 1;
        let remaining = limit - entry.0;
        drop(state);
        self.dirty.store(true, Ordering::Relaxed);
        (Taken::Allowed { remaining, reset }, overflowed)
    }

    /// The use of every key of consumer `name` in the current window: its own key and those
    /// of token consumers with that name, whatever their issuer.
    #[must_use]
    pub fn usage_of(&self, name: &str) -> Vec<Usage> {
        let mut out: Vec<Usage> = self
            .lock()
            .counts
            .iter()
            .filter(|(key, _)| names(key, name))
            .map(|(key, &(used, limit))| Usage {
                key: key.clone(),
                used,
                limit,
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }

    /// Forgets the counts of every key of consumer `name` (see [`usage_of`](Self::usage_of));
    /// returns whether there was one.
    pub fn reset_consumer(&self, name: &str) -> bool {
        let mut state = self.lock();
        let keys: Vec<String> = state
            .counts
            .keys()
            .filter(|key| names(key, name))
            .cloned()
            .collect();
        for key in &keys {
            state.remove(key);
        }
        drop(state);
        if !keys.is_empty() {
            self.dirty.store(true, Ordering::Relaxed);
        }
        !keys.is_empty()
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
        let removed = self.lock().remove(key);
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

    /// The counts now (window start, key → used), as a base for [`Self::increments_since`].
    #[must_use]
    pub fn snapshot(&self) -> (i64, HashMap<String, u64>) {
        let state = self.lock();
        (
            state.start,
            state
                .counts
                .iter()
                .map(|(k, &(used, _))| (k.clone(), used))
                .collect(),
        )
    }

    /// What was counted since `base` in the same window: (key, increment, limit). Empty when
    /// the window changed since (the new window's counts are then all increments).
    #[must_use]
    pub fn increments_since(
        &self,
        base: &(i64, HashMap<String, u64>),
    ) -> (i64, Vec<(String, u64, u64)>) {
        let state = self.lock();
        let same_window = state.start == base.0;
        let out = state
            .counts
            .iter()
            .filter_map(|(key, &(used, limit))| {
                let before = if same_window {
                    base.1.get(key).copied().unwrap_or(0)
                } else {
                    0
                };
                (used > before).then(|| (key.clone(), used - before, limit))
            })
            .collect();
        (state.start, out)
    }

    /// Adds what another process counted (binary upgrade: the old process's draining
    /// connections) when it is for the current window.
    pub fn add_increments(&self, start: i64, increments: &[(String, u64, u64)]) {
        let mut state = self.lock();
        if state.start != start {
            return;
        }
        for (key, delta, limit) in increments {
            if !state.counts.contains_key(key)
                && let Some(class) = KeyClass::of(key)
            {
                state.sizes[class.index()] += 1;
            }
            let entry = state.counts.entry(key.clone()).or_insert((0, *limit));
            entry.0 = entry.0.saturating_add(*delta);
        }
        drop(state);
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Reads the counts from the file again, replacing those in memory, when it holds the
    /// current window. A process that counted nothing yet calls this when it takes over from
    /// one that wrote its counts last (binary upgrade).
    pub fn reread(&self) {
        let Some(file) = self.path.as_deref().and_then(read_file) else {
            return;
        };
        let mut state = self.lock();
        if file.window == self.window && file.start == state.start {
            state.counts = file.counts;
            state.recount();
        }
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
/// (or a crash) never sees half a file. The counts name consumers (e-mail addresses after an
/// OIDC login) and client addresses, so on Unix the directory is `0700` and the file `0600`
/// whatever the umask (L6 of the v0.8 review), as for the audit log and ACME files.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&tmp).and_then(|mut file| {
        // A temporary file left by an older version keeps its mode through `open`.
        #[cfg(unix)]
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(err) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        // A full disk leaves no half-written temporary file behind (ADR-0033); the counts
        // in memory stay authoritative and the next save tries again.
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

/// Every `quota` middleware's counters, by middleware name, for the life of the process: a
/// reload keeps a middleware's counts unless its window changed.
#[derive(Debug)]
pub struct QuotaRegistry {
    dir: Mutex<Option<PathBuf>>,
    clock: Arc<dyn Clock>,
    counters: Mutex<HashMap<String, Arc<QuotaCounter>>>,
    /// Failed writes, for the metric and a log line a minute.
    persistence: crate::Persistence,
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
            persistence: crate::Persistence::default(),
        }
    }

    /// Writes of counter files that failed since the start (a full disk).
    #[must_use]
    pub fn write_failures(&self) -> u64 {
        self.persistence.failures()
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
            if counter.due() {
                let result = counter.flush();
                self.persistence.outcome("quota counters", &name, &result);
            }
        }
    }

    /// Writes every changed counter (at shutdown).
    pub fn flush_all(&self) {
        for (name, counter) in self.counters() {
            let result = counter.flush();
            self.persistence.outcome("quota counters", &name, &result);
        }
    }
}

/// A file name for a middleware name (`name@provider` included): safe characters only, plus
/// a hash so two names never share a file.
pub(crate) fn file_name(name: &str) -> String {
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
