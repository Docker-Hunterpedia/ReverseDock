//! Named stores implementing pingora-cache's `Storage`: memory and disk.
//!
//! Stores are process-lifetime objects (`&'static`, as pingora-cache requires): the
//! [`crate::Registry`] creates each once and reuses it on every reload.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use pingora::cache::key::CacheHashKey;
use pingora::cache::storage::{HandleHit, MissHandler, PurgeOutcome, PurgeTarget, PurgeType};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{CacheKey, CacheMeta, HitHandler, Storage};
use pingora::{Error, ErrorType};

use crate::metrics::CacheMetrics;

pub(crate) mod disk;
mod index;
mod memory;

pub(crate) use index::Evicted;

/// A stored object's key: pingora-cache's combined key (BLAKE2b-128 of the primary key and
/// the variance).
pub(crate) type Id = [u8; 16];

/// Facts about a response the proxy attaches to its `CacheMeta` before the fill: the URL it is
/// purged by and its tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    /// Public URL (`scheme://host/path?query`), see `policy::invalidate::public_url`.
    pub url: Arc<str>,
    /// Tags, lower case.
    pub tags: Arc<[Box<str>]>,
}

impl ObjectInfo {
    /// Info for `url` with `tags`.
    #[must_use]
    pub fn new(url: &str, tags: &[String]) -> Self {
        Self {
            url: Arc::from(url),
            tags: tags.iter().map(|t| Box::from(t.as_str())).collect(),
        }
    }
}

/// What a purge removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// Every variant of one URL (normalised with `policy::invalidate::normalize_url`).
    Url(String),
    /// Every object whose URL starts with this (normalised the same way).
    Prefix(String),
    /// Every object with this tag (lower case).
    Tag(String),
    /// Everything.
    All,
}

/// Why a purge failed.
#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    /// The disk store could not delete files.
    #[error("cache store `{store}`: {source}")]
    Io {
        /// Store name.
        store: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// A store's size and counters, for the admin API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    /// Store name.
    pub name: String,
    /// `memory` or `disk`.
    pub kind: &'static str,
    /// Objects stored.
    pub objects: u64,
    /// Bytes stored.
    pub bytes: u64,
    /// `max_size`.
    pub max_size: u64,
    /// `max_objects` (disk stores).
    pub max_objects: Option<u64>,
    /// Lookups that found an object.
    pub hits: u64,
    /// Lookups that found none.
    pub misses: u64,
    /// Objects stored since start.
    pub stored: u64,
    /// Objects evicted since start.
    pub evictions: u64,
    /// Objects removed by purges and invalidations since start.
    pub purged: u64,
    /// Disk objects dropped at start because they were damaged or incomplete.
    pub dropped: u64,
}

#[derive(Debug, Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    stored: AtomicU64,
    evictions: AtomicU64,
    purged: AtomicU64,
    dropped: AtomicU64,
}

#[derive(Debug)]
enum Backend {
    Memory(memory::Memory),
    Disk(disk::Disk),
}

/// A named cache store.
#[derive(Debug)]
pub struct Store {
    name: Arc<str>,
    backend: Backend,
    counters: Counters,
    metrics: Option<CacheMetrics>,
    /// When a refused write was last logged.
    write_error_logged: std::sync::Mutex<Option<std::time::Instant>>,
}

// `pingora::Result` carries errors boxed.
#[allow(clippy::unnecessary_box_returns)]
pub(crate) fn internal_error(message: impl Into<String>) -> Box<Error> {
    Error::explain(ErrorType::InternalError, message.into())
}

impl Store {
    /// A memory store of at most `max_size` bytes.
    #[must_use]
    pub fn memory(name: &str, max_size: u64, metrics: Option<CacheMetrics>) -> Self {
        let store = Self {
            name: Arc::from(name),
            backend: Backend::Memory(memory::Memory::new(max_size)),
            counters: Counters::default(),
            metrics,
            write_error_logged: std::sync::Mutex::new(None),
        };
        store.report_size(0, 0);
        store
    }

    /// A disk store at `path`: the directory is created (mode 0700) if needed and walked to
    /// rebuild the index, removing partial and damaged files.
    ///
    /// # Errors
    ///
    /// The directory cannot be created, opened or read.
    pub fn disk(
        name: &str,
        path: &std::path::Path,
        max_size: u64,
        max_objects: u64,
        metrics: Option<CacheMetrics>,
    ) -> std::io::Result<Self> {
        let (disk, walk) = disk::Disk::open(path, max_size, max_objects)?;
        let store = Self {
            name: Arc::from(name),
            backend: Backend::Disk(disk),
            counters: Counters::default(),
            metrics,
            write_error_logged: std::sync::Mutex::new(None),
        };
        let dropped = walk.corrupt + walk.partial;
        store.counters.dropped.store(dropped, Ordering::Relaxed);
        if let Some(m) = &store.metrics {
            for (reason, n) in [("corrupt", walk.corrupt), ("partial", walk.partial)] {
                if n > 0 {
                    m.dropped.with_label_values(&[name, reason]).inc_by(n);
                }
            }
        }
        store.note_evictions(&walk.evicted);
        store.report_size(walk.objects, walk.bytes);
        if dropped > 0 {
            tracing::warn!(
                store = name,
                corrupt = walk.corrupt,
                partial = walk.partial,
                "dropped damaged or incomplete cache objects at start"
            );
        }
        Ok(store)
    }

    /// The store's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `memory` or `disk`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self.backend {
            Backend::Memory(_) => "memory",
            Backend::Disk(_) => "disk",
        }
    }

    /// The metrics handle, when the store reports metrics.
    #[must_use]
    pub fn metrics(&self) -> Option<&CacheMetrics> {
        self.metrics.as_ref()
    }

    /// Size and counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let (objects, bytes, max_size, max_objects) = match &self.backend {
            Backend::Memory(m) => {
                let (o, b) = m.size();
                (o, b, m.max_size(), None)
            }
            Backend::Disk(d) => {
                let (o, b) = d.size();
                (o, b, d.max_size(), Some(d.max_objects()))
            }
        };
        let c = &self.counters;
        Stats {
            name: self.name.to_string(),
            kind: self.kind(),
            objects: objects as u64,
            bytes,
            max_size,
            max_objects,
            hits: c.hits.load(Ordering::Relaxed),
            misses: c.misses.load(Ordering::Relaxed),
            stored: c.stored.load(Ordering::Relaxed),
            evictions: c.evictions.load(Ordering::Relaxed),
            purged: c.purged.load(Ordering::Relaxed),
            dropped: c.dropped.load(Ordering::Relaxed),
        }
    }

    /// Removes what `selector` covers, and cancels fills in progress it covers so they do not
    /// commit afterwards. Returns the number of objects removed.
    ///
    /// # Errors
    ///
    /// A disk store could not delete a file (the index no longer lists it either way).
    pub async fn purge(&'static self, selector: Selector) -> Result<u64, PurgeError> {
        let removed = match &self.backend {
            Backend::Memory(m) => Ok(m.purge(&selector)),
            Backend::Disk(d) => d.purge(selector).await,
        };
        let removed = removed.map_err(|source| PurgeError::Io {
            store: self.name.to_string(),
            source,
        })?;
        self.counters.purged.fetch_add(removed, Ordering::Relaxed);
        self.report();
        Ok(removed)
    }

    /// Invalidates every variant of each URL (RFC 9111 §4.4). Failures are logged.
    pub async fn invalidate(&'static self, urls: Vec<String>) -> u64 {
        let mut removed = 0;
        for url in urls {
            match self.purge(Selector::Url(url)).await {
                Ok(n) => removed += n,
                Err(e) => tracing::warn!(error = %e, "cache invalidation failed"),
            }
        }
        removed
    }

    fn report(&self) {
        let (objects, bytes) = match &self.backend {
            Backend::Memory(m) => m.size(),
            Backend::Disk(d) => d.size(),
        };
        self.report_size(objects, bytes);
    }

    fn report_size(&self, objects: usize, bytes: u64) {
        if let Some(m) = &self.metrics {
            m.set_size(&self.name, objects, bytes);
        }
    }

    pub(crate) fn note_stored(&self) {
        self.counters.stored.fetch_add(1, Ordering::Relaxed);
    }

    /// An object the disk refused to store (a full disk): the response is served all the
    /// same, uncached (ADR-0033). Counted as `rdock_cache_dropped_total{reason="write_error"}`
    /// and logged once a minute.
    pub(crate) fn note_write_error(&self, error: &str) {
        if let Some(m) = &self.metrics {
            m.dropped
                .with_label_values(&[&*self.name, "write_error"])
                .inc();
        }
        let now = std::time::Instant::now();
        let mut last = self
            .write_error_logged
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_none_or(|at| now.duration_since(at) >= std::time::Duration::from_secs(60)) {
            *last = Some(now);
            tracing::warn!(store = %self.name, %error,
                "cannot store a cache object; responses are served uncached until the disk takes writes again (logged once a minute)");
        }
    }

    pub(crate) fn note_evictions(&self, evicted: &[Evicted]) {
        if evicted.is_empty() {
            return;
        }
        self.counters
            .evictions
            .fetch_add(evicted.len() as u64, Ordering::Relaxed);
        if let Some(m) = &self.metrics {
            for reason in evicted {
                m.evictions
                    .with_label_values(&[&*self.name, reason.label()])
                    .inc();
            }
        }
    }

    pub(crate) fn after_commit(&self, evicted: &[Evicted], objects: usize, bytes: u64) {
        self.note_stored();
        self.note_evictions(evicted);
        self.report_size(objects, bytes);
    }

    fn note_lookup(&self, found: bool) {
        let counter = if found {
            &self.counters.hits
        } else {
            &self.counters.misses
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

fn info_of(meta: &CacheMeta) -> ObjectInfo {
    meta.extensions()
        .get::<ObjectInfo>()
        .cloned()
        .unwrap_or_else(|| ObjectInfo::new("", &[]))
}

#[async_trait]
impl Storage for Store {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let id = key.combined_bin();
        let found = match &self.backend {
            Backend::Memory(m) => m.lookup(&id)?,
            Backend::Disk(d) => d.lookup(&id).await?,
        };
        self.note_lookup(found.is_some());
        Ok(found)
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<MissHandler> {
        let id = key.combined_bin();
        let info = info_of(meta);
        let (internal, header) = meta.serialize()?;
        let variance = key.variance_bin();
        match &self.backend {
            Backend::Memory(m) => Ok(m.miss_handler(self, id, info, internal, header)),
            Backend::Disk(d) => {
                d.miss_handler(self, id, variance, info, internal, header)
                    .await
            }
        }
    }

    async fn purge(
        &'static self,
        target: PurgeTarget<'_>,
        _purge_type: PurgeType,
        _trace: &SpanHandle,
    ) -> pingora::Result<PurgeOutcome> {
        let id = target.key().combined_bin();
        let removed = match &self.backend {
            Backend::Memory(m) => m.remove(&id),
            Backend::Disk(d) => d
                .remove(id)
                .await
                .map_err(|e| internal_error(format!("removing a cache object: {e}")))?,
        };
        self.report();
        Ok(if removed {
            self.counters.purged.fetch_add(1, Ordering::Relaxed);
            PurgeOutcome::Purged(None)
        } else {
            PurgeOutcome::NotFound
        })
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        let id = key.combined_bin();
        let (internal, header) = meta.serialize()?;
        let info = meta.extensions().get::<ObjectInfo>().cloned();
        let updated = match &self.backend {
            Backend::Memory(m) => m.update_meta(&id, internal, header, info),
            Backend::Disk(d) => d.update_meta(id, internal, header, info).await?,
        };
        self.report();
        Ok(updated)
    }

    fn support_streaming_partial_write(&self) -> bool {
        // Waiters read an object once its fill has committed (ADR-0030: no partial reads).
        false
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

/// Reads at most `max` bytes per call from a hit, for both stores.
pub(crate) const READ_CHUNK: usize = 64 * 1024;

/// Clamps a seek to the body: `(start, end)` with `end` exclusive.
pub(crate) fn clamp_range(
    len: usize,
    start: usize,
    end: Option<usize>,
) -> pingora::Result<(usize, usize)> {
    if start >= len && len > 0 {
        return Err(internal_error(format!(
            "seek start {start} beyond the body ({len} bytes)"
        )));
    }
    let end = end.map_or(len, |e| e.min(len));
    Ok((start.min(end), end))
}

/// Shared hit-handler plumbing.
pub(crate) fn boxed<H: HandleHit + Send + Sync + 'static>(hit: H) -> HitHandler {
    Box::new(hit)
}
