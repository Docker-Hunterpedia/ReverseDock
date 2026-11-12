//! Metrics of the cache, registered by `rdock-observability` and handed to the stores.

use prometheus::{IntCounterVec, IntGaugeVec};

/// The cache's Prometheus metrics. Every label value comes from the configuration (store and
/// route names) or from a fixed set, so their number stays bounded.
#[derive(Debug, Clone)]
pub struct CacheMetrics {
    /// `rdock_cache_requests_total{store,route,status}`: requests on caching routes by
    /// outcome (`hit`, `stale`, `revalidated`, `expired`, `miss`, `bypass`).
    pub requests: IntCounterVec,
    /// `rdock_cache_objects{store}`: objects stored.
    pub objects: IntGaugeVec,
    /// `rdock_cache_bytes{store}`: bytes stored.
    pub bytes: IntGaugeVec,
    /// `rdock_cache_evictions_total{store,reason}`: objects removed to stay under `max_size`
    /// (`size`) or `max_objects` (`count`).
    pub evictions: IntCounterVec,
    /// `rdock_cache_lock_waits_total{store}`: requests that waited for another request's fill.
    pub lock_waits: IntCounterVec,
    /// `rdock_cache_dropped_total{store,reason}`: disk objects dropped at start (`corrupt`,
    /// `partial`).
    pub dropped: IntCounterVec,
}

impl CacheMetrics {
    pub(crate) fn set_size(&self, store: &str, objects: usize, bytes: u64) {
        self.objects
            .with_label_values(&[store])
            .set(i64::try_from(objects).unwrap_or(i64::MAX));
        self.bytes
            .with_label_values(&[store])
            .set(i64::try_from(bytes).unwrap_or(i64::MAX));
    }
}
