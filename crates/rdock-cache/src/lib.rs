#![doc = include_str!("../README.md")]

mod lock;
mod metrics;
pub mod policy;
mod registry;
mod route;
mod store;

pub use lock::{CoalescingLock, lock_for};
pub use metrics::CacheMetrics;
pub use registry::{Finding, Registry, Resolved};
pub use route::{Identity, LockPolicy, OVERRIDE_HEADERS, RoutePolicy, has_body};
pub use store::{ObjectInfo, PurgeError, Selector, Stats, Store};

/// The types of pingora-cache the proxy's hooks name. Everything else stays in this crate.
pub mod pingora_types {
    pub use pingora::cache::key::HashBinary;
    pub use pingora::cache::lock::CacheKeyLockImpl;
    pub use pingora::cache::{
        CacheKey, CacheMeta, CacheOptionOverrides, CachePhase, ForcedFreshness, HitHandler,
        NoCacheReason, RespCacheable,
    };
}

/// Decodes a disk-store file header the way a store does at start, for the fuzz target in
/// `tests/fuzz`: arbitrary bytes must be rejected, never panic or allocate without bound.
#[doc(hidden)]
pub fn fuzz_decode_disk_header(bytes: &[u8]) {
    store::disk::format::fuzz(bytes);
}
