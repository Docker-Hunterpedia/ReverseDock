//! Wall clocks for lease expiry. The control plane's store judges every lease by its own clock;
//! a shared directory is judged by each instance's clock, so their skew matters there. Tests use
//! [`ManualClock`] to move time and to give instances different clocks.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Now, in milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// A clock that moves only when told to, optionally offset from a shared base (two instances
/// whose clocks disagree).
#[derive(Debug, Clone)]
pub struct ManualClock {
    base: Arc<AtomicU64>,
    offset_ms: Arc<AtomicI64>,
}

impl ManualClock {
    /// A clock at `start_ms`.
    #[must_use]
    pub fn new(start_ms: u64) -> Self {
        Self {
            base: Arc::new(AtomicU64::new(start_ms)),
            offset_ms: Arc::new(AtomicI64::new(0)),
        }
    }

    /// A clock on the same base that runs `offset_ms` ahead (negative: behind).
    #[must_use]
    pub fn skewed(&self, offset_ms: i64) -> Self {
        Self {
            base: self.base.clone(),
            offset_ms: Arc::new(AtomicI64::new(offset_ms)),
        }
    }

    /// Moves the shared base forward by `ms`.
    pub fn advance(&self, ms: u64) {
        self.base.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        let base = self.base.load(Ordering::SeqCst);
        let offset = self.offset_ms.load(Ordering::SeqCst);
        base.saturating_add_signed(offset)
    }
}

/// `now + ttl` in milliseconds.
pub(crate) fn deadline(now_ms: u64, ttl: std::time::Duration) -> u64 {
    now_ms.saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX))
}
