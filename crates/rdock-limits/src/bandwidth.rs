//! Bytes per second per key, for the `bandwidth` middleware. Each key has a bucket of `burst`
//! bytes refilled at `rate`. Sending more than the bucket holds is allowed but leaves a debt,
//! and the caller waits the returned time before the next chunk, so the long-run rate holds
//! without splitting chunks.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
struct Bucket {
    bytes: f64,
    updated: Instant,
}

/// A byte-rate limiter keyed by an arbitrary value, tracking at most `max_keys` keys.
#[derive(Debug)]
pub struct ByteLimiter {
    rate: f64,
    burst: f64,
    max_keys: usize,
    hasher: RandomState,
    buckets: Mutex<HashMap<u64, Bucket>>,
}

impl ByteLimiter {
    /// `rate` bytes per second with bursts of `burst` bytes (zero is treated as one).
    #[must_use]
    pub fn new(rate: u64, burst: u64, max_keys: usize) -> Self {
        #[allow(clippy::cast_precision_loss)]
        let (rate, burst) = (rate.max(1) as f64, burst.max(1) as f64);
        Self {
            rate,
            burst,
            max_keys: max_keys.max(1),
            hasher: RandomState::new(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Records `bytes` sent for `key` at `now`; returns how long to wait before sending more.
    pub fn take<K: Hash + ?Sized>(&self, key: &K, bytes: usize, now: Instant) -> Duration {
        let hash = self.hasher.hash_one(key);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if !buckets.contains_key(&hash) && buckets.len() >= self.max_keys {
            // Full buckets belong to idle clients; dropping them loses nothing.
            let (rate, burst) = (self.rate, self.burst);
            buckets.retain(|_, b| {
                b.bytes + now.saturating_duration_since(b.updated).as_secs_f64() * rate < burst
            });
            if buckets.len() >= self.max_keys
                && let Some(oldest) = buckets
                    .iter()
                    .min_by_key(|(_, b)| b.updated)
                    .map(|(k, _)| *k)
            {
                buckets.remove(&oldest);
            }
        }
        let bucket = buckets.entry(hash).or_insert(Bucket {
            bytes: self.burst,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        #[allow(clippy::cast_precision_loss)]
        let sent = bytes as f64;
        bucket.bytes = (bucket.bytes + elapsed * self.rate).min(self.burst) - sent;
        bucket.updated = now;
        if bucket.bytes >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-bucket.bytes / self.rate)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_burst_is_free_then_the_rate_holds() {
        let limiter = ByteLimiter::new(1_000, 2_000, 16);
        let t0 = Instant::now();
        assert_eq!(limiter.take("a", 2_000, t0), Duration::ZERO);
        assert_eq!(limiter.take("a", 500, t0), Duration::from_millis(500));
        // After waiting, the debt is paid and one second refills 1 000 bytes.
        let t1 = t0 + Duration::from_millis(1_500);
        assert_eq!(limiter.take("a", 1_000, t1), Duration::ZERO);
        assert_eq!(
            limiter.take("b", 100, t0),
            Duration::ZERO,
            "keys are separate"
        );
    }

    #[test]
    fn keys_stay_bounded() {
        let limiter = ByteLimiter::new(1, 1, 8);
        let t0 = Instant::now();
        for i in 0..100u32 {
            let _ = limiter.take(&i, 10, t0);
        }
        assert!(limiter.buckets.lock().unwrap().len() <= 8);
    }
}
