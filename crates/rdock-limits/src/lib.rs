#![doc = include_str!("../README.md")]

mod bandwidth;
mod concurrency;

pub use bandwidth::ByteLimiter;
pub use concurrency::{Admitted, ConcurrencyLimiter, Refused};

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const SHARDS: usize = 64;

/// Token-bucket rate limiter keyed by an arbitrary value (client IP, header value, …) with a
/// hard cap on the number of tracked keys.
///
/// Each key has a bucket of `burst` tokens refilled at `average / period`. A request takes one
/// token. When the cap is reached, full buckets (idle clients) are dropped first, then the least
/// recently used one, so memory stays bounded under any key cardinality.
#[derive(Debug)]
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    keys_per_shard: usize,
    hasher: RandomState,
    shards: Vec<Mutex<HashMap<u64, Bucket>>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// Result of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed.
    Allow,
    /// The request is over the limit; a token is available again after `retry_after`.
    Deny {
        /// Time until the next token.
        retry_after: Duration,
    },
}

impl RateLimiter {
    /// `average` requests per `period`, bursts of up to `burst`, tracking at most `max_keys`
    /// keys. Zero values are treated as one.
    #[must_use]
    pub fn new(average: u32, period: Duration, burst: u32, max_keys: usize) -> Self {
        let period = period.max(Duration::from_millis(1));
        Self {
            rate: f64::from(average.max(1)) / period.as_secs_f64(),
            burst: f64::from(burst.max(1)),
            keys_per_shard: max_keys.div_ceil(SHARDS).max(1),
            hasher: RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    /// Takes a token for `key` at time `now`.
    pub fn check<K: Hash + ?Sized>(&self, key: &K, now: Instant) -> Decision {
        let hash = self.hasher.hash_one(key);
        let index = usize::try_from(hash % SHARDS as u64).unwrap_or(0);
        // A poisoned shard only means another thread panicked while holding it; the buckets are
        // plain numbers and remain valid.
        let mut shard = self.shards[index]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !shard.contains_key(&hash) && shard.len() >= self.keys_per_shard {
            self.evict(&mut shard, now);
        }
        let bucket = shard.entry(hash).or_insert(Bucket {
            tokens: self.burst,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Decision::Allow
        } else {
            let wait = (1.0 - bucket.tokens) / self.rate;
            Decision::Deny {
                retry_after: Duration::from_secs_f64(wait),
            }
        }
    }

    /// Drops buckets that have refilled completely; if none did, drops the least recently used.
    fn evict(&self, shard: &mut HashMap<u64, Bucket>, now: Instant) {
        let before = shard.len();
        shard.retain(|_, b| {
            let elapsed = now.saturating_duration_since(b.updated).as_secs_f64();
            b.tokens + elapsed * self.rate < self.burst
        });
        if shard.len() == before
            && let Some(oldest) = shard.iter().min_by_key(|(_, b)| b.updated).map(|(k, _)| *k)
        {
            shard.remove(&oldest);
        }
    }

    /// Number of tracked keys.
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_bursts_then_refills_at_the_average_rate() {
        let limiter = RateLimiter::new(10, Duration::from_secs(1), 3, 100);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.check(&"ip", t0), Decision::Allow);
        }
        let Decision::Deny { retry_after } = limiter.check(&"ip", t0) else {
            panic!("fourth request in the burst must be denied")
        };
        assert!(retry_after <= Duration::from_millis(100), "{retry_after:?}");
        assert_eq!(
            limiter.check(&"ip", t0 + Duration::from_millis(100)),
            Decision::Allow
        );
        assert_eq!(limiter.check(&"other", t0), Decision::Allow);
    }

    #[test]
    fn memory_stays_bounded() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60), 1, 128);
        let t0 = Instant::now();
        for i in 0..10_000u32 {
            let _ = limiter.check(&i, t0 + Duration::from_millis(u64::from(i)));
        }
        assert!(
            limiter.tracked_keys() <= 128 + SHARDS,
            "{}",
            limiter.tracked_keys()
        );
    }
}
