//! Requests in flight per key, for the `in_flight` middleware (Traefik's `inFlightReq`). A
//! request over the limit waits in a bounded queue for at most a deadline, or is refused.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
struct Slot {
    permits: Arc<Semaphore>,
    waiting: AtomicU32,
}

/// Why a request was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The limit is reached and the queue is full (or there is none).
    Full,
    /// The request waited `queue_timeout` without getting a slot.
    Timeout,
}

/// One admitted request; dropping it frees the slot.
#[derive(Debug)]
pub struct Admitted {
    _permit: OwnedSemaphorePermit,
}

/// A concurrency limiter keyed by an arbitrary value.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    amount: u32,
    queue: u32,
    queue_timeout: Duration,
    max_keys: usize,
    hasher: RandomState,
    slots: Mutex<HashMap<u64, Arc<Slot>>>,
}

impl ConcurrencyLimiter {
    /// `amount` requests in flight per key (at least one), up to `queue` more waiting for at
    /// most `queue_timeout`, tracking at most `max_keys` keys.
    #[must_use]
    pub fn new(amount: u32, queue: u32, queue_timeout: Duration, max_keys: usize) -> Self {
        Self {
            amount: amount.max(1),
            queue,
            queue_timeout,
            max_keys: max_keys.max(1),
            hasher: RandomState::new(),
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slot<K: Hash + ?Sized>(&self, key: &K) -> Arc<Slot> {
        let hash = self.hasher.hash_one(key);
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if !slots.contains_key(&hash) && slots.len() >= self.max_keys {
            // A slot only this map holds has no request in flight or waiting.
            slots.retain(|_, slot| Arc::strong_count(slot) > 1);
        }
        slots
            .entry(hash)
            .or_insert_with(|| {
                Arc::new(Slot {
                    permits: Arc::new(Semaphore::new(self.amount as usize)),
                    waiting: AtomicU32::new(0),
                })
            })
            .clone()
    }

    /// Admits a request for `key`, waiting in the queue if there is room in it.
    pub async fn admit<K: Hash + ?Sized>(&self, key: &K) -> Result<Admitted, Refused> {
        let slot = self.slot(key);
        if let Ok(permit) = slot.permits.clone().try_acquire_owned() {
            return Ok(Admitted { _permit: permit });
        }
        let queued = slot.waiting.fetch_add(1, Ordering::AcqRel);
        if queued >= self.queue {
            slot.waiting.fetch_sub(1, Ordering::AcqRel);
            return Err(Refused::Full);
        }
        let waited =
            tokio::time::timeout(self.queue_timeout, slot.permits.clone().acquire_owned()).await;
        slot.waiting.fetch_sub(1, Ordering::AcqRel);
        match waited {
            Ok(Ok(permit)) => Ok(Admitted { _permit: permit }),
            // The semaphore is never closed; treat it like a timeout if it ever were.
            Ok(Err(_)) | Err(_) => Err(Refused::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admits_up_to_the_limit_then_queues_then_refuses() {
        let limiter = Arc::new(ConcurrencyLimiter::new(
            1,
            1,
            Duration::from_millis(200),
            16,
        ));
        let first = limiter.admit("ip").await.unwrap();
        assert_eq!(
            limiter.admit("other").await.map(drop),
            Ok(()),
            "keys are separate"
        );
        let waiter = {
            let limiter = limiter.clone();
            tokio::spawn(async move { limiter.admit("ip").await.map(drop) })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            limiter.admit("ip").await.map(drop),
            Err(Refused::Full),
            "the queue holds one"
        );
        drop(first);
        assert_eq!(
            waiter.await.unwrap(),
            Ok(()),
            "the queued request got the slot"
        );
    }

    #[tokio::test]
    async fn a_queued_request_gives_up_at_the_deadline() {
        let limiter = ConcurrencyLimiter::new(1, 4, Duration::from_millis(50), 16);
        let _held = limiter.admit("ip").await.unwrap();
        assert_eq!(limiter.admit("ip").await.map(drop), Err(Refused::Timeout));
    }
}
