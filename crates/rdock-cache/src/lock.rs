//! Request coalescing (ADR-0030): pingora-cache's lock, with one change to its release rule.
//!
//! pingora-cache elects a new writer among the waiters when a fill fails
//! (`LockStatus::TransientError`). ADR-0030 wants a failed fetch to release the waiters to
//! fetch on their own, as an uncacheable one does, so a failing origin is never asked once per
//! waiter in turn: this wrapper turns that status into `GiveUp`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use pingora::cache::CacheKey;
use pingora::cache::lock::{
    CacheKeyLock, CacheKeyLockImpl, CacheLock, LockStatus, Locked, WritePermit,
};

/// pingora-cache's [`CacheLock`] where a failed fill releases the waiters (`GiveUp`) instead
/// of electing one of them to try again.
#[derive(Debug)]
pub struct CoalescingLock {
    inner: CacheLock,
}

impl CoalescingLock {
    /// A lock whose writers hold it for at most `age_timeout`.
    #[must_use]
    pub fn new(age_timeout: Duration) -> Self {
        Self {
            inner: CacheLock::new(age_timeout),
        }
    }
}

/// The status a writer's release reports to the waiters.
#[must_use]
pub fn release_status(status: LockStatus) -> LockStatus {
    match status {
        LockStatus::TransientError => LockStatus::GiveUp,
        other => other,
    }
}

impl CacheKeyLock for CoalescingLock {
    fn lock(&self, key: &CacheKey, stale_writer: bool) -> Locked {
        self.inner.lock(key, stale_writer)
    }

    fn release(&self, key: &CacheKey, permit: WritePermit, reason: LockStatus) {
        self.inner.release(key, permit, release_status(reason));
    }
}

/// The process-wide lock for writers held at most `timeout`. pingora-cache takes locks as
/// `&'static`; one is made per distinct timeout and kept for the life of the process (keys
/// include the store and route, so routes never contend across locks).
#[must_use]
pub fn lock_for(timeout: Duration) -> &'static CacheKeyLockImpl {
    static LOCKS: OnceLock<Mutex<HashMap<u128, &'static CoalescingLock>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let lock: &'static CoalescingLock = locks
        .entry(timeout.as_millis())
        .or_insert_with(|| Box::leak(Box::new(CoalescingLock::new(timeout))));
    lock
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_fill_releases_waiters_to_fetch_on_their_own() {
        assert_eq!(
            release_status(LockStatus::TransientError),
            LockStatus::GiveUp
        );
        assert_eq!(release_status(LockStatus::Done), LockStatus::Done);
        assert_eq!(release_status(LockStatus::GiveUp), LockStatus::GiveUp);
    }

    #[test]
    fn locks_are_shared_per_timeout() {
        let five = lock_for(Duration::from_secs(5));
        assert!(std::ptr::addr_eq(five, lock_for(Duration::from_secs(5))));
        assert!(!std::ptr::addr_eq(five, lock_for(Duration::from_secs(6))));
    }

    #[tokio::test]
    async fn waiters_see_give_up_when_the_writer_fails() {
        let lock = CoalescingLock::new(Duration::from_secs(5));
        let key = CacheKey::new(b"k".to_vec(), "r");
        let Locked::Write(permit) = lock.lock(&key, false) else {
            panic!("the first request writes");
        };
        let Locked::Read(read) = lock.lock(&key, false) else {
            panic!("the second request waits");
        };
        lock.release(&key, permit, LockStatus::TransientError);
        read.wait().await;
        assert_eq!(read.lock_status(), LockStatus::GiveUp);
    }
}
