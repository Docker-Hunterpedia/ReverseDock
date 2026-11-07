//! One lock per zone, so the read-modify-write of a record set never interleaves with another
//! on the same zone: two values presented at once on one name (a wildcard and its base name)
//! both stay, and Route 53 sees no concurrent change to the zone (ADR-0026).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// Locks keyed by zone, for the life of one solver.
#[derive(Debug, Default)]
pub(crate) struct ZoneLocks {
    locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl ZoneLocks {
    /// Waits until no other caller holds `zone`, and holds it until the guard is dropped.
    pub(crate) async fn lock(&self, zone: &str) -> OwnedMutexGuard<()> {
        let lock = self
            .locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(zone.to_owned())
            .or_default()
            .clone();
        lock.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn one_holder_per_zone_and_zones_are_independent() {
        let locks = Arc::new(ZoneLocks::default());
        let held = locks.lock("example.com").await;
        let other = tokio::time::timeout(Duration::from_millis(50), locks.lock("example.org"))
            .await
            .expect("another zone is not blocked");
        drop(other);
        let waiting = {
            let locks = locks.clone();
            tokio::spawn(async move { locks.lock("example.com").await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "the second caller waits");
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("released")
            .unwrap();
    }
}
