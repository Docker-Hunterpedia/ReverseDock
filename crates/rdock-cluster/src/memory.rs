//! A store in memory: one lock, one clock, fencing enforced. Used by tests and simulations; the
//! control plane's store is an exclusive [`crate::DirStore`] with the same guarantees on disk.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;

use crate::clock::{Clock, SystemClock, deadline};
use crate::store::{ClusterStore, Entry, Expect, Fencing, Lease, StoreError, check_key};

#[derive(Debug, Default)]
struct Inner {
    values: BTreeMap<String, Entry>,
    leases: BTreeMap<String, Lease>,
    /// The last version handed out; versions grow across all keys.
    version: u64,
}

/// A store in memory with enforced fencing.
#[derive(Debug, Clone)]
pub struct MemoryStore {
    inner: Arc<Mutex<Inner>>,
    clock: Arc<dyn Clock>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// An empty store on the system clock.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    /// An empty store judging leases by `clock`.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            clock,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether `fence` is the current, unexpired lease.
fn fence_holds(inner: &Inner, fence: Option<&Lease>, now: u64) -> Result<(), StoreError> {
    let Some(fence) = fence else { return Ok(()) };
    match inner.leases.get(&fence.name) {
        Some(current)
            if current.token == fence.token
                && current.holder == fence.holder
                && current.expires_at_ms > now =>
        {
            Ok(())
        }
        _ => Err(StoreError::Fenced {
            lease: fence.name.clone(),
            token: fence.token,
        }),
    }
}

fn expect_holds(inner: &Inner, key: &str, expect: Expect) -> Result<(), StoreError> {
    let current = inner.values.get(key).map_or(0, |e| e.version);
    let ok = match expect {
        Expect::Any => true,
        Expect::Absent => current == 0,
        Expect::Version(v) => current == v,
    };
    if ok {
        Ok(())
    } else {
        Err(StoreError::Conflict {
            key: key.to_owned(),
            current,
        })
    }
}

#[async_trait]
impl ClusterStore for MemoryStore {
    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError> {
        check_key(key, false)?;
        Ok(self.lock().values.get(key).cloned())
    }

    async fn put(
        &self,
        key: &str,
        value: Vec<u8>,
        expect: Expect,
        fence: Option<&Lease>,
    ) -> Result<u64, StoreError> {
        check_key(key, false)?;
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        fence_holds(&inner, fence, now)?;
        expect_holds(&inner, key, expect)?;
        inner.version += 1;
        let version = inner.version;
        inner
            .values
            .insert(key.to_owned(), Entry { value, version });
        Ok(version)
    }

    async fn delete(
        &self,
        key: &str,
        expect: Expect,
        fence: Option<&Lease>,
    ) -> Result<(), StoreError> {
        check_key(key, false)?;
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        fence_holds(&inner, fence, now)?;
        expect_holds(&inner, key, expect)?;
        inner.values.remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        check_key(prefix, true)?;
        let inner = self.lock();
        Ok(inner
            .values
            .keys()
            .filter(|k| {
                prefix.is_empty()
                    || k.strip_prefix(prefix)
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            })
            .cloned()
            .collect())
    }

    async fn acquire(
        &self,
        name: &str,
        holder: &str,
        ttl: Duration,
    ) -> Result<Option<Lease>, StoreError> {
        check_key(name, false)?;
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        let previous = inner.leases.get(name).cloned();
        let token = match &previous {
            Some(current) if current.expires_at_ms > now && current.holder != holder => {
                return Ok(None);
            }
            Some(current) if current.expires_at_ms > now => current.token,
            Some(current) => current.token + 1,
            None => 1,
        };
        let lease = Lease {
            name: name.to_owned(),
            holder: holder.to_owned(),
            token,
            expires_at_ms: deadline(now, ttl),
        };
        inner.leases.insert(name.to_owned(), lease.clone());
        Ok(Some(lease))
    }

    async fn renew(&self, lease: &Lease, ttl: Duration) -> Result<Lease, StoreError> {
        let now = self.clock.now_ms();
        let mut inner = self.lock();
        match inner.leases.get_mut(&lease.name) {
            Some(current)
                if current.token == lease.token
                    && current.holder == lease.holder
                    && current.expires_at_ms > now =>
            {
                current.expires_at_ms = deadline(now, ttl);
                Ok(current.clone())
            }
            _ => Err(StoreError::Lost(lease.name.clone())),
        }
    }

    async fn release(&self, lease: &Lease) -> Result<(), StoreError> {
        let mut inner = self.lock();
        if let Some(current) = inner.leases.get_mut(&lease.name)
            && current.token == lease.token
            && current.holder == lease.holder
        {
            // Kept, expired, so the next holder's token is larger.
            current.expires_at_ms = 0;
        }
        Ok(())
    }

    async fn lease(&self, name: &str) -> Result<Option<Lease>, StoreError> {
        check_key(name, false)?;
        Ok(self.lock().leases.get(name).cloned())
    }

    fn fencing(&self) -> Fencing {
        Fencing::Enforced
    }
}
