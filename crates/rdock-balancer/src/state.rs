//! Per-backend state that outlives a configuration generation (ADR-0022): a reload that keeps a
//! backend keeps its counters; a removed backend's state goes away with the last generation
//! that still uses it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};

/// What is known about one backend address.
#[derive(Debug, Default)]
pub struct BackendState {
    in_flight: AtomicU32,
}

impl BackendState {
    /// Requests currently sent to this backend.
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Counts a request until the returned guard is dropped.
    #[must_use]
    pub fn begin(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlight(self.clone())
    }
}

/// One request in flight to a backend; dropping it ends the count.
#[derive(Debug)]
pub struct InFlight(Arc<BackendState>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The backends of one service, by identity (resolved address or socket path).
#[derive(Debug, Default)]
pub struct Pool {
    backends: RwLock<HashMap<String, Arc<BackendState>>>,
}

impl Pool {
    /// The state of backend `id`, created on first use.
    pub fn state(&self, id: &str) -> Arc<BackendState> {
        if let Some(state) = self
            .backends
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
        {
            return state.clone();
        }
        self.backends
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(id.to_owned())
            .or_default()
            .clone()
    }

    /// Forgets backends not in `live` (addresses that left DNS or the configuration).
    pub fn retain(&self, live: &HashSet<&str>) {
        self.backends
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| live.contains(id.as_str()));
    }
}

/// Pools by service name, shared by every configuration generation.
#[derive(Debug, Default)]
pub struct Registry {
    pools: Mutex<HashMap<String, Weak<Pool>>>,
}

impl Registry {
    /// The pool of `service`, shared with earlier generations while they are alive.
    pub fn pool(&self, service: &str) -> Arc<Pool> {
        let mut pools = self.pools.lock().unwrap_or_else(PoisonError::into_inner);
        pools.retain(|_, pool| pool.strong_count() > 0);
        if let Some(pool) = pools.get(service).and_then(Weak::upgrade) {
            return pool;
        }
        let pool = Arc::new(Pool::default());
        pools.insert(service.to_owned(), Arc::downgrade(&pool));
        pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_counts_until_the_guard_drops() {
        let pool = Pool::default();
        let state = pool.state("10.0.0.1:80");
        let a = state.begin();
        let b = pool.state("10.0.0.1:80").begin();
        assert_eq!(state.in_flight(), 2);
        drop(a);
        drop(b);
        assert_eq!(state.in_flight(), 0);
    }

    #[test]
    fn pools_survive_while_a_generation_holds_them() {
        let registry = Registry::default();
        let first = registry.pool("api");
        let state = first.state("a");
        let _guard = state.begin();
        let second = registry.pool("api");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.state("a").in_flight(), 1);
        drop((first, second));
        let third = registry.pool("api");
        assert_eq!(
            third.state("a").in_flight(),
            0,
            "a new pool after the last one went"
        );
    }

    #[test]
    fn retain_forgets_gone_backends() {
        let pool = Pool::default();
        let old = pool.state("a");
        let _keep = pool.state("b");
        pool.retain(&HashSet::from(["b"]));
        assert!(!Arc::ptr_eq(&old, &pool.state("a")));
    }
}
