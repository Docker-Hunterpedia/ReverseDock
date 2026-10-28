//! Per-backend state that outlives a configuration generation (ADR-0022): a reload that keeps a
//! backend keeps its counters; a removed backend's state goes away with the last generation
//! that still uses it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

use crate::health::{Availability, BreakerState, EjectPolicy, Health, ProbePolicy};

/// What is known about one backend address.
#[derive(Debug, Default)]
pub struct BackendState {
    in_flight: AtomicU32,
    pool_in_flight: Arc<AtomicU32>,
    health: Mutex<Health>,
}

/// What a recorded failure did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ejection {
    /// Nothing changed.
    None,
    /// The backend was ejected for this long.
    Ejected(Duration),
    /// The threshold was reached, but the pool already has its maximum share ejected.
    Refused,
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
        self.pool_in_flight.fetch_add(1, Ordering::Relaxed);
        InFlight(self.clone())
    }

    fn health(&self) -> MutexGuard<'_, Health> {
        self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the backend may get a request now.
    pub fn availability(&self, now: Instant) -> Availability {
        self.health().availability(now)
    }

    /// The circuit-breaker state.
    pub fn breaker(&self, now: Instant) -> BreakerState {
        self.health().state(now)
    }

    /// Marks the request just sent to this half-open backend as its trial.
    pub fn start_trial(&self, now: Instant) {
        self.health().start_trial(now);
    }

    /// Records a probe result; returns the new verdict when it changed (`true` = healthy).
    pub fn probe(&self, ok: bool, policy: ProbePolicy, now: Instant) -> Option<bool> {
        self.health().probe(ok, policy, now)
    }

    /// Records a successful request; returns `true` when it ended an ejection.
    pub fn success(&self, now: Instant) -> bool {
        self.health().success(now)
    }

    /// Keeps the backend out until `until` (the backend asked for it with `Retry-After`).
    pub fn pause(&self, until: Instant) {
        self.health().pause(until);
    }

    /// `weight`, reduced while the backend ramps up after recovering.
    pub fn weight(&self, weight: u32, slow_start: Option<Duration>, now: Instant) -> u32 {
        self.health().weight(weight, slow_start, now)
    }

    fn is_ejected(&self) -> bool {
        self.health().is_ejected()
    }
}

/// One request in flight to a backend; dropping it ends the count.
#[derive(Debug)]
pub struct InFlight(Arc<BackendState>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.0.pool_in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The backends of one service, by identity (resolved address or socket path).
#[derive(Debug, Default)]
pub struct Pool {
    backends: RwLock<HashMap<String, Arc<BackendState>>>,
    in_flight: Arc<AtomicU32>,
    retries: Arc<AtomicU32>,
}

/// Retries in flight that are always allowed, whatever the budget (Envoy's
/// `min_retry_concurrency`).
pub const MIN_RETRIES: u32 = 3;

/// One retry in flight; dropping it returns it to the budget.
#[derive(Debug)]
pub struct RetryPermit(Arc<AtomicU32>);

impl Drop for RetryPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
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
            .or_insert_with(|| {
                Arc::new(BackendState {
                    pool_in_flight: self.in_flight.clone(),
                    ..BackendState::default()
                })
            })
            .clone()
    }

    /// Requests in flight to any backend of the pool.
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// A permit for one more retry, while retries in flight stay within `percent` of the
    /// requests in flight (or below [`MIN_RETRIES`]).
    pub fn try_retry(&self, percent: u32) -> Option<RetryPermit> {
        let allowed =
            (u64::from(self.in_flight()) * u64::from(percent) / 100).max(u64::from(MIN_RETRIES));
        let mut current = self.retries.load(Ordering::Relaxed);
        loop {
            if u64::from(current) >= allowed {
                return None;
            }
            match self.retries.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(RetryPermit(self.retries.clone())),
                Err(now) => current = now,
            }
        }
    }

    /// Forgets backends not in `live` (addresses that left DNS or the configuration).
    pub fn retain(&self, live: &HashSet<&str>) {
        self.backends
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| live.contains(id.as_str()));
    }

    /// Records a failed request to `state`; ejects it when `policy` says so and fewer than
    /// `max_percent` of the pool's backends are ejected.
    pub fn failure(
        &self,
        state: &BackendState,
        policy: EjectPolicy,
        max_percent: u32,
        now: Instant,
    ) -> Ejection {
        if !state.health().failure(policy, now) {
            return Ejection::None;
        }
        let (total, ejected) = {
            let backends = self.backends.read().unwrap_or_else(PoisonError::into_inner);
            let ejected = backends.values().filter(|b| b.is_ejected()).count();
            (backends.len(), ejected)
        };
        // A backend being re-ejected after its trial is already counted.
        let already = usize::from(state.is_ejected());
        if (ejected - already + 1) * 100 > total * max_percent as usize {
            return Ejection::Refused;
        }
        Ejection::Ejected(state.health().eject(policy, now))
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

    #[test]
    fn the_retry_budget_scales_with_traffic() {
        let pool = Pool::default();
        let permits: Vec<_> = (0..5).filter_map(|_| pool.try_retry(20)).collect();
        assert_eq!(
            permits.len(),
            MIN_RETRIES as usize,
            "at least three when idle"
        );
        let state = pool.state("a");
        let busy: Vec<_> = (0..50).map(|_| state.begin()).collect();
        let more: Vec<_> = (0..20).filter_map(|_| pool.try_retry(20)).collect();
        assert_eq!(permits.len() + more.len(), 10, "20 % of 50 in flight");
        drop((permits, more, busy));
        assert!(pool.try_retry(0).is_some(), "permits return to the budget");
    }

    #[test]
    fn pool_counts_in_flight_and_caps_ejections() {
        let pool = Pool::default();
        let a = pool.state("a");
        let b = pool.state("b");
        let _c = pool.state("c");
        let _ga = a.begin();
        let _gb = b.begin();
        assert_eq!(pool.in_flight(), 2);
        let policy = EjectPolicy {
            failures: 1,
            window: Duration::from_secs(10),
            ejection: Duration::from_secs(30),
        };
        let now = Instant::now();
        assert_eq!(
            pool.failure(&a, policy, 50, now),
            Ejection::Ejected(Duration::from_secs(30))
        );
        assert_eq!(
            pool.failure(&b, policy, 50, now),
            Ejection::Refused,
            "two of three would be more than half"
        );
        assert_eq!(b.availability(now), Availability::Up);
    }
}
