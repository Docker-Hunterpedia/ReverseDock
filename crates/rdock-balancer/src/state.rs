//! Per-backend state that outlives a configuration generation (ADR-0022): a reload that keeps a
//! backend keeps its counters; a removed backend's state goes away with the last generation
//! that still uses it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

use crate::ewma::Latency;
use crate::health::{Availability, BreakerState, EjectPolicy, Health, ProbePolicy, SlowStart};
use crate::outlier::{Detector, Outlier, outliers};

/// What is known about one backend address.
#[derive(Debug, Default)]
pub struct BackendState {
    in_flight: AtomicU32,
    pool_in_flight: Arc<AtomicU32>,
    health: Mutex<Health>,
    /// Taken out of rotation by an operator: no new requests, open ones finish.
    drained: AtomicBool,
    /// Latency estimate for `peak_ewma`.
    latency: Latency,
    /// Attempts and failed attempts since the outlier detectors last looked.
    attempts: AtomicU32,
    failed: AtomicU32,
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

    /// The share of its weight the backend has now while it ramps up after recovering or
    /// joining; `None` at full weight.
    pub fn ramp(&self, slow_start: Option<&SlowStart>, now: Instant) -> Option<f64> {
        self.health().ramp(slow_start, now)
    }

    /// Marks the backend as new in its pool (slow start `on: [join]`).
    pub fn join(&self, now: Instant) {
        self.health().join(now);
    }

    /// The latency estimate used by `peak_ewma`.
    pub fn latency(&self) -> &Latency {
        &self.latency
    }

    /// Counts an attempt for the outlier detectors.
    pub fn record_outcome(&self, ok: bool) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The `(attempts, failures)` since the last call; the counters start again from zero.
    pub fn take_outcomes(&self) -> (u32, u32) {
        let failed = self.failed.swap(0, Ordering::Relaxed);
        let attempts = self.attempts.swap(0, Ordering::Relaxed);
        (attempts, failed.min(attempts))
    }

    fn is_ejected(&self) -> bool {
        self.health().is_ejected()
    }

    /// Why the backend gets no requests now (health, ejection, `Retry-After`, drain); `None`
    /// when it may get them.
    pub fn exclusion(&self, now: Instant) -> Option<String> {
        if self.is_drained() {
            return Some("drained by an operator".to_owned());
        }
        self.health().exclusion(now)
    }

    /// Whether an operator drained the backend.
    pub fn is_drained(&self) -> bool {
        self.drained.load(Ordering::Relaxed)
    }

    /// Drains (`true`) or returns (`false`) the backend.
    pub fn set_drained(&self, drained: bool) {
        self.drained.store(drained, Ordering::Relaxed);
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
    /// The state of backend `id` if it exists; never creates one.
    pub fn existing(&self, id: &str) -> Option<Arc<BackendState>> {
        self.backends
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// The state of backend `id`, created on first use.
    pub fn state(&self, id: &str) -> Arc<BackendState> {
        self.state_created(id).0
    }

    /// The state of backend `id`, and whether this call created it.
    pub fn state_created(&self, id: &str) -> (Arc<BackendState>, bool) {
        if let Some(state) = self
            .backends
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
        {
            return (state.clone(), false);
        }
        let mut created = false;
        let state = self
            .backends
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(id.to_owned())
            .or_insert_with(|| {
                created = true;
                Arc::new(BackendState {
                    pool_in_flight: self.in_flight.clone(),
                    ..BackendState::default()
                })
            })
            .clone();
        (state, created)
    }

    /// Whether some backend of the pool takes traffic at full weight now: a backend that joins
    /// such a pool ramps up (slow start `on: [join]`); one that joins an empty or recovering
    /// pool does not (the rule of AWS ALB target groups).
    pub fn has_settled_backend(&self, slow_start: Option<&SlowStart>, now: Instant) -> bool {
        self.backends
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .any(|b| {
                !b.is_drained()
                    && b.availability(now) == Availability::Up
                    && b.ramp(slow_start, now).is_none()
            })
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

    /// Ejects `state` now, found by an outlier detector, unless it is already ejected or the
    /// pool has `max_percent` of its backends ejected. The ejection time and its back-off are
    /// those of a failure ejection.
    pub fn eject_outlier(
        &self,
        state: &BackendState,
        policy: EjectPolicy,
        max_percent: u32,
        now: Instant,
    ) -> Ejection {
        if state.is_ejected() {
            return Ejection::None;
        }
        if !self.room_to_eject(max_percent) {
            return Ejection::Refused;
        }
        Ejection::Ejected(state.health().eject(policy, now))
    }

    fn room_to_eject(&self, max_percent: u32) -> bool {
        let backends = self.backends.read().unwrap_or_else(PoisonError::into_inner);
        let ejected = backends.values().filter(|b| b.is_ejected()).count();
        (ejected + 1) * 100 <= backends.len() * max_percent as usize
    }

    /// Runs the outlier detectors over the counts since the last run (which start again) and
    /// ejects what they find, within `max_percent`. Returns each backend found, the detector
    /// and what happened, in no particular order.
    pub fn detect_outliers(
        &self,
        detectors: &Outlier,
        policy: EjectPolicy,
        max_percent: u32,
        now: Instant,
    ) -> Vec<(String, Detector, Ejection)> {
        let backends: Vec<(String, Arc<BackendState>)> = self
            .backends
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(id, state)| (id.clone(), state.clone()))
            .collect();
        let counts: Vec<(u32, u32)> = backends.iter().map(|(_, s)| s.take_outcomes()).collect();
        outliers(&counts, detectors)
            .into_iter()
            .filter_map(|(i, detector)| {
                let (id, state) = backends.get(i)?;
                let result = self.eject_outlier(state, policy, max_percent, now);
                Some((id.clone(), detector, result))
            })
            .collect()
    }
}

/// Pools by service name, shared by every configuration generation.
#[derive(Debug, Default)]
pub struct Registry {
    pools: Mutex<HashMap<String, Weak<Pool>>>,
}

impl Registry {
    /// The pool of `service` if a live generation uses it; never creates one.
    pub fn existing(&self, service: &str) -> Option<Arc<Pool>> {
        self.pools
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(service)
            .and_then(Weak::upgrade)
    }

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
            jitter: Duration::ZERO,
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

    fn detectors() -> Outlier {
        Outlier {
            success_rate: Some(crate::SuccessRate {
                stdev_factor: 1.9,
                minimum_hosts: 5,
                request_volume: 10,
            }),
            failure_percentage: None,
        }
    }

    const POLICY: EjectPolicy = EjectPolicy {
        failures: 5,
        window: Duration::from_secs(30),
        ejection: Duration::from_secs(30),
        jitter: Duration::ZERO,
    };

    #[test]
    fn outliers_are_ejected_through_the_ordinary_machinery() {
        let pool = Pool::default();
        let states: Vec<_> = (0..5).map(|i| pool.state(&format!("b{i}"))).collect();
        for (i, state) in states.iter().enumerate() {
            for n in 0..10 {
                state.record_outcome(!(i == 4 && n % 5 < 2));
            }
        }
        let now = Instant::now();
        let found = pool.detect_outliers(&detectors(), POLICY, 50, now);
        assert_eq!(
            found,
            vec![(
                "b4".to_owned(),
                Detector::SuccessRate,
                Ejection::Ejected(Duration::from_secs(30))
            )]
        );
        assert_eq!(states[4].availability(now), Availability::Down);
        assert_eq!(
            states[0].take_outcomes(),
            (0, 0),
            "the counters start again"
        );
        // The back-off of a failure ejection applies: after a failed trial, twice as long.
        let later = now + Duration::from_secs(31);
        states[4].start_trial(later);
        assert_eq!(
            pool.failure(&states[4], POLICY, 50, later),
            Ejection::Ejected(Duration::from_secs(60))
        );
    }

    #[test]
    fn outlier_ejections_respect_the_cap() {
        let pool = Pool::default();
        let states: Vec<_> = (0..5).map(|i| pool.state(&format!("b{i}"))).collect();
        let now = Instant::now();
        assert!(matches!(
            pool.eject_outlier(&states[0], POLICY, 20, now),
            Ejection::Ejected(_)
        ));
        assert_eq!(
            pool.eject_outlier(&states[1], POLICY, 20, now),
            Ejection::Refused,
            "one of five is 20 %"
        );
        assert_eq!(
            pool.eject_outlier(&states[0], POLICY, 100, now),
            Ejection::None,
            "already ejected"
        );
    }

    #[test]
    fn joining_needs_a_settled_pool() {
        let slow = SlowStart {
            window: Duration::from_secs(60),
            aggression: 1.0,
            min_weight_percent: 10,
            on_recovery: true,
            on_join: true,
        };
        let pool = Pool::default();
        let now = Instant::now();
        assert!(!pool.has_settled_backend(Some(&slow), now), "empty");
        let (a, created) = pool.state_created("a");
        assert!(created);
        assert!(!pool.state_created("a").1);
        assert!(pool.has_settled_backend(Some(&slow), now));
        a.join(now);
        assert!(
            !pool.has_settled_backend(Some(&slow), now),
            "a ramping backend is not settled"
        );
        assert_eq!(a.ramp(Some(&slow), now), Some(0.1));
    }
}
