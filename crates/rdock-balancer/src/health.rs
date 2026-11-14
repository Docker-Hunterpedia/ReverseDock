//! Health of one backend: the verdict of active probes, passive ejection with a half-open
//! trial, a pause asked for by `Retry-After`, and slow start (ADR-0022, ADR-0031).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Ejections in a row double the ejection time up to this.
pub const MAX_EJECTION: Duration = Duration::from_secs(300);
/// A trial request that never reports back frees the trial after this.
const TRIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Thresholds of active probes.
#[derive(Debug, Clone, Copy)]
pub struct ProbePolicy {
    /// Successes in a row that make a backend healthy.
    pub healthy: u32,
    /// Failures in a row that make it unhealthy.
    pub unhealthy: u32,
}

/// When observed failures eject a backend.
#[derive(Debug, Clone, Copy)]
pub struct EjectPolicy {
    /// Failures within `window` that eject.
    pub failures: u32,
    /// Counting window.
    pub window: Duration,
    /// First ejection time.
    pub ejection: Duration,
    /// Up to this much is added at random to each ejection time (Envoy's
    /// `max_ejection_time_jitter`), so ejected backends of many instances do not return at once.
    pub jitter: Duration,
}

/// Weights are multiplied by this while slow start is configured, so that a ramp is smooth even
/// for a backend of weight 1.
pub const WEIGHT_SCALE: u32 = 1_000;

/// How a backend's weight ramps up after it recovers or joins (Envoy's `SlowStartConfig`):
/// `weight × max(min_weight_percent / 100, (elapsed / window)^(1 / aggression))`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlowStart {
    /// Time to full weight.
    pub window: Duration,
    /// Shape: 1.0 is linear; larger values ramp faster at first.
    pub aggression: f64,
    /// The weight never starts below this share, in percent.
    pub min_weight_percent: u32,
    /// Ramp after recovering from failed probes or an ejection.
    pub on_recovery: bool,
    /// Ramp a backend that newly appears in a pool that already had a backend at full weight.
    pub on_join: bool,
}

impl SlowStart {
    /// The share of its weight a backend has `elapsed` after the ramp started, from
    /// `min_weight_percent` to 1.
    #[must_use]
    pub fn factor(&self, elapsed: Duration) -> f64 {
        if self.window.is_zero() || elapsed >= self.window {
            return 1.0;
        }
        let time = elapsed.as_secs_f64() / self.window.as_secs_f64();
        let shaped = if self.aggression > 0.0 {
            time.powf(1.0 / self.aggression)
        } else {
            time
        };
        shaped
            .max(f64::from(self.min_weight_percent.min(100)) / 100.0)
            .clamp(0.0, 1.0)
    }

    /// `weight` scaled by [`WEIGHT_SCALE`] and by `factor`, at least 1.
    #[must_use]
    pub fn scaled(weight: u32, factor: f64) -> u32 {
        let full = f64::from(weight.min(u32::MAX / WEIGHT_SCALE) * WEIGHT_SCALE);
        if weight == 0 {
            return 0;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ramped = (full * factor.clamp(0.0, 1.0)).ceil() as u32;
        ramped.max(1)
    }
}

/// Whether a backend may receive a request now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Healthy.
    Up,
    /// Ejected, but its ejection time is over and no trial request is running: one request
    /// may test it.
    Trial,
    /// Not now.
    Down,
}

/// The states exported in metrics and `rdock status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Taking traffic.
    Closed,
    /// Ejected by observed failures or failing probes.
    Open,
    /// Waiting for, or running, a trial request.
    HalfOpen,
}

impl BreakerState {
    /// Lower-case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Health {
    probes_down: bool,
    ok_streak: u32,
    fail_streak: u32,
    failures: VecDeque<Instant>,
    ejected_until: Option<Instant>,
    ejections: u32,
    trial_since: Option<Instant>,
    paused_until: Option<Instant>,
    up_since: Option<Instant>,
    joined_at: Option<Instant>,
}

impl Health {
    pub(crate) fn availability(&self, now: Instant) -> Availability {
        if self.probes_down || self.paused_until.is_some_and(|t| now < t) {
            return Availability::Down;
        }
        match self.ejected_until {
            None => Availability::Up,
            Some(until) if now < until => Availability::Down,
            Some(_) => match self.trial_since {
                Some(since) if now.duration_since(since) < TRIAL_TIMEOUT => Availability::Down,
                _ => Availability::Trial,
            },
        }
    }

    pub(crate) fn state(&self, now: Instant) -> BreakerState {
        match (self.probes_down, self.ejected_until) {
            (true, _) => BreakerState::Open,
            (false, None) => BreakerState::Closed,
            (false, Some(until)) if now < until => BreakerState::Open,
            (false, Some(_)) => BreakerState::HalfOpen,
        }
    }

    pub(crate) fn start_trial(&mut self, now: Instant) {
        self.trial_since = Some(now);
    }

    /// Makes a request sent in panic mode to an ejected backend count as its trial: a success
    /// ends the ejection at once (the backend answers), a failure ejects it again for longer.
    /// A backend that is not ejected is left alone.
    pub(crate) fn start_panic_trial(&mut self, now: Instant) {
        if self.ejected_until.is_some() {
            self.trial_since = Some(now);
        }
    }

    /// A probe result; returns the new verdict when it changed (`true` = healthy).
    pub(crate) fn probe(&mut self, ok: bool, policy: ProbePolicy, now: Instant) -> Option<bool> {
        if ok {
            self.ok_streak += 1;
            self.fail_streak = 0;
            if self.probes_down && self.ok_streak >= policy.healthy {
                self.probes_down = false;
                self.up_since = Some(now);
                return Some(true);
            }
        } else {
            self.fail_streak += 1;
            self.ok_streak = 0;
            if !self.probes_down && self.fail_streak >= policy.unhealthy {
                self.probes_down = true;
                return Some(false);
            }
        }
        None
    }

    /// A failed request. Returns `true` when it reaches the ejection threshold (the caller
    /// decides whether the pool can afford the ejection).
    pub(crate) fn failure(&mut self, policy: EjectPolicy, now: Instant) -> bool {
        if self.trial_since.take().is_some() {
            // The trial failed: eject again at once, for longer.
            return true;
        }
        if self.ejected_until.is_some() {
            return false;
        }
        while self
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) > policy.window)
        {
            self.failures.pop_front();
        }
        self.failures.push_back(now);
        self.failures.len() >= policy.failures as usize
    }

    pub(crate) fn eject(&mut self, policy: EjectPolicy, now: Instant) -> Duration {
        let factor = 1u32 << self.ejections.min(16);
        let mut time = policy.ejection.saturating_mul(factor).min(MAX_EJECTION);
        if !policy.jitter.is_zero() {
            time += policy.jitter.mul_f64(fastrand::f64());
        }
        self.ejections = self.ejections.saturating_add(1);
        self.ejected_until = Some(now + time);
        self.failures.clear();
        time
    }

    /// A successful request. Returns `true` when it closed an ejection.
    pub(crate) fn success(&mut self, now: Instant) -> bool {
        if self.trial_since.take().is_some() || self.ejected_until.is_some_and(|t| now >= t) {
            self.ejected_until = None;
            self.ejections = 0;
            self.failures.clear();
            self.up_since = Some(now);
            return true;
        }
        false
    }

    pub(crate) fn pause(&mut self, until: Instant) {
        self.paused_until = Some(self.paused_until.map_or(until, |t| t.max(until)));
    }

    /// Why the backend gets no requests now, in words for operators; `None` when it may.
    pub(crate) fn exclusion(&self, now: Instant) -> Option<String> {
        if self.probes_down {
            return Some(format!(
                "failed its health checks ({} in a row)",
                self.fail_streak.max(1)
            ));
        }
        if let Some(until) = self.paused_until.filter(|t| now < *t) {
            return Some(format!(
                "paused for {} s more: it answered 503 with Retry-After",
                until.duration_since(now).as_secs().max(1)
            ));
        }
        match self.ejected_until {
            Some(until) if now < until => Some(format!(
                "ejected after repeated failures ({} times so far), {} s left",
                self.ejections,
                until.duration_since(now).as_secs().max(1)
            )),
            Some(_) if self.availability(now) == Availability::Down => {
                Some("ejection over; a trial request is testing it".to_owned())
            }
            _ => None,
        }
    }

    pub(crate) fn is_ejected(&self) -> bool {
        self.ejected_until.is_some()
    }

    /// Whether only passive ejection (or a running trial) keeps the backend out: its active
    /// checks, if any, pass and it has not asked for a pause. Panic routing prefers these.
    pub(crate) fn passes_checks(&self, now: Instant) -> bool {
        !self.probes_down && self.paused_until.is_none_or(|t| now >= t)
    }

    /// Marks the backend as having just joined its pool.
    pub(crate) fn join(&mut self, now: Instant) {
        self.joined_at = Some(now);
    }

    /// The share of its weight the backend has now under `slow_start`; `None` at full weight.
    pub(crate) fn ramp(&self, slow_start: Option<&SlowStart>, now: Instant) -> Option<f64> {
        let slow = slow_start?;
        let since = [
            self.up_since.filter(|_| slow.on_recovery),
            self.joined_at.filter(|_| slow.on_join),
        ]
        .into_iter()
        .flatten()
        .max()?;
        let factor = slow.factor(now.saturating_duration_since(since));
        (factor < 1.0).then_some(factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBES: ProbePolicy = ProbePolicy {
        healthy: 2,
        unhealthy: 3,
    };
    const EJECT: EjectPolicy = EjectPolicy {
        failures: 3,
        window: Duration::from_secs(10),
        ejection: Duration::from_secs(30),
        jitter: Duration::ZERO,
    };

    fn slow(on_recovery: bool, on_join: bool) -> SlowStart {
        SlowStart {
            window: Duration::from_secs(100),
            aggression: 1.0,
            min_weight_percent: 10,
            on_recovery,
            on_join,
        }
    }

    #[test]
    fn a_panic_request_that_succeeds_ends_the_ejection() {
        let now = Instant::now();
        let mut h = Health::default();
        h.start_panic_trial(now);
        assert!(h.trial_since.is_none(), "not ejected: no trial");
        h.failure(EJECT, now);
        h.failure(EJECT, now);
        h.failure(EJECT, now);
        h.eject(EJECT, now);
        h.start_panic_trial(now);
        assert!(h.success(now), "a success in panic mode ends the ejection");
        assert_eq!(h.availability(now), Availability::Up);
    }

    #[test]
    fn passive_ejection_alone_still_passes_checks() {
        let now = Instant::now();
        let mut h = Health::default();
        for _ in 0..EJECT.failures {
            h.failure(EJECT, now);
        }
        h.eject(EJECT, now);
        assert_eq!(h.availability(now), Availability::Down);
        assert!(
            h.passes_checks(now),
            "ejected by failures, probes still pass"
        );
        for _ in 0..PROBES.unhealthy {
            h.probe(false, PROBES, now);
        }
        assert!(!h.passes_checks(now), "failing probes");
        let mut paused = Health::default();
        paused.pause(now + Duration::from_secs(5));
        assert!(!paused.passes_checks(now), "asked for a pause");
        assert!(paused.passes_checks(now + Duration::from_secs(6)));
    }

    #[test]
    fn probes_need_streaks_both_ways() {
        let now = Instant::now();
        let mut h = Health::default();
        assert_eq!(
            h.availability(now),
            Availability::Up,
            "new backends start healthy"
        );
        assert_eq!(h.probe(false, PROBES, now), None);
        assert_eq!(h.probe(false, PROBES, now), None);
        assert_eq!(h.probe(false, PROBES, now), Some(false));
        assert_eq!(h.availability(now), Availability::Down);
        assert_eq!(h.probe(true, PROBES, now), None);
        assert_eq!(
            h.probe(false, PROBES, now),
            None,
            "a failure resets the success streak"
        );
        assert_eq!(h.probe(true, PROBES, now), None);
        assert_eq!(h.probe(true, PROBES, now), Some(true));
        assert_eq!(h.availability(now), Availability::Up);
    }

    #[test]
    fn failures_in_the_window_eject_then_a_trial_decides() {
        let t0 = Instant::now();
        let mut h = Health::default();
        assert!(!h.failure(EJECT, t0));
        assert!(
            !h.failure(EJECT, t0 + Duration::from_secs(11)),
            "the first one aged out"
        );
        assert!(!h.failure(EJECT, t0 + Duration::from_secs(12)));
        assert!(h.failure(EJECT, t0 + Duration::from_secs(13)));
        let t1 = t0 + Duration::from_secs(13);
        assert_eq!(h.eject(EJECT, t1), Duration::from_secs(30));
        assert_eq!(h.availability(t1), Availability::Down);
        assert_eq!(h.state(t1), BreakerState::Open);
        let later = t1 + Duration::from_secs(31);
        assert_eq!(h.availability(later), Availability::Trial);
        assert_eq!(h.state(later), BreakerState::HalfOpen);
        h.start_trial(later);
        assert_eq!(
            h.availability(later),
            Availability::Down,
            "one trial at a time"
        );
        // The trial fails: ejected again, for twice as long.
        assert!(h.failure(EJECT, later));
        assert_eq!(h.eject(EJECT, later), Duration::from_secs(60));
        let after = later + Duration::from_secs(61);
        h.start_trial(after);
        assert!(h.success(after));
        assert_eq!(h.availability(after), Availability::Up);
        assert_eq!(h.state(after), BreakerState::Closed);
    }

    #[test]
    fn ejection_time_is_capped_and_lost_trials_expire() {
        let now = Instant::now();
        let mut h = Health::default();
        for _ in 0..20 {
            h.eject(EJECT, now);
        }
        assert_eq!(h.eject(EJECT, now), MAX_EJECTION);
        let open = now + MAX_EJECTION;
        h.start_trial(open);
        assert_eq!(
            h.availability(open + Duration::from_secs(5)),
            Availability::Down
        );
        assert_eq!(
            h.availability(open + TRIAL_TIMEOUT),
            Availability::Trial,
            "a trial that never reported back is given up"
        );
    }

    #[test]
    fn pauses_and_slow_start() {
        let now = Instant::now();
        let mut h = Health::default();
        h.pause(now + Duration::from_secs(5));
        assert_eq!(h.availability(now), Availability::Down);
        assert_eq!(
            h.availability(now + Duration::from_secs(5)),
            Availability::Up
        );
        let ramp = slow(true, false);
        assert_eq!(h.ramp(Some(&ramp), now), None, "never down: full weight");
        h.up_since = Some(now);
        let at = |secs| h.ramp(Some(&ramp), now + Duration::from_secs(secs));
        assert_eq!(at(0), Some(0.1), "the floor");
        assert_eq!(at(50), Some(0.5));
        assert_eq!(at(100), None);
        assert_eq!(h.ramp(None, now), None);
        assert_eq!(
            h.ramp(Some(&slow(false, true)), now),
            None,
            "recovery not ramped"
        );
    }

    #[test]
    fn slow_start_follows_envoys_formula() {
        let mut s = slow(true, true);
        let t = |secs| Duration::from_secs(secs);
        assert!((s.factor(t(25)) - 0.25).abs() < 1e-12, "linear");
        assert!((s.factor(t(5)) - 0.10).abs() < 1e-12, "min_weight_percent");
        s.aggression = 2.0;
        assert!(
            (s.factor(t(25)) - 0.5).abs() < 1e-12,
            "square root at aggression 2"
        );
        s.min_weight_percent = 0;
        s.aggression = 1.0;
        assert!(s.factor(t(0)).abs() < 1e-12);
        assert!((s.factor(t(100)) - 1.0).abs() < 1e-12);
        assert_eq!(SlowStart::scaled(1, 0.1), 100, "weight 1 ramps too");
        assert_eq!(SlowStart::scaled(3, 1.0), 3_000);
        assert_eq!(SlowStart::scaled(1, 0.0), 1, "never zero");
        assert_eq!(SlowStart::scaled(0, 1.0), 0);
    }

    #[test]
    fn joining_and_recovering_take_the_later_start() {
        let now = Instant::now();
        let mut h = Health::default();
        h.join(now);
        let both = slow(true, true);
        assert_eq!(
            h.ramp(Some(&both), now + Duration::from_secs(50)),
            Some(0.5)
        );
        assert_eq!(
            h.ramp(Some(&slow(true, false)), now),
            None,
            "join not ramped"
        );
        h.up_since = Some(now + Duration::from_secs(50));
        assert_eq!(
            h.ramp(Some(&both), now + Duration::from_secs(60)),
            Some(0.1),
            "a recovery restarts the ramp"
        );
    }

    #[test]
    fn jitter_lengthens_an_ejection_by_at_most_its_bound() {
        let now = Instant::now();
        let policy = EjectPolicy {
            jitter: Duration::from_secs(5),
            ..EJECT
        };
        for _ in 0..20 {
            let mut h = Health::default();
            let time = h.eject(policy, now);
            assert!(time >= EJECT.ejection && time <= EJECT.ejection + policy.jitter);
        }
    }
}
