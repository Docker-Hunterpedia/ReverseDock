//! Health of one backend: the verdict of active probes, passive ejection with a half-open
//! trial, a pause asked for by `Retry-After`, and slow start (ADR-0022).

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
        let time = policy.ejection.saturating_mul(factor).min(MAX_EJECTION);
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

    pub(crate) fn is_ejected(&self) -> bool {
        self.ejected_until.is_some()
    }

    /// `weight` reduced while the backend ramps up after becoming healthy.
    pub(crate) fn weight(&self, weight: u32, slow_start: Option<Duration>, now: Instant) -> u32 {
        let (Some(ramp), Some(since)) = (slow_start, self.up_since) else {
            return weight;
        };
        let elapsed = now.duration_since(since);
        if elapsed >= ramp || ramp.is_zero() {
            return weight;
        }
        let share = elapsed.as_secs_f64() / ramp.as_secs_f64();
        // At least 1, so a ramping backend still gets a little traffic and can prove itself.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ramped = (f64::from(weight) * share).ceil() as u32;
        ramped.clamp(1, weight.max(1))
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
    };

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
        let ramp = Some(Duration::from_secs(100));
        assert_eq!(h.weight(10, ramp, now), 10, "never down: full weight");
        h.up_since = Some(now);
        assert_eq!(h.weight(10, ramp, now), 1);
        assert_eq!(h.weight(10, ramp, now + Duration::from_secs(50)), 5);
        assert_eq!(h.weight(10, ramp, now + Duration::from_secs(100)), 10);
        assert_eq!(h.weight(10, None, now), 10);
    }
}
