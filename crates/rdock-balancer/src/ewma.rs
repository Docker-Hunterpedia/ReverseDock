//! Peak-EWMA (H-LB-01, ADR-0031): a latency estimate per backend that is "highly sensitive to
//! peaks", weighted by the requests in flight and the backend's weight, and compared between
//! two distinct random backends (power of two choices).
//!
//! The estimate follows Finagle's `PeakEwma` and `tower::load::peak_ewma`: a sample above the
//! estimate replaces it at once; a lower sample is averaged in with the weight
//! `1 − e^(−elapsed / decay)` for the time since the last update; reading the estimate first
//! applies a zero sample, so an idle backend's estimate decays towards zero and it is tried
//! again. The cost of a backend is `estimate × (in_flight + 1) / weight`. A backend without a
//! sample starts from the mean estimate of the candidates that have one (at least
//! [`SEED_FLOOR`]), or [`SEED_FALLBACK`] when none has (Linkerd's defaults).

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::Choice;

/// Seeds are never below this, so a fresh backend is not over-selected in a fast pool
/// (Linkerd's floor).
pub const SEED_FLOOR: Duration = Duration::from_millis(1);
/// The seed when no candidate has a sample yet (Linkerd's default RTT).
pub const SEED_FALLBACK: Duration = Duration::from_millis(30);
/// A failed attempt counts as a sample of at least this (tower's default RTT): a backend that
/// refuses connections at once must not look fast.
pub const FAILURE_PENALTY: Duration = Duration::from_secs(1);

/// The latency estimate of one backend; shared across configuration generations with the rest
/// of its state.
#[derive(Debug, Default)]
pub struct Latency(Mutex<Option<Estimate>>);

#[derive(Debug, Clone, Copy)]
struct Estimate {
    /// Seconds.
    value: f64,
    at: Instant,
}

/// The estimate after a sample of `rtt` seconds, `elapsed` after the last update.
#[must_use]
pub fn update(estimate: f64, elapsed: Duration, rtt: f64, decay: Duration) -> f64 {
    if rtt > estimate {
        // Be sensitive to peaks.
        return rtt;
    }
    let weight = if decay.is_zero() {
        0.0
    } else {
        (-elapsed.as_secs_f64() / decay.as_secs_f64()).exp()
    };
    estimate * weight + rtt * (1.0 - weight)
}

impl Latency {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Estimate>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a sample: the time an attempt took (to the first or the last byte, as
    /// configured), or [`FAILURE_PENALTY`] and more for a failed one.
    pub fn observe(&self, rtt: Duration, decay: Duration, now: Instant) {
        let rtt = rtt.as_secs_f64();
        let mut current = self.lock();
        let value = match *current {
            Some(e) => update(e.value, now.saturating_duration_since(e.at), rtt, decay),
            None => rtt,
        };
        *current = Some(Estimate { value, at: now });
    }

    /// Records a failed attempt that took `elapsed`.
    pub fn observe_failure(&self, elapsed: Duration, decay: Duration, now: Instant) {
        self.observe(elapsed.max(FAILURE_PENALTY), decay, now);
    }

    /// The estimate decayed to `now` without changing it, or `None` before the first sample.
    #[must_use]
    pub fn peek(&self, decay: Duration, now: Instant) -> Option<Duration> {
        let e = (*self.lock())?;
        let value = update(e.value, now.saturating_duration_since(e.at), 0.0, decay);
        Some(Duration::from_secs_f64(value.max(0.0)))
    }

    /// Reads the estimate as the balancer does: applies a zero sample (pure decay) and stores
    /// the result. `None` before the first sample or seed.
    fn read(&self, decay: Duration, now: Instant) -> Option<f64> {
        let mut current = self.lock();
        let e = (*current)?;
        let value = update(e.value, now.saturating_duration_since(e.at), 0.0, decay);
        *current = Some(Estimate { value, at: now });
        Some(value)
    }

    /// The estimate, seeding it with `seed` seconds first when there is none.
    fn read_or_seed(&self, decay: Duration, now: Instant, seed: impl FnOnce() -> f64) -> f64 {
        if let Some(value) = self.read(decay, now) {
            return value;
        }
        let value = seed();
        let mut current = self.lock();
        // Another request may have seeded or sampled it meanwhile; keep that.
        current.get_or_insert(Estimate { value, at: now }).value
    }
}

/// Settings of the `peak_ewma` policy.
#[derive(Debug, Clone, Copy)]
pub struct PeakEwma {
    /// Time constant of the moving average.
    pub decay: Duration,
}

impl Default for PeakEwma {
    fn default() -> Self {
        Self {
            decay: Duration::from_secs(10),
        }
    }
}

impl PeakEwma {
    /// Picks the cheaper of two distinct random candidates with a positive weight (the only
    /// one when there is one).
    pub(crate) fn pick(&self, choices: &[Choice<'_>], first: u64, second: u64) -> Option<usize> {
        let now = Instant::now();
        let positive = choices.iter().filter(|c| c.weight > 0).count();
        let a = nth_positive(choices, usize_from(first, positive)?)?;
        if positive == 1 {
            return Some(a);
        }
        // A second draw among the others: never the same backend twice (tower's
        // `sample_floyd2`).
        let mut k = usize_from(second, positive - 1)?;
        if k >= positive_rank(choices, a) {
            k += 1;
        }
        let b = nth_positive(choices, k)?;
        let seed = || self.seed(choices, now);
        let cost_a = self.cost(&choices[a], now, seed);
        let cost_b = self.cost(&choices[b], now, seed);
        Some(if cost_b < cost_a { b } else { a })
    }

    /// `estimate × (in_flight + 1) / weight`.
    fn cost(&self, choice: &Choice<'_>, now: Instant, seed: impl FnOnce() -> f64) -> f64 {
        let estimate = match choice.latency {
            Some(l) => l.read_or_seed(self.decay, now, seed),
            None => seed(),
        };
        cost(estimate, choice.in_flight, choice.weight)
    }

    /// The mean estimate of the candidates that have one, at least [`SEED_FLOOR`]; else
    /// [`SEED_FALLBACK`].
    fn seed(&self, choices: &[Choice<'_>], now: Instant) -> f64 {
        let known: Vec<f64> = choices
            .iter()
            .filter_map(|c| c.latency?.peek(self.decay, now))
            .map(|d| d.as_secs_f64())
            .collect();
        seed_from(&known)
    }
}

/// The seed for a backend without a sample, from the estimates (seconds) of the others.
#[must_use]
pub fn seed_from(known: &[f64]) -> f64 {
    if known.is_empty() {
        return SEED_FALLBACK.as_secs_f64();
    }
    #[allow(clippy::cast_precision_loss)]
    let mean = known.iter().sum::<f64>() / known.len() as f64;
    mean.max(SEED_FLOOR.as_secs_f64())
}

/// The load of a backend: `estimate × (in_flight + 1) / weight`; infinite for weight 0.
#[must_use]
pub fn cost(estimate: f64, in_flight: u32, weight: u32) -> f64 {
    if weight == 0 {
        return f64::INFINITY;
    }
    estimate * (f64::from(in_flight) + 1.0) / f64::from(weight)
}

fn usize_from(random: u64, n: usize) -> Option<usize> {
    if n == 0 {
        return None;
    }
    // `n` fits in u64; the remainder is below `n`, so it fits in usize.
    usize::try_from(random % n as u64).ok()
}

/// The index of the `k`-th choice (from 0) with a positive weight.
fn nth_positive(choices: &[Choice<'_>], k: usize) -> Option<usize> {
    choices
        .iter()
        .enumerate()
        .filter(|(_, c)| c.weight > 0)
        .nth(k)
        .map(|(i, _)| i)
}

/// How many positive-weight choices come before index `i`.
fn positive_rank(choices: &[Choice<'_>], i: usize) -> usize {
    choices[..i].iter().filter(|c| c.weight > 0).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECAY: Duration = Duration::from_secs(10);

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn a_peak_replaces_the_estimate_at_once() {
        assert!(close(
            update(0.010, Duration::from_secs(5), 0.200, DECAY),
            0.200
        ));
        let l = Latency::default();
        let t0 = Instant::now();
        l.observe(Duration::from_millis(10), DECAY, t0);
        l.observe(
            Duration::from_millis(200),
            DECAY,
            t0 + Duration::from_millis(1),
        );
        assert_eq!(
            l.peek(DECAY, t0 + Duration::from_millis(1)),
            Some(Duration::from_millis(200))
        );
    }

    #[test]
    fn lower_samples_are_averaged_with_the_time_weight() {
        // After one time constant the old estimate keeps e^-1 of its weight.
        let w = (-1.0f64).exp();
        let expected = 0.200 * w + 0.010 * (1.0 - w);
        assert!(close(update(0.200, DECAY, 0.010, DECAY), expected));
        // No time passed: the sample has no weight yet (tower's formula).
        assert!(close(update(0.200, Duration::ZERO, 0.010, DECAY), 0.200));
        // A very long gap: the sample takes over.
        assert!(update(0.200, DECAY * 100, 0.010, DECAY) - 0.010 < 1e-9);
    }

    #[test]
    fn reading_decays_an_idle_estimate_towards_zero() {
        let l = Latency::default();
        let t0 = Instant::now();
        l.observe(Duration::from_millis(100), DECAY, t0);
        let later = t0 + DECAY;
        let expected = 0.100 * (-1.0f64).exp();
        assert!(close(l.read(DECAY, later).unwrap_or(0.0), expected));
        // The read stored the decayed value: another time constant halves it again by e.
        let again = l.read(DECAY, later + DECAY).unwrap_or(0.0);
        assert!(close(again, expected * (-1.0f64).exp()));
    }

    #[test]
    fn failures_count_as_a_penalty() {
        let l = Latency::default();
        let t0 = Instant::now();
        l.observe(Duration::from_millis(2), DECAY, t0);
        l.observe_failure(Duration::from_millis(1), DECAY, t0);
        assert_eq!(l.peek(DECAY, t0), Some(FAILURE_PENALTY));
        l.observe_failure(Duration::from_secs(3), DECAY, t0);
        assert_eq!(l.peek(DECAY, t0), Some(Duration::from_secs(3)));
    }

    #[test]
    fn seeds_are_the_pool_mean_with_a_floor_and_a_fallback() {
        assert!(close(seed_from(&[]), 0.030));
        assert!(close(seed_from(&[0.010, 0.030]), 0.020));
        assert!(close(seed_from(&[0.0001, 0.0003]), 0.001), "1 ms floor");
        let lat = [Latency::default(), Latency::default(), Latency::default()];
        let t0 = Instant::now();
        lat[0].observe(Duration::from_millis(10), DECAY, t0);
        lat[1].observe(Duration::from_millis(30), DECAY, t0);
        let choices: Vec<Choice<'_>> = lat
            .iter()
            .map(|l| Choice {
                id: "x",
                weight: 1,
                in_flight: 0,
                latency: Some(l),
            })
            .collect();
        let p = PeakEwma::default();
        let seed = p.seed(&choices, t0);
        assert!((seed - 0.020).abs() < 1e-6, "{seed}");
        let value = lat[2].read_or_seed(DECAY, t0, || seed);
        assert!((value - 0.020).abs() < 1e-6);
        assert!(lat[2].peek(DECAY, t0).is_some(), "the seed is kept");
    }

    #[test]
    fn the_cost_weighs_latency_by_load_and_weight() {
        assert!(close(cost(0.010, 0, 1), 0.010));
        assert!(close(cost(0.010, 3, 1), 0.040));
        assert!(close(cost(0.010, 3, 2), 0.020));
        assert!(cost(0.010, 0, 0).is_infinite());
    }

    fn pool<'a>(lat: &'a [Latency], weights: &[u32]) -> Vec<Choice<'a>> {
        lat.iter()
            .zip(weights)
            .map(|(l, w)| Choice {
                id: "x",
                weight: *w,
                in_flight: 0,
                latency: Some(l),
            })
            .collect()
    }

    #[test]
    fn two_distinct_backends_are_compared() {
        let lat: Vec<Latency> = (0..3).map(|_| Latency::default()).collect();
        let t0 = Instant::now();
        lat[0].observe(Duration::from_millis(200), DECAY, t0);
        lat[1].observe(Duration::from_millis(5), DECAY, t0);
        lat[2].observe(Duration::from_millis(5), DECAY, t0);
        let choices = pool(&lat, &[1, 1, 1]);
        let p = PeakEwma::default();
        for first in 0..3u64 {
            for second in 0..2u64 {
                let picked = p.pick(&choices, first, second);
                assert_ne!(picked, Some(0), "the slow one loses every comparison");
            }
        }
        // With equal draws the second index skips the first: (0, 0) compares a and b.
        let single = pool(&lat[..1], &[1]);
        assert_eq!(p.pick(&single, 7, 9), Some(0), "a pool of one");
        assert_eq!(p.pick(&pool(&lat, &[0, 0, 0]), 0, 0), None);
        let weighted = pool(&lat, &[0, 1, 0]);
        assert_eq!(p.pick(&weighted, 5, 5), Some(1), "zero weights are skipped");
    }

    #[test]
    fn weights_and_load_change_the_winner() {
        let lat: Vec<Latency> = (0..2).map(|_| Latency::default()).collect();
        let t0 = Instant::now();
        lat[0].observe(Duration::from_millis(10), DECAY, t0);
        lat[1].observe(Duration::from_millis(15), DECAY, t0);
        let p = PeakEwma::default();
        assert_eq!(p.pick(&pool(&lat, &[1, 1]), 0, 0), Some(0));
        assert_eq!(p.pick(&pool(&lat, &[1, 2]), 0, 0), Some(1), "15/2 < 10/1");
        let mut busy = pool(&lat, &[1, 1]);
        busy[0].in_flight = 2;
        assert_eq!(p.pick(&busy, 0, 0), Some(1), "10 × 3 > 15 × 1");
    }

    #[test]
    fn an_unmeasured_backend_competes_with_the_pool_mean() {
        let lat: Vec<Latency> = (0..3).map(|_| Latency::default()).collect();
        let t0 = Instant::now();
        lat[0].observe(Duration::from_millis(10), DECAY, t0);
        lat[1].observe(Duration::from_millis(50), DECAY, t0);
        let p = PeakEwma::default();
        // c (seeded at the mean, 30 ms) against b (50 ms): c wins.
        assert_eq!(p.pick(&pool(&lat, &[1, 1, 1]), 2, 1), Some(2));
        // a (10 ms) against c (now 30 ms): a wins.
        assert_eq!(p.pick(&pool(&lat, &[1, 1, 1]), 0, 1), Some(0));
    }
}
