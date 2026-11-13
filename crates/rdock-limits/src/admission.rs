//! An adaptive concurrency limit for the `admission` middleware (H-LB-04, ADR-0031).
//!
//! The limit is a congestion window over requests in flight, as in Netflix's
//! concurrency-limits (<https://github.com/Netflix/concurrency-limits>, read 2026-11-13):
//!
//! - [`Algorithm::Aimd`] is its `AIMDLimit`: a sample that was dropped (an upstream error or
//!   timeout) or slower than `latency` multiplies the limit by `backoff`; any other sample
//!   adds one while at least half the limit is in use.
//! - [`Algorithm::Gradient`] combines the gradient of Envoy's adaptive concurrency filter
//!   (<https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/adaptive_concurrency_filter>,
//!   read 2026-11-13) with the smoothing of Netflix's `Gradient2Limit`: `gradient =
//!   clamp(tolerance × min_latency / sample, 0.5, 1)`, `estimate = limit × gradient + queue`,
//!   smoothed into the limit, which does not grow while less than half of it is in use
//!   ("app-limited"). The reference is a measured no-load latency, as in Envoy: at start and
//!   every `window` samples the limit is pinned to `min` until `probe` samples taken at that
//!   concurrency or below have finished, and their median becomes the reference. Gradient2's
//!   long-term average is not used: against a backend whose latency grows with concurrency
//!   (a fixed throughput) it follows the overloaded latency, the gradient returns to 1 and the
//!   limit climbs to `max` (see the tests).
//!
//! Admission takes no lock: the requests in flight are one atomic counter, raised with a
//! compare-and-swap only while below the class's share of the limit. Samples update the
//! algorithm under a `try_lock`; a sample that finds the lock taken is skipped, so no request
//! ever waits on another. Memory is a fixed few words per middleware, whatever the traffic.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How the limit adapts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algorithm {
    /// Additive increase, multiplicative decrease.
    Aimd {
        /// Samples slower than this count as drops.
        latency: Duration,
        /// Factor applied on a drop, 0.5–0.99.
        backoff: f64,
    },
    /// The measured no-load latency against each sample.
    Gradient {
        /// How much slower than the no-load latency a sample may be (≥ 1).
        tolerance: f64,
        /// Weight of a new estimate (0–1].
        smoothing: f64,
        /// Requests allowed above the estimate.
        queue: f64,
        /// Samples between two measurements of the no-load latency.
        window: u32,
        /// Samples at `min` concurrency or below that make one measurement.
        probe: u32,
    },
}

/// The settings of a limit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Settings {
    /// The algorithm.
    pub algorithm: Algorithm,
    /// Lowest limit (at least 1).
    pub min: u32,
    /// Highest limit.
    pub max: u32,
    /// Limit at start.
    pub initial: u32,
    /// Share of the limit `normal` requests may fill, in percent.
    pub normal_percent: u32,
    /// Share of the limit `sheddable` requests may fill, in percent.
    pub sheddable_percent: u32,
}

/// The class of a request: lower classes are refused first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// May fill the whole limit.
    Critical,
    /// May fill the `normal` share.
    Normal,
    /// May fill the `sheddable` share.
    Sheddable,
}

impl Class {
    fn index(self) -> usize {
        match self {
            Self::Critical => 0,
            Self::Normal => 1,
            Self::Sheddable => 2,
        }
    }
}

#[derive(Debug)]
struct Estimate {
    /// The limit with its fraction (gradient smoothing needs it).
    limit: f64,
    /// `gradient`: the measured no-load latency in seconds, once measured.
    min_latency: Option<f64>,
    /// `gradient`: latencies of the measurement in progress (at most `probe`).
    low: Vec<f64>,
    /// `gradient`: samples since the last measurement.
    since: u64,
    /// `gradient`: the limit is pinned to `min` while a measurement runs.
    probing: bool,
}

/// An adaptive concurrency limit shared by the routes of one `admission` middleware.
#[derive(Debug)]
pub struct AdaptiveLimit {
    settings: Settings,
    limit: AtomicU32,
    in_flight: AtomicU32,
    /// Requests in flight per class (`critical`, `normal`, `sheddable`).
    by_class: [AtomicU32; 3],
    estimate: Mutex<Estimate>,
    skipped: AtomicU64,
}

/// One admitted request; dropping it frees its place.
#[derive(Debug)]
pub struct Permit {
    limit: Arc<AdaptiveLimit>,
    /// Requests in flight when this one was admitted, itself included.
    in_flight: u32,
    class: Class,
}

impl Permit {
    /// Requests in flight when this one was admitted, itself included.
    #[must_use]
    pub fn in_flight_at_start(&self) -> u32 {
        self.in_flight
    }

    /// The limit this permit belongs to.
    #[must_use]
    pub fn limit(&self) -> &Arc<AdaptiveLimit> {
        &self.limit
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.limit.by_class[self.class.index()].fetch_sub(1, Ordering::AcqRel);
        self.limit.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl AdaptiveLimit {
    /// A limit with `settings`; `min` is raised to 1 and `max` to `min`, `initial` kept
    /// between them.
    #[must_use]
    pub fn new(settings: Settings) -> Self {
        let min = settings.min.max(1);
        let max = settings.max.max(min);
        let initial = settings.initial.clamp(min, max);
        let settings = Settings {
            min,
            max,
            initial,
            ..settings
        };
        // `gradient` starts by measuring the no-load latency, at `min`.
        let (probing, probe) = match settings.algorithm {
            Algorithm::Aimd { .. } => (false, 0),
            Algorithm::Gradient { probe, .. } => (true, probe.max(1)),
        };
        Self {
            settings,
            limit: AtomicU32::new(if probing { min } else { initial }),
            in_flight: AtomicU32::new(0),
            by_class: [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)],
            estimate: Mutex::new(Estimate {
                limit: f64::from(initial),
                min_latency: None,
                low: Vec::with_capacity(usize::try_from(probe).unwrap_or(0)),
                since: 0,
                probing,
            }),
            skipped: AtomicU64::new(0),
        }
    }

    /// The current limit (`min` while `gradient` measures the no-load latency).
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit.load(Ordering::Acquire)
    }

    /// Requests in flight now.
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Samples skipped because another update held the estimate.
    #[must_use]
    pub fn skipped_samples(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }

    /// How many requests of `class` may be in flight under `limit`: the whole limit for
    /// `critical`, its share (rounded down, at least one) for the others.
    #[must_use]
    pub fn cap(&self, class: Class, limit: u32) -> u32 {
        let percent = match class {
            Class::Critical => return limit,
            Class::Normal => self.settings.normal_percent,
            Class::Sheddable => self.settings.sheddable_percent,
        };
        let share = u64::from(limit) * u64::from(percent.min(100)) / 100;
        u32::try_from(share).unwrap_or(limit).max(1)
    }

    /// The part of `limit` kept for `class` alone: `limit − normal share` for `critical`,
    /// `normal share − sheddable share` for `normal`, nothing for `sheddable`.
    #[must_use]
    pub fn reserved(&self, class: Class, limit: u32) -> u32 {
        match class {
            Class::Critical => limit.saturating_sub(self.cap(Class::Normal, limit)),
            Class::Normal => self
                .cap(Class::Normal, limit)
                .saturating_sub(self.cap(Class::Sheddable, limit)),
            Class::Sheddable => 0,
        }
    }

    /// Admits a request of `class` while the requests in flight are below its cap, or while
    /// its own class has less in flight than its reserved part. The reserve keeps critical
    /// (and normal) requests going after the limit fell below what lower classes still hold:
    /// those drain first. So the requests in flight stay below `limit` plus the reserves
    /// (`2 × limit − sheddable share` at worst), and below `limit` once the limit is steady.
    pub fn try_acquire(self: &Arc<Self>, class: Class) -> Option<Permit> {
        let limit = self.limit();
        let cap = self.cap(class, limit);
        let reserved = self.reserved(class, limit);
        let mine = &self.by_class[class.index()];
        let own = mine.fetch_add(1, Ordering::AcqRel) < reserved;
        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            if current >= cap && !own {
                mine.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Permit {
                        limit: self.clone(),
                        in_flight: current + 1,
                        class,
                    });
                }
                Err(now) => current = now,
            }
        }
    }

    /// Feeds one finished request: its latency (admission to response headers), the requests
    /// in flight when it was admitted, and whether it was dropped (an upstream error or
    /// timeout). Returns the new limit, or `None` when the sample was skipped.
    pub fn record(&self, latency: Duration, in_flight: u32, dropped: bool) -> Option<u32> {
        let Ok(mut estimate) = self.estimate.try_lock() else {
            self.skipped.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let next = self.update(&mut estimate, latency.as_secs_f64(), in_flight, dropped);
        estimate.limit = next;
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "clamped to min..=max, both u32"
        )]
        let whole = next.floor() as u32;
        let whole = if estimate.probing {
            self.settings.min
        } else {
            whole.clamp(self.settings.min, self.settings.max)
        };
        self.limit.store(whole, Ordering::Release);
        Some(whole)
    }

    /// Whether `gradient` is measuring the no-load latency now.
    #[must_use]
    pub fn measuring(&self) -> bool {
        self.estimate.lock().is_ok_and(|e| e.probing)
    }

    fn update(&self, e: &mut Estimate, rtt: f64, in_flight: u32, dropped: bool) -> f64 {
        let (min, max) = (f64::from(self.settings.min), f64::from(self.settings.max));
        let in_flight = f64::from(in_flight);
        let next = match self.settings.algorithm {
            Algorithm::Aimd { latency, backoff } => {
                if dropped || rtt > latency.as_secs_f64() {
                    (e.limit * backoff).floor()
                } else if in_flight * 2.0 >= e.limit {
                    e.limit + 1.0
                } else {
                    e.limit
                }
            }
            Algorithm::Gradient {
                tolerance,
                smoothing,
                queue,
                window,
                probe,
            } => {
                let sample = rtt.max(1e-6);
                e.since += 1;
                // A request admitted at `min` concurrency or below saw (close to) no load.
                if in_flight <= min {
                    e.low.push(sample);
                    if e.low.len() >= usize::try_from(probe.max(1)).unwrap_or(1) {
                        e.low.sort_by(f64::total_cmp);
                        e.min_latency = e.low.get(e.low.len() / 2).copied();
                        e.low.clear();
                        e.since = 0;
                        e.probing = false;
                    }
                }
                if !e.probing && e.since >= u64::from(window) {
                    e.probing = true;
                    e.low.clear();
                }
                let Some(reference) = e.min_latency.filter(|_| !e.probing) else {
                    return e.limit.clamp(min, max);
                };
                if in_flight < e.limit / 2.0 && !dropped {
                    // App-limited: the latency says nothing about a larger limit.
                    return e.limit.clamp(min, max);
                }
                let gradient = (tolerance * reference / sample).clamp(0.5, 1.0);
                let estimate = e.limit * gradient + queue;
                e.limit * (1.0 - smoothing) + estimate * smoothing
            }
        };
        next.clamp(min, max)
    }
}

#[cfg(test)]
mod tests;
