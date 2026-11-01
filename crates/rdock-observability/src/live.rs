//! Live traffic for the dashboard (ADR-0024, "Live data without touching the request path"):
//! per route and per service, 900 one-second slots of counters and a 40-bucket latency
//! histogram, about 190 KiB each. The request path increments atomics in the current slot:
//! no lock and no allocation. A slot is cleared by the first request of a new second; counts
//! that race with that clearing can be lost, which the dashboard tolerates.
//!
//! Latency buckets are logarithmic with two per octave from 50 µs: bucket `i` holds
//! `[50 µs × 2^(i/2), 50 µs × 2^((i+1)/2))`, so 40 buckets reach about 52 s and the last also
//! takes anything slower. Reported percentiles interpolate inside the bucket; the error is at
//! most 19 % at a bucket edge and usually far less.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Seconds kept.
pub const SLOTS: usize = 900;
/// Latency buckets.
pub const BUCKETS: usize = 40;
const FIRST_BUCKET_NANOS: u128 = 50_000;
const FIRST_BUCKET_SECONDS: f64 = 50e-6;

struct Slot {
    /// The Unix second this slot holds, or 0.
    second: AtomicU64,
    /// 1xx … 5xx; their sum is the request count.
    classes: [AtomicU32; 5],
    /// Requests that ended without a response from a backend (status 0 or 502–504).
    errors: AtomicU32,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    latency: [AtomicU32; BUCKETS],
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            second: AtomicU64::new(0),
            classes: std::array::from_fn(|_| AtomicU32::new(0)),
            errors: AtomicU32::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            latency: std::array::from_fn(|_| AtomicU32::new(0)),
        }
    }
}

impl Slot {
    fn clear(&self) {
        for c in &self.classes {
            c.store(0, Ordering::Relaxed);
        }
        self.errors.store(0, Ordering::Relaxed);
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        for b in &self.latency {
            b.store(0, Ordering::Relaxed);
        }
    }
}

/// The bucket for a duration, in integer arithmetic: with `r = elapsed × 1024 / 50 µs`, the
/// octave is `floor(log2 r) − 10`, and the upper half of an octave starts at `√2` times its
/// start, where `r² ≥ 2^(2·log2 r + 1)`.
#[must_use]
pub fn bucket(elapsed: Duration) -> usize {
    let scaled = elapsed.as_nanos().saturating_mul(1024) / FIRST_BUCKET_NANOS;
    if scaled < 1024 {
        return 0;
    }
    let log2 = scaled.ilog2();
    let upper_half = scaled.saturating_mul(scaled) >= 1u128 << (2 * log2 + 1).min(127);
    let index = 2 * (log2 - 10) as usize + usize::from(upper_half);
    index.min(BUCKETS - 1)
}

/// The lower bound of bucket `i`, in seconds.
fn bucket_start(i: usize) -> f64 {
    let half_octaves = f64::from(u32::try_from(i).unwrap_or(u32::MAX));
    FIRST_BUCKET_SECONDS * 2f64.powf(half_octaves / 2.0)
}

/// A count as a float for rates and ranks; counts here stay far below 2^52.
#[expect(
    clippy::cast_precision_loss,
    reason = "request counts stay far below 2^52"
)]
fn float(count: u64) -> f64 {
    count as f64
}

/// The slot index of a Unix second.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the remainder is below SLOTS"
)]
fn index(second: u64) -> usize {
    (second % SLOTS as u64) as usize
}

/// One request, as recorded.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Response status; 0 when none was sent.
    pub status: u16,
    /// Time to the end of the response.
    pub elapsed: Duration,
    /// Request body bytes.
    pub bytes_in: u64,
    /// Response body bytes.
    pub bytes_out: u64,
}

/// 900 seconds of one route or service.
pub struct Ring {
    slots: Box<[Slot]>,
}

impl Default for Ring {
    fn default() -> Self {
        Self {
            slots: (0..SLOTS).map(|_| Slot::default()).collect(),
        }
    }
}

impl std::fmt::Debug for Ring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ring").finish_non_exhaustive()
    }
}

fn unix_second(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Ring {
    /// Records one request at `now`. Lock-free and allocation-free.
    pub fn record(&self, sample: Sample, now: SystemTime) {
        let second = unix_second(now);
        let slot = &self.slots[index(second)];
        let held = slot.second.load(Ordering::Acquire);
        if held != second
            && slot
                .second
                .compare_exchange(held, second, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            slot.clear();
        }
        let class = usize::from(sample.status / 100).clamp(1, 5) - 1;
        slot.classes[class].fetch_add(1, Ordering::Relaxed);
        if matches!(sample.status, 0 | 502..=504) {
            slot.errors.fetch_add(1, Ordering::Relaxed);
        }
        slot.bytes_in.fetch_add(sample.bytes_in, Ordering::Relaxed);
        slot.bytes_out
            .fetch_add(sample.bytes_out, Ordering::Relaxed);
        slot.latency[bucket(sample.elapsed)].fetch_add(1, Ordering::Relaxed);
    }

    /// The last `window` seconds before `now` (at most [`SLOTS`]), summed, with one point
    /// per second for charts.
    #[must_use]
    pub fn summary(&self, window: Duration, now: SystemTime) -> Summary {
        combined(&[self], window, now)
    }
}

/// Several rings summed second by second, with percentiles over all their requests: the
/// whole proxy is the combination of its routes.
#[must_use]
pub fn combined(rings: &[&Ring], window: Duration, now: SystemTime) -> Summary {
    let seconds = window.as_secs().clamp(1, SLOTS as u64);
    let end = unix_second(now);
    let mut total = Summary::default();
    let mut latency = [0u64; BUCKETS];
    for second in (end + 1 - seconds)..=end {
        let mut point = Point {
            second,
            ..Point::default()
        };
        for ring in rings {
            let slot = &ring.slots[index(second)];
            if slot.second.load(Ordering::Acquire) != second {
                continue;
            }
            point.errors += u64::from(slot.errors.load(Ordering::Relaxed));
            for (sum, class) in point.classes.iter_mut().zip(&slot.classes) {
                let count = u64::from(class.load(Ordering::Relaxed));
                *sum += count;
                point.requests += count;
            }
            for (sum, bucket) in latency.iter_mut().zip(&slot.latency) {
                *sum += u64::from(bucket.load(Ordering::Relaxed));
            }
            total.bytes_in += slot.bytes_in.load(Ordering::Relaxed);
            total.bytes_out += slot.bytes_out.load(Ordering::Relaxed);
        }
        total.requests += point.requests;
        total.errors += point.errors;
        for (sum, c) in total.classes.iter_mut().zip(point.classes) {
            *sum += c;
        }
        total.series.push(point);
    }
    total.window_seconds = seconds;
    total.rate = float(total.requests) / float(seconds);
    total.p50 = percentile(&latency, 0.50);
    total.p95 = percentile(&latency, 0.95);
    total.p99 = percentile(&latency, 0.99);
    total
}

/// The `q` quantile in seconds, interpolating inside the bucket; `None` without requests.
fn percentile(buckets: &[u64; BUCKETS], q: f64) -> Option<f64> {
    let count: u64 = buckets.iter().sum();
    if count == 0 {
        return None;
    }
    let rank = q * float(count);
    let mut seen = 0.0;
    for (i, &n) in buckets.iter().enumerate() {
        let next = seen + float(n);
        if next >= rank && n > 0 {
            let (low, high) = (bucket_start(i), bucket_start(i + 1));
            let within = ((rank - seen) / float(n)).clamp(0.0, 1.0);
            return Some(low + (high - low) * within);
        }
        seen = next;
    }
    Some(bucket_start(BUCKETS))
}

/// One second.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Point {
    /// Unix second.
    pub second: u64,
    /// Requests.
    pub requests: u64,
    /// Responses by class, 1xx … 5xx.
    pub classes: [u64; 5],
    /// Requests without a backend response.
    pub errors: u64,
}

/// A window of traffic.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    /// Seconds covered.
    pub window_seconds: u64,
    /// Requests.
    pub requests: u64,
    /// Requests per second over the window.
    pub rate: f64,
    /// Responses by class, 1xx … 5xx.
    pub classes: [u64; 5],
    /// Requests without a backend response.
    pub errors: u64,
    /// Request body bytes.
    pub bytes_in: u64,
    /// Response body bytes.
    pub bytes_out: u64,
    /// Latency percentiles in seconds.
    pub p50: Option<f64>,
    /// 95th percentile.
    pub p95: Option<f64>,
    /// 99th percentile.
    pub p99: Option<f64>,
    /// One point per second, oldest first.
    pub series: Vec<Point>,
}

/// Rings by name, shared by every configuration generation while one uses them.
#[derive(Debug, Default)]
pub struct Rings {
    rings: Mutex<HashMap<String, Weak<Ring>>>,
}

impl Rings {
    /// The ring for `name`, created when no live generation has one.
    pub fn ring(&self, name: &str) -> Arc<Ring> {
        let mut rings = self.rings.lock().unwrap_or_else(PoisonError::into_inner);
        rings.retain(|_, ring| ring.strong_count() > 0);
        if let Some(ring) = rings.get(name).and_then(Weak::upgrade) {
            return ring;
        }
        let ring = Arc::new(Ring::default());
        rings.insert(name.to_owned(), Arc::downgrade(&ring));
        ring
    }

    /// Every live ring by name.
    pub fn all(&self) -> Vec<(String, Arc<Ring>)> {
        self.rings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(|(name, ring)| ring.upgrade().map(|r| (name.clone(), r)))
            .collect()
    }
}

/// Routes' and services' rings.
#[derive(Debug, Default)]
pub struct Live {
    /// By route name.
    pub routes: Rings,
    /// By service name.
    pub services: Rings,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(second: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(second)
    }

    fn sample(status: u16, millis: u64) -> Sample {
        Sample {
            status,
            elapsed: Duration::from_millis(millis),
            bytes_in: 10,
            bytes_out: 100,
        }
    }

    #[test]
    fn buckets_cover_50_microseconds_to_a_minute() {
        assert_eq!(bucket(Duration::from_micros(10)), 0);
        assert_eq!(bucket(Duration::from_micros(50)), 0);
        assert_eq!(bucket(Duration::from_micros(71)), 1);
        assert_eq!(bucket(Duration::from_micros(100)), 2);
        assert_eq!(bucket(Duration::from_secs(60)), BUCKETS - 1);
        assert!(bucket_start(BUCKETS - 1) < 60.0 && bucket_start(BUCKETS) > 50.0);
        // Two buckets per octave: the widest error at an edge is sqrt(2) - 1, below 19 %…
        // … measured from the bucket's middle, as the interpolation uses.
        let ratio = bucket_start(11) / bucket_start(10);
        assert!((ratio - std::f64::consts::SQRT_2).abs() < 1e-9);
    }

    #[test]
    fn summaries_count_classes_errors_and_percentiles() {
        let ring = Ring::default();
        for i in 0..100 {
            ring.record(sample(200, 10 + i % 10), at(1_000));
        }
        for _ in 0..5 {
            ring.record(sample(502, 2_000), at(1_001));
        }
        ring.record(sample(404, 1), at(1_001));
        let summary = ring.summary(Duration::from_secs(60), at(1_001));
        assert_eq!(summary.requests, 106);
        assert_eq!(summary.classes, [0, 100, 0, 1, 5]);
        assert_eq!(summary.errors, 5);
        assert_eq!(summary.bytes_out, 10_600);
        assert_eq!(summary.series.len(), 60);
        assert_eq!(summary.series.last().unwrap().requests, 6);
        let p50 = summary.p50.unwrap();
        assert!((0.008..0.025).contains(&p50), "{p50}");
        assert!(summary.p99.unwrap() > 1.0, "the slow request shows in p99");
    }

    #[test]
    fn old_seconds_are_not_counted_after_the_ring_wraps() {
        let ring = Ring::default();
        ring.record(sample(200, 1), at(5_000));
        let later = 5_000 + SLOTS as u64;
        ring.record(sample(500, 1), at(later));
        let summary = ring.summary(Duration::from_secs(10), at(later));
        assert_eq!(
            summary.requests, 1,
            "the slot was cleared for its new second"
        );
        assert_eq!(summary.classes[4], 1);
        assert_eq!(
            ring.summary(Duration::from_secs(1), at(later + 5)).requests,
            0
        );
    }

    #[test]
    fn rings_live_while_a_generation_holds_them() {
        let rings = Rings::default();
        let a = rings.ring("app");
        assert!(Arc::ptr_eq(&a, &rings.ring("app")));
        assert_eq!(rings.all().len(), 1);
        drop(a);
        assert!(rings.all().is_empty());
        let (x, y) = (Ring::default(), Ring::default());
        x.record(sample(200, 5), at(10));
        y.record(sample(500, 5), at(10));
        let both = combined(&[&x, &y], Duration::from_secs(5), at(10));
        assert_eq!(both.requests, 2);
        assert_eq!(both.classes, [0, 1, 0, 0, 1]);
        assert!(
            std::mem::size_of::<Slot>() * SLOTS <= 192 * 1024,
            "about 190 KiB a ring"
        );
    }
}
