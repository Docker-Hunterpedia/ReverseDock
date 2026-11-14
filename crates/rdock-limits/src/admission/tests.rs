use super::*;

const BASE: f64 = 0.010;

/// A backend with a fixed throughput: `capacity` requests at once take `BASE`, more queue, so
/// the latency grows with the requests in flight (Little's law: latency = in flight /
/// throughput).
fn latency(in_flight: u32, capacity: u32) -> Duration {
    Duration::from_secs_f64(BASE * (f64::from(in_flight) / f64::from(capacity)).max(1.0))
}

fn aimd(min: u32, max: u32) -> Settings {
    Settings {
        algorithm: Algorithm::Aimd {
            latency: Duration::from_secs_f64(BASE * 1.5),
            backoff: 0.9,
        },
        min,
        max,
        initial: 20,
        normal_percent: 90,
        sheddable_percent: 75,
    }
}

fn gradient(min: u32, max: u32) -> Settings {
    Settings {
        algorithm: Algorithm::Gradient {
            tolerance: 1.5,
            smoothing: 0.2,
            queue: 4.0,
            interval: Duration::from_secs(1),
            jitter: 0.0,
            probe: 50,
            probe_timeout: Duration::from_millis(500),
        },
        min,
        max,
        initial: 20,
        normal_percent: 90,
        sheddable_percent: 75,
    }
}

/// A closed loop with more demand than any limit: every completion is replaced at once, so
/// `demand.min(limit)` requests are in flight. One request finishes per step, with the latency
/// of the load it was admitted under, and the simulated clock moves on by the time one
/// completion takes at that load (latency / in flight). Returns the limit after each step.
fn run(
    limit: &Arc<AdaptiveLimit>,
    clock: &mut Instant,
    steps: usize,
    demand: u32,
    capacity: impl Fn(usize) -> u32,
) -> Vec<u32> {
    let mut out = Vec::with_capacity(steps);
    for step in 0..steps {
        let mut held = Vec::new();
        while u32::try_from(held.len()).unwrap_or(u32::MAX) < demand {
            match limit.try_acquire(Class::Critical, *clock) {
                Some(permit) => held.push(permit),
                None => break,
            }
        }
        let n = limit.in_flight();
        assert!(n <= limit.limit().max(1), "admitted past the limit");
        let rtt = latency(n, capacity(step));
        *clock += rtt / n.max(1);
        limit.record(rtt, n, false, *clock);
        drop(held);
        out.push(limit.limit());
    }
    out
}

fn range(values: &[u32]) -> (u32, u32) {
    (
        values.iter().copied().min().unwrap_or(0),
        values.iter().copied().max().unwrap_or(0),
    )
}

#[test]
fn aimd_converges_near_the_latency_threshold_and_stays_in_bounds() {
    let mut clock = Instant::now();
    let limit = Arc::new(AdaptiveLimit::new_at(aimd(3, 1000), clock));
    let history = run(&limit, &mut clock, 20_000, u32::MAX, |_| 40);
    // Drops start above 1.5 × 40 = 60 in flight; the limit saws between 0.9 × 61 and 61.
    let (low, high) = range(&history[2_000..]);
    assert!(low >= 54 && high <= 61, "{low}..{high}");
    // Bounds hold even when the backend is hopeless or idle.
    let mut clock = Instant::now();
    let limit = Arc::new(AdaptiveLimit::new_at(aimd(5, 30), clock));
    let history = run(&limit, &mut clock, 5_000, u32::MAX, |_| 1);
    assert!(history.iter().all(|l| (5..=30).contains(l)));
    assert_eq!(
        *history.last().unwrap(),
        5,
        "stuck at min while every sample is slow"
    );
    let history = run(&limit, &mut clock, 5_000, u32::MAX, |_| 10_000);
    assert_eq!(*history.last().unwrap(), 30, "capped at max");
}

#[test]
fn aimd_backs_off_on_drops_and_does_not_grow_when_idle() {
    let limit = AdaptiveLimit::new_at(aimd(3, 1000), Instant::now());
    assert_eq!(
        limit.record(Duration::from_millis(1), 1, true, Instant::now()),
        Some(18)
    );
    // Under half the limit in use: no growth.
    assert_eq!(
        limit.record(Duration::from_millis(1), 2, false, Instant::now()),
        Some(18)
    );
    assert_eq!(
        limit.record(Duration::from_millis(1), 9, false, Instant::now()),
        Some(19)
    );
}

#[test]
fn gradient_converges_after_measuring_the_no_load_latency() {
    let mut clock = Instant::now();
    let limit = Arc::new(AdaptiveLimit::new_at(gradient(3, 1000), clock));
    assert_eq!(limit.limit(), 3, "starts pinned to min while it measures");
    let history = run(&limit, &mut clock, 20_000, u32::MAX, |_| 40);
    // tolerance × capacity + queue = 1.5 × 40 + 4.
    let settled: Vec<u32> = history[2_000..]
        .iter()
        .copied()
        .filter(|l| *l > 3)
        .collect();
    let (low, high) = range(&settled);
    assert!(low >= 60 && high <= 66, "{low}..{high}");
    assert!(history.iter().all(|l| (3..=1000).contains(l)));
}

#[test]
fn gradient_follows_the_backend_up_and_down() {
    let mut clock = Instant::now();
    let limit = Arc::new(AdaptiveLimit::new_at(gradient(3, 1000), clock));
    let history = run(&limit, &mut clock, 30_000, u32::MAX, |step| match step {
        0..10_000 => 40,
        10_000..20_000 => 100,
        _ => 20,
    });
    let settled = |from: usize, to: usize| {
        let values: Vec<u32> = history[from..to]
            .iter()
            .copied()
            .filter(|l| *l > 3)
            .collect();
        range(&values)
    };
    let (low, high) = settled(15_000, 20_000);
    assert!(
        low >= 150 && high <= 160,
        "recovered to 1.5 × 100 + 4: {low}..{high}"
    );
    let (low, high) = settled(25_000, 30_000);
    assert!(
        low >= 30 && high <= 36,
        "shrunk to 1.5 × 20 + 4: {low}..{high}"
    );
}

/// Why `gradient` measures a reference: Gradient2's long-term average follows a stationary
/// overloaded latency, so its gradient returns to 1 and the limit climbs to `max`.
#[test]
fn a_long_term_average_alone_would_climb_to_max() {
    let (mut limit, mut long, mut samples) = (20.0_f64, 0.0_f64, 0.0_f64);
    for _ in 0..20_000 {
        let n = limit.floor();
        let short = BASE * (n / 40.0).max(1.0);
        samples += 1.0;
        long = if samples <= 10.0 {
            long + (short - long) / samples
        } else {
            long * (1.0 - 2.0 / 601.0) + short * 2.0 / 601.0
        };
        let gradient = (1.5 * long / short).clamp(0.5, 1.0);
        limit = (limit * 0.8 + (limit * gradient + 4.0) * 0.2).clamp(3.0, 1000.0);
    }
    assert!(limit >= 999.0, "{limit}");
}

#[test]
fn classes_get_their_share_and_lower_ones_are_refused_first() {
    let limit = Arc::new(AdaptiveLimit::new(Settings {
        initial: 20,
        ..aimd(3, 1000)
    }));
    assert_eq!(limit.cap(Class::Critical, 20), 20);
    assert_eq!(limit.cap(Class::Normal, 20), 18);
    assert_eq!(limit.cap(Class::Sheddable, 20), 15);
    assert_eq!(limit.cap(Class::Sheddable, 1), 1, "at least one");
    let mut held: Vec<Permit> = (0..15)
        .map(|_| limit.try_acquire(Class::Sheddable, Instant::now()).unwrap())
        .collect();
    assert!(
        limit
            .try_acquire(Class::Sheddable, Instant::now())
            .is_none()
    );
    held.extend((0..3).map(|_| limit.try_acquire(Class::Normal, Instant::now()).unwrap()));
    assert!(limit.try_acquire(Class::Normal, Instant::now()).is_none());
    held.extend((0..2).map(|_| limit.try_acquire(Class::Critical, Instant::now()).unwrap()));
    assert!(limit.try_acquire(Class::Critical, Instant::now()).is_none());
    assert_eq!(limit.in_flight(), 20);
    drop(held);
    assert_eq!(limit.in_flight(), 0, "permits free their place");
}

#[test]
fn critical_requests_keep_their_reserve_after_the_limit_falls() {
    let limit = Arc::new(AdaptiveLimit::new(Settings {
        initial: 40,
        ..aimd(3, 1000)
    }));
    // Sheddable requests fill 75 % of 40 = 30.
    let held: Vec<Permit> =
        std::iter::from_fn(|| limit.try_acquire(Class::Sheddable, Instant::now())).collect();
    assert_eq!(held.len(), 30);
    // Slow answers bring the limit down to 10, below what is in flight.
    while limit.limit() > 10 {
        limit.record(Duration::from_secs(1), 30, false, Instant::now());
    }
    let limit_now = limit.limit();
    assert!(
        limit
            .try_acquire(Class::Sheddable, Instant::now())
            .is_none()
    );
    // Critical requests still get their reserve: limit − 90 % of it.
    let reserve = limit.reserved(Class::Critical, limit_now);
    assert!(reserve >= 1);
    let critical: Vec<Permit> =
        std::iter::from_fn(|| limit.try_acquire(Class::Critical, Instant::now())).collect();
    assert_eq!(u32::try_from(critical.len()).unwrap(), reserve);
    drop(held);
    // Once the sheddable ones drained, critical requests may fill the whole limit again.
    let more: Vec<Permit> =
        std::iter::from_fn(|| limit.try_acquire(Class::Critical, Instant::now())).collect();
    assert_eq!(
        u32::try_from(critical.len() + more.len()).unwrap(),
        limit_now
    );
}

#[test]
fn concurrent_admission_never_exceeds_the_limit() {
    let limit = Arc::new(AdaptiveLimit::new(Settings {
        initial: 8,
        ..aimd(8, 8)
    }));
    let peak = Arc::new(AtomicU32::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (limit, peak) = (limit.clone(), peak.clone());
            std::thread::spawn(move || {
                for _ in 0..2_000 {
                    if let Some(permit) = limit.try_acquire(Class::Critical, Instant::now()) {
                        peak.fetch_max(limit.in_flight(), Ordering::Relaxed);
                        limit.record(
                            Duration::from_millis(1),
                            permit.in_flight_at_start(),
                            false,
                            Instant::now(),
                        );
                    }
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert!(peak.load(Ordering::Relaxed) <= 8);
    assert_eq!(limit.in_flight(), 0);
}

fn gradient_every(interval: Duration, probe_timeout: Duration) -> Settings {
    Settings {
        algorithm: Algorithm::Gradient {
            tolerance: 1.5,
            smoothing: 0.2,
            queue: 4.0,
            interval,
            jitter: 0.0,
            probe: 50,
            probe_timeout,
        },
        ..gradient(3, 1000)
    }
}

/// A measurement of the no-load latency, by samples at `min` concurrency.
fn measure(limit: &AdaptiveLimit, clock: &mut Instant, rtt: Duration) {
    for _ in 0..50 {
        *clock += Duration::from_millis(1);
        limit.record(rtt, 1, false, *clock);
    }
}

#[test]
fn gradient_measures_on_a_time_interval_not_a_sample_count() {
    let mut clock = Instant::now();
    let limit = Arc::new(AdaptiveLimit::new_at(
        gradient_every(Duration::from_secs(60), Duration::from_secs(5)),
        clock,
    ));
    measure(&limit, &mut clock, Duration::from_millis(10));
    assert!(!limit.measuring());
    // A busy route: 100,000 samples within ten seconds start no measurement.
    for _ in 0..100_000 {
        clock += Duration::from_micros(100);
        limit.record(Duration::from_millis(12), 30, false, clock);
        assert!(!limit.measuring(), "a sample count never starts one");
    }
    assert!(limit.limit() > 3);
    // After the interval, the next sample starts one.
    clock += Duration::from_secs(60);
    limit.record(Duration::from_millis(12), 30, false, clock);
    assert!(limit.measuring());
    assert_eq!(limit.limit(), 3);
}

#[test]
fn a_measurement_ends_within_its_timeout_whatever_the_traffic() {
    let mut clock = Instant::now();
    let settings = gradient_every(Duration::from_secs(10), Duration::from_secs(2));
    let limit = Arc::new(AdaptiveLimit::new_at(settings, clock));
    measure(&limit, &mut clock, Duration::from_millis(10));
    // Grow the limit, then let the interval pass.
    for _ in 0..2_000 {
        clock += Duration::from_millis(1);
        limit.record(Duration::from_millis(11), 40, false, clock);
    }
    let before = limit.limit();
    assert!(before > 10, "{before}");
    clock += Duration::from_secs(10);
    // Only samples above `min` arrive (long requests admitted earlier): no low sample.
    limit.record(Duration::from_millis(30), 20, false, clock);
    assert!(limit.measuring());
    clock += Duration::from_millis(1_999);
    limit.record(Duration::from_millis(30), 20, false, clock);
    assert!(limit.measuring(), "still within the timeout");
    clock += Duration::from_millis(2);
    limit.record(Duration::from_millis(30), 20, false, clock);
    assert!(!limit.measuring(), "ended by the timeout");
    assert!(limit.limit() > 3, "the previous estimate is back");
}

#[test]
fn a_measurement_with_no_sample_at_all_ends_on_the_next_admission() {
    // Idle upgraded connections hold nothing, but no request may finish either: the timeout is
    // checked when requests ask to be admitted.
    let mut clock = Instant::now();
    let settings = Settings {
        initial: 40,
        ..gradient_every(Duration::from_secs(10), Duration::from_secs(2))
    };
    let limit = Arc::new(AdaptiveLimit::new_at(settings, clock));
    assert_eq!(limit.limit(), 3, "measuring from the start");
    let held: Vec<Permit> = (0..3)
        .filter_map(|_| limit.try_acquire(Class::Critical, clock))
        .collect();
    assert_eq!(held.len(), 3);
    clock += Duration::from_secs(3);
    let more: Vec<Permit> = std::iter::from_fn(|| limit.try_acquire(Class::Critical, clock))
        .take(100)
        .collect();
    assert!(!limit.measuring());
    assert_eq!(limit.limit(), 40, "no reference yet: the initial limit");
    assert_eq!(held.len() + more.len(), 40);
}

#[test]
fn a_measurement_uses_the_samples_it_has_when_it_runs_out() {
    let mut clock = Instant::now();
    let limit = Arc::new(AdaptiveLimit::new_at(
        gradient_every(Duration::from_secs(10), Duration::from_secs(1)),
        clock,
    ));
    for _ in 0..5 {
        clock += Duration::from_millis(10);
        limit.record(Duration::from_millis(20), 1, false, clock);
    }
    clock += Duration::from_secs(1);
    limit.record(Duration::from_millis(20), 10, false, clock);
    assert!(!limit.measuring());
    // The reference is 20 ms: a 20 ms sample at full use is no slowdown, so the limit grows.
    let start = limit.limit();
    for _ in 0..200 {
        clock += Duration::from_millis(1);
        limit.record(Duration::from_millis(20), limit.limit(), false, clock);
    }
    assert!(limit.limit() > start, "{start} → {}", limit.limit());
}

#[test]
fn critical_and_normal_keep_two_places_at_low_limits() {
    let limit = Arc::new(AdaptiveLimit::new(Settings {
        initial: 3,
        ..aimd(3, 1000)
    }));
    assert_eq!(limit.reserved(Class::Critical, 3), 2);
    assert_eq!(limit.reserved(Class::Normal, 3), 2);
    assert_eq!(
        limit.reserved(Class::Critical, 1),
        1,
        "never more than the limit"
    );
    let now = Instant::now();
    let normal: Vec<Permit> =
        std::iter::from_fn(|| limit.try_acquire(Class::Normal, now)).collect();
    assert_eq!(normal.len(), 2, "normal fills its share of 3 (2)");
    // A back-to-back critical client: its previous request still holds its place.
    let first = limit.try_acquire(Class::Critical, now).expect("first");
    let second = limit.try_acquire(Class::Critical, now);
    assert!(
        second.is_some(),
        "the next request is not shed while the last one ends"
    );
    drop((first, second, normal));
}
