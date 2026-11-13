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
            window: 600,
            probe: 50,
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
/// of the load it was admitted under. Returns the limit after each step.
fn run(
    limit: &Arc<AdaptiveLimit>,
    steps: usize,
    demand: u32,
    capacity: impl Fn(usize) -> u32,
) -> Vec<u32> {
    let mut out = Vec::with_capacity(steps);
    for step in 0..steps {
        let mut held = Vec::new();
        while u32::try_from(held.len()).unwrap_or(u32::MAX) < demand {
            match limit.try_acquire(Class::Critical) {
                Some(permit) => held.push(permit),
                None => break,
            }
        }
        let n = limit.in_flight();
        assert!(n <= limit.limit().max(1), "admitted past the limit");
        limit.record(latency(n, capacity(step)), n, false);
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
    let limit = Arc::new(AdaptiveLimit::new(aimd(3, 1000)));
    let history = run(&limit, 20_000, u32::MAX, |_| 40);
    // Drops start above 1.5 × 40 = 60 in flight; the limit saws between 0.9 × 61 and 61.
    let (low, high) = range(&history[2_000..]);
    assert!(low >= 54 && high <= 61, "{low}..{high}");
    // Bounds hold even when the backend is hopeless or idle.
    let limit = Arc::new(AdaptiveLimit::new(aimd(5, 30)));
    let history = run(&limit, 5_000, u32::MAX, |_| 1);
    assert!(history.iter().all(|l| (5..=30).contains(l)));
    assert_eq!(
        *history.last().unwrap(),
        5,
        "stuck at min while every sample is slow"
    );
    let history = run(&limit, 5_000, u32::MAX, |_| 10_000);
    assert_eq!(*history.last().unwrap(), 30, "capped at max");
}

#[test]
fn aimd_backs_off_on_drops_and_does_not_grow_when_idle() {
    let limit = AdaptiveLimit::new(aimd(3, 1000));
    assert_eq!(limit.record(Duration::from_millis(1), 1, true), Some(18));
    // Under half the limit in use: no growth.
    assert_eq!(limit.record(Duration::from_millis(1), 2, false), Some(18));
    assert_eq!(limit.record(Duration::from_millis(1), 9, false), Some(19));
}

#[test]
fn gradient_converges_after_measuring_the_no_load_latency() {
    let limit = Arc::new(AdaptiveLimit::new(gradient(3, 1000)));
    assert_eq!(limit.limit(), 3, "starts pinned to min while it measures");
    let history = run(&limit, 20_000, u32::MAX, |_| 40);
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
    let limit = Arc::new(AdaptiveLimit::new(gradient(3, 1000)));
    let history = run(&limit, 30_000, u32::MAX, |step| match step {
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
        .map(|_| limit.try_acquire(Class::Sheddable).unwrap())
        .collect();
    assert!(limit.try_acquire(Class::Sheddable).is_none());
    held.extend((0..3).map(|_| limit.try_acquire(Class::Normal).unwrap()));
    assert!(limit.try_acquire(Class::Normal).is_none());
    held.extend((0..2).map(|_| limit.try_acquire(Class::Critical).unwrap()));
    assert!(limit.try_acquire(Class::Critical).is_none());
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
    let held: Vec<Permit> = std::iter::from_fn(|| limit.try_acquire(Class::Sheddable)).collect();
    assert_eq!(held.len(), 30);
    // Slow answers bring the limit down to 10, below what is in flight.
    while limit.limit() > 10 {
        limit.record(Duration::from_secs(1), 30, false);
    }
    let limit_now = limit.limit();
    assert!(limit.try_acquire(Class::Sheddable).is_none());
    // Critical requests still get their reserve: limit − 90 % of it.
    let reserve = limit.reserved(Class::Critical, limit_now);
    assert!(reserve >= 1);
    let critical: Vec<Permit> = std::iter::from_fn(|| limit.try_acquire(Class::Critical)).collect();
    assert_eq!(u32::try_from(critical.len()).unwrap(), reserve);
    drop(held);
    // Once the sheddable ones drained, critical requests may fill the whole limit again.
    let more: Vec<Permit> = std::iter::from_fn(|| limit.try_acquire(Class::Critical)).collect();
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
                    if let Some(permit) = limit.try_acquire(Class::Critical) {
                        peak.fetch_max(limit.in_flight(), Ordering::Relaxed);
                        limit.record(Duration::from_millis(1), permit.in_flight_at_start(), false);
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
