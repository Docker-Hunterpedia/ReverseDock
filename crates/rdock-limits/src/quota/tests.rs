use std::sync::atomic::AtomicI64;

use super::*;

#[derive(Debug, Default)]
struct Fake(AtomicI64);

impl Fake {
    fn set(&self, t: i64) {
        self.0.store(t, Ordering::SeqCst);
    }
}

impl Clock for Fake {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// 2026-11-30T23:59:58Z.
const NOV_30_LATE: i64 = 1_796_083_198;

#[test]
fn windows_are_calendar_aligned_in_utc() {
    assert_eq!(Window::Hour.bounds(3601), (3600, 7200));
    assert_eq!(Window::Day.bounds(86_399), (0, 86_400));
    // November 2026 has 30 days; December starts at 2026-12-01T00:00:00Z.
    let (start, end) = Window::Month.bounds(NOV_30_LATE);
    assert_eq!(end - NOV_30_LATE, 2);
    assert_eq!(end - start, 30 * 86_400);
    // February of a leap year.
    let feb_2028 = 1_832_976_000; // 2028-02-01T00:00:00Z
    assert_eq!(
        Window::Month.bounds(feb_2028 + 5),
        (feb_2028, feb_2028 + 29 * 86_400)
    );
}

#[test]
fn a_window_roll_over_renews_the_quota() {
    let clock = Arc::new(Fake::default());
    clock.set(NOV_30_LATE);
    let counter = QuotaCounter::open(Window::Month, None, clock.clone());
    assert_eq!(
        counter.take("acme", 2),
        Taken::Allowed {
            remaining: 1,
            reset: 2
        }
    );
    assert_eq!(
        counter.take("acme", 2),
        Taken::Allowed {
            remaining: 0,
            reset: 2
        }
    );
    assert_eq!(counter.take("acme", 2), Taken::Exceeded { reset: 2 });
    assert_eq!(
        counter.take("other", 2),
        Taken::Allowed {
            remaining: 1,
            reset: 2
        }
    );
    clock.set(NOV_30_LATE + 2);
    let Taken::Allowed {
        remaining: 1,
        reset,
    } = counter.take("acme", 2)
    else {
        panic!("the new month renews the quota")
    };
    assert_eq!(reset, 31 * 86_400, "December has 31 days");
    assert_eq!(counter.usage("other"), None);
}

#[test]
fn counters_survive_a_restart_within_the_window_only() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Fake::default());
    clock.set(10 * 86_400 + 100);
    let registry = QuotaRegistry::with_clock(clock.clone());
    registry.set_dir(dir.path().to_owned());
    let counter = registry.counter("daily@file", Window::Day);
    for _ in 0..3 {
        let _ = counter.take("acme", 5);
    }
    registry.flush_all();
    let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(files.len(), 1);

    let restarted = QuotaRegistry::with_clock(clock.clone());
    restarted.set_dir(dir.path().to_owned());
    let counter = restarted.counter("daily@file", Window::Day);
    assert_eq!(counter.usage("acme").unwrap().used, 3);
    assert_eq!(
        counter.take("acme", 5),
        Taken::Allowed {
            remaining: 1,
            reset: 86_300
        }
    );

    // The next day the file's counts are stale.
    clock.set(11 * 86_400 + 1);
    let next_day = QuotaRegistry::with_clock(clock);
    next_day.set_dir(dir.path().to_owned());
    assert_eq!(
        next_day.counter("daily@file", Window::Day).usage("acme"),
        None
    );
}

#[test]
fn reloads_keep_counts_unless_the_window_changes_and_reset_forgets() {
    let registry = QuotaRegistry::default();
    let a = registry.counter("q", Window::Day);
    let _ = a.take("acme", 10);
    let b = registry.counter("q", Window::Day);
    assert!(Arc::ptr_eq(&a, &b));
    assert!(b.reset("acme"));
    assert!(!b.reset("acme"));
    let _ = b.take("acme", 10);
    let hourly = registry.counter("q", Window::Hour);
    assert_eq!(hourly.usage("acme"), None);
}

#[test]
fn counts_are_exact_under_concurrency() {
    let counter = Arc::new(QuotaCounter::open(Window::Day, None, Arc::new(SystemClock)));
    let allowed = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (counter, allowed) = (counter.clone(), allowed.clone());
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    if matches!(counter.take("acme", 5000), Taken::Allowed { .. }) {
                        allowed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(allowed.load(Ordering::Relaxed), 5000);
    assert_eq!(counter.usage("acme").unwrap().used, 5000);
}

#[test]
fn keys_past_the_cap_share_one_counter() {
    let counter = QuotaCounter::open(Window::Day, None, Arc::new(SystemClock));
    {
        let mut state = counter.state.lock().unwrap();
        for i in 0..MAX_KEYS {
            state.counts.insert(format!("k{i}"), (0, 1));
        }
    }
    assert!(matches!(counter.take("new-1", 1), Taken::Allowed { .. }));
    assert!(matches!(counter.take("new-2", 1), Taken::Exceeded { .. }));
    assert_eq!(counter.usage(OVERFLOW_KEY).unwrap().used, 1);
}
