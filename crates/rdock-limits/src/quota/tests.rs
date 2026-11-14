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

/// Fills `class` of `counter` with `MAX_KEYS` keys made by `key`.
fn fill(counter: &QuotaCounter, key: impl Fn(usize) -> String) {
    let mut state = counter.state.lock().unwrap();
    for i in 0..MAX_KEYS {
        state.counts.insert(key(i), (0, 1));
    }
    state.recount();
}

#[test]
fn keys_past_the_cap_share_one_counter() {
    let counter = QuotaCounter::open(Window::Day, None, Arc::new(SystemClock));
    fill(&counter, |i| format!("ip:10.0.{}.{}", i / 256, i % 256));
    let (taken, overflowed) = counter.take_counted("ip:192.0.2.1", 1);
    assert!(matches!(taken, Taken::Allowed { remaining: 0, .. }));
    assert_eq!(overflowed, Some(KeyClass::Anonymous));
    assert!(matches!(
        counter.take("ip:192.0.2.2", 1),
        Taken::Exceeded { .. }
    ));
    assert_eq!(counter.usage(OVERFLOW_KEY).unwrap().used, 1);
}

/// M2 of the v0.8 review: anonymous addresses filling their keys never push a consumer onto
/// a shared counter; token consumers have a budget of their own; configured consumers none.
#[test]
fn anonymous_keys_never_crowd_out_consumers() {
    let counter = QuotaCounter::open(Window::Day, None, Arc::new(SystemClock));
    fill(&counter, |i| format!("ip:10.0.{}.{}", i / 256, i % 256));
    // A consumer seen for the first time gets its own counter, as does a token consumer.
    assert_eq!(counter.take_counted("acme", 2).1, None);
    assert_eq!(counter.take_counted("acme", 2).1, None);
    assert!(matches!(counter.take("acme", 2), Taken::Exceeded { .. }));
    let alice = consumer_key(Some("https://idp.example"), "alice@example.com");
    assert_eq!(counter.take_counted(&alice, 1).1, None);
    assert_eq!(counter.usage("acme").unwrap().used, 2);
    assert_eq!(counter.usage(OVERFLOW_KEY), None);

    // Token consumers overflow among themselves only.
    fill(&counter, |i| {
        consumer_key(Some("https://idp.example"), &format!("u{i}")).into_owned()
    });
    assert_eq!(
        counter
            .take_counted(&consumer_key(Some("https://idp.example"), "late"), 5)
            .1,
        Some(KeyClass::Token)
    );
    assert_eq!(counter.usage(TOKEN_OVERFLOW_KEY).unwrap().used, 1);
    // Configured consumers are bounded by the configuration and never overflow.
    fill(&counter, |i| format!("c{i}"));
    assert_eq!(counter.take_counted("newcomer", 5).1, None);
    assert_eq!(counter.usage("newcomer").unwrap().used, 1);
    // Forgetting a key frees its place.
    assert!(counter.reset("ip:10.0.0.0"));
    assert_eq!(counter.take_counted("ip:192.0.2.9", 5).1, None);
}

#[test]
fn consumer_keys_name_their_consumer() {
    assert_eq!(consumer_key(None, "acme"), "acme");
    let token = consumer_key(Some("https://idp.example"), "alice");
    assert_eq!(token, "~19:https://idp.examplealice");
    assert_eq!(key_consumer(&token), Some("alice"));
    assert_eq!(key_consumer("acme"), Some("acme"));
    assert_eq!(key_consumer("ip:192.0.2.1"), None);
    assert_eq!(key_consumer(OVERFLOW_KEY), None);
    assert_eq!(key_consumer("~99:short"), None);
    // Different issuers or names never give the same key.
    assert_ne!(
        consumer_key(Some("a b"), "c"),
        consumer_key(Some("a"), "b c")
    );

    let counter = QuotaCounter::open(Window::Day, None, Arc::new(SystemClock));
    let _ = counter.take("alice", 5);
    let _ = counter.take(&token, 5);
    let _ = counter.take(&consumer_key(Some("https://other.example"), "alice"), 5);
    let _ = counter.take("bob", 5);
    assert_eq!(counter.usage_of("alice").len(), 3);
    assert!(counter.reset_consumer("alice"));
    assert_eq!(counter.usage_of("alice").len(), 0);
    assert_eq!(counter.usage("bob").unwrap().used, 1);
}

/// Files written before the key classes existed (one budget, one overflow counter) still load.
#[test]
fn files_of_earlier_versions_load() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Fake::default());
    clock.set(10 * 86_400 + 100);
    let path = dir.path().join("q.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"version":1,"window":"day","start":{},"counts":{{"acme":[3,5],"ip:192.0.2.1":[1,5],"\u0000overflow":[2,5]}}}}"#,
            10 * 86_400
        ),
    )
    .unwrap();
    let counter = QuotaCounter::open(Window::Day, Some(path), clock);
    assert_eq!(counter.usage("acme").unwrap().used, 3);
    assert_eq!(counter.usage(OVERFLOW_KEY).unwrap().used, 2);
    let state = counter.state.lock().unwrap();
    assert_eq!(state.sizes, [1, 0, 1]);
}

/// L6 of the v0.8 review: the counts name people and addresses; only the owner reads them.
#[cfg(unix)]
#[test]
fn quota_files_are_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let quota = dir.path().join("quota");
    let registry = QuotaRegistry::with_clock(Arc::new(SystemClock));
    registry.set_dir(quota.clone());
    let counter = registry.counter("daily", Window::Day);
    // A temporary file an older version left world-readable.
    std::fs::create_dir_all(&quota).unwrap();
    let name = file_name("daily");
    let tmp = quota.join(format!("{name}.tmp"));
    std::fs::write(&tmp, b"{}").unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&quota, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = counter.take("alice@example.com", 5);
    counter.flush().unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&quota.join(name)), 0o600);
    assert_eq!(mode(&quota), 0o700);
}

#[test]
fn increments_move_to_the_next_process_and_a_reread_takes_the_written_counts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("q.json");
    let clock = Arc::new(Fake::default());
    clock.set(10);
    let old = QuotaCounter::open(Window::Hour, Some(path.clone()), clock.clone());
    old.take("consumer:a", 100);
    old.flush().unwrap();
    // The new process opened the counters before the old one wrote its last counts.
    let new = QuotaCounter::open(Window::Hour, Some(path.clone()), clock.clone());
    old.take("consumer:a", 100);
    old.flush().unwrap();
    let base = old.snapshot();
    new.reread();
    assert_eq!(new.usage("consumer:a").unwrap().used, 2);
    // Requests the old process counted while draining reach the new one at its exit.
    old.take("consumer:a", 100);
    old.take("consumer:b", 100);
    let (start, increments) = old.increments_since(&base);
    new.add_increments(start, &increments);
    assert_eq!(new.usage("consumer:a").unwrap().used, 3);
    assert_eq!(new.usage("consumer:b").unwrap().used, 1);
    // Increments of another window are dropped.
    new.add_increments(start - 3600, &increments);
    assert_eq!(new.usage("consumer:a").unwrap().used, 3);
}
