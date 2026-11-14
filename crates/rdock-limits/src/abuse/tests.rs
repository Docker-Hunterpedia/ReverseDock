#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use super::*;

#[derive(Debug, Default)]
struct Fake(AtomicI64);

impl Clock for Fake {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl Fake {
    fn at(t: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(t)))
    }

    fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

const T0: i64 = 1_796_000_000;

fn policy() -> Policy {
    Policy {
        threshold: 3,
        window: 60,
        ban: 600,
        max_keys: 1_000,
        max_bans: 10,
    }
}

fn abuse(clock: &Arc<Fake>, policy: Policy) -> Abuse {
    Abuse::new(
        policy,
        Arc::new(LocalBans::open(policy.max_bans, None, clock.now())),
        clock.clone(),
    )
}

#[test]
fn the_threshold_within_a_window_bans_until_expiry() {
    let clock = Fake::at(T0);
    let a = abuse(&clock, policy());
    assert_eq!(a.record("ip:192.0.2.1"), Recorded::Counted);
    assert_eq!(a.record("ip:192.0.2.1"), Recorded::Counted);
    assert!(a.banned("ip:192.0.2.1").is_none());
    assert_eq!(a.record("ip:192.0.2.1"), Recorded::Banned);
    let ban = a.banned("ip:192.0.2.1").unwrap();
    assert_eq!((ban.since, ban.until), (T0, T0 + 600));
    assert!(
        a.banned("ip:192.0.2.2").is_none(),
        "other keys are not banned"
    );
    clock.advance(599);
    assert!(a.banned("ip:192.0.2.1").is_some());
    clock.advance(1);
    assert!(a.banned("ip:192.0.2.1").is_none(), "the ban ends");
}

#[test]
fn events_in_an_older_window_do_not_count() {
    let clock = Fake::at(T0);
    let a = abuse(&clock, policy());
    a.record("k");
    a.record("k");
    clock.advance(60);
    assert_eq!(a.record("k"), Recorded::Counted, "a new window starts at 1");
    assert_eq!(a.record("k"), Recorded::Counted);
    assert_eq!(a.record("k"), Recorded::Banned);
}

#[test]
fn the_counter_table_stays_bounded_under_a_million_keys() {
    let clock = Fake::at(T0);
    let a = abuse(
        &clock,
        Policy {
            max_keys: 10_000,
            ..policy()
        },
    );
    for i in 0..1_000_000_u32 {
        a.record(&format!("ip:{i}"));
        assert!(a.counters() <= 10_000);
    }
    assert!(a.counters() <= 10_000);
}

#[test]
fn counter_churn_never_evicts_a_ban_and_a_full_list_refuses() {
    let clock = Fake::at(T0);
    let a = abuse(
        &clock,
        Policy {
            max_keys: 100,
            max_bans: 2,
            ..policy()
        },
    );
    for _ in 0..3 {
        a.record("victim");
    }
    assert!(a.banned("victim").is_some());
    // An attacker churns the counter table with many keys and fills the ban list.
    for i in 0..10_000 {
        a.record(&format!("churn:{i}"));
    }
    for _ in 0..3 {
        a.record("second");
    }
    assert!(a.banned("victim").is_some(), "never evicted by churn");
    assert!(a.banned("second").is_some());
    let mut last = Recorded::Counted;
    for _ in 0..3 {
        last = a.record("third");
    }
    assert_eq!(last, Recorded::Refused, "a full ban list refuses");
    assert!(a.banned("third").is_none());
    assert!(a.banned("victim").is_some(), "the refusal lifts nothing");
    // Once the first bans end, room frees up.
    clock.advance(600);
    for _ in 0..3 {
        last = a.record("third");
    }
    assert_eq!(last, Recorded::Banned);
}

#[test]
fn bans_persist_with_private_permissions_and_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Fake::at(T0);
    let registry = AbuseRegistry::with_clock(clock.clone());
    registry.set_dir(dir.path().join("abuse"));
    let a = registry.get("guard", policy());
    for _ in 0..3 {
        a.record("ip:192.0.2.9");
    }
    registry.flush_all();
    let file = std::fs::read_dir(dir.path().join("abuse"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A new process.
    let restarted = AbuseRegistry::with_clock(clock.clone());
    restarted.set_dir(dir.path().join("abuse"));
    let b = restarted.get("guard", policy());
    assert!(b.banned("ip:192.0.2.9").is_some());
    assert_eq!(restarted.bans().len(), 1);
    // A policy change keeps the bans.
    let changed = restarted.get(
        "guard",
        Policy {
            threshold: 9,
            ..policy()
        },
    );
    assert!(changed.banned("ip:192.0.2.9").is_some());
    // Unban, written at the next flush.
    assert_eq!(restarted.unban("ip:192.0.2.9", None), 1);
    assert_eq!(restarted.unban("ip:192.0.2.9", None), 0);
    restarted.flush_all();
    let again = AbuseRegistry::with_clock(clock);
    again.set_dir(dir.path().join("abuse"));
    assert!(
        again
            .get("guard", policy())
            .banned("ip:192.0.2.9")
            .is_none()
    );
}

#[test]
fn expired_bans_are_not_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Fake::at(T0);
    let registry = AbuseRegistry::with_clock(clock.clone());
    registry.set_dir(dir.path().to_owned());
    let a = registry.get("guard", policy());
    for _ in 0..3 {
        a.record("k");
    }
    registry.flush_all();
    clock.advance(601);
    let later = AbuseRegistry::with_clock(clock);
    later.set_dir(dir.path().to_owned());
    let _ = later.get("guard", policy());
    assert_eq!(later.bans(), Vec::new());
}
