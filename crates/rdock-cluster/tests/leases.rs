//! Lease and fencing simulations against the memory store and the directory store (shared and
//! exclusive), with manual clocks: expiry, takeover, a stale holder's write refused, and what
//! clock skew does to a shared directory.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use rdock_cluster::{
    ClusterStore, DirStore, Expect, Fencing, ManualClock, MemoryStore, StoreError,
};

const TTL: Duration = Duration::from_secs(30);
const TTL_MS: u64 = 30_000;
const START: u64 = 1_800_000_000_000;

/// Two members' views of one store and the clock that moves both.
struct World {
    a: Arc<dyn ClusterStore>,
    b: Arc<dyn ClusterStore>,
    clock: ManualClock,
    _dir: Option<tempfile::TempDir>,
}

fn memory() -> World {
    let clock = ManualClock::new(START);
    let store: Arc<dyn ClusterStore> = Arc::new(MemoryStore::with_clock(Arc::new(clock.clone())));
    World {
        a: store.clone(),
        b: store,
        clock,
        _dir: None,
    }
}

/// Two instances on one shared directory; `skew_ms` is how far `b`'s clock runs ahead.
fn shared(skew_ms: i64) -> World {
    let dir = tempfile::tempdir().unwrap();
    let clock = ManualClock::new(START);
    World {
        a: Arc::new(DirStore::shared_with_clock(
            dir.path(),
            Arc::new(clock.clone()),
        )),
        b: Arc::new(DirStore::shared_with_clock(
            dir.path(),
            Arc::new(clock.skewed(skew_ms)),
        )),
        clock,
        _dir: Some(dir),
    }
}

async fn every_world(check: impl AsyncFn(World)) {
    check(memory()).await;
    check(shared(0)).await;
}

#[tokio::test]
async fn one_holder_at_a_time_until_expiry_then_takeover_with_a_larger_token() {
    every_world(async |w| {
        let first = w.a.acquire("cert/app", "a", TTL).await.unwrap().unwrap();
        assert_eq!(first.token, 1);
        assert!(w.b.acquire("cert/app", "b", TTL).await.unwrap().is_none());
        // The holder asking again keeps its token.
        let again = w.a.acquire("cert/app", "a", TTL).await.unwrap().unwrap();
        assert_eq!(again.token, 1);
        w.clock.advance(TTL_MS - 1);
        assert!(w.b.acquire("cert/app", "b", TTL).await.unwrap().is_none());
        w.clock.advance(2);
        let second = w.b.acquire("cert/app", "b", TTL).await.unwrap().unwrap();
        assert_eq!(second.token, 2, "a takeover raises the token");
        assert!(matches!(
            w.a.renew(&first, TTL).await,
            Err(StoreError::Lost(_))
        ));
        // Release keeps the counter: the next holder's token is larger still.
        w.b.release(&second).await.unwrap();
        let third = w.a.acquire("cert/app", "a", TTL).await.unwrap().unwrap();
        assert_eq!(third.token, 3);
        // Renewal moves the expiry.
        w.clock.advance(TTL_MS / 2);
        let renewed = w.a.renew(&third, TTL).await.unwrap();
        assert!(renewed.expires_at_ms > third.expires_at_ms);
    })
    .await;
}

#[tokio::test]
async fn a_stale_holders_fenced_write_is_refused() {
    every_world(async |w| {
        let stale = w.a.acquire("cert/app", "a", TTL).await.unwrap().unwrap();
        w.a.put(
            "certs/app/meta.json",
            b"a1".to_vec(),
            Expect::Any,
            Some(&stale),
        )
        .await
        .unwrap();
        // `a` pauses past its lease; `b` takes over and writes.
        w.clock.advance(TTL_MS + 1);
        let fresh = w.b.acquire("cert/app", "b", TTL).await.unwrap().unwrap();
        w.b.put(
            "certs/app/meta.json",
            b"b1".to_vec(),
            Expect::Any,
            Some(&fresh),
        )
        .await
        .unwrap();
        // `a` wakes up and tries to write with its old lease.
        let refused =
            w.a.put(
                "certs/app/meta.json",
                b"a2".to_vec(),
                Expect::Any,
                Some(&stale),
            )
            .await;
        assert!(
            matches!(refused, Err(StoreError::Fenced { token: 1, .. })),
            "{refused:?}"
        );
        let deleted =
            w.a.delete("certs/app/meta.json", Expect::Any, Some(&stale))
                .await;
        assert!(matches!(deleted, Err(StoreError::Fenced { .. })));
        assert_eq!(
            w.a.get("certs/app/meta.json").await.unwrap().unwrap().value,
            b"b1"
        );
    })
    .await;
}

#[tokio::test]
async fn compare_and_swap_refuses_a_lost_update() {
    every_world(async |w| {
        let v1 =
            w.a.put("k/v", b"one".to_vec(), Expect::Absent, None)
                .await
                .unwrap();
        assert!(matches!(
            w.b.put("k/v", b"two".to_vec(), Expect::Absent, None).await,
            Err(StoreError::Conflict { current, .. }) if current == v1
        ));
        let v2 =
            w.b.put("k/v", b"two".to_vec(), Expect::Version(v1), None)
                .await
                .unwrap();
        assert_ne!(v1, v2);
        assert!(matches!(
            w.a.put("k/v", b"three".to_vec(), Expect::Version(v1), None)
                .await,
            Err(StoreError::Conflict { .. })
        ));
        w.a.put("k/w", b"x".to_vec(), Expect::Any, None)
            .await
            .unwrap();
        w.a.put("other", b"x".to_vec(), Expect::Any, None)
            .await
            .unwrap();
        assert_eq!(w.b.list("k").await.unwrap(), ["k/v", "k/w"]);
        assert_eq!(w.b.list("").await.unwrap(), ["k/v", "k/w", "other"]);
        w.b.delete("k/v", Expect::Version(v2), None).await.unwrap();
        assert!(w.a.get("k/v").await.unwrap().is_none());
        assert!(w.a.delete("k/v", Expect::Any, None).await.is_ok());
        assert!(matches!(
            w.a.get("../escape").await,
            Err(StoreError::InvalidKey(_))
        ));
    })
    .await;
}

#[tokio::test]
async fn concurrent_acquires_have_one_winner() {
    for w in [memory(), shared(0)] {
        let mut tasks = Vec::new();
        for i in 0..8 {
            let store = if i % 2 == 0 { w.a.clone() } else { w.b.clone() };
            tasks.push(tokio::spawn(async move {
                store
                    .acquire("cert/race", &format!("m{i}"), TTL)
                    .await
                    .unwrap()
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }
}

#[tokio::test]
async fn clock_skew_on_a_shared_directory() {
    // `b`'s clock runs 10 s ahead: within the margin the lease leaves (renewal every third of
    // 30 s), `b` still sees `a`'s renewed lease as held.
    let w = shared(10_000);
    let lease = w.a.acquire("cert/app", "a", TTL).await.unwrap().unwrap();
    w.clock.advance(10_000);
    let lease = w.a.renew(&lease, TTL).await.unwrap();
    assert!(w.b.acquire("cert/app", "b", TTL).await.unwrap().is_none());

    // 40 s ahead, more than the lease: `b` believes the live lease expired and takes it, and
    // `a`'s fenced write fails only because the file now names `b`. This is the documented
    // limit of the shared directory, which `cluster.store` warns about.
    let w2 = shared(40_000);
    let held = w2.a.acquire("cert/app", "a", TTL).await.unwrap().unwrap();
    let taken = w2.b.acquire("cert/app", "b", TTL).await.unwrap();
    assert!(taken.is_some(), "a clock 40 s ahead takes a live lease");
    assert!(matches!(
        w2.a.put("x", b"a".to_vec(), Expect::Any, Some(&held)).await,
        Err(StoreError::Fenced { .. })
    ));
    let _ = lease;

    // The memory store has one clock: skew between members cannot happen there.
    assert_eq!(memory().a.fencing(), Fencing::Enforced);
    assert_eq!(w.a.fencing(), Fencing::BestEffort);
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(DirStore::exclusive(dir.path()).fencing(), Fencing::Enforced);
}

#[cfg(unix)]
#[tokio::test]
async fn directory_values_are_private_and_hidden_files_are_not_listed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = DirStore::exclusive(dir.path());
    store
        .put("certs/app/key.pem", b"secret".to_vec(), Expect::Any, None)
        .await
        .unwrap();
    store.acquire("cert/app", "a", TTL).await.unwrap().unwrap();
    let mode = std::fs::metadata(dir.path().join("certs/app/key.pem"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(store.list("").await.unwrap(), ["certs/app/key.pem"]);
}
