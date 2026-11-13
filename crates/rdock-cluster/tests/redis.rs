//! The Redis backend of cluster-scoped limits against the testkit's in-process RESP server:
//! claims never pass the limit, `AUTH` with the password, TLS verified against a CA file, a
//! wrong password or an unreachable server is an error within the timeout (never a hang),
//! and three drivers sharing one server stay within the bound, fall back to their share while
//! it is stopped and reconcile when it returns.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use rdock_cluster::limits::{LimitsDriver, Observer, RedisShares, ShareBackend};
use rdock_cluster::resp::{RespClient, RespSettings, tls_config};
use rdock_limits::shared::{SharedLimits, Take, WindowKind, bound};
use rdock_testkit::redis::FakeRedis;

fn settings(fake: &FakeRedis, password: Option<&str>) -> RespSettings {
    RespSettings {
        host: "127.0.0.1".to_owned(),
        port: fake.addr.port(),
        database: 2,
        tls: None,
        username: None,
        password: password.map(str::to_owned),
        timeout: Duration::from_millis(500),
    }
}

#[tokio::test]
async fn claims_are_capped_and_expire_after_their_window() {
    let fake = FakeRedis::start(Some("s3cret-test")).await;
    let shares = RedisShares::new(
        RespClient::new(settings(&fake, Some("s3cret-test"))),
        "rdock:",
    );
    let window = (60_000, 120_000);
    assert_eq!(
        shares
            .claim("q-a", window, "k", 6, 10, false)
            .await
            .unwrap(),
        (6, 6)
    );
    assert_eq!(
        shares
            .claim("q-a", window, "k", 6, 10, false)
            .await
            .unwrap(),
        (4, 10)
    );
    assert_eq!(
        shares
            .claim("q-a", window, "k", 1, 10, false)
            .await
            .unwrap(),
        (0, 10)
    );
    assert_eq!(
        shares.claim("q-a", window, "k", 2, 10, true).await.unwrap(),
        (2, 12)
    );
    assert_eq!(fake.get("rdock:limits:q-a:60000:k"), Some(12));
    assert_eq!(fake.expiry("rdock:limits:q-a:60000:k"), Some(180_000));
    assert_eq!(shares.heartbeat("edge-1").await.unwrap(), 1);
    assert_eq!(shares.heartbeat("edge-2").await.unwrap(), 2);
}

#[tokio::test]
async fn a_wrong_password_and_an_absent_server_are_errors_within_the_timeout() {
    let fake = FakeRedis::start(Some("right")).await;
    let shares = RedisShares::new(RespClient::new(settings(&fake, Some("wrong"))), "rdock:");
    let error = shares.heartbeat("edge-1").await.unwrap_err().to_string();
    assert!(error.contains("WRONGPASS"), "{error}");
    assert!(
        !error.contains("wrong"),
        "the password is never in an error: {error}"
    );
    let no_password = RedisShares::new(RespClient::new(settings(&fake, None)), "rdock:");
    assert!(
        no_password
            .heartbeat("edge-1")
            .await
            .unwrap_err()
            .to_string()
            .contains("NOAUTH")
    );
    // A port nobody answers on.
    let mut gone = FakeRedis::start(None).await;
    gone.stop();
    let shares = RedisShares::new(RespClient::new(settings(&gone, None)), "rdock:");
    let started = Instant::now();
    assert!(shares.heartbeat("edge-1").await.is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn tls_is_verified_against_the_ca_file() {
    let dir = tempfile::tempdir().unwrap();
    let ca = rdock_testkit::certs::TestCa::new();
    let issued = ca.issue(dir.path(), "redis", &["127.0.0.1"]);
    let fake = FakeRedis::start_tls(Some("pw-test"), &issued.cert_pem, &issued.key_pem).await;
    let mut good = settings(&fake, Some("pw-test"));
    good.tls = Some(tls_config(Some(&ca.pem())).unwrap());
    let shares = RedisShares::new(RespClient::new(good), "rdock:");
    assert_eq!(
        shares
            .claim("q", (0, 1000), "k", 3, 5, false)
            .await
            .unwrap(),
        (3, 3)
    );
    // Another CA: the handshake fails.
    let other = rdock_testkit::certs::TestCa::new();
    let mut bad = settings(&fake, Some("pw-test"));
    bad.tls = Some(tls_config(Some(&other.pem())).unwrap());
    let shares = RedisShares::new(RespClient::new(bad), "rdock:");
    let error = shares.heartbeat("edge-1").await.unwrap_err().to_string();
    assert!(error.contains("TLS"), "{error}");
}

async fn wait(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct Counting(std::sync::atomic::AtomicU64);

impl Observer for Counting {
    fn store(&self, up: bool) {
        if !up {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    fn claim(&self, _: &'static str) {}
    fn members(&self, _: u64) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_drivers_share_a_budget_and_survive_the_server_going_away() {
    let mut fake = FakeRedis::start(Some("pw")).await;
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let observer = Arc::new(Counting(std::sync::atomic::AtomicU64::new(0)));
    let mut instances = Vec::new();
    for i in 0..3 {
        let limits = SharedLimits::default();
        limits.configure(10, false);
        let driver = LimitsDriver {
            limits: limits.clone(),
            backend: Arc::new(RedisShares::new(
                RespClient::new(settings(&fake, Some("pw"))),
                "rdock:",
            )),
            instance: format!("edge-{i}"),
            sync_interval: Duration::from_millis(100),
            observer: observer.clone(),
            store_name: "redis",
        };
        tokio::spawn(driver.run(stop_rx.clone()));
        let budget = limits.budget("q-api", WindowKind::Fixed(Duration::from_secs(3600)));
        instances.push((limits, budget));
    }
    wait("three members", || {
        instances
            .iter()
            .all(|(l, _)| l.members() == 3 && l.store_up())
    })
    .await;
    let limit = 90;
    let mut admitted = 0;
    for _ in 0..100 {
        for (_, budget) in &instances {
            if matches!(budget.take("k", limit), Take::Allowed { .. }) {
                admitted += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    assert!(admitted <= bound(limit, 10, 3), "admitted {admitted}");
    assert!(admitted >= limit - 3, "admitted only {admitted}");

    // The server goes away: every instance notices, and a fresh key gets ⌈L / N⌉ per instance.
    fake.stop();
    wait("every instance to see the store away", || {
        instances.iter().all(|(l, _)| !l.store_up())
    })
    .await;
    assert!(observer.0.load(std::sync::atomic::Ordering::SeqCst) >= 3);
    let mut during = 0;
    for _ in 0..100 {
        for (_, budget) in &instances {
            if matches!(budget.take("fresh", limit), Take::Allowed { .. }) {
                during += 1;
            }
        }
    }
    assert_eq!(during, 90, "three shares of ⌈90 / 3⌉");
    // It returns: what was admitted meanwhile is added to its count.
    fake.resume().await;
    wait("every instance to see the store again", || {
        instances.iter().all(|(l, _)| l.store_up())
    })
    .await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let key = |fake: &FakeRedis| {
        fake.keys("rdock:limits:q-api:")
            .into_iter()
            .map(|k| fake.get(&k).unwrap_or(0))
            .collect::<Vec<_>>()
    };
    while !key(&fake).contains(&90) {
        assert!(
            Instant::now() < deadline,
            "the fallback admissions were not reconciled: {:?}",
            key(&fake)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // At most each instance's headroom more (c = ⌈90 × 10 / 300⌉ = 3), then nothing.
    let mut after = 0;
    for _ in 0..40 {
        for (_, budget) in &instances {
            if matches!(budget.take("fresh", limit), Take::Allowed { .. }) {
                after += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(after <= 9, "admitted {after} after the store returned");
    for (_, budget) in &instances {
        assert!(matches!(budget.take("fresh", limit), Take::Exceeded { .. }));
    }
    let _ = stop.send(true);
}
