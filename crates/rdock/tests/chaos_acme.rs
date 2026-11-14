//! Chaos suite, scenario 3 "CA down" (ADR-0033, vision §7). Rootless: the testkit's in-process
//! ACME CA (`fake_acme`) refuses connections, hangs, or answers `429`/`500` with or without
//! `Retry-After`. `RDOCK_TEST_ACME_RETRY=1` (debug builds only) shortens the first backoff from
//! a minute to a second so retries show within seconds; the doubling stays. The variants against
//! Pebble (`e2e_acme`, `pebble.stop_ca()`) run where Docker is available.
//!
//! Pass: certificates already issued keep serving for the whole outage (zero failed HTTPS
//! requests), attempts back off (connections at the CA stay bounded), a renewal after the CA
//! returns places exactly one order, a hanging CA is given up after the 30 s request deadline
//! instead of stalling certificate work, and a `Retry-After` is waited out.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod chaos_common;

use std::time::{Duration, Instant};

use chaos_common::*;
use rdock_testkit::backend::Backend;
use rdock_testkit::fake_acme::{CaMode, FakeAcme};
use rdock_testkit::load::{Load, Target};
use rdock_testkit::rdock::Rdock;

const NAME: &str = "a.example.com";

struct Lab {
    fake: FakeAcme,
    ports: Ports,
    rdock: Rdock,
    trust: std::sync::Arc<rustls::ClientConfig>,
    _backend: Backend,
    _dir: tempfile::TempDir,
}

async fn lab(mode: CaMode) -> Lab {
    let backend = Backend::start("app").await;
    let ports = Ports::new();
    let fake = FakeAcme::start(vec![ports.http()], vec![ports.https()]).await;
    fake.set_mode(mode);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.pem");
    std::fs::write(&root, fake.root_pem()).unwrap();
    let rdock = Rdock::try_start_in(
        RDOCK,
        &acme_config(&fake.directory(), &root, &ports, &[NAME], backend.addr),
        &[("RDOCK_TEST_ACME_RETRY", "1")],
        None,
        Duration::from_secs(30),
    )
    .unwrap_or_else(|log| panic!("rdock did not start:\n{log}"));
    let trust = trust(fake.issuing_pem());
    Lab {
        fake,
        ports,
        rdock,
        trust,
        _backend: backend,
        _dir: dir,
    }
}

fn orders(fake: &FakeAcme) -> usize {
    fake.orders_created().get(NAME).copied().unwrap_or(0)
}

fn failures(rdock: &Rdock) -> u64 {
    cert_status(rdock, NAME)["failures"].as_u64().unwrap_or(0)
}

/// First issuance while the CA is down: the handshake for the name has no certificate (the
/// documented behaviour without `defaults.certificate`), plain HTTP keeps answering, the
/// attempts back off, and the certificate comes once the CA does, from one order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_issuance_waits_for_the_ca_without_hammering_it() {
    let lab = lab(CaMode::Down).await;
    let load = Load::start(
        vec![Target::http(lab.ports.http(), NAME, "/").expecting(&[200, 301, 308])],
        30,
    );
    let outage = Instant::now();
    wait_until(
        &lab.rdock,
        Duration::from_secs(30),
        "two failed attempts",
        || failures(&lab.rdock) >= 2,
    )
    .await;
    assert!(served(lab.ports.https(), NAME, &lab.trust).await.is_none());
    // Keep the CA away a little longer and count what reached it.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let seconds = outage.elapsed().as_secs() + 1;
    let connections = lab.fake.connections();
    assert!(
        connections <= 4 * seconds.min(8) + 8,
        "{connections} connections to a CA that is down in {seconds} s: no backoff"
    );
    lab.fake.set_mode(CaMode::Up);
    let back = Instant::now();
    issued(
        &lab.rdock,
        lab.ports.https(),
        NAME,
        &lab.trust,
        None,
        Duration::from_secs(60),
    )
    .await;
    eprintln!("issued {:?} after the CA returned", back.elapsed());
    assert_eq!(orders(&lab.fake), 1, "one order");
    let report = load.stop().await;
    report.assert_clean("CA down at first issuance", &lab.rdock.log());
}

/// A renewal that falls due while the CA is down (forced through the admin API, the same
/// path as a renewal reaching its ARI window): the current certificate keeps serving, the
/// failures show, and the renewal goes through with exactly one order once the CA is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewal_survives_a_ca_outage_and_orders_once() {
    let lab = lab(CaMode::Up).await;
    let first = issued(
        &lab.rdock,
        lab.ports.https(),
        NAME,
        &lab.trust,
        None,
        Duration::from_secs(60),
    )
    .await;
    let load = Load::start(
        vec![Target::https(
            lab.ports.https(),
            NAME,
            "/",
            lab.trust.clone(),
        )],
        40,
    );
    load.wait_for_ok(40, Duration::from_secs(30)).await;
    lab.fake.set_mode(CaMode::Down);
    force_renewal(&lab.rdock, NAME);
    wait_until(
        &lab.rdock,
        Duration::from_secs(30),
        "two failed renewal attempts",
        || failures(&lab.rdock) >= 2,
    )
    .await;
    assert!(metric(&lab.rdock, "rdock_cert_renewal_failures_total", NAME) >= 2.0);
    assert_eq!(
        served(lab.ports.https(), NAME, &lab.trust).await.as_deref(),
        Some(first.as_slice())
    );
    lab.fake.set_mode(CaMode::Up);
    let back = Instant::now();
    let renewed = issued(
        &lab.rdock,
        lab.ports.https(),
        NAME,
        &lab.trust,
        Some(&first),
        Duration::from_secs(60),
    )
    .await;
    eprintln!("renewed {:?} after the CA returned", back.elapsed());
    assert_ne!(renewed, first);
    load.wait_for_ok(40, Duration::from_secs(30)).await;
    assert_eq!(orders(&lab.fake), 2, "exactly one renewal order");
    let report = load.stop().await;
    report.assert_clean("CA down at renewal", &lab.rdock.log());
    assert_data_dir_consistent(&lab.rdock);
}

/// A CA that accepts connections and never answers is given up after the request deadline
/// (30 s); before the fix such an order stalled all certificate work for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hanging_ca_is_given_up_and_retried() {
    let lab = lab(CaMode::Up).await;
    let first = issued(
        &lab.rdock,
        lab.ports.https(),
        NAME,
        &lab.trust,
        None,
        Duration::from_secs(60),
    )
    .await;
    let load = Load::start(
        vec![Target::https(
            lab.ports.https(),
            NAME,
            "/",
            lab.trust.clone(),
        )],
        20,
    );
    lab.fake.set_mode(CaMode::Hang);
    force_renewal(&lab.rdock, NAME);
    let mut seen = serde_json::Value::Null;
    let gave_up = wait_for(Duration::from_secs(50), || {
        seen = cert_status(&lab.rdock, NAME);
        seen["failures"].as_u64() >= Some(1)
    })
    .await;
    assert!(
        gave_up,
        "the hanging order was not given up: {seen}\n{}",
        lab.rdock.log()
    );
    assert!(
        seen["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("did not answer")),
        "{seen}"
    );
    lab.fake.set_mode(CaMode::Up);
    let renewed = issued(
        &lab.rdock,
        lab.ports.https(),
        NAME,
        &lab.trust,
        Some(&first),
        Duration::from_secs(60),
    )
    .await;
    assert_ne!(renewed, first);
    let report = load.stop().await;
    report.assert_clean("hanging CA", &lab.rdock.log());
}

/// `429` with `Retry-After: 6`: the next attempt waits six seconds, not the one-second backoff.
/// A `500` without `Retry-After` is retried after the backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_after_is_waited_out() {
    let lab = lab(CaMode::Up).await;
    let first = issued(
        &lab.rdock,
        lab.ports.https(),
        NAME,
        &lab.trust,
        None,
        Duration::from_secs(60),
    )
    .await;
    lab.fake.fail_new_orders(1, 429, Some(6));
    let asked = Instant::now();
    force_renewal(&lab.rdock, NAME);
    wait_until(
        &lab.rdock,
        Duration::from_secs(20),
        "the rate-limited attempt",
        || failures(&lab.rdock) >= 1,
    )
    .await;
    let refused = asked.elapsed();
    let renewed = issued(
        &lab.rdock,
        lab.ports.https(),
        NAME,
        &lab.trust,
        Some(&first),
        Duration::from_secs(60),
    )
    .await;
    let waited = asked.elapsed().saturating_sub(refused);
    eprintln!("429: refused after {refused:?}, renewed {waited:?} later");
    assert!(
        waited >= Duration::from_secs(5),
        "the next attempt came {waited:?} after a Retry-After of 6 s"
    );
    assert_eq!(
        orders(&lab.fake),
        2,
        "the refused order is not counted, the next one is"
    );

    lab.fake.fail_new_orders(1, 500, None);
    let asked = Instant::now();
    force_renewal(&lab.rdock, NAME);
    let again = issued(
        &lab.rdock,
        lab.ports.https(),
        NAME,
        &lab.trust,
        Some(&renewed),
        Duration::from_secs(60),
    )
    .await;
    assert_ne!(again, renewed);
    eprintln!("500: renewed {:?} after the request", asked.elapsed());
}
