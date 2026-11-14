//! Chaos suite, scenario 5 "backend flapping" (ADR-0033, vision §7): the rootless variant of
//! `chaos.rs` (which uses Toxiproxy in Docker), under steady concurrent load instead of 60
//! sequential requests, with the two gaps the research named: a backend flapping faster than
//! the health-check interval, and every backend flapping in turn so that one is always up.
//!
//! Each backend sits behind a testkit `FaultProxy` that resets every connection while "down".
//! The schedule of the flapping is the fault itself, so it is timed; nothing waits for a fixed
//! time to let rdock catch up. Pass: zero failed requests (one backend is always up and GET
//! is retried on connect and reset), and every backend serves again after the flapping stops,
//! within the ejection plus one active interval (bounded at 10 s here).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod chaos_common;

use std::time::Duration;

use chaos_common::*;
use rdock_testkit::backend::Backend;
use rdock_testkit::fault_proxy::{Fault, FaultProxy};
use rdock_testkit::free_port;
use rdock_testkit::load::{Load, Target};
use rdock_testkit::rdock::Rdock;

struct Lab {
    backends: Vec<Backend>,
    proxies: Vec<FaultProxy>,
    port: u16,
    rdock: Rdock,
}

async fn lab() -> Lab {
    let mut backends = Vec::new();
    let mut proxies = Vec::new();
    for i in 0..3 {
        let backend = Backend::start(&format!("b{i}")).await;
        proxies.push(FaultProxy::start(free_port(), backend.addr).await);
        backends.push(backend);
    }
    let list: Vec<String> = proxies
        .iter()
        .map(|p| format!("{{ address: \"{}\" }}", p.addr))
        .collect();
    let port = free_port();
    let config = format!(
        r#"listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "Host(`app.test`)", service: app }}
services:
  app:
    backends: [{}]
    retries: {{ attempts: 2, on: [connect, reset], budget_percent: 100 }}
    health:
      active: {{ path: /healthz, interval: 500ms, timeout: 1s, healthy: 1, unhealthy: 1 }}
      passive: {{ failures: 1, window: 10s, ejection: 1s }}
"#,
        list.join(", ")
    );
    let rdock = Rdock::start(RDOCK, &config);
    Lab {
        backends,
        proxies,
        port,
        rdock,
    }
}

/// Waits until every backend has served a request since `before` (its count).
async fn all_serve_again(lab: &Lab, before: &[usize]) {
    let start = std::time::Instant::now();
    while lab
        .backends
        .iter()
        .zip(before)
        .any(|(b, n)| b.requests() <= *n)
    {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "a backend is not back in rotation: {:?} → {:?}\n{}",
            before,
            lab.backends
                .iter()
                .map(Backend::requests)
                .collect::<Vec<_>>(),
            lab.rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flapping_faster_than_the_health_interval_costs_nothing() {
    let lab = lab().await;
    let load = Load::start(vec![Target::http(addr(lab.port), "app.test", "/")], 100);
    load.wait_for_ok(100, Duration::from_secs(30)).await;
    // b1 is down for good; b2 flips every 150 ms, faster than the 500 ms active interval.
    lab.proxies[1].set(Fault::Reset);
    for i in 0..30 {
        lab.proxies[2].set(if i % 2 == 0 {
            Fault::Reset
        } else {
            Fault::Pass
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    lab.proxies[1].set(Fault::Pass);
    lab.proxies[2].set(Fault::Pass);
    let before: Vec<usize> = lab.backends.iter().map(Backend::requests).collect();
    all_serve_again(&lab, &before).await;
    let report = load.stop().await;
    eprintln!("load: {report:?}");
    report.assert_clean("flapping faster than the health interval", &lab.rdock.log());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_backend_flapping_in_turn_costs_nothing() {
    let lab = lab().await;
    let load = Load::start(vec![Target::http(addr(lab.port), "app.test", "/")], 100);
    load.wait_for_ok(100, Duration::from_secs(30)).await;
    // One backend up at a time, in turn; the next comes up before the last goes down. A
    // backend that just came back is eligible again after the passive ejection (1 s) and the
    // next active check (500 ms), so it gets that long before the others go down: rdock's
    // view of "healthy" lags by exactly that, which is the bound the criterion allows.
    for step in 0..6 {
        let up = step % 3;
        lab.proxies[up].set(Fault::Pass);
        tokio::time::sleep(Duration::from_millis(1600)).await;
        for (i, proxy) in lab.proxies.iter().enumerate() {
            if i != up {
                proxy.set(Fault::Reset);
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    for proxy in &lab.proxies {
        proxy.set(Fault::Pass);
    }
    let before: Vec<usize> = lab.backends.iter().map(Backend::requests).collect();
    all_serve_again(&lab, &before).await;
    let report = load.stop().await;
    eprintln!("load: {report:?}");
    report.assert_clean("every backend flapping in turn", &lab.rdock.log());
}
