//! End-to-end: balancing policies and sticky sessions (ADR-0022) through the real binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

struct Pool {
    backends: Vec<Backend>,
    port: u16,
    _rdock: Rdock,
}

/// Three backends `b0`, `b1`, `b2` behind one service with `service_extra` settings.
async fn pool(service_extra: &str) -> Pool {
    let mut backends = Vec::new();
    for i in 0..3 {
        backends.push(Backend::start(&format!("b{i}")).await);
    }
    let list: Vec<String> = backends
        .iter()
        .map(|b| format!("{{ address: \"{}\" }}", b.addr))
        .collect();
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    backends: [{}]
{service_extra}
"#,
        list.join(", ")
    );
    let rdock = Rdock::start(RDOCK, &config);
    Pool {
        backends,
        port,
        _rdock: rdock,
    }
}

fn header_request(name: &str, value: &str) -> http::Request<http_body_util::Full<bytes::Bytes>> {
    let mut req = get("a", "/");
    req.headers_mut().insert(
        http::HeaderName::try_from(name).unwrap(),
        value.parse().unwrap(),
    );
    req
}

#[tokio::test]
async fn header_hash_keeps_a_key_on_one_backend() {
    let pool = pool("    load_balancer: { policy: header_hash, hash_on: x-user }").await;
    let mut seen = BTreeSet::new();
    for user in 0..30 {
        let key = format!("user-{user}");
        let first = client::http1(addr(pool.port), header_request("x-user", &key)).await;
        let backend = first.header("x-backend").unwrap().to_owned();
        for _ in 0..3 {
            let again = client::http1(addr(pool.port), header_request("x-user", &key)).await;
            assert_eq!(again.header("x-backend"), Some(backend.as_str()), "{key}");
        }
        seen.insert(backend);
    }
    assert_eq!(seen.len(), 3, "30 keys spread over all three backends");
}

#[tokio::test]
async fn least_requests_avoids_busy_backends() {
    let pool = pool("    load_balancer: { policy: least_requests }").await;
    let port = pool.port;
    // Two slow requests occupy two backends; every short request meanwhile goes to the third.
    let slow = || tokio::spawn(client::http1(addr(port), get("a", "/slow/1500")));
    // Started a moment apart: two requests picked at the same instant may both see an idle
    // backend before either is counted.
    let a = slow();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let b = slow();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let idle = client::http1(addr(port), get("a", "/")).await;
    let idle = idle.header("x-backend").unwrap().to_owned();
    for _ in 0..5 {
        // rdock stops counting a request after the client has its response, so the next one
        // could still see this backend as busy and tie it with the two slow ones.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let reply = client::http1(addr(port), get("a", "/")).await;
        assert_eq!(reply.header("x-backend"), Some(idle.as_str()));
    }
    let (a, b) = (a.await.unwrap().text(), b.await.unwrap().text());
    assert!(!a.contains(&idle) && !b.contains(&idle), "{a} {b} {idle}");
    assert_ne!(a, b, "the two slow requests used different backends");
}

#[tokio::test]
async fn sticky_cookie_pins_a_client_and_is_signed() {
    let pool =
        pool("    sticky: { cookie: { name: srv, secret: \"0123456789abcdef0123456789abcdef\" } }")
            .await;
    let first = client::http1(addr(pool.port), get("a", "/")).await;
    let cookie = first.header("set-cookie").unwrap().to_owned();
    assert!(cookie.starts_with("srv="), "{cookie}");
    assert!(
        cookie.contains("; Path=/") && cookie.contains("; Secure") && cookie.contains("; HttpOnly"),
        "{cookie}"
    );
    assert!(cookie.contains("; SameSite=Lax"), "{cookie}");
    for b in &pool.backends {
        assert!(
            !cookie.contains(&b.addr.to_string()),
            "the address never leaks"
        );
    }
    let value = cookie.split(';').next().unwrap().to_owned();
    let backend = first.header("x-backend").unwrap().to_owned();
    for _ in 0..6 {
        let reply = client::http1(addr(pool.port), header_request("cookie", &value)).await;
        assert_eq!(reply.header("x-backend"), Some(backend.as_str()));
        assert_eq!(reply.header("set-cookie"), None, "a valid cookie is kept");
    }
    // A forged cookie is ignored and replaced.
    let forged = client::http1(addr(pool.port), header_request("cookie", "srv=00ff")).await;
    assert!(forged.header("set-cookie").unwrap().starts_with("srv="));
}

// ---------------------------------------------------------------------------------------------
// Peak-EWMA, tiers, zones and slow start (H-LB-01…03, H-HA-05, ADR-0031)

/// Backend names of `n` sequential requests, counted.
async fn shares(port: u16, path: &str, n: usize) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for _ in 0..n {
        let reply = client::http1(addr(port), get("a", path)).await;
        assert_eq!(reply.status, 200);
        *counts
            .entry(reply.header("x-backend").unwrap().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

#[tokio::test]
async fn peak_ewma_sheds_a_slow_backend_and_takes_it_back() {
    let pool = pool("    load_balancer: { policy: peak_ewma, decay: 1s }").await;
    pool.backends[0].set_delay(Duration::from_millis(200));
    let slow = shares(pool.port, "/", 90).await;
    let b0 = slow.get("b0").copied().unwrap_or(0);
    assert!(
        b0 <= 6,
        "the slow backend gets a clearly smaller share: {slow:?}"
    );
    assert!(slow.get("b1").copied().unwrap_or(0) > 20 && slow.get("b2").copied().unwrap_or(0) > 20);
    // Without the delay, its estimate decays (200 ms × e^(-t / 1 s) is below the others'
    // after about 6 s) and it competes again.
    pool.backends[0].set_delay(Duration::ZERO);
    tokio::time::sleep(Duration::from_secs(8)).await;
    let recovered = shares(pool.port, "/", 90).await;
    assert!(
        recovered.get("b0").copied().unwrap_or(0) >= 10,
        "it recovered: {recovered:?}"
    );
}

#[tokio::test]
async fn peak_ewma_respects_weights_under_load() {
    let heavy = Backend::start("heavy").await;
    let light = Backend::start("light").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    load_balancer: {{ policy: peak_ewma }}
    backends: [{{ address: "{}", weight: 3 }}, {{ address: "{}" }}]
"#,
        heavy.addr, light.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            tokio::spawn(async move {
                for _ in 0..25 {
                    let reply = client::http1(addr(port), get("a", "/slow/20")).await;
                    assert_eq!(reply.status, 200);
                }
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
    let (h, l) = (heavy.traffic(), light.traffic());
    assert_eq!(h + l, 200);
    assert!(h > l * 3 / 2, "weight 3 against 1: {h} and {l}");
    assert!(l > 0, "the light backend still gets some: {h} and {l}");
}

const PROBES: &str =
    "      active: { path: /healthz, interval: 200ms, timeout: 1s, healthy: 1, unhealthy: 1 }";

/// Waits until `n` requests in a row satisfy `ok`.
async fn until(port: u16, ok: impl Fn(&std::collections::BTreeMap<String, usize>) -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let seen = shares(port, "/", 10).await;
        if ok(&seen) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never settled: {seen:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn tiered(port: u16, backends: &str, service_extra: &str, top: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    backends: [{backends}]
    health:
{PROBES}
{service_extra}
{top}
"#
    )
}

#[tokio::test]
async fn tier_one_takes_over_and_hands_back() {
    let first = Backend::start("first").await;
    let second = Backend::start("second").await;
    let port = free_port();
    let backends = format!(
        "{{ address: \"{}\" }}, {{ address: \"{}\", priority: 1 }}",
        first.addr, second.addr
    );
    let _rdock = Rdock::start(RDOCK, &tiered(port, &backends, "", ""));
    until(port, |s| s.keys().eq(["first"])).await;
    first.set_healthy(false);
    until(port, |s| s.keys().eq(["second"])).await;
    first.set_healthy(true);
    until(port, |s| s.keys().eq(["first"])).await;
}

#[tokio::test]
async fn spill_sends_part_of_the_traffic_to_the_next_tier() {
    let a = Backend::start("a").await;
    let b = Backend::start("b").await;
    let c = Backend::start("c").await;
    let port = free_port();
    let backends = format!(
        "{{ address: \"{}\" }}, {{ address: \"{}\" }}, {{ address: \"{}\", priority: 1 }}",
        a.addr, b.addr, c.addr
    );
    let _rdock = Rdock::start(RDOCK, &tiered(port, &backends, "    failover: spill", ""));
    until(port, |s| !s.contains_key("c")).await;
    // Half of tier 0 down: 50 % × 1.4 = 70 % stays, 30 % goes to tier 1.
    a.set_healthy(false);
    until(port, |s| !s.contains_key("a")).await;
    let seen = shares(port, "/", 300).await;
    let tier1 = seen.get("c").copied().unwrap_or(0);
    assert!(
        (50..=130).contains(&tier1),
        "about 90 of 300 expected: {seen:?}"
    );
}

#[tokio::test]
async fn a_zone_outage_falls_back_to_other_zones() {
    let near = Backend::start("near").await;
    let far = Backend::start("far").await;
    let port = free_port();
    let backends = format!(
        "{{ address: \"{}\", zone: eu-1a }}, {{ address: \"{}\", zone: eu-1b }}",
        near.addr, far.addr
    );
    let _rdock = Rdock::start(
        RDOCK,
        &tiered(
            port,
            &backends,
            "",
            "locality: { zone: eu-1a, mode: prefer }",
        ),
    );
    until(port, |s| s.keys().eq(["near"])).await;
    near.set_healthy(false);
    until(port, |s| s.keys().eq(["far"])).await;
    near.set_healthy(true);
    until(port, |s| s.keys().eq(["near"])).await;
}

#[tokio::test]
async fn a_backend_added_by_a_reload_ramps_up() {
    let a = Backend::start("a").await;
    let b = Backend::start("b").await;
    let c = Backend::start("c").await;
    let port = free_port();
    let slow =
        "    health: { slow_start: { window: 5m, min_weight_percent: 10, on: [recovery, join] } }";
    let config = |list: &[&Backend]| {
        let backends: Vec<String> = list
            .iter()
            .map(|b| format!("{{ address: \"{}\" }}", b.addr))
            .collect();
        format!(
            r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    backends: [{}]
{slow}
"#,
            backends.join(", ")
        )
    };
    let rdock = Rdock::start(RDOCK, &config(&[&a, &b]));
    let start = shares(port, "/", 40).await;
    assert_eq!(start.get("a"), Some(&20), "no ramp at start-up: {start:?}");
    rdock.write_config(&config(&[&a, &b, &c]));
    let (status, body) = rdock.reload();
    assert_eq!(status, 200, "{body}");
    let after = shares(port, "/", 210).await;
    let joined = after.get("c").copied().unwrap_or(0);
    // Weights 1000, 1000 and 100 (10 % of 1000): about 10 of 210.
    assert!((5..=20).contains(&joined), "{after:?}");
}
