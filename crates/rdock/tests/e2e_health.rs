//! End-to-end: active and passive health, fail-open, backups and limits (ADR-0022).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn config(port: u16, scheme: &str, backends: &str, service_extra: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    scheme: {scheme}
    backends: [{backends}]
{service_extra}
"#
    )
}

fn list(backends: &[&Backend]) -> String {
    backends
        .iter()
        .map(|b| format!("{{ address: \"{}\" }}", b.addr))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Sends `n` requests and returns the backend names that answered.
async fn backends_hit(port: u16, n: usize) -> Vec<String> {
    let mut seen = Vec::new();
    for _ in 0..n {
        let reply = client::http1(addr(port), get("a", "/")).await;
        seen.push(reply.header("x-backend").unwrap_or("-").to_owned());
    }
    seen
}

/// Waits until every one of `n` requests goes to `only`.
async fn until_only(port: u16, only: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if backends_hit(port, 6).await.iter().all(|b| b == only) {
            return;
        }
        assert!(Instant::now() < deadline, "traffic never settled on {only}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

const ACTIVE: &str = "    health:\n      active: { path: /healthz, interval: 200ms, timeout: 1s, healthy: 1, unhealthy: 2 }";

#[tokio::test]
async fn active_http_checks_take_a_sick_backend_out_and_back() {
    let a = Backend::start("a").await;
    let b = Backend::start("b").await;
    let port = free_port();
    let _rdock = Rdock::start(RDOCK, &config(port, "http", &list(&[&a, &b]), ACTIVE));
    assert!(backends_hit(port, 4).await.contains(&"b".to_owned()));
    b.set_healthy(false);
    until_only(port, "a").await;
    b.set_healthy(true);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !backends_hit(port, 4).await.contains(&"b".to_owned()) {
        assert!(Instant::now() < deadline, "b never came back");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn grpc_and_tcp_checks() {
    let a = Backend::start("a").await;
    let b = Backend::start("b").await;
    let port = free_port();
    let grpc = "    health:\n      active: { mode: grpc, interval: 200ms, timeout: 1s, healthy: 1, unhealthy: 2 }";
    let _rdock = Rdock::start(RDOCK, &config(port, "h2c", &list(&[&a, &b]), grpc));
    b.set_healthy(false);
    until_only(port, "a").await;

    // TCP checks: a backend whose port is closed is taken out.
    let c = Backend::start("c").await;
    let closed = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let port = free_port();
    let tcp = "    health:\n      active: { mode: tcp, interval: 200ms, timeout: 1s, healthy: 1, unhealthy: 2 }";
    let backends = format!("{}, {{ address: \"{closed}\" }}", list(&[&c]));
    let _tcp = Rdock::start(RDOCK, &config(port, "http", &backends, tcp));
    until_only(port, "c").await;
}

#[tokio::test]
async fn every_backend_down_fails_open_unless_told_otherwise() {
    let a = Backend::start("a").await;
    a.set_healthy(false);
    let port = free_port();
    let _open = Rdock::start(RDOCK, &config(port, "http", &list(&[&a]), ACTIVE));
    tokio::time::sleep(Duration::from_millis(800)).await;
    let reply = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(
        reply.status, 200,
        "a broken health check must not cause an outage"
    );

    let port = free_port();
    let closed = "    health:\n      when_all_down: fail_closed\n      active: { path: /healthz, interval: 200ms, timeout: 1s, healthy: 1, unhealthy: 2 }";
    let _closed = Rdock::start(RDOCK, &config(port, "http", &list(&[&a]), closed));
    tokio::time::sleep(Duration::from_millis(800)).await;
    let reply = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(reply.status, 503);
    assert!(reply.header("retry-after").is_some());
}

#[tokio::test]
async fn passive_health_ejects_a_failing_backend_and_retries_it_later() {
    let good = Backend::start("good").await;
    // Nothing listens here: every request to it fails to connect.
    let dead = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let port = free_port();
    // Retries off, so the client sees each failure that counts towards the ejection (the
    // default retry would hide them, ADR-0028).
    let passive = "    health:\n      passive: { failures: 2, window: 10s, ejection: 1s }\n    retries: { attempts: 0 }";
    let backends = format!("{}, {{ address: \"{dead}\" }}", list(&[&good]));
    let rdock = Rdock::start(RDOCK, &config(port, "http", &backends, passive));
    let mut failures = 0;
    for _ in 0..10 {
        if client::http1(addr(port), get("a", "/")).await.status == 502 {
            failures += 1;
        }
    }
    assert_eq!(
        failures, 2,
        "two failures eject the dead backend; then only `good` answers"
    );
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        metrics.contains(&format!(
            "rdock_backend_ejections_total{{backend=\"{dead}\",service=\"app\"}} 1"
        )),
        "{metrics}"
    );
    // After the ejection time one request tries it again (and fails, ejecting it for 2 s).
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let statuses: Vec<u16> = {
        let mut out = Vec::new();
        for _ in 0..6 {
            out.push(client::http1(addr(port), get("a", "/")).await.status);
        }
        out
    };
    assert_eq!(
        statuses.iter().filter(|s| **s == 502).count(),
        1,
        "{statuses:?}"
    );
}

#[tokio::test]
async fn backups_take_over_only_when_primaries_are_down() {
    let primary = Backend::start("primary").await;
    let backup = Backend::start("backup").await;
    let port = free_port();
    let backends = format!(
        "{{ address: \"{}\" }}, {{ address: \"{}\", backup: true }}",
        primary.addr, backup.addr
    );
    let _rdock = Rdock::start(RDOCK, &config(port, "http", &backends, ACTIVE));
    assert!(backends_hit(port, 6).await.iter().all(|b| b == "primary"));
    primary.set_healthy(false);
    until_only(port, "backup").await;
    let before = primary.traffic();
    assert!(backends_hit(port, 6).await.iter().all(|b| b == "backup"));
    assert_eq!(primary.traffic(), before, "a down primary gets nothing");
}

#[tokio::test]
async fn max_requests_answers_503_when_the_pool_is_full() {
    let a = Backend::start("a").await;
    let port = free_port();
    let _rdock = Rdock::start(
        RDOCK,
        &config(port, "http", &list(&[&a]), "    max_requests: 1"),
    );
    let slow = tokio::spawn(client::http1(addr(port), get("a", "/slow/800")));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reply = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(reply.status, 503);
    assert_eq!(slow.await.unwrap().status, 200);
    assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
}

#[tokio::test]
async fn the_ping_path_answers_for_any_host_before_routing() {
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}", ping: /rdock/ping }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "Host(`app.test`)", service: app }}
services:
  app: {{ backends: [{{ address: "127.0.0.1:1" }}] }}
"#
    );
    let _rdock = Rdock::start(RDOCK, &config);
    for host in ["app.test", "anything.example", "203.0.113.9"] {
        let reply = client::http1(addr(port), get(host, "/rdock/ping")).await;
        assert_eq!(reply.status, 200, "{host}");
        assert_eq!(reply.text(), "OK\n");
        assert_eq!(reply.header("cache-control"), Some("no-store"));
    }
    let routed = client::http1(addr(port), get("app.test", "/other")).await;
    assert_eq!(routed.status, 502, "other paths are routed as usual");
}

// ---------------------------------------------------------------------------------------------
// Outlier detection (H-LB-02, ADR-0031)

/// `n` backends, the last failing 40 % of its requests, behind the success-rate detector.
/// Returns the backends, the proxy and its port after about 2.5 s of traffic.
async fn outlier_pool(n: usize) -> (Vec<Backend>, Rdock, u16) {
    let mut backends = Vec::new();
    for i in 0..n {
        backends.push(Backend::start(&format!("b{i}")).await);
    }
    backends[n - 1].fail_pattern(2, 5);
    let port = free_port();
    // The windowed failure ejection is set out of reach, so only the detector ejects.
    let health = "    health:\n      passive:\n        failures: 100000\n        outlier:\n          interval: 1s\n          success_rate: { enabled: true, request_volume: 20, minimum_hosts: 5 }\n    retries: { attempts: 0 }";
    let refs: Vec<&Backend> = backends.iter().collect();
    let rdock = Rdock::start(RDOCK, &config(port, "http", &list(&refs), health));
    let deadline = Instant::now() + Duration::from_millis(2_500);
    while Instant::now() < deadline {
        client::http1(addr(port), get("a", "/")).await;
    }
    (backends, rdock, port)
}

#[tokio::test]
async fn the_success_rate_detector_ejects_a_backend_failing_40_percent() {
    let (backends, rdock, port) = outlier_pool(5).await;
    let failing = &backends[4];
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        metrics.contains(&format!(
            "rdock_backend_outlier_ejections_total{{backend=\"{}\",detector=\"success_rate\",service=\"app\"}} 1",
            failing.addr
        )),
        "{metrics}"
    );
    let before = failing.traffic();
    let seen = backends_hit(port, 20).await;
    assert!(!seen.contains(&"b4".to_owned()), "{seen:?}");
    assert_eq!(failing.traffic(), before, "an ejected backend gets nothing");
}

#[tokio::test]
async fn a_pool_of_four_is_not_evaluated() {
    let (backends, rdock, port) = outlier_pool(4).await;
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        !metrics.contains("rdock_backend_outlier_ejections_total{"),
        "{metrics}"
    );
    let before = backends[3].traffic();
    backends_hit(port, 20).await;
    assert!(backends[3].traffic() > before, "still in the pool");
}
