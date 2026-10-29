//! Chaos suite (H-ENG-02, v0.4 done-when): Toxiproxy injects latency, resets, outages and
//! flapping between rdock and its backends, and the documented behaviour must hold. Needs
//! Docker; runs when `RDOCK_CHAOS_TESTS=1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::Duration;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rdock_testkit::toxiproxy::Toxiproxy;
use serde_json::json;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn enabled() -> bool {
    if std::env::var("RDOCK_CHAOS_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set RDOCK_CHAOS_TESTS=1 (needs Docker)");
    false
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// `n` backends, each behind a Toxiproxy proxy `b<i>`, and rdock in front with `service`.
struct Lab {
    _backends: Vec<Backend>,
    toxiproxy: Toxiproxy,
    port: u16,
    rdock: Rdock,
}

async fn lab(n: usize, service: &str) -> Lab {
    let mut backends = Vec::new();
    for i in 0..n {
        backends.push(Backend::start_public(&format!("b{i}")).await);
    }
    let listen: Vec<u16> = (0..n).map(|_| free_port()).collect();
    let toxiproxy = Toxiproxy::start(&listen);
    for (i, backend) in backends.iter().enumerate() {
        toxiproxy.proxy(&format!("b{i}"), listen[i], backend.addr.port());
    }
    let list: Vec<String> = listen
        .iter()
        .map(|p| format!("{{ address: \"127.0.0.1:{p}\" }}"))
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
{service}
"#,
        list.join(", ")
    );
    let rdock = Rdock::start(RDOCK, &config);
    Lab {
        _backends: backends,
        toxiproxy,
        port,
        rdock,
    }
}

async fn statuses(port: u16, n: usize) -> Vec<u16> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(client::http1(addr(port), get("a", "/")).await.status);
    }
    out
}

#[tokio::test]
async fn a_slow_backend_is_routed_around() {
    if !enabled() {
        return;
    }
    let lab = lab(
        2,
        "    timeouts: { read: 300ms }\n    retries: { attempts: 1, on: [timeout] }\n    health: { passive: { failures: 2, window: 30s, ejection: 30s } }",
    )
    .await;
    lab.toxiproxy.toxic(
        "b0",
        "slow",
        &json!({ "type": "latency", "attributes": { "latency": 2000 } }),
    );
    let results = statuses(lab.port, 20).await;
    assert!(results.iter().all(|s| *s == 200), "{results:?}");
    let (_, metrics) = lab.rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        metrics.contains("rdock_backend_ejections_total"),
        "the slow backend was ejected:\n{metrics}"
    );
    assert!(
        metrics.contains("rdock_retries_total{reason=\"timeout\""),
        "{metrics}"
    );
}

#[tokio::test]
async fn resets_are_retried_only_for_idempotent_requests() {
    if !enabled() {
        return;
    }
    let lab = lab(2, "    retries: { attempts: 1, on: [connect, reset] }").await;
    lab.toxiproxy.toxic(
        "b0",
        "reset",
        &json!({ "type": "reset_peer", "attributes": { "timeout": 0 } }),
    );
    for _ in 0..6 {
        assert_eq!(
            client::http1(addr(lab.port), get("a", "/")).await.status,
            200
        );
    }
    let mut failed_posts = 0;
    for _ in 0..6 {
        let status = client::http1(addr(lab.port), request("POST", "a", "/", "order"))
            .await
            .status;
        if status != 200 {
            failed_posts += 1;
        }
    }
    assert!(
        failed_posts > 0,
        "a POST that reached a resetting backend is not resent"
    );
}

#[tokio::test]
async fn an_outage_and_a_flapping_backend_cost_no_requests() {
    if !enabled() {
        return;
    }
    let lab = lab(
        3,
        "    retries: { attempts: 2, on: [connect, reset] }\n    health:\n      active: { path: /healthz, interval: 200ms, timeout: 1s, healthy: 1, unhealthy: 1 }\n      passive: { failures: 1, window: 10s, ejection: 1s }",
    )
    .await;
    lab.toxiproxy.set_enabled("b1", false);
    let flapping = {
        let toxiproxy = &lab.toxiproxy;
        async move {
            for i in 0..10 {
                toxiproxy.set_enabled("b2", i % 2 == 1);
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    };
    let load = async {
        let mut results = Vec::new();
        for _ in 0..60 {
            results.push(client::http1(addr(lab.port), get("a", "/")).await.status);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        results
    };
    let ((), results) = tokio::join!(flapping, load);
    let failures = results.iter().filter(|s| **s != 200).count();
    assert_eq!(failures, 0, "{results:?}\n{}", lab.rdock.log());
}
