//! End-to-end: retries (ADR-0010, ADR-0015, ADR-0022) through the real binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn config(port: u16, backends: &[String], service_extra: &str) -> String {
    let list: Vec<String> = backends
        .iter()
        .map(|a| format!("{{ address: \"{a}\" }}"))
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
{service_extra}
"#,
        list.join(", ")
    )
}

#[tokio::test]
async fn connect_failures_go_to_another_backend_for_any_method() {
    let good = Backend::start("good").await;
    let dead = SocketAddr::from(([127, 0, 0, 1], free_port())).to_string();
    let port = free_port();
    let backends = [dead, good.addr.to_string()];
    let rdock = Rdock::start(
        RDOCK,
        &config(port, &backends, "    retries: { attempts: 1 }"),
    );
    for _ in 0..6 {
        assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
        let order = request("POST", "a", "/", "body");
        assert_eq!(
            client::http1(addr(port), order).await.status,
            200,
            "nothing reached the dead backend"
        );
    }
    // Each retry also advances round-robin, so every request meets the dead backend first.
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        metrics.contains("rdock_retries_total{reason=\"connect\",service=\"app\"} 12"),
        "{metrics}"
    );
}

#[tokio::test]
async fn status_retries_skip_post_and_pass_the_last_answer_through() {
    let sick = Backend::start("sick").await;
    let fine = Backend::start("fine").await;
    sick.set_healthy(false);
    let port = free_port();
    let backends = [sick.addr.to_string(), fine.addr.to_string()];
    let retries = "    retries: { attempts: 1, on: [connect, \"503\"] }";
    let _rdock = Rdock::start(RDOCK, &config(port, &backends, retries));

    // Round-robin sends the first request to `sick`; the 503 is retried on `fine`.
    let reply = client::http1(addr(port), get("a", "/flaky")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("x-backend"), Some("fine"));

    // `sick` asked for 30 s with Retry-After: it gets nothing more for now.
    for _ in 0..4 {
        let reply = client::http1(addr(port), get("a", "/flaky")).await;
        assert_eq!(reply.header("x-backend"), Some("fine"));
    }
    assert_eq!(sick.traffic(), 1);

    // With both answering 503, the client gets the backend's own answer.
    fine.set_healthy(false);
    let reply = client::http1(addr(port), get("a", "/flaky")).await;
    assert_eq!(reply.status, 503);
    assert!(
        reply.text().starts_with("status 503 from"),
        "{}",
        reply.text()
    );
}

#[tokio::test]
async fn non_idempotent_requests_are_not_resent_after_an_answer() {
    let sick = Backend::start("sick").await;
    let fine = Backend::start("fine").await;
    sick.set_healthy(false);
    let port = free_port();
    let backends = [sick.addr.to_string(), fine.addr.to_string()];
    let retries = "    retries: { attempts: 2, on: [\"503\"] }";
    let _rdock = Rdock::start(RDOCK, &config(port, &backends, retries));
    let order = request("POST", "a", "/flaky", "order");
    assert_eq!(
        client::http1(addr(port), order).await.status,
        503,
        "POST reached `sick`"
    );
    assert_eq!(sick.traffic(), 1);
    assert_eq!(fine.traffic(), 0, "and was not sent again");
}
