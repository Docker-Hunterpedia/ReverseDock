//! End-to-end: retries (ADR-0010, ADR-0015, ADR-0022) through the real binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

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
async fn a_backend_that_never_answers_costs_the_attempt_budget_not_the_connect_timeout() {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): never routed, so a connect gets no answer,
    // like a stopped container whose address no longer answers ARP (ADR-0026).
    let good = Backend::start("good").await;
    let port = free_port();
    let backends = ["192.0.2.1:9".to_owned(), good.addr.to_string()];
    let _rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            &backends,
            "    retries: { attempts: 1 }\n    timeouts: { connect: 5s, connect_attempt: 500ms }",
        ),
    );
    for _ in 0..4 {
        let started = Instant::now();
        assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "took {:?}: the dead backend should cost connect_attempt, not connect",
            started.elapsed()
        );
    }
}

#[tokio::test]
async fn a_service_without_retries_still_moves_a_failed_connect_to_another_backend() {
    // ADR-0028: no `retries` means the `retries: {}` defaults, which retry connect failures.
    let good = Backend::start("good").await;
    let dead = SocketAddr::from(([127, 0, 0, 1], free_port())).to_string();
    let port = free_port();
    let _rdock = Rdock::start(RDOCK, &config(port, &[dead, good.addr.to_string()], ""));
    for _ in 0..6 {
        assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
        let order = request("POST", "a", "/", "body");
        assert_eq!(client::http1(addr(port), order).await.status, 200);
    }
}

#[tokio::test]
async fn attempts_zero_turns_the_default_retries_off() {
    let good = Backend::start("good").await;
    let dead = SocketAddr::from(([127, 0, 0, 1], free_port())).to_string();
    let port = free_port();
    let _rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            &[dead, good.addr.to_string()],
            "    retries: { attempts: 0 }",
        ),
    );
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(client::http1(addr(port), get("a", "/")).await.status);
    }
    assert!(
        statuses.contains(&502),
        "round-robin meets the dead backend: {statuses:?}"
    );
}

#[tokio::test]
async fn a_timed_out_connect_is_not_repeated_on_the_same_backend() {
    // The only backend never answers (TEST-NET-1): one connect timeout, not three.
    let port = free_port();
    let _rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            &["192.0.2.1:9".to_owned()],
            "    timeouts: { connect: 1s }",
        ),
    );
    let started = Instant::now();
    let status = client::http1(addr(port), get("a", "/")).await.status;
    assert_eq!(status, 504);
    assert!(
        started.elapsed() < Duration::from_millis(1900),
        "took {:?}: the timed-out connect was repeated",
        started.elapsed()
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

/// Sends `clients × per_client` requests to a pool where every backend answers 503 and returns
/// how many requests the backends received in total.
async fn outage(budget_percent: u32) -> (usize, usize) {
    let a = Backend::start("a").await;
    let b = Backend::start("b").await;
    let port = free_port();
    let backends = [a.addr.to_string(), b.addr.to_string()];
    let retries =
        format!("    retries: {{ attempts: 5, on: [\"503\"], budget_percent: {budget_percent} }}");
    let _rdock = Rdock::start(RDOCK, &config(port, &backends, &retries));
    let (clients, per_client) = (40, 10);
    let mut tasks = Vec::new();
    for _ in 0..clients {
        tasks.push(tokio::spawn(async move {
            for _ in 0..per_client {
                let reply = client::http1(addr(port), get("a", "/status/503")).await;
                assert_eq!(reply.status, 503);
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    (clients * per_client, a.requests() + b.requests())
}

#[tokio::test]
async fn the_retry_budget_prevents_amplification_in_an_outage() {
    let (sent, with_budget) = outage(20).await;
    let (_, without_budget) = outage(100).await;
    eprintln!(
        "outage: {sent} requests; backends got {with_budget} with a 20 % budget, {without_budget} without"
    );
    // Without a budget nearly every request is tried 6 times; with 20 % only a few retry.
    assert!(
        without_budget > 4 * sent,
        "control: {without_budget} backend requests for {sent}"
    );
    assert!(
        2 * with_budget < 5 * sent,
        "budget: {with_budget} backend requests for {sent}"
    );
}

// ---------------------------------------------------------------------------------------------
// Per-try timeout (H-LB-03, ADR-0031)

const PER_TRY: &str = "    retries: { attempts: 1, on: [connect, timeout], per_try_timeout: 300ms }\n    timeouts: { read: 3s }";

#[tokio::test]
async fn a_stalled_attempt_is_answered_by_another_backend_within_the_per_try_timeout() {
    let stalled = Backend::start("stalled").await;
    let good = Backend::start("good").await;
    stalled.set_delay(Duration::from_secs(10));
    let port = free_port();
    let backends = [stalled.addr.to_string(), good.addr.to_string()];
    let rdock = Rdock::start(RDOCK, &config(port, &backends, PER_TRY));
    for _ in 0..4 {
        let started = Instant::now();
        let reply = client::http1(addr(port), get("a", "/")).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("x-backend"), Some("good"));
        assert!(
            started.elapsed() < Duration::from_millis(1_500),
            "took {:?}: the stalled attempt should end after 300 ms, not timeouts.read",
            started.elapsed()
        );
    }
    assert!(
        stalled.traffic() >= 1,
        "round-robin met the stalled backend"
    );
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        metrics.contains("rdock_retries_total{reason=\"timeout\",service=\"app\"}"),
        "{metrics}"
    );
}

#[tokio::test]
async fn a_stalled_post_is_not_retried_and_waits_the_read_timeout() {
    let stalled = Backend::start("stalled").await;
    let good = Backend::start("good").await;
    stalled.set_delay(Duration::from_secs(10));
    let port = free_port();
    let backends = [stalled.addr.to_string(), good.addr.to_string()];
    let extra = "    retries: { attempts: 1, on: [connect, timeout], per_try_timeout: 300ms }\n    timeouts: { read: 1s }";
    let _rdock = Rdock::start(RDOCK, &config(port, &backends, extra));
    let mut statuses = Vec::new();
    for _ in 0..2 {
        let started = Instant::now();
        let reply = client::http1(addr(port), request("POST", "a", "/", "order")).await;
        if reply.status == 504 {
            assert!(
                started.elapsed() >= Duration::from_millis(900),
                "a POST is not bounded by per_try_timeout: {:?}",
                started.elapsed()
            );
        }
        statuses.push(reply.status);
    }
    assert_eq!(
        statuses.iter().filter(|s| **s == 504).count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(stalled.traffic(), 1);
    assert_eq!(good.traffic(), 1, "the stalled POST was not sent again");
}

#[tokio::test]
async fn an_exhausted_retry_budget_answers_504() {
    let stalled = Backend::start("stalled").await;
    let good = Backend::start("good").await;
    stalled.set_delay(Duration::from_secs(10));
    // Retries hold their permit while the retried attempt runs.
    good.set_delay(Duration::from_millis(200));
    let port = free_port();
    let backends = [stalled.addr.to_string(), good.addr.to_string()];
    let extra = "    retries: { attempts: 1, on: [timeout], per_try_timeout: 300ms, budget_percent: 0 }\n    timeouts: { read: 3s }";
    let _rdock = Rdock::start(RDOCK, &config(port, &backends, extra));
    let tasks: Vec<_> = (0..10)
        .map(|_| tokio::spawn(client::http1(addr(port), get("a", "/"))))
        .collect();
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.unwrap().status);
    }
    let timeouts = statuses.iter().filter(|s| **s == 504).count();
    let ok = statuses.iter().filter(|s| **s == 200).count();
    // About five requests meet the stalled backend at once; three retries are always allowed
    // (MIN_RETRIES), the rest answer 504 at the per-try timeout.
    assert!(timeouts >= 1, "{statuses:?}");
    assert!(ok >= 7, "{statuses:?}");
    assert_eq!(ok + timeouts, 10, "{statuses:?}");
}

/// A backend whose first connection answers one request with keep-alive, then resets when the
/// next request arrives on it (a pooled connection the backend dropped); every other
/// connection answers normally. Returns its address and how many requests got an answer.
async fn resetting_backend() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn head(stream: &mut tokio::net::TcpStream, buf: &mut Vec<u8>) -> Option<usize> {
        loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Some(end + 4);
            }
            let mut chunk = [0_u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answered = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = answered.clone();
    tokio::spawn(async move {
        let mut index = 0_usize;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let first = index == 0;
            index += 1;
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut served = 0_usize;
                while let Some(end) = head(&mut stream, &mut buf).await {
                    if first && served == 1 {
                        // The second request on the first connection: reset it.
                        let _ = stream.set_zero_linger();
                        return;
                    }
                    let text = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let length: usize = text
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < end + length {
                        let mut chunk = [0_u8; 4096];
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    buf.drain(..end + length);
                    served += 1;
                    counter.fetch_add(1, Ordering::SeqCst);
                    let reply =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nok{served:02}");
                    if stream.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, answered)
}

/// ci-1: a request that fails on a reused pooled connection before any answer is sent once
/// more on another connection when it is idempotent, even with retries off. Which error the
/// reset surfaces as (a read error while waiting for the answer, or `EPIPE` while writing the
/// body, as in the CI failure) depends on timing; this test usually sees the first, so the
/// decision for write errors is pinned by the unit test
/// `connection_failures_of_pooled_connections_are_recognised` in `rdock-proxy`.
#[tokio::test]
async fn an_idempotent_request_on_a_dropped_pooled_connection_gets_another_connection() {
    let (backend, answered) = resetting_backend().await;
    let port = free_port();
    let _rdock = Rdock::start(
        RDOCK,
        &config(port, &[backend.to_string()], "    retries: { attempts: 0 }"),
    );
    // The first request leaves its upstream connection in rdock's pool.
    assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
    assert_eq!(answered.load(std::sync::atomic::Ordering::SeqCst), 1);
    // The PUT is given the pooled connection, which the backend resets.
    let body = "x".repeat(1024);
    let put = client::http1(addr(port), request("PUT", "a", "/config/x", body)).await;
    assert_eq!(put.status, 200, "{}", put.text());
    assert_eq!(answered.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// Review 10, M1: the attempt after a failed pooled connection replays the body into fresh
/// counts, so a body over half of `max_body` is not counted twice and refused with 413.
#[tokio::test]
async fn a_replayed_body_on_another_connection_is_counted_once() {
    let (backend, answered) = resetting_backend().await;
    let port = free_port();
    let _rdock = Rdock::start(
        RDOCK,
        &format!(
            r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app, max_body: 60KiB }}
services:
  app:
    backends: [{{ address: "{backend}" }}]
    retries: {{ attempts: 0 }}
"#
        ),
    );
    assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
    // 40 KiB: over half of the limit, inside Pingora's 64 KiB replay buffer.
    let body = "x".repeat(40 * 1024);
    let put = client::http1(addr(port), request("PUT", "a", "/config/x", body)).await;
    assert_eq!(put.status, 200, "{}", put.text());
    assert_eq!(answered.load(std::sync::atomic::Ordering::SeqCst), 2);
}
