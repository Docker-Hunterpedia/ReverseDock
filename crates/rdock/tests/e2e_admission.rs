//! End-to-end: an `admission` middleware in front of a backend with a fixed throughput sheds
//! sheddable requests under overload while critical ones keep succeeding, and its limit grows
//! back once the backend is fast again (H-LB-04, ADR-0031).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

/// A backend that serves `SLOTS` requests at a time, each taking the current service time:
/// more requests queue, so the latency grows with the requests in flight.
struct Slow {
    addr: SocketAddr,
    service_ms: Arc<AtomicU64>,
}

const SLOTS: usize = 4;

async fn slow_backend(service_ms: u64) -> Slow {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = Arc::new(AtomicU64::new(service_ms));
    let slots = Arc::new(tokio::sync::Semaphore::new(SLOTS));
    let time = service.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (slots, time) = (slots.clone(), time.clone());
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    // One request at a time on this connection, kept alive.
                    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let end = buffer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    buffer.drain(..end);
                    {
                        let _slot = slots.acquire().await.unwrap();
                        tokio::time::sleep(Duration::from_millis(time.load(Ordering::Relaxed)))
                            .await;
                    }
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Slow {
        addr,
        service_ms: service,
    }
}

fn metric(text: &str, name: &str, labels: &str) -> f64 {
    text.lines()
        .find(|l| l.starts_with(name) && l.contains(labels))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0)
}

/// Counts of answers per status while `clients` loop on `host` until `stop`.
fn flood(
    proxy: SocketAddr,
    host: &'static str,
    clients: usize,
    stop: &Arc<AtomicBool>,
) -> Vec<tokio::task::JoinHandle<(u64, u64, u64)>> {
    (0..clients)
        .map(|_| {
            let stop = stop.clone();
            tokio::spawn(async move {
                let (mut ok, mut shed, mut other) = (0, 0, 0);
                while !stop.load(Ordering::Relaxed) {
                    let reply = client::http1(proxy, get(host, "/")).await;
                    match reply.status {
                        200 => ok += 1,
                        503 => {
                            assert_eq!(reply.header("retry-after"), Some("1"));
                            shed += 1;
                            // A client that honours nothing still should not spin.
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        _ => other += 1,
                    }
                }
                (ok, shed, other)
            })
        })
        .collect()
}

async fn totals(tasks: Vec<tokio::task::JoinHandle<(u64, u64, u64)>>) -> (u64, u64, u64) {
    let mut sum = (0, 0, 0);
    for task in tasks {
        let (a, b, c) = task.await.unwrap();
        sum = (sum.0 + a, sum.1 + b, sum.2 + c);
    }
    sum
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overload_sheds_sheddable_requests_first_and_the_limit_recovers() {
    let backend = slow_backend(50).await;
    let port = free_port();
    // 4 slots × 50 ms: latency passes 200 ms above 16 requests in flight.
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\n\
         defaults: {{ listeners: [web], tls: off, errors: {{ format: problem }} }}\n\
         middlewares:\n  adm: {{ type: admission, mode: aimd, min: 4, max: 64, initial: 8, latency: 200ms }}\n\
         routes:\n\
         \x20 checkout: {{ match: \"Host(`critical.test`)\", service: slow, middlewares: [adm], priority_class: critical }}\n\
         \x20 reports: {{ match: \"Host(`bulk.test`)\", service: slow, middlewares: [adm], priority_class: sheddable }}\n\
         services:\n  slow:\n    backends: [{{ address: \"{}\" }}]\n    timeouts: {{ read: 30s }}\n",
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));
    assert_eq!(
        client::http1(proxy, get("bulk.test", "/")).await.status,
        200
    );

    // Overload: 48 clients on the sheddable route, one on the critical route.
    let stop = Arc::new(AtomicBool::new(false));
    let bulk = flood(proxy, "bulk.test", 48, &stop);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (mut critical_ok, mut critical_failed) = (0_u32, Vec::new());
    let mut limits = Vec::new();
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        let reply = client::http1(proxy, get("critical.test", "/")).await;
        if reply.status == 200 {
            critical_ok += 1;
        } else {
            critical_failed.push(reply.status);
        }
        if critical_ok % 10 == 0 {
            let text = rdock.get_admin("/metrics").unwrap().1;
            limits.push(metric(&text, "rdock_admission_limit", "middleware=\"adm\""));
        }
    }
    stop.store(true, Ordering::Relaxed);
    let (bulk_ok, bulk_shed, bulk_other) = totals(bulk).await;
    let text = rdock.get_admin("/metrics").unwrap().1;
    let shed = |class: &str| {
        metric(
            &text,
            "rdock_admission_shed_total",
            &format!("class=\"{class}\""),
        )
    };
    let report = format!(
        "critical ok {critical_ok}, failed {critical_failed:?}; bulk ok {bulk_ok}, shed {bulk_shed}, other {bulk_other}; limits {limits:?}\n{}",
        rdock.log()
    );
    assert!(critical_ok >= 10, "{report}");
    assert!(
        critical_failed.is_empty(),
        "critical requests keep succeeding: {report}"
    );
    assert!(bulk_shed > 0 && bulk_ok > 0, "{report}");
    assert_eq!(bulk_other, 0, "{report}");
    assert!(
        shed("sheddable") >= 1.0 && shed("critical") == 0.0,
        "{report}"
    );
    assert!(
        limits.iter().all(|l| (4.0..=64.0).contains(l)),
        "the limit stays within min and max: {report}"
    );
    let overloaded = metric(&text, "rdock_admission_limit", "middleware=\"adm\"");
    assert!(overloaded <= 32.0, "the limit came down near 16: {report}");
    // The shed answers are problem details and named in the access log.
    let reply = {
        let stop = Arc::new(AtomicBool::new(false));
        let hold = flood(proxy, "bulk.test", 48, &stop);
        let deadline = Instant::now() + Duration::from_secs(30);
        let found = loop {
            let mut req = get("bulk.test", "/");
            req.headers_mut()
                .insert("accept", "application/problem+json".parse().unwrap());
            let reply = client::http1(proxy, req).await;
            if reply.status == 503 || Instant::now() > deadline {
                break reply;
            }
        };
        stop.store(true, Ordering::Relaxed);
        totals(hold).await;
        found
    };
    assert_eq!(reply.status, 503, "{}", rdock.log());
    assert!(
        reply.json()["type"]
            .as_str()
            .is_some_and(|t| t.ends_with("#overloaded")),
        "{}",
        reply.text()
    );
    let logged = rdock
        .access_log()
        .iter()
        .any(|r| r["admission"] == "shed:sheddable" && r["status"] == 503);
    assert!(logged, "{}", rdock.log());

    // Recovery: a fast backend lets the limit grow past its overloaded value.
    backend.service_ms.store(2, Ordering::Relaxed);
    let stop = Arc::new(AtomicBool::new(false));
    let bulk = flood(proxy, "bulk.test", 24, &stop);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut recovered = 0.0;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let text = rdock.get_admin("/metrics").unwrap().1;
        recovered = metric(&text, "rdock_admission_limit", "middleware=\"adm\"");
        if recovered >= overloaded + 8.0 {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let (ok, _, other) = totals(bulk).await;
    assert!(
        recovered >= overloaded + 8.0,
        "limit {overloaded} → {recovered}\n{}",
        rdock.log()
    );
    assert!(ok > 0 && other == 0);
    assert_eq!(
        client::http1(proxy, get("bulk.test", "/")).await.status,
        200
    );
}
