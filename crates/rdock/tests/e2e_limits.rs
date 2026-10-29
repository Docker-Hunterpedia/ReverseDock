//! End-to-end: concurrency, load shedding, bandwidth, body limits and compression (ADR-0022).

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

fn config(port: u16, backend: SocketAddr, route_extra: &str, top: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
{top}
routes:
  app:
    match: "PathPrefix(`/`)"
    service: app
{route_extra}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#
    )
}

#[tokio::test]
async fn in_flight_queues_then_refuses() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let top = "middlewares:\n  one: { type: in_flight, amount: 1, queue: 1, queue_timeout: 2s }";
    let _rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, "    middlewares: [one]", top),
    );
    let slow = || tokio::spawn(client::http1(addr(port), get("a", "/slow/600")));
    let first = slow();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let queued = slow();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let refused = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(
        refused.status, 429,
        "one running, one queued: the third is refused"
    );
    assert!(refused.header("retry-after").is_some());
    assert_eq!(first.await.unwrap().status, 200);
    assert_eq!(
        queued.await.unwrap().status,
        200,
        "the queued request ran after the first"
    );
}

#[tokio::test]
async fn max_in_flight_sheds_load() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let top = "security:\n  limits: { max_in_flight: 1 }";
    let _rdock = Rdock::start(RDOCK, &config(port, backend.addr, "", top));
    let slow = tokio::spawn(client::http1(addr(port), get("a", "/slow/600")));
    tokio::time::sleep(Duration::from_millis(150)).await;
    let shed = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(shed.status, 503);
    assert!(shed.header("retry-after").is_some());
    assert_eq!(slow.await.unwrap().status, 200);
    assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
}

#[tokio::test]
async fn bandwidth_slows_responses_to_the_rate() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let top = "middlewares:\n  slow: { type: bandwidth, rate: 20KiB }";
    let _rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, "    middlewares: [slow]", top),
    );
    let started = Instant::now();
    let reply = client::http1(addr(port), get("a", "/bytes/61440")).await;
    assert_eq!(reply.body.len(), 61_440);
    // 20 KiB free as the burst, then 40 KiB at 20 KiB/s: about two seconds.
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(1_500), "{took:?}");
    assert!(took < Duration::from_secs(6), "{took:?}");
}

#[tokio::test]
async fn a_route_can_allow_larger_bodies_than_the_default() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let top = "security:\n  limits: { max_body_bytes: 1KiB }";
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
{top}
routes:
  small: {{ match: "PathPrefix(`/`)", service: app }}
  upload: {{ match: "PathPrefix(`/upload`)", service: app, max_body: 64KiB }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let body = "x".repeat(10 * 1024);
    let small = client::http1(addr(port), request("POST", "a", "/", body.clone())).await;
    assert_eq!(small.status, 413);
    let upload = client::http1(addr(port), request("POST", "a", "/upload", body)).await;
    assert_eq!(upload.status, 200);
}

#[tokio::test]
async fn compression_negotiates_zstd_brotli_and_gzip() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let top = "middlewares:\n  zip: { type: compress }";
    let _rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, "    middlewares: [zip]", top),
    );
    for (accept, expected) in [
        ("gzip, deflate, br, zstd", "zstd"),
        ("gzip, br", "br"),
        ("gzip", "gzip"),
        ("br;q=0.5, gzip;q=0.9", "gzip"),
    ] {
        let mut req = get("a", "/bytes/4096");
        req.headers_mut()
            .insert("accept-encoding", accept.parse().unwrap());
        let reply = client::http1(addr(port), req).await;
        assert_eq!(reply.header("content-encoding"), Some(expected), "{accept}");
        let plain = match expected {
            "zstd" => zstd::stream::decode_all(&reply.body[..]).unwrap(),
            "br" => {
                let mut out = Vec::new();
                std::io::Read::read_to_end(
                    &mut brotli::Decompressor::new(&reply.body[..], 4096),
                    &mut out,
                )
                .unwrap();
                out
            }
            _ => {
                let mut out = Vec::new();
                std::io::Read::read_to_end(
                    &mut flate2::read::GzDecoder::new(&reply.body[..]),
                    &mut out,
                )
                .unwrap();
                out
            }
        };
        assert_eq!(plain, vec![b'a'; 4096], "{accept}");
    }
}

#[tokio::test]
async fn rate_limits_can_count_by_cookie() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let top = "middlewares:\n  per-session: { type: rate_limit, key: \"cookie:sid\", average: 1, period: 1m }";
    let _rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, "    middlewares: [per-session]", top),
    );
    let with = |sid: &str| {
        let mut req = get("a", "/");
        req.headers_mut()
            .insert("cookie", format!("sid={sid}").parse().unwrap());
        client::http1(addr(port), req)
    };
    assert_eq!(with("one").await.status, 200);
    assert_eq!(with("one").await.status, 429);
    assert_eq!(
        with("two").await.status,
        200,
        "another session has its own bucket"
    );
}
