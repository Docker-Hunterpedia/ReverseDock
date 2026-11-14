//! Chaos suite, scenario 1 "control plane down" (ADR-0033, vision §7), part (b): the
//! in-process admin and control side made unusable while the data plane keeps serving
//! (ADR-0009, ADR-0012: the data plane never depends on the admin API at request time).
//!
//! Part (a), the cluster control plane killed and restarted under three data planes, is
//! `e2e_cluster::three_data_planes_survive_a_control_plane_outage` and is not repeated here.
//!
//! The admin side is attacked from outside, with a normal build: hundreds of connections that
//! send half a request and stall, a flood of the most expensive read calls, configuration writes
//! back to back (each compiles a whole configuration), and the admin Unix socket file removed.
//! A panicking or aborted admin runtime needs the `fault-injection` build and stays in the lab
//! (`benchmarks/isolation/`). Pass: zero failed proxied requests, the slowest under 2 s (a debug build on a loaded runner), and the
//! admin API answering again within 10 s of the attack's end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod chaos_common;

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chaos_common::*;
use rdock_testkit::backend::Backend;
use rdock_testkit::free_port;
use rdock_testkit::load::{Load, Target};
use rdock_testkit::rdock::Rdock;
use serde_json::json;

/// Stalled connections held open against the admin listener.
const STALLED: usize = 300;

fn admin_ready(rdock: &Rdock) -> bool {
    let Ok(mut stream) = std::net::TcpStream::connect(rdock.admin) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer.starts_with("HTTP/1.1 200")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unusable_admin_side_costs_no_requests() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes:\n  app: {{ match: \"Host(`app.test`)\", service: app }}\nservices:\n  app: {{ backends: [{{ address: \"{}\" }}] }}\n",
        backend.addr
    );
    let rdock = Arc::new(Rdock::start(RDOCK, &config));
    let load = Load::start(vec![Target::http(addr(port), "app.test", "/")], 100);
    load.wait_for_ok(100, Duration::from_secs(30)).await;

    // Half requests that never finish.
    let mut stalled = Vec::new();
    for _ in 0..STALLED {
        if let Ok(mut stream) = std::net::TcpStream::connect(rdock.admin) {
            let _ = stream.write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nX-Slow: ");
            stalled.push(stream);
        }
    }
    // A flood of expensive reads and back-to-back writes over the socket.
    let stop = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for worker in 0..4 {
        let (rdock, stop, calls) = (rdock.clone(), stop.clone(), calls.clone());
        workers.push(std::thread::spawn(move || {
            let paths = ["/metrics", "/api/v1/status", "/api/v1/config/history", "/api/v1/config"];
            let mut n = 0usize;
            while !stop.load(Ordering::Relaxed) {
                if worker == 0 {
                    let document = json!({
                        "routes": { format!("r{n}"): { "match": format!("Host(`r{n}.test`)"), "service": "s" } },
                        "services": { "s": { "backends": [{ "address": "127.0.0.1:9" }] } }
                    });
                    // Attack traffic: a call that fails under the flood is fine.
                    if let Some((_, head, _)) = rdock.admin_send("GET", "/api/v1/config/api", &[], "")
                        && let Some(tag) = head.lines().find_map(|l| {
                            l.to_ascii_lowercase()
                                .starts_with("etag:")
                                .then(|| l[5..].trim().to_owned())
                        })
                    {
                        let _ = rdock.admin_send(
                            "PUT",
                            "/api/v1/config/api",
                            &[("Content-Type", "application/json"), ("If-Match", &tag)],
                            &document.to_string(),
                        );
                    }
                } else {
                    let _ = rdock.get_admin(paths[n % paths.len()]);
                }
                calls.fetch_add(1, Ordering::Relaxed);
                n += 1;
            }
        }));
    }
    load.wait_for_ok(500, Duration::from_secs(60)).await;
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        worker.join().unwrap();
    }
    // The CLI's socket goes away; the TCP listener and the stalls stay.
    let socket = rdock.data_dir().join("admin.sock");
    std::fs::remove_file(&socket).unwrap();
    load.wait_for_ok(200, Duration::from_secs(60)).await;
    eprintln!(
        "{} admin calls and {} stalled connections during the attack",
        calls.load(Ordering::Relaxed),
        stalled.len()
    );
    drop(stalled);
    let ended = Instant::now();
    let took = wait_until(
        &rdock,
        Duration::from_secs(10),
        "the admin API answers again",
        || admin_ready(&rdock),
    )
    .await;
    eprintln!(
        "admin answered {:?} after the attack ended",
        ended.elapsed().max(took)
    );
    let report = load.stop().await;
    eprintln!("load: {report:?}");
    report.assert_clean("admin side unusable", &rdock.log());
    assert!(
        report.slowest < Duration::from_secs(2),
        "the slowest request took {:?}",
        report.slowest
    );
}
