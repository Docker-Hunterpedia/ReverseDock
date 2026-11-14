//! Chaos suite, scenario 2 "Docker socket down" (ADR-0033, vision §7). Rootless: the Docker
//! provider talks to the testkit's fake Engine API on a Unix socket (`fake_docker`), which can
//! disappear, hang (accept and never answer), answer `500`, and come back. The variant against
//! a real daemon is `e2e_docker` (CI sets `RDOCK_DOCKER_TESTS=1`).
//!
//! Pass: zero failed requests to the routes known before the outage (served from the last
//! snapshot), the route never flaps (the provider's route count never drops), the provider
//! reports `degraded` and is `connected` again within 40 s of the socket's return (backoff cap
//! 30 s), it does not hammer a failing daemon (at most one call a second on average plus the
//! listing), and rdock starts within 15 s while the socket is absent or hanging, serves its file
//! routes, serves a stored Docker snapshot, and picks Docker up when it returns.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod chaos_common;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chaos_common::*;
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::fake_docker::{DockerMode, FakeContainer, FakeDocker};
use rdock_testkit::free_port;
use rdock_testkit::load::{Load, Target};
use rdock_testkit::rdock::Rdock;

/// Recovery bound once the socket is back: the provider's backoff caps at 30 s.
const RECONNECT: Duration = Duration::from_secs(40);
/// A hanging socket is noticed after the Engine API request timeout (30 s).
const HANG_NOTICED: Duration = Duration::from_secs(45);

fn config(port: u16, socket: &Path, backend: std::net::SocketAddr) -> String {
    format!(
        r#"listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  file: {{ match: "Host(`file.test`)", service: file }}
services:
  file: {{ backends: [{{ address: "{backend}" }}] }}
providers:
  docker: {{ endpoint: "unix://{}" }}
"#,
        socket.display()
    )
}

fn provider(rdock: &Rdock) -> (Option<String>, Option<u64>) {
    let status = status(rdock).unwrap_or_default();
    let docker = &status["providers"]["docker"];
    (
        docker["state"].as_str().map(str::to_owned),
        docker["routes"].as_u64(),
    )
}

async fn wait_state(rdock: &Rdock, state: &str, limit: Duration) -> Duration {
    wait_until(
        rdock,
        limit,
        &format!("the Docker provider is {state}"),
        || provider(rdock).0.as_deref() == Some(state),
    )
    .await
}

/// Samples the provider's route count every 100 ms; the lowest seen.
fn watch_routes(rdock: &Arc<Rdock>) -> (Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
    let lowest = Arc::new(AtomicU64::new(u64::MAX));
    let (seen, rdock) = (lowest.clone(), rdock.clone());
    let task = tokio::spawn(async move {
        loop {
            let routes = tokio::task::block_in_place(|| provider(&rdock).1);
            if let Some(routes) = routes {
                seen.fetch_min(routes, Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    (lowest, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn docker_socket_outages_keep_the_last_routes() {
    let backend = Backend::start("app").await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("docker.sock");
    let docker = FakeDocker::start(&socket);
    docker.set_containers(vec![FakeContainer::routed(
        "web-1",
        "docker.test",
        backend.addr.port(),
    )]);
    let port = free_port();
    let rdock = Arc::new(Rdock::start(RDOCK, &config(port, &socket, backend.addr)));
    wait_state(&rdock, "connected", Duration::from_secs(20)).await;
    wait_until(
        &rdock,
        Duration::from_secs(20),
        "the container is routed",
        || provider(&rdock).1 == Some(1),
    )
    .await;
    let load = Load::start(
        vec![
            Target::http(addr(port), "docker.test", "/"),
            Target::http(addr(port), "file.test", "/"),
        ],
        50,
    );
    load.wait_for_ok(50, Duration::from_secs(30)).await;
    let (lowest, sampler) = watch_routes(&rdock);

    for (fault, noticed) in [
        (DockerMode::Down, Duration::from_secs(20)),
        (DockerMode::Error, Duration::from_secs(20)),
        (DockerMode::Hang, HANG_NOTICED),
    ] {
        let before = docker.requests();
        let started = Instant::now();
        docker.set_mode(fault);
        let took = wait_state(&rdock, "degraded", noticed).await;
        eprintln!("{fault:?}: degraded after {took:?}");
        // Requests keep flowing from the last snapshot.
        load.wait_for_ok(100, Duration::from_secs(60)).await;
        let calls = docker.requests() - before;
        let seconds = started.elapsed().as_secs() + 1;
        assert!(
            calls <= seconds + 5,
            "{fault:?}: {calls} calls to a failing daemon in {seconds} s"
        );
        docker.set_mode(DockerMode::Up);
        let back = wait_state(&rdock, "connected", RECONNECT).await;
        eprintln!("{fault:?}: connected again after {back:?}");
        load.wait_for_ok(50, Duration::from_secs(30)).await;
    }
    sampler.abort();
    let report = load.stop().await;
    eprintln!("load: {report:?}");
    report.assert_clean("Docker socket down", &rdock.log());
    assert_eq!(
        lowest.load(Ordering::Relaxed),
        1,
        "the Docker route never left the snapshot"
    );
    assert_data_dir_consistent(&rdock);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rdock_starts_while_the_docker_socket_is_absent_or_hanging() {
    let backend = Backend::start("app").await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("docker.sock");
    let container = FakeContainer::routed("web-1", "docker.test", backend.addr.port());

    for start_mode in [DockerMode::Down, DockerMode::Hang] {
        let docker = FakeDocker::start(&socket);
        docker.set_mode(start_mode);
        let port = free_port();
        let started = Instant::now();
        let rdock = Rdock::try_start_in(
            RDOCK,
            &config(port, &socket, backend.addr),
            &[],
            None,
            Duration::from_secs(15),
        )
        .unwrap_or_else(|log| panic!("{start_mode:?}: not ready within 15 s:\n{log}"));
        eprintln!("{start_mode:?}: ready after {:?}", started.elapsed());
        let file = client::http1(addr(port), get("file.test", "/")).await;
        assert_eq!(file.status, 200, "file routes are served");
        // A socket that never answers is noticed after the Engine API request timeout, not
        // before and not never.
        let took = wait_state(&rdock, "degraded", HANG_NOTICED).await;
        eprintln!("{start_mode:?}: degraded after {took:?}");
        assert_eq!(
            client::http1(addr(port), get("file.test", "/"))
                .await
                .status,
            200,
            "file routes are served while the provider waits"
        );
        // Docker comes back with a container: it is picked up.
        docker.set_containers(vec![container.clone()]);
        docker.set_mode(DockerMode::Up);
        let took = wait_until(&rdock, RECONNECT, "the container is routed", || {
            provider(&rdock).1 == Some(1)
        })
        .await;
        eprintln!("{start_mode:?}: Docker picked up after {took:?}");
        let start = Instant::now();
        while client::http1(addr(port), get("docker.test", "/"))
            .await
            .status
            != 200
        {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "docker.test is not served"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // A restart while the socket is absent serves the stored snapshot at once.
        let mut rdock = rdock;
        rdock.stop(Duration::from_secs(15));
        docker.set_mode(DockerMode::Down);
        rdock
            .start_again()
            .unwrap_or_else(|log| panic!("no restart without Docker:\n{log}"));
        let load = Load::start(vec![Target::http(addr(port), "docker.test", "/")], 40);
        load.wait_for_ok(40, Duration::from_secs(30)).await;
        wait_state(&rdock, "degraded", Duration::from_secs(20)).await;
        docker.set_mode(DockerMode::Up);
        wait_state(&rdock, "connected", RECONNECT).await;
        load.wait_for_ok(20, Duration::from_secs(30)).await;
        let report = load.stop().await;
        report.assert_clean("restart without Docker", &rdock.log());
        drop(docker);
    }
}
