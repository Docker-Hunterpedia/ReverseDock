//! End-to-end on a single-node swarm (W-SWM-01, ADR-0026): a service's `deploy.labels` become
//! a route whose backends are the task addresses, scaling 1 → 3 → 1 changes the pool, a task
//! Swarm is stopping leaves the pool before it exits, `rdock.swarm.lbswarm=true` switches to
//! the virtual IP, and a `dnsrr` service in that mode is diagnosed.
//!
//! The checks read the translated configuration through the admin API, not traffic: ReverseDock
//! runs on the host here, and overlay task addresses are reachable only from containers on the
//! overlay. Traffic through a swarm (rolling updates without 5xx, several nodes) is checked on
//! the lab before each release.
//!
//! Needs a Docker daemon that is not part of a swarm and `RDOCK_SWARM_TESTS=1`; CI sets it.
//! The test runs `docker swarm init`, and `docker swarm leave --force` only for a swarm it
//! created; a daemon already in a swarm is left alone and the test is skipped.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::process::Command;
use std::time::{Duration, Instant};

use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const WHOAMI: &str = "traefik/whoami:v1.11.0";
/// `sleep` as PID 1 ignores SIGTERM, so a stopped task keeps running for its grace period.
const BUSYBOX: &str = "busybox:1.37";
/// How long a scheduling change may take to show (image start plus one poll).
const SETTLE: Duration = Duration::from_secs(60);

fn enabled() -> bool {
    let on = std::env::var("RDOCK_SWARM_TESTS").is_ok_and(|v| v == "1");
    if !on {
        eprintln!("skipped: set RDOCK_SWARM_TESTS=1 to run against a single-node swarm");
    }
    on
}

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A swarm this test created; leaving it removes everything the test made in it.
struct OwnSwarm;

impl OwnSwarm {
    /// Initialises a swarm, or `None` when the daemon is already in one.
    fn init() -> Option<Self> {
        let state = docker(&["info", "--format", "{{.Swarm.LocalNodeState}}"]);
        if state != "inactive" {
            eprintln!(
                "skipped: the Docker daemon is already in a swarm (state `{state}`); this test only uses a swarm it creates"
            );
            return None;
        }
        docker(&["swarm", "init", "--advertise-addr", "127.0.0.1"]);
        Some(Self)
    }
}

impl Drop for OwnSwarm {
    /// Leaving can fail while removed services are still shutting down: try again until the
    /// daemon is out of the swarm.
    fn drop(&mut self) {
        for _ in 0..10 {
            let left = Command::new("docker")
                .args(["swarm", "leave", "--force"])
                .output()
                .is_ok_and(|out| out.status.success());
            let state = Command::new("docker")
                .args(["info", "--format", "{{.Swarm.LocalNodeState}}"])
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
                .unwrap_or_default();
            if left && state == "inactive" {
                return;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        eprintln!("could not leave the test swarm; run `docker swarm leave --force`");
    }
}

/// Removes a service even when an assertion fails (before the swarm is left).
struct ServiceGuard(String);

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["service", "rm", &self.0])
            .output();
    }
}

/// Removes a network even when an assertion fails; leaving the swarm removes it otherwise.
struct NetworkGuard(String);

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["network", "rm", &self.0])
            .output();
    }
}

/// `docker service create [options] image [command]` on `network`.
fn create_service(
    name: &str,
    network: &str,
    options: &[&str],
    image_and_command: &[&str],
) -> ServiceGuard {
    let mut args = vec![
        "service",
        "create",
        "--detach",
        "--quiet",
        "--name",
        name,
        "--network",
        network,
    ];
    args.extend_from_slice(options);
    args.extend_from_slice(image_and_command);
    docker(&args);
    ServiceGuard(name.to_owned())
}

/// The backend addresses of `service@swarm`, or `None` while it does not exist.
fn backends(rdock: &Rdock, service: &str) -> Option<BTreeSet<String>> {
    let (status, body) = rdock.get_admin(&format!("/api/v1/services/{service}@swarm"))?;
    if status != 200 {
        return None;
    }
    let object: serde_json::Value = serde_json::from_str(&body).ok()?;
    let list = object["spec"]["backends"].as_array()?;
    Some(
        list.iter()
            .filter_map(|b| b["address"].as_str().map(str::to_owned))
            .collect(),
    )
}

/// The Swarm provider's diagnostics in the admin status.
fn provider_messages(rdock: &Rdock) -> Vec<String> {
    let Some((_, body)) = rdock.get_admin("/api/v1/status") else {
        return Vec::new();
    };
    let status: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    status["providers"]["swarm"]["diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d["message"].as_str().map(str::to_owned))
        .collect()
}

/// Waits until `check` holds, or fails with `what` and the log.
async fn wait_until(
    rdock: &Rdock,
    what: &str,
    limit: Duration,
    check: impl Fn() -> bool,
) -> Duration {
    let start = Instant::now();
    while start.elapsed() < limit {
        if check() {
            return start.elapsed();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("{what} within {limit:?}\n{}", rdock.log());
}

/// The running tasks' addresses on `network`, with `port`.
fn task_addresses(service: &str, network: &str, port: u16) -> BTreeSet<String> {
    let ids = docker(&[
        "service",
        "ps",
        "--quiet",
        "--filter",
        "desired-state=running",
        service,
    ]);
    ids.lines()
        .filter(|id| !id.is_empty())
        .filter_map(|id| {
            let format = format!(
                "{{{{range .NetworksAttachments}}}}{{{{if eq .Network.Spec.Name \"{network}\"}}}}{{{{index .Addresses 0}}}}{{{{end}}}}{{{{end}}}}"
            );
            let cidr = docker(&["inspect", "--format", &format, id]);
            let ip = cidr.split('/').next()?.to_owned();
            (!ip.is_empty()).then(|| format!("{ip}:{port}"))
        })
        .collect()
}

/// `--label` options exposing `host` on `port` without TLS, plus `extra` labels.
fn labels(host: &str, port: u16, extra: &[&str]) -> Vec<String> {
    let mut all = vec![
        "rdock.enable=true".to_owned(),
        format!("rdock.host={host}"),
        format!("rdock.port={port}"),
        "rdock.tls=off".to_owned(),
    ];
    all.extend(extra.iter().map(|l| (*l).to_owned()));
    all.into_iter()
        .flat_map(|label| ["--label".to_owned(), label])
        .collect()
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[tokio::test]
async fn swarm_tasks_become_backends_and_follow_the_schedule() {
    if !enabled() {
        return;
    }
    docker(&["pull", "-q", WHOAMI]);
    docker(&["pull", "-q", BUSYBOX]);
    let Some(_swarm) = OwnSwarm::init() else {
        return;
    };
    let id = std::process::id();
    let network = format!("rdock-e2e-{id}");
    docker(&[
        "network",
        "create",
        "--driver",
        "overlay",
        "--attachable",
        &network,
    ]);
    let _network = NetworkGuard(network.clone());
    let web = format!("rdock-e2e-web-{id}");
    let options = labels(&format!("{web}.test"), 80, &[]);
    let _web = create_service(&web, &network, &strs(&options), &[WHOAMI]);
    let port = free_port();
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nacme: false\nproviders:\n  swarm: {{ endpoint: \"unix:///var/run/docker.sock\", poll_interval: 1s }}\n"
    );
    let mut rdock = Rdock::start(RDOCK, &config);

    scaling_changes_the_pool(&rdock, &web, &network).await;
    let _slow = a_stopping_task_leaves_the_pool(&rdock, &network, id).await;
    the_lbswarm_label_switches_to_the_virtual_ip(&rdock, &web).await;
    let _dns = a_dnsrr_service_is_diagnosed(&rdock, &network, id).await;

    rdock.stop(Duration::from_secs(10));
}

/// One replica is one backend, the task's address on the overlay; scaling 1 → 3 → 1 follows.
async fn scaling_changes_the_pool(rdock: &Rdock, web: &str, network: &str) {
    let took = wait_until(rdock, "the service did not get its task", SETTLE, || {
        backends(rdock, web).is_some_and(|b| b.len() == 1)
    })
    .await;
    eprintln!("routed {took:?} after the provider started");
    assert_eq!(
        backends(rdock, web).unwrap(),
        task_addresses(web, network, 80)
    );
    docker(&["service", "scale", "--detach", &format!("{web}=3")]);
    wait_until(
        rdock,
        "three replicas did not join the pool",
        SETTLE,
        || backends(rdock, web).is_some_and(|b| b.len() == 3),
    )
    .await;
    assert_eq!(
        backends(rdock, web).unwrap(),
        task_addresses(web, network, 80)
    );
    docker(&["service", "scale", "--detach", &format!("{web}=1")]);
    wait_until(rdock, "two replicas did not leave the pool", SETTLE, || {
        backends(rdock, web).is_some_and(|b| b.len() == 1)
    })
    .await;
}

/// A task Swarm is stopping leaves the pool long before its 60 s grace period ends.
async fn a_stopping_task_leaves_the_pool(rdock: &Rdock, network: &str, id: u32) -> ServiceGuard {
    let slow = format!("rdock-e2e-slow-{id}");
    let mut options = vec!["--replicas".to_owned(), "2".to_owned()];
    options.extend(["--stop-grace-period".to_owned(), "60s".to_owned()]);
    options.extend(labels(&format!("{slow}.test"), 8080, &[]));
    let guard = create_service(&slow, network, &strs(&options), &[BUSYBOX, "sleep", "3600"]);
    wait_until(
        rdock,
        "the slow service did not get two tasks",
        SETTLE,
        || backends(rdock, &slow).is_some_and(|b| b.len() == 2),
    )
    .await;
    docker(&["service", "scale", "--detach", &format!("{slow}=1")]);
    let limit = Duration::from_secs(20);
    let drained = wait_until(
        rdock,
        "the stopping task did not leave the pool",
        limit,
        || backends(rdock, &slow).is_some_and(|b| b.len() == 1),
    )
    .await;
    eprintln!("the stopping task left the pool after {drained:?}");
    let format = "{{.CurrentState}}";
    let state = docker(&[
        "service",
        "ps",
        "--filter",
        "desired-state=remove",
        "--format",
        format,
        &slow,
    ]);
    assert!(
        state.starts_with("Running"),
        "the task should still be running out its grace period: {state}"
    );
    guard
}

/// `rdock.swarm.lbswarm=true`: the virtual IP is the one backend.
async fn the_lbswarm_label_switches_to_the_virtual_ip(rdock: &Rdock, web: &str) {
    let label = "rdock.swarm.lbswarm=true";
    docker(&[
        "service",
        "update",
        "--detach",
        "--quiet",
        "--label-add",
        label,
        web,
    ]);
    let format = "{{range .Endpoint.VirtualIPs}}{{.Addr}} {{end}}";
    let vips = docker(&["service", "inspect", "--format", format, web]);
    let vip = vips.split_whitespace().next().unwrap();
    let ip = vip.split('/').next().unwrap();
    let expected = BTreeSet::from([format!("{ip}:80")]);
    wait_until(
        rdock,
        "the service did not switch to its virtual IP",
        SETTLE,
        || backends(rdock, web).as_ref() == Some(&expected),
    )
    .await;
}

/// A `dnsrr` service has no virtual IP: diagnosed, no backends.
async fn a_dnsrr_service_is_diagnosed(rdock: &Rdock, network: &str, id: u32) -> ServiceGuard {
    let dns = format!("rdock-e2e-dns-{id}");
    let mut options = vec!["--endpoint-mode".to_owned(), "dnsrr".to_owned()];
    options.extend(labels(
        &format!("{dns}.test"),
        80,
        &["rdock.swarm.lbswarm=true"],
    ));
    let guard = create_service(&dns, network, &strs(&options), &[WHOAMI]);
    wait_until(rdock, "the dnsrr service was not diagnosed", SETTLE, || {
        provider_messages(rdock)
            .iter()
            .any(|m| m.contains("uses `dnsrr`"))
    })
    .await;
    assert_eq!(backends(rdock, &dns), None);
    guard
}
