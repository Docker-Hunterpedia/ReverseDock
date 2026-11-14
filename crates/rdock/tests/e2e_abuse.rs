//! End-to-end: abuse counters and bans (H-SEC-01): 20 × 401 bans the client, the ban answers
//! `403 banned`, ends on time, can be lifted through the admin API, survives a restart, failed
//! authentications count, and exempt addresses are never banned.

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

async fn status(port: u16, host: &str, path: &str) -> u16 {
    client::http1(addr(port), get(host, path)).await.status
}

fn config(port: u16, backend: SocketAddr) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off, errors: {{ format: problem }} }}
routes:
  long: {{ match: "Host(`long.test`)", service: app, middlewares: [long] }}
  short: {{ match: "Host(`short.test`)", service: app, middlewares: [short] }}
  open: {{ match: "Host(`open.test`)", service: app, middlewares: [open] }}
  login:
    match: "Host(`login.test`)"
    service: app
    middlewares: [logins, auth]
middlewares:
  long: {{ type: abuse, events: [401], threshold: 20, window: 1m, ban: 10m, exempt: [] }}
  short: {{ type: abuse, events: [4xx], threshold: 5, window: 1m, ban: 2s, exempt: [] }}
  open: {{ type: abuse, events: [401], threshold: 3 }}
  logins: {{ type: abuse, events: [auth_failure], threshold: 3, ban: 10m, exempt: [] }}
  auth:
    type: basic_auth
    users: ["alice:$2y$05$C4h3k1o0bq3K6k8x2v1QOe8m5Kk2B1b0u2wS0q3m3m6sQb1oU1H5S"]
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#
    )
}

#[tokio::test]
async fn twenty_failures_ban_the_client_until_lifted_or_over() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let mut rdock = Rdock::start(RDOCK, &config(port, backend.addr));

    for i in 0..20 {
        assert_eq!(
            status(port, "long.test", "/status/401").await,
            401,
            "attempt {i}"
        );
    }
    let mut ask = get("long.test", "/");
    ask.headers_mut()
        .insert("accept", "application/problem+json".parse().unwrap());
    let banned = client::http1(addr(port), ask).await;
    assert_eq!(banned.status, 403);
    assert!(
        banned.json()["type"].as_str().unwrap().ends_with("#banned"),
        "{}",
        banned.text()
    );
    assert_eq!(
        status(port, "short.test", "/").await,
        200,
        "bans are per middleware"
    );

    // The admin API lists the ban.
    let (code, body) = rdock.get_admin("/api/v1/abuse/bans").unwrap();
    assert_eq!(code, 200, "{body}");
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    let ban = &list["bans"][0];
    assert_eq!(ban["middleware"], "long", "{list}");
    assert_eq!(ban["key"], "ip:127.0.0.1", "{list}");
    assert!(ban["remaining_seconds"].as_u64().unwrap() > 500);

    // A restart keeps it.
    rdock.restart().unwrap();
    assert_eq!(
        status(port, "long.test", "/").await,
        403,
        "the restart kept the ban"
    );

    // An operator lifts it; the call is audited.
    let (code, body) = rdock
        .admin_request(
            "DELETE",
            "/api/v1/abuse/bans/ip%3A127.0.0.1?middleware=long",
        )
        .unwrap();
    assert_eq!(code, 200, "{body}");
    assert_eq!(status(port, "long.test", "/").await, 200);
    let (code, _) = rdock
        .admin_request("DELETE", "/api/v1/abuse/bans/ip%3A127.0.0.1")
        .unwrap();
    assert_eq!(code, 404, "nothing left to lift");
    let (_, audit) = rdock.get_admin("/api/v1/audit").unwrap();
    assert!(audit.contains("abuse.unban"), "{audit}");

    // A short ban ends by itself.
    for _ in 0..5 {
        assert_eq!(status(port, "short.test", "/status/404").await, 404);
    }
    assert_eq!(status(port, "short.test", "/").await, 403);
    let started = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if status(port, "short.test", "/").await == 200 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the 2s ban never ended"
        );
    }
}

#[tokio::test]
async fn failed_logins_count_and_exempt_clients_are_never_banned() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr));

    // Missing credentials are not failures; wrong ones are.
    for _ in 0..5 {
        assert_eq!(status(port, "login.test", "/").await, 401);
    }
    for _ in 0..3 {
        let mut req = get("login.test", "/");
        req.headers_mut()
            .insert("authorization", "Basic bWFsbG9yeTp4".parse().unwrap());
        assert_eq!(client::http1(addr(port), req).await.status, 401);
    }
    assert_eq!(
        status(port, "login.test", "/").await,
        403,
        "three failed logins ban"
    );

    // `open` keeps the default exemptions (loopback): never banned.
    for _ in 0..30 {
        assert_eq!(status(port, "open.test", "/status/401").await, 401);
    }
    assert_eq!(status(port, "open.test", "/").await, 200);
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(
        metrics.contains("rdock_abuse_actions_total{action=\"ban\",middleware=\"logins\"} 1"),
        "{metrics}"
    );
}
