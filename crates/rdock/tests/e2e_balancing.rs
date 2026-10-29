//! End-to-end: balancing policies and sticky sessions (ADR-0022) through the real binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

struct Pool {
    backends: Vec<Backend>,
    port: u16,
    _rdock: Rdock,
}

/// Three backends `b0`, `b1`, `b2` behind one service with `service_extra` settings.
async fn pool(service_extra: &str) -> Pool {
    let mut backends = Vec::new();
    for i in 0..3 {
        backends.push(Backend::start(&format!("b{i}")).await);
    }
    let list: Vec<String> = backends
        .iter()
        .map(|b| format!("{{ address: \"{}\" }}", b.addr))
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
{service_extra}
"#,
        list.join(", ")
    );
    let rdock = Rdock::start(RDOCK, &config);
    Pool {
        backends,
        port,
        _rdock: rdock,
    }
}

fn header_request(name: &str, value: &str) -> http::Request<http_body_util::Full<bytes::Bytes>> {
    let mut req = get("a", "/");
    req.headers_mut().insert(
        http::HeaderName::try_from(name).unwrap(),
        value.parse().unwrap(),
    );
    req
}

#[tokio::test]
async fn header_hash_keeps_a_key_on_one_backend() {
    let pool = pool("    load_balancer: { policy: header_hash, hash_on: x-user }").await;
    let mut seen = BTreeSet::new();
    for user in 0..30 {
        let key = format!("user-{user}");
        let first = client::http1(addr(pool.port), header_request("x-user", &key)).await;
        let backend = first.header("x-backend").unwrap().to_owned();
        for _ in 0..3 {
            let again = client::http1(addr(pool.port), header_request("x-user", &key)).await;
            assert_eq!(again.header("x-backend"), Some(backend.as_str()), "{key}");
        }
        seen.insert(backend);
    }
    assert_eq!(seen.len(), 3, "30 keys spread over all three backends");
}

#[tokio::test]
async fn least_requests_avoids_busy_backends() {
    let pool = pool("    load_balancer: { policy: least_requests }").await;
    let port = pool.port;
    // Two slow requests occupy two backends; every short request meanwhile goes to the third.
    let slow = || tokio::spawn(client::http1(addr(port), get("a", "/slow/1500")));
    // Started a moment apart: two requests picked at the same instant may both see an idle
    // backend before either is counted.
    let a = slow();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let b = slow();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let idle = client::http1(addr(port), get("a", "/")).await;
    let idle = idle.header("x-backend").unwrap().to_owned();
    for _ in 0..5 {
        let reply = client::http1(addr(port), get("a", "/")).await;
        assert_eq!(reply.header("x-backend"), Some(idle.as_str()));
    }
    let (a, b) = (a.await.unwrap().text(), b.await.unwrap().text());
    assert!(!a.contains(&idle) && !b.contains(&idle), "{a} {b} {idle}");
    assert_ne!(a, b, "the two slow requests used different backends");
}

#[tokio::test]
async fn sticky_cookie_pins_a_client_and_is_signed() {
    let pool =
        pool("    sticky: { cookie: { name: srv, secret: \"0123456789abcdef0123456789abcdef\" } }")
            .await;
    let first = client::http1(addr(pool.port), get("a", "/")).await;
    let cookie = first.header("set-cookie").unwrap().to_owned();
    assert!(cookie.starts_with("srv="), "{cookie}");
    assert!(
        cookie.contains("; Path=/") && cookie.contains("; Secure") && cookie.contains("; HttpOnly"),
        "{cookie}"
    );
    assert!(cookie.contains("; SameSite=Lax"), "{cookie}");
    for b in &pool.backends {
        assert!(
            !cookie.contains(&b.addr.to_string()),
            "the address never leaks"
        );
    }
    let value = cookie.split(';').next().unwrap().to_owned();
    let backend = first.header("x-backend").unwrap().to_owned();
    for _ in 0..6 {
        let reply = client::http1(addr(pool.port), header_request("cookie", &value)).await;
        assert_eq!(reply.header("x-backend"), Some(backend.as_str()));
        assert_eq!(reply.header("set-cookie"), None, "a valid cookie is kept");
    }
    // A forged cookie is ignored and replaced.
    let forged = client::http1(addr(pool.port), header_request("cookie", "srv=00ff")).await;
    assert!(forged.header("set-cookie").unwrap().starts_with("srv="));
}
