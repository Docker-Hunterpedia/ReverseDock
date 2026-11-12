//! End-to-end: per-consumer rate limits with group overrides and `quota` (F-GW-02): `429`
//! with `Retry-After`, the draft `RateLimit` headers when asked, counters that survive a
//! restart, and a reset through the admin API.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;

use http_body_util::Full;
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn mint() -> (String, String, String) {
    let made = rdock_credentials::API_KEY.generate().unwrap();
    (made.value.into_inner(), made.id, made.secret_sha256)
}

fn call(host: &str, key: &str) -> http::Request<Full<bytes::Bytes>> {
    let mut req = get(host, "/");
    req.headers_mut().insert("x-api-key", key.parse().unwrap());
    req
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quotas_count_per_consumer_survive_a_restart_and_reset() {
    let backend = Backend::start("api").await;
    let port = free_port();
    let (basic_key, basic_id, basic_hash) = mint();
    let (gold_key, gold_id, gold_hash) = mint();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off, errors: {{ format: problem }} }}
consumers:
  basic: {{ keys: [{{ id: {basic_id}, hash: "{basic_hash}" }}] }}
  gold: {{ groups: [partners, gold], keys: [{{ id: {gold_id}, hash: "{gold_hash}" }}] }}
routes:
  quota: {{ match: "Host(`quota.test`)", service: api, middlewares: [keys, daily] }}
  rate: {{ match: "Host(`rate.test`)", service: api, middlewares: [keys, burst] }}
middlewares:
  keys: {{ type: api_key }}
  daily: {{ type: quota, limit: 2, window: day, overrides: {{ gold: 4 }}, headers: draft, flush_interval: 1s }}
  burst: {{ type: rate_limit, key: consumer, average: 1, period: 1m, overrides: {{ gold: {{ average: 3 }} }} }}
services:
  api: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        backend = backend.addr,
    );
    let mut rdock = Rdock::start(RDOCK, &config);

    // Quota: two per day for `basic`, four for `gold` (its group override).
    let first = client::http1(addr(port), call("quota.test", &basic_key)).await;
    assert_eq!(first.status, 200);
    assert_eq!(
        first.header("ratelimit-policy"),
        Some("\"daily\";q=2;w=86400")
    );
    let state = first.header("ratelimit").unwrap();
    assert!(state.starts_with("\"daily\";r=1;t="), "{state}");
    assert_eq!(
        client::http1(addr(port), call("quota.test", &basic_key))
            .await
            .status,
        200
    );
    let refused = client::http1(addr(port), call("quota.test", &basic_key)).await;
    assert_eq!(refused.status, 429);
    let retry: u64 = refused.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=86_400).contains(&retry), "until the day ends: {retry}");
    let body = refused.json();
    assert!(
        body["type"].as_str().unwrap().ends_with("#quota-exceeded"),
        "{body}"
    );
    assert_eq!(body["retry_after"], retry);
    assert!(refused.header("ratelimit").unwrap().contains(";r=0;"));
    for _ in 0..4 {
        assert_eq!(
            client::http1(addr(port), call("quota.test", &gold_key))
                .await
                .status,
            200
        );
    }
    assert_eq!(
        client::http1(addr(port), call("quota.test", &gold_key))
            .await
            .status,
        429
    );

    // Rate limit by consumer: separate buckets, and the group override.
    assert_eq!(
        client::http1(addr(port), call("rate.test", &basic_key))
            .await
            .status,
        200
    );
    let limited = client::http1(addr(port), call("rate.test", &basic_key)).await;
    assert_eq!(limited.status, 429);
    assert!(
        limited.json()["type"]
            .as_str()
            .unwrap()
            .ends_with("#rate-limited")
    );
    for _ in 0..3 {
        assert_eq!(
            client::http1(addr(port), call("rate.test", &gold_key))
                .await
                .status,
            200
        );
    }
    assert_eq!(
        client::http1(addr(port), call("rate.test", &gold_key))
            .await
            .status,
        429
    );

    // The counts are readable through the admin API, and survive a restart.
    let (status, body) = rdock.get_admin("/api/v1/quota/basic").unwrap();
    assert_eq!(status, 200);
    let usage: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(usage["quotas"][0]["usage"][0]["used"], 2, "{usage}");
    rdock.restart().unwrap();
    assert_eq!(
        client::http1(addr(port), call("quota.test", &basic_key))
            .await
            .status,
        429,
        "the restart kept the count"
    );
    let files: Vec<_> = std::fs::read_dir(rdock.data_dir().join("quota"))
        .unwrap()
        .collect();
    assert_eq!(files.len(), 1);

    // A reset gives the consumer its quota back.
    let (status, body) = rdock
        .admin_request("DELETE", "/api/v1/quota/basic")
        .unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        client::http1(addr(port), call("quota.test", &basic_key))
            .await
            .status,
        200
    );
}

#[test]
fn counting_per_consumer_needs_a_middleware_that_sets_one() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    std::fs::write(
        &file,
        "routes:\n  r: { match: \"PathPrefix(`/`)\", service: s, middlewares: [daily, keys] }\nmiddlewares:\n  keys: { type: api_key }\n  daily: { type: quota, limit: 5, window: hour }\n  rl: { type: rate_limit, average: 1, overrides: { gold: { average: 2 } } }\nservices:\n  s: { backends: [{ address: \"127.0.0.1:1\" }] }\n",
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .arg("validate")
        .arg(&file)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success());
    assert!(
        text.contains("`daily` counts per consumer, but no middleware before it sets one"),
        "{text}"
    );
    assert!(text.contains("middlewares.rl.overrides"), "{text}");
}
