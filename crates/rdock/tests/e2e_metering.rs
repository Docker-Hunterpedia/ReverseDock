//! End-to-end: usage metering (F-GW-05). Events of requests with a consumer reach a
//! `CloudEvents` webhook and an OTLP logs endpoint in batches, signed, retried with the same
//! event IDs after a `503`; and a receiver that never answers does not slow requests down: the
//! queue fills, drops and counts.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http_body_util::Full;
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rdock_testkit::receiver::{Mode, Receiver};
use serde_json::Value;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
/// A throw-away Standard Webhooks secret (base64 of 24 bytes).
const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn mint() -> (String, String, String) {
    let made = rdock_credentials::API_KEY.generate().unwrap();
    (made.value.into_inner(), made.id, made.secret_sha256)
}

fn call(key: Option<&str>) -> http::Request<Full<bytes::Bytes>> {
    let mut req = get("api.test", "/");
    if let Some(key) = key {
        req.headers_mut().insert("x-api-key", key.parse().unwrap());
    }
    req
}

fn config(port: u16, backend: SocketAddr, key: (&str, &str), metering: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
consumers:
  acme: {{ groups: [gold], keys: [{{ id: {id}, hash: "{hash}" }}] }}
routes:
  api: {{ match: "Host(`api.test`)", service: api, middlewares: [keys] }}
middlewares:
  keys: {{ type: api_key, anonymous: allow }}
services:
  api: {{ backends: [{{ address: "{backend}" }}] }}
observability:
  metering:
{metering}
"#,
        id = key.0,
        hash = key.1,
    )
}

async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_are_batched_signed_and_retried_with_the_same_ids() {
    let backend = Backend::start("api").await;
    let webhook = Receiver::start().await;
    let otlp = Receiver::start().await;
    webhook.then(&[Mode::Status(503)]);
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("whsec");
    std::fs::write(&secret_file, SECRET).unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "metering-token-for-tests\n").unwrap();
    let (key, id, hash) = mint();
    let port = free_port();
    let metering = format!(
        "    webhook:\n      url: \"{}/ingest\"\n      source: rdock/test\n      secret: \"${{file:{}}}\"\n      token: \"${{file:{}}}\"\n      allow_private_targets: true\n    otlp: {{ endpoint: \"{}\" }}\n    max_batch: 3\n    flush_interval: 300ms\n",
        webhook.url(),
        secret_file.display(),
        token_file.display(),
        otlp.url()
    );
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr, (&id, &hash), &metering));
    for _ in 0..3 {
        assert_eq!(
            client::http1(addr(port), call(Some(&key))).await.status,
            200
        );
    }
    // Anonymous requests are not metered unless `all_requests` is set.
    assert_eq!(client::http1(addr(port), call(None)).await.status, 200);

    wait_for("a delivered batch", || {
        webhook
            .received()
            .iter()
            .any(|r| r.answered == Mode::Accept)
    })
    .await;
    let received = webhook.received();
    assert_eq!(received[0].answered, Mode::Status(503));
    let (refused, accepted) = (&received[0], &received[1]);
    let ids = |r: &rdock_testkit::receiver::Received| -> Vec<String> {
        r.json()
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        ids(refused),
        ids(accepted),
        "a retry carries the same event IDs"
    );
    assert_eq!(
        ids(accepted).len(),
        3,
        "one batch of three; the anonymous request is not metered"
    );
    assert_eq!(accepted.path, "/ingest");
    assert_eq!(
        accepted.header("content-type"),
        Some("application/cloudevents-batch+json")
    );
    assert_eq!(
        accepted.header("authorization"),
        Some("Bearer metering-token-for-tests")
    );
    let event = &accepted.json()[0];
    assert_eq!(event["specversion"], "1.0");
    assert_eq!(event["type"], "dev.reversedock.request.v1");
    assert_eq!(event["source"], "rdock/test");
    assert_eq!(event["subject"], "acme");
    let data = &event["data"];
    assert_eq!(data["consumer"], "acme");
    assert_eq!(data["groups"][0], "gold");
    assert_eq!(data["key_id"], id.as_str());
    assert_eq!(data["route"], "api");
    assert_eq!(data["method"], "GET");
    assert_eq!(data["status"], 200);
    assert!(data["bytes_out"].as_u64().unwrap() > 0);
    assert_eq!(
        uuid::Uuid::parse_str(event["id"].as_str().unwrap())
            .unwrap()
            .get_version_num(),
        7
    );
    // Standard Webhooks signature over `id.timestamp.body`.
    let message = accepted.header("webhook-id").unwrap();
    assert_eq!(
        message,
        refused.header("webhook-id").unwrap(),
        "the delivery keeps its ID"
    );
    let timestamp = accepted.header("webhook-timestamp").unwrap();
    let key_bytes = STANDARD
        .decode(SECRET.trim_start_matches("whsec_"))
        .unwrap();
    let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes);
    let signed = format!(
        "{message}.{timestamp}.{}",
        String::from_utf8_lossy(&accepted.body)
    );
    let expected = format!(
        "v1,{}",
        STANDARD.encode(ring::hmac::sign(&mac, signed.as_bytes()).as_ref())
    );
    assert_eq!(
        accepted.header("webhook-signature"),
        Some(expected.as_str())
    );
    let body = String::from_utf8_lossy(&accepted.body);
    assert!(!body.contains(&key), "never the key itself");

    // The same events as OTLP log records.
    wait_for("OTLP logs", || !otlp.received().is_empty()).await;
    let logs = &otlp.received()[0];
    assert_eq!(logs.path, "/v1/logs");
    let records = &logs.json()["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
    assert_eq!(records.as_array().unwrap().len(), 3);
    let attributes: Vec<&Value> = records[0]["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .collect();
    assert!(
        attributes
            .iter()
            .any(|a| a["key"] == "rdock.consumer" && a["value"]["stringValue"] == "acme")
    );

    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(
        metrics.contains("rdock_metering_events_total{result=\"sent\",sink=\"webhook\"} 3"),
        "{metrics}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hanging_receiver_never_delays_requests() {
    let backend = Backend::start("api").await;
    let webhook = Receiver::start().await;
    webhook.set(Mode::Hang);
    let (key, id, hash) = mint();
    let port = free_port();
    let metering = format!(
        "    webhook: {{ url: \"{}/ingest\", allow_private_targets: true }}\n    max_batch: 1\n    flush_interval: 10ms\n    queue: 5\n",
        webhook.url()
    );
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr, (&id, &hash), &metering));
    // Warm up the connection and the route.
    assert_eq!(
        client::http1(addr(port), call(Some(&key))).await.status,
        200
    );
    wait_for("the receiver to hold a delivery", || {
        !webhook.received().is_empty()
    })
    .await;
    let mut slowest = Duration::ZERO;
    let start = Instant::now();
    for _ in 0..60 {
        let t = Instant::now();
        assert_eq!(
            client::http1(addr(port), call(Some(&key))).await.status,
            200
        );
        slowest = slowest.max(t.elapsed());
    }
    let total = start.elapsed();
    assert!(
        slowest < Duration::from_millis(500),
        "a request waited for the receiver: {slowest:?}"
    );
    assert!(total < Duration::from_secs(10), "{total:?}");
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    let dropped: u64 = metrics
        .lines()
        .find(|l| {
            l.starts_with("rdock_metering_dropped_total{reason=\"queue_full\",sink=\"webhook\"}")
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(
        dropped >= 50,
        "the full queue drops and counts: {dropped}\n{metrics}"
    );
}
