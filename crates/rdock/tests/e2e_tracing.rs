//! End-to-end: OpenTelemetry traces over OTLP/HTTP, backend metrics and access-log sampling
//! (M-OBS-01…03).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// An OTLP/HTTP receiver that keeps the bodies posted to `/v1/traces`.
async fn collector() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let bodies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let store = bodies.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let store = store.clone();
            tokio::spawn(async move {
                let mut data = Vec::new();
                let mut buf = vec![0u8; 65536];
                // Read the head, then exactly content-length bytes of body.
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    data.extend_from_slice(&buf[..n]);
                    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if data.len() >= end + 4 + length {
                        if head.starts_with("post /v1/traces") {
                            store
                                .lock()
                                .unwrap()
                                .push(data[end + 4..end + 4 + length].to_vec());
                        }
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/x-protobuf\r\ncontent-length: 0\r\n\r\n")
                            .await;
                        data.clear();
                    }
                }
            });
        }
    });
    (address, bodies)
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn requests_are_traced_and_the_trace_continues_upstream() {
    let (otlp, bodies) = collector().await;
    let backend = Backend::start("app").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
observability:
  tracing: {{ otlp: "http://{otlp}" }}
"#,
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let mut req = get("a", "/orders");
    req.headers_mut().insert(
        "traceparent",
        format!("00-{TRACE_ID}-00f067aa0ba902b7-01")
            .parse()
            .unwrap(),
    );
    let reply = client::http1(addr(port), req).await;
    assert_eq!(reply.status, 200);
    let upstream = reply.json()["headers"]["traceparent"][0]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        upstream.starts_with(&format!("00-{TRACE_ID}-")),
        "{upstream}"
    );
    assert!(
        !upstream.contains("00f067aa0ba902b7"),
        "the backend's parent is rdock's client span"
    );

    // The batch processor exports within its 5-second delay.
    let trace_id = hex(TRACE_ID);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let found = bodies.lock().unwrap().iter().any(|b| {
            b.windows(trace_id.len()).any(|w| w == trace_id.as_slice())
                && b.windows(7).any(|w| w == b"GET app")
        });
        if found {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no span reached the collector:\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        metrics.contains(&format!(
            "rdock_backend_requests_total{{backend=\"{}\",service=\"app\",status_class=\"2xx\"}} 1",
            backend.addr
        )),
        "{metrics}"
    );
    assert!(
        metrics.contains("rdock_upstream_duration_seconds_count{service=\"app\"} 1"),
        "{metrics}"
    );
}

#[tokio::test]
async fn sampled_access_logs_keep_every_error() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
observability:
  access_log: {{ sample: 0 }}
"#,
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    for _ in 0..5 {
        assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
    }
    assert_eq!(
        client::http1(addr(port), get("a", "/status/500"))
            .await
            .status,
        500
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let statuses: Vec<u64> = rdock
        .access_log()
        .iter()
        .filter_map(|r| r["status"].as_u64())
        .collect();
    assert_eq!(statuses, vec![500], "only the error is logged");
}
