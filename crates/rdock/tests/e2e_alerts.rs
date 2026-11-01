//! End-to-end: alerts reach their channels (ADR-0024): a rejected configuration fires a signed
//! webhook and a Slack-format message, and the next applied configuration resolves it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rdock_testkit::backend::Backend;
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

/// Collects every request (head and body) sent to it, answering 204.
async fn receiver() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let store = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let store = store.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buffer = [0u8; 8192];
                loop {
                    let n = stream.read(&mut buffer).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buffer[..n]);
                    let text = String::from_utf8_lossy(&raw).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if body.len() >= length {
                            break;
                        }
                    }
                }
                store
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&raw).to_string());
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    (addr, seen)
}

fn config(
    port: u16,
    backend: std::net::SocketAddr,
    hook: std::net::SocketAddr,
    broken: bool,
) -> String {
    format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes:\n  app: {{ match: \"PathPrefix(`/`)\", service: {} }}\nservices:\n  app: {{ backends: [{{ address: \"{backend}\" }}] }}\nobservability:\n  alerts:\n    min_interval: 1m\n    channels:\n      signed: {{ type: webhook, url: \"http://{hook}/hook\", secret: \"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw\", allow_private_targets: true }}\n      chat: {{ type: slack_compatible, url: \"http://{hook}/chat\", allow_private_targets: true, rules: [config] }}\n",
        if broken { "missing" } else { "app" }
    )
}

async fn wait_for(seen: &Arc<Mutex<Vec<String>>>, count: usize) -> Vec<String> {
    for _ in 0..100 {
        let list = seen.lock().unwrap().clone();
        if list.len() >= count {
            return list;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "expected {count} alert requests, got {:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_configuration_alerts_and_the_next_good_one_resolves() {
    let backend = Backend::start("alerts").await;
    let (hook, seen) = receiver().await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr, hook, false));

    std::fs::write(rdock.config_path(), config(port, backend.addr, hook, true)).unwrap();
    assert_eq!(rdock.reload().0, 422);
    let fired = wait_for(&seen, 2).await;
    let signed = fired
        .iter()
        .find(|r| r.starts_with("POST /hook"))
        .expect("the webhook got it");
    let lower = signed.to_ascii_lowercase();
    assert!(lower.contains("webhook-signature: v1,"), "{signed}");
    assert!(
        lower.contains("webhook-id: msg_") && lower.contains("webhook-timestamp: "),
        "{signed}"
    );
    assert!(
        signed.contains("\"type\":\"rdock.alert.firing\"") && signed.contains("config_rejected"),
        "{signed}"
    );
    let chat = fired
        .iter()
        .find(|r| r.starts_with("POST /chat"))
        .expect("the chat got it");
    assert!(
        chat.contains("\"text\":\"[FIRING] A configuration was rejected"),
        "{chat}"
    );

    std::fs::write(rdock.config_path(), config(port, backend.addr, hook, false)).unwrap();
    assert_eq!(rdock.reload().0, 200);
    let all = wait_for(&seen, 4).await;
    assert!(
        all.iter()
            .any(|r| r.starts_with("POST /chat")
                && r.contains("[RESOLVED] Configuration applied again")),
        "{all:?}"
    );
}
