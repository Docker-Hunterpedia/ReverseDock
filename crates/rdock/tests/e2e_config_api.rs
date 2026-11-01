//! End-to-end: routes written through the configuration API are served, conditional on the
//! version, survive a file reload and a restart, and roll back (ADR-0024).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn etag(head: &str) -> String {
    head.lines()
        .find_map(|l| {
            l.strip_prefix("etag: ")
                .or_else(|| l.strip_prefix("ETag: "))
        })
        .unwrap()
        .trim()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_routes_are_served_and_roll_back() {
    let backend = Backend::start("api-backend").await;
    let port = free_port();
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes:\n  file: {{ match: \"Host(`file.test`)\", service: file }}\nservices:\n  file: {{ backends: [{{ address: \"{}\" }}] }}\n",
        backend.addr
    );
    let mut rdock = Rdock::start(RDOCK, &config);
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));

    let (status, head, body) = rdock
        .admin_send("GET", "/api/v1/config/api", &[], "")
        .unwrap();
    assert_eq!(status, 200, "{body}");
    let first = etag(&head);
    let document = serde_json::json!({
        "routes": { "app": { "match": "Host(`api.test`)", "service": "app" } },
        "services": { "app": { "backends": [{ "address": backend.addr.to_string() }] } }
    })
    .to_string();
    let json = [("Content-Type", "application/json")];

    let (status, _, _) = rdock
        .admin_send("PUT", "/api/v1/config/api", &json, &document)
        .unwrap();
    assert_eq!(status, 428);
    let with_tag = [
        ("Content-Type", "application/json"),
        ("If-Match", first.as_str()),
    ];
    let (status, head, body) = rdock
        .admin_send("PUT", "/api/v1/config/api", &with_tag, &document)
        .unwrap();
    assert_eq!(status, 200, "{body}");
    let second = etag(&head);
    let reply = client::http1(proxy, get("api.test", "/")).await;
    assert_eq!(reply.status, 200, "the API route is served");

    // A configuration that does not compile is refused and changes nothing.
    let broken = serde_json::json!({ "routes": { "x": { "match": "Host(`x.test`)", "service": "missing" } } }).to_string();
    let tag = [
        ("Content-Type", "application/json"),
        ("If-Match", second.as_str()),
    ];
    let (status, _, body) = rdock
        .admin_send("PUT", "/api/v1/config/api", &tag, &broken)
        .unwrap();
    assert_eq!(status, 422, "{body}\n{}", rdock.log());
    let (status, _, body) = rdock
        .admin_send("POST", "/api/v1/config/validate", &json, &broken)
        .unwrap();
    assert_eq!(status, 200);
    let checked: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(checked["valid"], false, "{body}");
    assert_eq!(checked["diagnostics"][0]["severity"], "error", "{body}");
    assert_eq!(client::http1(proxy, get("api.test", "/")).await.status, 200);

    // The objects show their owner and survive a file reload and a restart.
    let (_, _, body) = rdock.admin_send("GET", "/api/v1/config", &[], "").unwrap();
    assert!(body.contains("\"app@api\":\"api\""), "{body}");
    let (status, _) = rdock.reload();
    assert_eq!(status, 200);
    assert_eq!(client::http1(proxy, get("api.test", "/")).await.status, 200);
    rdock.restart().unwrap();
    assert_eq!(
        client::http1(proxy, get("api.test", "/")).await.status,
        200,
        "restored after a restart"
    );

    // Roll back to the start, before the API route existed.
    let (_, _, history) = rdock
        .admin_send("GET", "/api/v1/config/history", &[], "")
        .unwrap();
    let history: serde_json::Value = serde_json::from_str(&history).unwrap();
    let oldest = history.as_array().unwrap().last().unwrap()["id"]
        .as_u64()
        .unwrap();
    let (_, head, _) = rdock
        .admin_send("GET", "/api/v1/config/api", &[], "")
        .unwrap();
    let current = etag(&head);
    let tag = [
        ("Content-Type", "application/json"),
        ("If-Match", current.as_str()),
    ];
    let body = serde_json::json!({ "id": oldest }).to_string();
    let (status, _, text) = rdock
        .admin_send("POST", "/api/v1/config/rollback", &tag, &body)
        .unwrap();
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        client::http1(proxy, get("api.test", "/")).await.status,
        404,
        "rolled back"
    );
    assert_eq!(
        client::http1(proxy, get("file.test", "/")).await.status,
        200
    );
}
