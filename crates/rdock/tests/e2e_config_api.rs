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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drained_backend_gets_no_new_requests() {
    let first = Backend::start("first").await;
    let second = Backend::start("second").await;
    let port = free_port();
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes:\n  app: {{ match: \"PathPrefix(`/`)\", service: app }}\nservices:\n  app: {{ backends: [{{ address: \"{}\" }}, {{ address: \"{}\" }}] }}\n",
        first.addr, second.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));
    let body =
        serde_json::json!({ "service": "app", "backend": first.addr.to_string() }).to_string();
    let json = [("Content-Type", "application/json")];
    let (status, _, text) = rdock
        .admin_send("POST", "/api/v1/backends/drain", &json, &body)
        .unwrap();
    assert_eq!(status, 200, "{text}");
    let (_, _, list) = rdock
        .admin_send("GET", "/api/v1/backends", &[], "")
        .unwrap();
    assert!(list.contains("\"drained\":true"), "{list}");
    for _ in 0..20 {
        let reply = client::http1(proxy, get("app.test", "/")).await;
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.json()["backend"],
            "second",
            "only the other backend answers"
        );
    }
    let (status, _, _) = rdock
        .admin_send("POST", "/api/v1/backends/undrain", &json, &body)
        .unwrap();
    assert_eq!(status, 200);
    let mut seen_first = false;
    for _ in 0..20 {
        seen_first |= client::http1(proxy, get("app.test", "/")).await.json()["backend"] == "first";
    }
    assert!(seen_first, "back in rotation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cli_manages_users_tokens_backends_and_history() {
    let backend = Backend::start("cli").await;
    let port = free_port();
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes:\n  app: {{ match: \"PathPrefix(`/`)\", service: app }}\nservices:\n  app: {{ backends: [{{ address: \"{}\" }}] }}\n",
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let ok = |output: std::process::Output| {
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "{out}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        out
    };

    // The first admin over the socket, then an operator.
    let setup = serde_json::json!({ "name": "root", "password": "correct horse battery staple" })
        .to_string();
    let (status, _, _) = rdock
        .admin_send(
            "POST",
            "/api/v1/setup",
            &[("Content-Type", "application/json")],
            &setup,
        )
        .unwrap();
    assert_eq!(status, 201);
    ok(rdock.command_with_input(
        &["users", "add", "ops", "--role", "operator"],
        "another long passphrase\n",
    ));
    let listed = ok(rdock.command(&["users", "list"]));
    assert!(
        listed.contains("ops") && listed.contains("operator"),
        "{listed}"
    );
    let weak = rdock.command_with_input(&["users", "add", "weak"], "password1234\n");
    assert!(!weak.status.success(), "common passwords are refused");
    ok(rdock.command(&["users", "set", "ops", "--disable"]));
    assert!(ok(rdock.command(&["users", "list"])).contains("disabled"));
    ok(rdock.command(&["users", "remove", "ops"]));

    let created = ok(rdock.command(&["tokens", "create", "ci", "--role", "viewer", "--days", "7"]));
    assert!(created.starts_with("rdk_pat_"), "{created}");
    let id = created.split('_').nth(2).unwrap().to_owned();
    assert!(ok(rdock.command(&["tokens", "list"])).contains(&id));
    ok(rdock.command(&["tokens", "revoke", &id]));

    let backends = ok(rdock.command(&["backends", "list"]));
    assert!(backends.contains(&backend.addr.to_string()), "{backends}");
    let addr = backend.addr.to_string();
    ok(rdock.command(&["backends", "drain", "app", &addr]));
    assert!(ok(rdock.command(&["backends", "list"])).contains("drained"));
    ok(rdock.command(&["backends", "undrain", "app", &addr]));

    let history = ok(rdock.command(&["config", "history"]));
    assert!(history.contains("gen"), "{history}");
    let candidate = rdock.path("candidate.yaml");
    std::fs::write(
        &candidate,
        "routes:\n  x: { match: \"Host(`x.test`)\", service: app@file }\n",
    )
    .unwrap();
    let diff = rdock.command(&["config", "diff", candidate.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&diff.stdout);
    assert!(text.contains("+++ candidate"), "{text}");

    let audit = ok(rdock.command(&["audit", "list", "--limit", "100"]));
    for action in [
        "user.create",
        "user.delete",
        "token.create",
        "token.revoke",
        "backend.drain",
    ] {
        assert!(audit.contains(action), "{action} missing:\n{audit}");
    }
    ok(rdock.command(&["audit", "verify"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_metrics_count_requests_per_route_and_service() {
    let backend = Backend::start("live").await;
    let port = free_port();
    let config = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nroutes:\n  app: {{ match: \"Host(`app.test`)\", service: app }}\nservices:\n  app: {{ backends: [{{ address: \"{}\" }}] }}\n",
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));
    for _ in 0..25 {
        assert_eq!(client::http1(proxy, get("app.test", "/")).await.status, 200);
    }
    let (status, _, body) = rdock
        .admin_send("GET", "/api/v1/metrics/summary?window=60", &[], "")
        .unwrap();
    assert_eq!(status, 200, "{body}");
    let summary: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(summary["total"]["requests"], 25, "{summary}");
    assert_eq!(summary["total"]["classes"][1], 25);
    assert_eq!(summary["total"]["series"].as_array().unwrap().len(), 60);
    assert_eq!(summary["routes"]["app"]["requests"], 25);
    assert_eq!(summary["services"]["app"]["requests"], 25);
    assert!(summary["routes"]["app"]["p99"].as_f64().unwrap() > 0.0);
    // A reload keeps the counts: the ring belongs to the route name, not the generation.
    assert_eq!(rdock.reload().0, 200);
    let (_, _, body) = rdock
        .admin_send("GET", "/api/v1/metrics/summary?window=60", &[], "")
        .unwrap();
    let summary: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(summary["routes"]["app"]["requests"], 25);
}
