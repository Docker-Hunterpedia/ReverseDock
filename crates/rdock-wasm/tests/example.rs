//! The Rust example guest (`examples/plugins/wasm-header`), built for `wasm32-wasip2`, signed
//! and loaded through the same checks as a configured plugin.

#![cfg(all(feature = "wasm", feature = "testing"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use rdock_plugin_api as api;
use rdock_wasm::artifact::{self, Source};
use rdock_wasm::testing::{TestKey, build_example};
use rdock_wasm::{Facts, Grants, Limits, Plugin, Settings};

fn settings() -> Settings {
    Settings {
        name: "example".into(),
        limits: Limits {
            fuel: 10_000_000,
            timeout: Duration::from_millis(100),
            memory: 16 * 1024 * 1024,
        },
        grants: Grants::default(),
        config: "{}".into(),
    }
}

fn facts() -> Facts<'static> {
    Facts {
        client_ip: "2001:db8::1".parse().unwrap(),
        route: "app",
        request_id: "req-42",
        tls: true,
        consumer: Some("alice"),
    }
}

#[test]
fn the_example_guest_runs_signed() {
    let wasm = build_example().unwrap();
    let bytes = std::fs::read(&wasm).unwrap();
    assert_eq!(&bytes[..4], b"\0asm");
    // Sign a copy, then load it as the middleware does.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("header.wasm");
    std::fs::write(&path, &bytes).unwrap();
    let key = TestKey::new(11);
    std::fs::write(
        artifact::default_signature_path(&path),
        key.sign(&bytes, true),
    )
    .unwrap();
    let keys = [key.public()];
    let sha256 = artifact::sha256_hex(&bytes);
    let verified = artifact::load(&Source {
        path: &path,
        sha256: &sha256,
        signature: None,
        trusted_keys: &keys,
        allow_unsigned: false,
    })
    .unwrap();
    let plugin = Plugin::compile(&verified.bytes, &settings()).unwrap();

    let mut instance = plugin.instantiate().unwrap();
    let mut req = api::RequestHead::get("/app?x=1").unwrap();
    assert_eq!(instance.on_request(&facts(), &mut req).unwrap(), None);
    assert_eq!(req.header("x-wasm"), Some("yes"));
    let mut resp = api::ResponseHead::new(http::StatusCode::OK);
    instance.on_response(&facts(), &mut resp).unwrap();
    assert_eq!(resp.header("x-wasm-response"), Some("yes"));
    assert_eq!(resp.header("x-wasm-request-id"), Some("req-42"));

    let mut blocked = api::RequestHead::get("/blocked").unwrap();
    let reply = plugin
        .instantiate()
        .unwrap()
        .on_request(&facts(), &mut blocked)
        .unwrap()
        .unwrap();
    assert_eq!(reply.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(reply.body().unwrap().as_ref(), b"denied by wasm\n");
}
