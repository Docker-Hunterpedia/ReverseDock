#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]

use rdock_model::transform::TransformConfig;
use serde_json::{Value, json};

use super::*;
use crate::test_support::{block_on, cx, header, request};

fn mw(value: Value) -> Transform {
    let config: TransformConfig = serde_json::from_value(value).unwrap();
    Transform::new("t", &config, None).unwrap()
}

/// Runs the request phases; returns the reply, or the body forwarded (`None`: unchanged).
fn send(mw: &Transform, content_type: Option<&str>, body: &str) -> Result<Option<String>, Reply> {
    let headers: Vec<(&'static str, &str)> = content_type
        .map(|t| ("content-type", t))
        .into_iter()
        .collect();
    let mut req = request("POST", "/", &headers);
    let mut cx = cx();
    cx.has_body = !body.is_empty();
    if let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx)) {
        return Err(reply);
    }
    let held = HeldBody::from_bytes(Bytes::from(body.to_owned()));
    match block_on(mw.request_body(&held, &mut cx)) {
        BodyVerdict::Continue => Ok(None),
        BodyVerdict::Replace(bytes) => Ok(Some(String::from_utf8(bytes.to_vec()).unwrap())),
        BodyVerdict::Reply(reply) => Err(reply),
    }
}

#[test]
fn request_bodies_are_patched() {
    let mw = mw(json!({
        "request": {
            "headers": { "set": { "x-api-version": "2" }, "remove": ["x-debug"] },
            "body": { "patch": [
                { "op": "remove", "path": "/debug" },
                { "op": "add", "path": "/source", "value": "gateway" }
            ] }
        }
    }));
    let caps = mw.capabilities();
    assert!(caps.body().unwrap().replaces);
    assert_eq!(caps.body().unwrap().max, 1 << 20);
    let out = send(&mw, Some("application/json"), r#"{"a": 1, "debug": true}"#)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&out).unwrap(),
        json!({"a": 1, "source": "gateway"})
    );
    // Non-JSON bodies pass untouched by default.
    assert_eq!(send(&mw, Some("text/plain"), "debug=1"), Ok(None));
    // Header rules apply to every request.
    let mut req = request("GET", "/", &[("x-debug", "1")]);
    let mut cx = cx();
    assert_eq!(block_on(mw.request(&mut req, &mut cx)), Flow::Next);
    assert_eq!(header(&req.headers, "x-api-version"), Some("2"));
    assert_eq!(header(&req.headers, "x-debug"), None);
}

#[test]
fn failed_patches_reject_or_pass() {
    let patch = json!([
        { "op": "test", "path": "/version", "value": 1 },
        { "op": "replace", "path": "/version", "value": 2 }
    ]);
    let strict = mw(json!({ "request": { "body": { "patch": patch } } }));
    let reply = send(
        &strict,
        Some("application/json"),
        r#"{"version": 3, "secret": "s3cr3t"}"#,
    )
    .unwrap_err();
    assert_eq!(reply.status, 422);
    assert_eq!(reply.problem, Some(ProblemKind::PatchFailed));
    let text = format!("{:?}", reply.extensions);
    assert!(
        text.contains("\"op\": String(\"test\")") || text.contains("test"),
        "{text}"
    );
    assert!(!text.contains("s3cr3t"), "{text}");
    let lax = mw(json!({ "request": { "body": { "patch": patch } }, "on_error": "pass" }));
    assert_eq!(
        send(&lax, Some("application/json"), r#"{"version": 3}"#),
        Ok(None)
    );
    let missing =
        mw(json!({ "request": { "body": { "patch": [{ "op": "remove", "path": "/a/b" }] } } }));
    assert_eq!(
        send(&missing, Some("application/json"), "{}")
            .unwrap_err()
            .status,
        422
    );
}

#[test]
fn non_json_can_be_rejected() {
    let mw = mw(json!({
        "request": { "body": { "patch": [{ "op": "add", "path": "/x", "value": 1 }] } },
        "on_non_json": "reject"
    }));
    assert_eq!(send(&mw, Some("text/plain"), "x").unwrap_err().status, 415);
    assert_eq!(send(&mw, None, "x").unwrap_err().status, 415);
    assert_eq!(
        send(&mw, Some("application/json"), "{oops")
            .unwrap_err()
            .status,
        400
    );
}

#[test]
fn bad_patches_do_not_build() {
    let config: TransformConfig = serde_json::from_value(json!({
        "response": { "body": { "patch": [{ "op": "move", "from": "/a", "path": "/a/b" }, { "op": "add", "path": "x", "value": 1 }] } }
    }))
    .unwrap();
    let Err(BuildError::Issues(issues)) = Transform::new("t", &config, None) else {
        panic!("expected issues");
    };
    assert_eq!(issues[0].path, "response.body.patch[0]");
    assert_eq!(issues[1].path, "response.body.patch[1]");
}

fn response(status: u16, headers: &[(&'static str, &str)]) -> ResponseHeader {
    let mut resp = ResponseHeader::build(status, None).unwrap();
    for (name, value) in headers {
        resp.insert_header(*name, *value).unwrap();
    }
    resp
}

/// Runs a response through the middleware in `chunks`; returns the head and the body sent.
fn receive(mw: &Transform, mut resp: ResponseHeader, chunks: &[&str]) -> (ResponseHeader, String) {
    let mut cx = cx();
    let mut req = request("GET", "/", &[]);
    block_on(mw.request(&mut req, &mut cx));
    block_on(mw.response(&mut resp, &mut cx));
    let mut out = String::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let mut body = Some(Bytes::from((*chunk).to_owned()));
        mw.response_body(&mut body, i + 1 == chunks.len(), &mut cx);
        if let Some(bytes) = body {
            out.push_str(std::str::from_utf8(&bytes).unwrap());
        }
    }
    (resp, out)
}

fn response_mw() -> Transform {
    mw(json!({
        "response": {
            "headers": { "set": { "x-patched": "1" } },
            "body": { "patch": [
                { "op": "remove", "path": "/internal" },
                { "op": "move", "from": "/n", "path": "/count" }
            ] }
        },
        "max_body": "1KiB"
    }))
}

#[test]
fn response_bodies_are_patched_when_eligible() {
    let mw = response_mw();
    assert!(mw.capabilities().phases().contains(Phases::RESPONSE_BODY));
    let (head, body) = receive(
        &mw,
        response(
            200,
            &[
                ("content-type", "application/json"),
                ("content-length", "27"),
                ("etag", "\"abc\""),
            ],
        ),
        &[r#"{"n": 2, "#, r#""internal": "x"}"#],
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"count": 2})
    );
    assert_eq!(header(&head.headers, "content-length"), None);
    assert_eq!(header(&head.headers, "etag"), None);
    assert_eq!(header(&head.headers, "x-patched"), Some("1"));
}

#[test]
fn other_responses_pass_unchanged() {
    let mw = response_mw();
    let original = r#"{"n": 2, "internal": "x"}"#;
    for (status, headers) in [
        (200, vec![("content-type", "text/html")]),
        (
            200,
            vec![
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
            ],
        ),
        (
            200,
            vec![
                ("content-type", "application/json"),
                ("content-length", "4096"),
            ],
        ),
        (206, vec![("content-type", "application/json")]),
        (404, vec![("content-type", "application/problem+json")]),
    ] {
        let (head, body) = receive(&mw, response(status, &headers), &[original]);
        assert_eq!(body, original, "{status} {headers:?}");
        assert_eq!(header(&head.headers, "x-patched"), Some("1"));
    }
    // A failing patch and invalid JSON leave the body as it was.
    let (_, body) = receive(
        &mw,
        response(200, &[("content-type", "application/json")]),
        &[r#"{"m": 1}"#],
    );
    assert_eq!(body, r#"{"m": 1}"#);
    let (_, body) = receive(
        &mw,
        response(200, &[("content-type", "application/json")]),
        &["{no"],
    );
    assert_eq!(body, "{no");
    // Without a length, a body that grows past the cap is sent as it came.
    let big = format!(r#"{{"n": 1, "pad": "{}"}}"#, "x".repeat(1100));
    let (_, body) = receive(
        &mw,
        response(200, &[("content-type", "application/json")]),
        &[&big[..600], &big[600..]],
    );
    assert_eq!(body, big);
}
