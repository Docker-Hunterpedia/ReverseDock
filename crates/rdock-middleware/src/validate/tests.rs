#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]

use bytes::Bytes;
use rdock_model::validation::{PathParameters, UnknownOperations, ValidateConfig, ValidationMode};
use serde_json::{Value, json};

use super::*;
use crate::test_support::{block_on, cx, reply_header, request};

fn config(value: Value) -> ValidateConfig {
    serde_json::from_value(value).unwrap()
}

fn mw(value: Value) -> Validate {
    Validate::new("v", &config(value), None).unwrap()
}

fn issues(value: Value) -> Vec<Issue> {
    match Validate::new("v", &config(value), None) {
        Err(BuildError::Issues(issues)) => issues,
        other => panic!("expected issues, got {other:?}"),
    }
}

/// Runs the request phase, and the body phase when the request phase asked for it.
fn run(
    mw: &Validate,
    method: &str,
    target: &str,
    headers: &[(&'static str, &str)],
    body: Option<&str>,
) -> Option<Reply> {
    let mut req = request(method, target, headers);
    let mut cx = cx();
    cx.has_body = body.is_some();
    match block_on(mw.request(&mut req, &mut cx)) {
        Flow::Reply(reply) => return Some(reply),
        Flow::Next => {}
    }
    let body = body?;
    let held = HeldBody::from_bytes(Bytes::from(body.to_owned()));
    match block_on(mw.request_body(&held, &mut cx)) {
        BodyVerdict::Reply(reply) => Some(reply),
        _ => None,
    }
}

fn errors(reply: &Reply) -> Vec<(String, String)> {
    let ext = reply.extensions.as_ref().unwrap();
    ext["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["pointer"].as_str().unwrap().to_owned(),
                e["message"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn query_parameters_are_converted_and_checked() {
    let mw = mw(json!({
        "query": {
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "maximum": 100 },
                "tag": { "type": "array", "items": { "type": "string" } },
                "active": { "type": "boolean" }
            },
            "required": ["limit"],
            "additionalProperties": false
        }
    }));
    assert_eq!(
        run(
            &mw,
            "GET",
            "/items?limit=10&tag=a&tag=b&active=true",
            &[],
            None
        ),
        None
    );
    let reply = run(&mw, "GET", "/items?limit=500", &[], None).unwrap();
    assert_eq!(reply.status, 400);
    assert_eq!(reply.problem, Some(ProblemKind::ValidationFailed));
    let list = errors(&reply);
    assert_eq!(
        list,
        vec![("/query/limit".to_owned(), "must be at most 100".to_owned())]
    );
    let reply = run(&mw, "GET", "/items?limit=ten", &[], None).unwrap();
    assert_eq!(errors(&reply)[0].1, "must be of type integer");
    let reply = run(&mw, "GET", "/items", &[], None).unwrap();
    assert_eq!(
        errors(&reply)[0],
        ("/query".to_owned(), "`limit` is required".to_owned())
    );
    // A repeated scalar parameter is refused (parameter pollution).
    let reply = run(&mw, "GET", "/items?limit=1&limit=2", &[], None).unwrap();
    assert_eq!(errors(&reply)[0].0, "/query/limit");
    let reply = run(&mw, "GET", "/items?limit=1&debug=1", &[], None).unwrap();
    assert_eq!(errors(&reply)[0].1, "has members the schema does not allow");
}

#[test]
fn messages_never_echo_the_value() {
    let mw = mw(json!({
        "headers": {
            "type": "object",
            "properties": { "x-token": { "type": "string", "pattern": "^tok_[a-z]{4}$" } }
        },
        "body": {
            "type": "object",
            "properties": {
                "password": { "type": "string", "maxLength": 4 },
                "role": { "enum": ["user", "admin"] }
            }
        }
    }));
    let reply = run(
        &mw,
        "POST",
        "/login",
        &[
            ("x-token", "s3cr3t-header"),
            ("content-type", "application/json"),
        ],
        None,
    )
    .unwrap();
    let text = format!("{:?}", reply.extensions);
    assert!(!text.contains("s3cr3t"), "{text}");
    let reply = run(
        &mw,
        "POST",
        "/login",
        &[("content-type", "application/json")],
        Some(r#"{"password": "hunter2-secret", "role": "root-secret"}"#),
    )
    .unwrap();
    let text = format!("{:?}", reply.extensions);
    assert!(
        !text.contains("hunter2") && !text.contains("root-secret"),
        "{text}"
    );
    assert_eq!(
        errors(&reply),
        vec![
            (
                "/body/password".to_owned(),
                "must be at most 4 characters long".to_owned()
            ),
            (
                "/body/role".to_owned(),
                "is not an allowed value".to_owned()
            ),
        ]
    );
}

#[test]
fn bodies_need_json() {
    let mw = mw(json!({
        "body": { "type": "object", "required": ["name"] },
        "body_required": true
    }));
    let json_type = [("content-type", "application/json; charset=utf-8")];
    assert_eq!(
        run(&mw, "POST", "/", &json_type, Some(r#"{"name": "a"}"#)),
        None
    );
    let reply = run(&mw, "POST", "/", &json_type, Some(r#"{"other": 1}"#)).unwrap();
    assert_eq!(
        errors(&reply)[0],
        ("/body".to_owned(), "`name` is required".to_owned())
    );
    let reply = run(&mw, "POST", "/", &json_type, Some("{not json")).unwrap();
    assert_eq!(reply.status, 400);
    assert_eq!(errors(&reply)[0].1, "is not valid JSON");
    let reply = run(
        &mw,
        "POST",
        "/",
        &[("content-type", "text/plain")],
        Some("x"),
    )
    .unwrap();
    assert_eq!(reply.status, 415);
    assert_eq!(reply.problem, Some(ProblemKind::UnsupportedMediaType));
    let reply = run(&mw, "POST", "/", &[], Some("x")).unwrap();
    assert_eq!(reply.status, 415);
    let reply = run(&mw, "POST", "/", &json_type, None).unwrap();
    assert_eq!(errors(&reply)[0].1, "a request body is required");
    // The hold follows `max_body`.
    let caps = mw.capabilities();
    assert_eq!(caps.body().unwrap().max, 1024 * 1024);
    assert!(!caps.body().unwrap().replaces);
}

#[test]
fn errors_are_capped() {
    let mw = mw(json!({
        "body": {
            "type": "object",
            "properties": {
                "a": { "type": "integer" }, "b": { "type": "integer" },
                "c": { "type": "integer" }, "d": { "type": "integer" }
            }
        },
        "max_errors": 2
    }));
    let reply = run(
        &mw,
        "POST",
        "/",
        &[("content-type", "application/json")],
        Some(r#"{"a": "x", "b": "x", "c": "x", "d": "x"}"#),
    )
    .unwrap();
    assert_eq!(errors(&reply).len(), 2);
    assert_eq!(reply.extensions.as_ref().unwrap()["errors_truncated"], true);
}

#[test]
fn path_parameters_come_from_named_groups() {
    let c = ValidateConfig {
        path: Some(PathParameters {
            regex: "^/users/(?<id>[^/]+)$".to_owned(),
            schema: json!({ "type": "object", "properties": { "id": { "type": "integer", "minimum": 1 } } }),
        }),
        ..ValidateConfig::default()
    };
    let mw = Validate::new("v", &c, None).unwrap();
    assert_eq!(run(&mw, "GET", "/users/42", &[], None), None);
    let reply = run(&mw, "GET", "/users/0", &[], None).unwrap();
    assert_eq!(
        errors(&reply)[0],
        ("/path/id".to_owned(), "must be at least 1".to_owned())
    );
    let reply = run(&mw, "GET", "/teams/1", &[], None).unwrap();
    assert_eq!(
        errors(&reply)[0],
        (
            "/path".to_owned(),
            "does not match the path pattern".to_owned()
        )
    );
}

#[test]
fn formats_are_asserted_by_default() {
    let schema = json!({
        "type": "object",
        "properties": { "email": { "type": "string", "format": "email" } }
    });
    let strict = mw(json!({ "query": schema }));
    let reply = run(&strict, "GET", "/?email=nope", &[], None).unwrap();
    assert_eq!(errors(&reply)[0].1, "is not a valid `email`");
    let lax = mw(json!({ "query": schema, "formats": false }));
    assert_eq!(run(&lax, "GET", "/?email=nope", &[], None), None);
}

#[test]
fn report_mode_lets_invalid_requests_through() {
    let mut c = config(
        json!({ "query": { "type": "object", "properties": { "n": { "type": "integer" } } } }),
    );
    c.mode = ValidationMode::Report;
    let mw = Validate::new("v", &c, None).unwrap();
    assert_eq!(run(&mw, "GET", "/?n=x", &[], None), None);
}

#[test]
fn schemas_that_do_not_compile_or_refer_outside_are_refused() {
    let found = issues(json!({ "query": { "type": 5 } }));
    assert_eq!(found[0].path, "query");
    assert!(
        found[0].message.contains("does not compile"),
        "{:?}",
        found[0]
    );
    let found = issues(json!({ "body": { "$ref": "https://example.com/schema.json" } }));
    assert_eq!(found[0].path, "body");
    let found = issues(json!({ "path": { "regex": "(", "schema": true } }));
    assert_eq!(found[0].path, "path.regex");
}

fn document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": { "title": "t", "version": "1" },
        "paths": {
            "/items": {
                "get": {
                    "parameters": [
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "maximum": 50 } }
                    ]
                },
                "post": {
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": { "schema": { "$ref": "#/components/schemas/Item" } }
                        }
                    }
                }
            },
            "/items/{id}": {
                "parameters": [
                    { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }
                ],
                "get": {},
                "delete": {
                    "parameters": [
                        { "name": "X-Reason", "in": "header", "required": true, "schema": { "type": "string" } }
                    ]
                }
            },
            "/items/latest": { "get": {} },
            "/upload": {
                "put": {
                    "requestBody": { "content": { "application/octet-stream": {} } }
                }
            }
        },
        "components": {
            "schemas": {
                "Item": {
                    "type": "object",
                    "required": ["name"],
                    "properties": { "name": { "type": "string", "minLength": 1 } }
                }
            }
        }
    })
}

fn router(unknown: UnknownOperations, base: Option<&str>) -> Validate {
    let router = openapi::Router::from_document(&document(), base, unknown, true).unwrap();
    Validate {
        name: Arc::from("v"),
        spec: Spec::OpenApi(router),
        mode: ValidationMode::Enforce,
        max_errors: 5,
        max_body: 1 << 20,
        metrics: None,
    }
}

#[test]
fn openapi_operations_are_matched_and_checked() {
    let mw = router(UnknownOperations::Deny, None);
    let json_type = [("content-type", "application/json")];
    assert_eq!(run(&mw, "GET", "/items?limit=5", &[], None), None);
    assert_eq!(run(&mw, "HEAD", "/items", &[], None), None);
    let reply = run(&mw, "GET", "/items?limit=500", &[], None).unwrap();
    assert_eq!(errors(&reply)[0].0, "/query/limit");
    assert_eq!(run(&mw, "GET", "/items/7", &[], None), None);
    let reply = run(&mw, "GET", "/items/seven", &[], None).unwrap();
    assert_eq!(
        errors(&reply)[0],
        ("/path/id".to_owned(), "must be of type integer".to_owned())
    );
    // A concrete path wins over a template.
    assert_eq!(run(&mw, "GET", "/items/latest", &[], None), None);
    let reply = run(&mw, "DELETE", "/items/7", &[], None).unwrap();
    assert_eq!(errors(&reply)[0].1, "`x-reason` is required");
    assert_eq!(
        run(&mw, "DELETE", "/items/7", &[("x-reason", "old")], None),
        None
    );
    assert_eq!(
        run(&mw, "POST", "/items", &json_type, Some(r#"{"name": "a"}"#)),
        None
    );
    let reply = run(&mw, "POST", "/items", &json_type, Some(r#"{"name": ""}"#)).unwrap();
    assert_eq!(errors(&reply)[0].0, "/body/name");
    let reply = run(
        &mw,
        "POST",
        "/items",
        &[("content-type", "text/xml")],
        Some("<a/>"),
    )
    .unwrap();
    assert_eq!(reply.status, 415);
    let reply = run(&mw, "POST", "/items", &json_type, None).unwrap();
    assert_eq!(errors(&reply)[0].1, "a request body is required");
    // Media types without a schema are accepted as they are.
    assert_eq!(
        run(
            &mw,
            "PUT",
            "/upload",
            &[("content-type", "application/octet-stream")],
            Some("..")
        ),
        None
    );
    // Unknown operations.
    let reply = run(&mw, "GET", "/nothing", &[], None).unwrap();
    assert_eq!(reply.status, 404);
    let reply = run(&mw, "PATCH", "/items", &[], None).unwrap();
    assert_eq!(reply.status, 405);
    assert_eq!(reply_header(&reply, "allow"), Some("GET, POST"));
    let open = router(UnknownOperations::Allow, None);
    assert_eq!(run(&open, "GET", "/nothing", &[], None), None);
    assert_eq!(run(&open, "PATCH", "/items", &[], None), None);
}

#[test]
fn openapi_paths_can_live_below_a_base_path() {
    let mw = router(UnknownOperations::Deny, Some("/api"));
    assert_eq!(run(&mw, "GET", "/api/items/3", &[], None), None);
    assert_eq!(run(&mw, "GET", "/items/3", &[], None).unwrap().status, 404);
    assert_eq!(
        run(&mw, "GET", "/apiitems/3", &[], None).unwrap().status,
        404
    );
}

#[test]
fn openapi_documents_are_checked_when_loaded() {
    let load = |doc: Value| {
        openapi::Router::from_document(&doc, None, UnknownOperations::Deny, true).map(|_| ())
    };
    let mut old = document();
    old["openapi"] = json!("3.0.3");
    assert!(load(old).unwrap_err()[0].contains("only OpenAPI 3.1"));
    let mut remote = document();
    remote["components"]["schemas"]["Item"] = json!({ "$ref": "https://example.com/item.json" });
    assert!(load(remote).unwrap_err()[0].contains("outside the document"));
    let mut styled = document();
    styled["paths"]["/items"]["get"]["parameters"][0]["style"] = json!("pipeDelimited");
    assert!(load(styled).unwrap_err()[0].contains("planned for a later version"));
    let mut broken = document();
    broken["components"]["schemas"]["Item"]["type"] = json!(7);
    assert!(load(broken).unwrap_err()[0].contains("does not compile"));
}

#[test]
fn openapi_files_are_read_as_yaml_or_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.yaml");
    std::fs::write(
        &path,
        "openapi: 3.1.0\ninfo: { title: t, version: '1' }\npaths:\n  /ping:\n    get: {}\n",
    )
    .unwrap();
    let mw = mw(json!({ "openapi": path }));
    assert_eq!(run(&mw, "GET", "/ping", &[], None), None);
    assert_eq!(run(&mw, "GET", "/pong", &[], None).unwrap().status, 404);
    assert!(
        !mw.capabilities()
            .phases()
            .contains(crate::Phases::REQUEST_BODY)
    );
    let missing = issues_or_file(json!({ "openapi": dir.path().join("none.yaml") }));
    assert!(missing.contains("cannot read"), "{missing}");
}

fn issues_or_file(value: Value) -> String {
    match Validate::new("v", &config(value), None) {
        Err(e) => e.to_string(),
        Ok(_) => String::new(),
    }
}
