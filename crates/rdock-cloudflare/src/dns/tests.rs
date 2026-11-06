//! The adapter against a fake Cloudflare API that records every call.

use rdock_testkit::fake_api::{FakeApi, Reply};

use super::*;

/// Answers like Cloudflare: one zone `example.com`, one existing challenge record.
async fn fake_api() -> FakeApi {
    let api = FakeApi::start().await;
    api.guard(|request| {
        (request.header("authorization") != Some("Bearer test-token")).then(|| {
            Reply::json(
                403,
                json!({ "success": false, "errors": [{ "code": 10000, "message": "Authentication error" }], "result": null }),
            )
        })
    });
    api.route("GET", "/zones", |request, _| {
        let zones = if request.query_param("name").as_deref() == Some("example.com") {
            json!([{ "id": "zone1" }])
        } else {
            json!([])
        };
        Reply::json(200, json!({ "success": true, "result": zones }))
    });
    api.route("GET", "/zones/zone1/dns_records", |_, _| {
        Reply::json(
            200,
            json!({ "success": true, "result": [{ "id": "rec1" }] }),
        )
    });
    for method in ["POST", "DELETE"] {
        api.route(method, "/zones/zone1/dns_records", |_, _| {
            Reply::json(200, json!({ "success": true, "result": {} }))
        });
        api.route(method, "/zones/zone1/dns_records/{id}", |_, _| {
            Reply::json(200, json!({ "success": true, "result": {} }))
        });
    }
    api
}

#[tokio::test]
async fn finds_the_zone_creates_and_removes_the_record() {
    let api = fake_api().await;
    let dns = CloudflareDns::new(api.url(), "test-token", None).unwrap();
    dns.present("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    dns.cleanup("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    let calls = api.requests();
    let lines = api.lines();
    assert_eq!(lines[0], "GET /zones?name=app.example.com");
    assert_eq!(lines[1], "GET /zones?name=example.com");
    assert_eq!(lines[2], "POST /zones/zone1/dns_records");
    assert_eq!(
        calls[2].body,
        r#"{"content":"v4lue","name":"_acme-challenge.app.example.com","ttl":60,"type":"TXT"}"#
    );
    assert!(
        lines[5].starts_with(
            "GET /zones/zone1/dns_records?type=TXT&name=_acme-challenge.app.example.com&content=v4lue"
        ),
        "{lines:?}"
    );
    assert_eq!(lines[6], "DELETE /zones/zone1/dns_records/rec1");
}

#[tokio::test]
async fn uses_the_configured_zone_and_reports_api_errors() {
    let api = fake_api().await;
    let dns = CloudflareDns::new(api.url(), "test-token", Some("zone1".into())).unwrap();
    dns.present("_acme-challenge.example.com", "x")
        .await
        .unwrap();
    assert!(api.lines()[0].starts_with("POST /zones/zone1/dns_records"));
    let wrong = CloudflareDns::new(api.url(), "wrong", Some("zone1".into())).unwrap();
    let error = wrong
        .present("_acme-challenge.example.com", "x")
        .await
        .unwrap_err();
    assert!(error.0.contains("Authentication error (10000)"), "{error}");
    assert!(
        !error.0.contains("wrong"),
        "the token never appears in errors"
    );
}
