//! The adapter against a fake Cloudflare API that records every call.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use http::{Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

use super::*;

type Calls = Arc<Mutex<Vec<String>>>;

/// Answers like Cloudflare: one zone `example.com`, one existing challenge record.
async fn answer(
    request: Request<Incoming>,
    calls: Calls,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let line = format!("{} {}", request.method(), request.uri());
    let auth = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = request
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    calls.lock().unwrap().push(
        format!("{line} {}", String::from_utf8_lossy(&body))
            .trim()
            .to_owned(),
    );
    let result = if auth != "Bearer test-token" {
        json!({ "success": false, "errors": [{ "code": 10000, "message": "Authentication error" }], "result": null })
    } else if line.starts_with("GET /zones?name=example.com") {
        json!({ "success": true, "result": [{ "id": "zone1" }] })
    } else if line.starts_with("GET /zones?name=") {
        json!({ "success": true, "result": [] })
    } else if line.starts_with("GET /zones/zone1/dns_records") {
        json!({ "success": true, "result": [{ "id": "rec1" }] })
    } else {
        json!({ "success": true, "result": {} })
    };
    let status = if result["success"] == true {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };
    Ok(Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(result.to_string())))
        .unwrap())
}

async fn fake_api() -> (String, Calls) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls: Calls = Arc::default();
    let recorded = calls.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let calls = recorded.clone();
            tokio::spawn(async move {
                let service = service_fn(move |r| answer(r, calls.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), calls)
}

#[tokio::test]
async fn finds_the_zone_creates_and_removes_the_record() {
    let (api, calls) = fake_api().await;
    let dns = CloudflareDns::new(&api, "test-token", None).unwrap();
    dns.present("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    dns.cleanup("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls[0], "GET /zones?name=app.example.com");
    assert_eq!(calls[1], "GET /zones?name=example.com");
    assert_eq!(
        calls[2],
        r#"POST /zones/zone1/dns_records {"content":"v4lue","name":"_acme-challenge.app.example.com","ttl":60,"type":"TXT"}"#
    );
    assert!(calls[5].starts_with("GET /zones/zone1/dns_records?type=TXT&name=_acme-challenge.app.example.com&content=v4lue"), "{calls:?}");
    assert_eq!(calls[6], "DELETE /zones/zone1/dns_records/rec1");
}

#[tokio::test]
async fn uses_the_configured_zone_and_reports_api_errors() {
    let (api, calls) = fake_api().await;
    let dns = CloudflareDns::new(&api, "test-token", Some("zone1".into())).unwrap();
    dns.present("_acme-challenge.example.com", "x")
        .await
        .unwrap();
    assert!(calls.lock().unwrap()[0].starts_with("POST /zones/zone1/dns_records"));
    let wrong = CloudflareDns::new(&api, "wrong", Some("zone1".into())).unwrap();
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
