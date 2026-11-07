//! The REST client against the fake API: retries, waits and error mapping.

use std::time::Instant;

use rdock_testkit::fake_api::{FakeApi, Reply};
use serde_json::json;

use super::*;

fn message(answer: &Value) -> Option<String> {
    answer["message"].as_str().map(str::to_owned)
}

async fn client() -> (FakeApi, RestClient) {
    let api = FakeApi::start().await;
    let client = RestClient::new("Test API", api.url(), "secret-token", message).unwrap();
    (api, client)
}

#[test]
fn server_waits_come_from_retry_after_or_the_rate_limit_reset() {
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let headers = |pairs: &[(&'static str, &str)]| {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    };
    let too_many = StatusCode::TOO_MANY_REQUESTS;
    assert_eq!(
        server_wait(too_many, &headers(&[("retry-after", "7")]), now),
        Some(Duration::from_secs(7))
    );
    let date = httpdate::fmt_http_date(now + Duration::from_secs(12));
    assert_eq!(
        server_wait(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers(&[("retry-after", &date)]),
            now
        ),
        Some(Duration::from_secs(12))
    );
    assert_eq!(
        server_wait(
            too_many,
            &headers(&[("ratelimit-reset", "1800000020")]),
            now
        ),
        Some(Duration::from_secs(20))
    );
    assert_eq!(
        server_wait(too_many, &headers(&[("RateLimit-Reset", "3")]), now),
        Some(Duration::from_secs(3))
    );
    assert_eq!(
        server_wait(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers(&[("ratelimit-reset", "1800000020")]),
            now
        ),
        None,
        "the reset time only matters when the limit is reached"
    );
}

#[tokio::test]
async fn honours_retry_after_then_succeeds() {
    let (api, client) = client().await;
    api.route("GET", "/x", |_, _| Reply::json(200, json!({ "ok": true })));
    api.fail("GET", "/x", 1, Reply::too_many_requests(1));
    let started = Instant::now();
    assert_eq!(client.get("/x").await.unwrap(), json!({ "ok": true }));
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "waited as asked"
    );
    let requests = api.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[1].header("authorization"),
        Some("Bearer secret-token")
    );
}

#[tokio::test]
async fn fails_at_once_when_the_limit_resets_too_late() {
    let (api, client) = client().await;
    let reset = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    api.fail(
        "GET",
        "/x",
        1,
        Reply::json(429, json!({ "message": "slow down" }))
            .header("ratelimit-reset", &reset.to_string()),
    );
    let error = client.get("/x").await.unwrap_err();
    assert!(matches!(error, RestError::RateLimited { .. }), "{error}");
    assert_eq!(api.requests().len(), 1);
}

#[tokio::test]
async fn gives_up_after_five_attempts() {
    let (api, client) = client().await;
    api.fail(
        "POST",
        "/x",
        10,
        Reply::json(503, json!({ "message": "down" })).header("retry-after", "0"),
    );
    let error = client.post("/x", &json!({})).await.unwrap_err();
    assert_eq!(api.requests().len(), 5);
    assert_eq!(
        error.to_string(),
        "Test API POST /x answered 503 Service Unavailable: down"
    );
}

#[tokio::test]
async fn client_errors_are_final_and_never_show_the_token() {
    let (api, client) = client().await;
    api.route("DELETE", "/x", |_, _| {
        Reply::json(401, json!({ "message": "Unable to authenticate you" }))
    });
    let error = client.delete("/x").await.unwrap_err();
    assert_eq!(api.requests().len(), 1);
    let text = error.to_string();
    assert!(
        text.contains("401 Unauthorized: Unable to authenticate you"),
        "{text}"
    );
    assert!(!text.contains("secret-token"));
}

#[tokio::test]
async fn empty_answers_are_null_and_bad_json_is_an_error() {
    let (api, client) = client().await;
    api.route("DELETE", "/empty", |_, _| Reply::status(204));
    api.route("GET", "/html", |_, _| Reply::status(200).body("<html>"));
    assert_eq!(client.delete("/empty").await.unwrap(), Value::Null);
    assert!(matches!(
        client.get("/html").await.unwrap_err(),
        RestError::NotJson { .. }
    ));
}

#[test]
fn segments_are_escaped() {
    assert_eq!(segment("_acme-challenge.app"), "_acme-challenge.app");
    assert_eq!(segment("a/b c"), "a%2Fb%20c");
}

fn transient_code(body: &[u8]) -> ProviderError {
    let text = String::from_utf8_lossy(body);
    ProviderError {
        transient: text.contains("Throttling"),
        message: Some(text.into_owned()),
    }
}

#[tokio::test]
async fn providers_can_mark_client_errors_as_transient() {
    let api = FakeApi::start().await;
    let client = RestClient::with(
        "Raw API",
        api.url(),
        Arc::new(StaticToken::new("Token", "t0ken", "token")),
        ErrorFormat::Raw(transient_code),
    )
    .unwrap();
    api.route("POST", "/x", |_, _| Reply::status(200).body("<ok/>"));
    api.fail("POST", "/x", 1, Reply::status(400).body("Throttling"));
    api.route("GET", "/bad", |_, _| Reply::status(400).body("Invalid"));
    let body = Body::new("application/xml", "<x/>");
    let answer = client
        .send(Method::POST, "/x", &[], Some(body))
        .await
        .unwrap();
    assert_eq!(answer, Bytes::from_static(b"<ok/>"));
    let requests = api.requests();
    assert_eq!(requests.len(), 2, "the transient 400 was retried");
    assert_eq!(requests[1].header("authorization"), Some("Token t0ken"));
    assert_eq!(requests[1].header("content-type"), Some("application/xml"));
    let error = client
        .send(Method::GET, "/bad", &[], None)
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::BAD_REQUEST));
    assert_eq!(api.requests().len(), 3, "other 400s are final");
}

#[tokio::test]
async fn forms_and_extra_headers_are_sent() {
    let (api, client) = client().await;
    api.route("POST", "/token", |request, _| {
        Reply::json(
            200,
            json!({ "body": String::from_utf8_lossy(&request.body) }),
        )
    });
    api.route("PUT", "/x", |request, _| {
        Reply::json(200, json!({ "if-match": request.header("if-match") }))
    });
    let answer = client
        .post_form("/token", &[("scope", "https://x/.default"), ("a b", "c+d")])
        .await
        .unwrap();
    assert_eq!(
        answer["body"],
        "scope=https%3A%2F%2Fx%2F.default&a%20b=c%2Bd"
    );
    let answer = client
        .json(
            Method::PUT,
            "/x",
            &[("if-match", "etag-1")],
            Some(&json!({})),
        )
        .await
        .unwrap();
    assert_eq!(answer["if-match"], "etag-1");
    assert_eq!(
        api.requests()[0].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
}

#[tokio::test]
async fn unreadable_credentials_fail_before_sending() {
    let api = FakeApi::start().await;
    let client = RestClient::new(
        "Test API",
        api.url(),
        "${file:/nonexistent/rdock-test-token}",
        message,
    )
    .unwrap();
    let error = client.get("/x").await.unwrap_err();
    assert!(matches!(error, RestError::Credentials(_)), "{error}");
    assert!(error.to_string().starts_with("api_token:"), "{error}");
    assert!(api.requests().is_empty());
}
