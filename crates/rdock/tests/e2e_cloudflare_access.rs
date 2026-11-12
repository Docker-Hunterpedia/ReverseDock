//! End-to-end: `cloudflare_access` (W-CF-06) against a fake Access team serving its certs in
//! Cloudflare's shape: key rotation, audience and issuer checks, expiry, header-before-cookie
//! precedence, and service tokens.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::time::Duration;

use http_body_util::Full;
use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::cloudflare_access::FakeAccess;
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use serde_json::{Value, json};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const AUD: &str = "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2";

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn with_header(token: &str) -> http::Request<Full<bytes::Bytes>> {
    let mut req = get("app.test", "/");
    req.headers_mut()
        .insert("cf-access-jwt-assertion", token.parse().unwrap());
    req.headers_mut()
        .insert("x-auth-email", "spoofed@example.com".parse().unwrap());
    req
}

fn with_cookie(req: &mut http::Request<Full<bytes::Bytes>>, token: &str) {
    req.headers_mut().insert(
        "cookie",
        format!("theme=dark; CF_Authorization={token}")
            .parse()
            .unwrap(),
    );
}

fn config(port: u16, backend: SocketAddr, access: &FakeAccess) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app, middlewares: [access] }}
middlewares:
  access:
    type: cloudflare_access
    team: acme.cloudflareaccess.com
    audience: {AUD}
    claims_to_headers: {{ email: X-Auth-Email, common_name: X-Auth-Service-Token }}
    certs_url: "{certs}"
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        certs = access.certs_url(),
    )
}

async fn status(port: u16, req: http::Request<Full<bytes::Bytes>>) -> u16 {
    client::http1(addr(port), req).await.status
}

#[tokio::test]
async fn access_tokens_are_verified_with_the_team_keys() {
    let access = FakeAccess::start("acme").await;
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr, &access));

    // No token: 401, nothing reaches the backend.
    let missing = client::http1(addr(port), get("app.test", "/")).await;
    assert_eq!(missing.status, 401);
    assert_eq!(missing.header("www-authenticate"), Some("Bearer"));

    // A user's token from the header: the claim header is set from the token.
    let alice = access.token(0, &access.user_claims(AUD, "alice@example.com"));
    let ok = client::http1(addr(port), with_header(&alice)).await;
    assert_eq!(ok.status, 200);
    let headers = &ok.json()["headers"];
    assert_eq!(headers["x-auth-email"][0], "alice@example.com");
    assert_eq!(
        headers["cf-access-jwt-assertion"][0], alice,
        "the token is forwarded for backends that check it again"
    );

    // Same team, another application's AUD tag: refused.
    let other_app = access.token(
        0,
        &access.user_claims("0000other-app-aud", "alice@example.com"),
    );
    assert_eq!(status(port, with_header(&other_app)).await, 401);
    // Expired beyond the leeway.
    let mut expired = access.user_claims(AUD, "alice@example.com");
    expired["exp"] = json!(rdock_testkit::cloudflare_access::now() - 3600);
    assert_eq!(
        status(port, with_header(&access.token(0, &expired))).await,
        401
    );
    // Another team's issuer, signed with a published key: refused.
    let mut foreign = access.user_claims(AUD, "alice@example.com");
    foreign["iss"] = json!("https://evil.cloudflareaccess.com");
    assert_eq!(
        status(port, with_header(&access.token(0, &foreign))).await,
        401
    );

    // The cookie alone works; with both, the header wins (Cloudflare's advice).
    let mut req = get("app.test", "/");
    with_cookie(&mut req, &alice);
    assert_eq!(status(port, req).await, 200);
    let mut req = with_header(&other_app);
    with_cookie(&mut req, &alice);
    assert_eq!(
        status(port, req).await,
        401,
        "a bad header is not rescued by a good cookie"
    );
    let mut req = with_header(&alice);
    with_cookie(&mut req, &other_app);
    assert_eq!(status(port, req).await, 200);

    // A service token: empty `sub`, identified by its `common_name`.
    let service = access.token(
        0,
        &access.service_claims(AUD, "88bf3b6d86161464f6509f7219099e57.access"),
    );
    let ok = client::http1(addr(port), with_header(&service)).await;
    assert_eq!(ok.status, 200);
    let headers = &ok.json()["headers"];
    assert_eq!(
        headers["x-auth-service-token"][0],
        "88bf3b6d86161464f6509f7219099e57.access"
    );
    assert!(
        headers["x-auth-email"].is_null(),
        "the spoofed copy was removed: {headers}"
    );

    // Rotation: tokens of the new key pass once it is published; the unknown key ID makes
    // rdock fetch the certs at once instead of after 10 minutes.
    access.publish(&[0, 1]);
    let rotated = access.token(1, &access.user_claims(AUD, "bob@example.com"));
    let mut passed = false;
    for _ in 0..50 {
        if status(port, with_header(&rotated)).await == 200 {
            passed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(passed, "the rotated key was never fetched");
    assert!(access.fetches() >= 2);
    assert_eq!(
        status(port, with_header(&alice)).await,
        200,
        "the old key overlaps"
    );

    let log = rdock.access_log();
    let consumer = |c: &str| {
        log.iter()
            .any(|r| r["consumer"] == json!(c) && r["status"] == json!(200))
    };
    assert!(consumer("alice@example.com"), "{log:?}");
    assert!(consumer("bob@example.com"), "{log:?}");
    assert!(
        consumer("88bf3b6d86161464f6509f7219099e57.access"),
        "{log:?}"
    );
    let users: Vec<&Value> = log.iter().map(|r| &r["user"]).collect();
    assert!(users.contains(&&json!("alice@example.com")), "{users:?}");
}

fn validate(yaml: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    std::fs::write(&file, yaml).unwrap();
    let out = std::process::Command::new(RDOCK)
        .arg("validate")
        .arg(&file)
        .output()
        .unwrap();
    assert!(!out.status.success());
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn audience_is_required_and_the_team_is_checked() {
    let text = validate(
        "middlewares:\n  a: { type: cloudflare_access, team: \"not a team!\", audience: [] }\n  c: { type: cloudflare_access, team: acme, audience: any, certs_url: \"http://certs.example.com/\" }\n",
    );
    assert!(text.contains("middlewares.a.team"), "{text}");
    assert!(text.contains("middlewares.a.audience"), "{text}");
    assert!(text.contains("middlewares.c.audience"), "{text}");
    assert!(text.contains("middlewares.c.certs_url"), "{text}");
    let text = validate("middlewares:\n  b: { type: cloudflare_access, team: acme }\n");
    assert!(text.contains("missing field `audience`"), "{text}");
}
