//! End-to-end: `oidc` login (F-GW-01, ADR-0030) against the fake provider in `rdock-testkit`,
//! driven by a cookie-keeping client: the full authorization code flow with PKCE, what the
//! backend sees, `401` for API requests, refused ID tokens (nonce, audience, issuer, expiry,
//! `alg: none`), state checks, open-redirect attempts, `allowed`, consumer limits after login,
//! refresh, expiry, logout, replicas sharing a key, key rotation, an unavailable provider, and
//! the settings validation refuses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use rdock_testkit::backend::Backend;
use rdock_testkit::client;
use rdock_testkit::free_port;
use rdock_testkit::oidc::{Browser, FakeIdp, User};
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const CLIENT: &str = "rdock-test";
const SECRET: &str = "test-client-secret-not-a-real-one";
const KEY_A: &str = "session-key-a-for-tests-only-0123456789abcdef";
const KEY_B: &str = "session-key-b-for-tests-only-0123456789abcdef";
const SESSION: &str = "__Host-rdock_oidc";
const HTML: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Writes the client secret and both session keys next to the test.
fn secrets(dir: &Path) {
    std::fs::write(dir.join("client_secret"), SECRET).unwrap();
    std::fs::write(dir.join("key_a"), KEY_A).unwrap();
    std::fs::write(dir.join("key_b"), KEY_B).unwrap();
}

/// A configuration with `login` on `app.test` and `quota.test`; `session` is the YAML of the
/// session's key settings, `extra` more middleware settings.
fn config(
    port: u16,
    backend: SocketAddr,
    idp: &FakeIdp,
    dir: &Path,
    session: &str,
    extra: &str,
) -> String {
    let dir = dir.display();
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "Host(`app.test`)", service: app, middlewares: [login, burst] }}
  quota: {{ match: "Host(`quota.test`)", service: app, middlewares: [login, daily] }}
  corp: {{ match: "Host(`corp.test`)", service: app, middlewares: [corp_login] }}
middlewares:
  login:
    type: oidc
    issuer: "{issuer}"
    client_id: {CLIENT}
    client_secret: "${{file:{dir}/client_secret}}"
    allow_private_targets: true
    claims_to_headers: {{ email: X-Auth-Email, groups: X-Auth-Groups }}
    session: {{ {session} }}
{extra}
  corp_login:
    type: oidc
    issuer: "{issuer}"
    client_id: {CLIENT}
    client_secret: "${{file:{dir}/client_secret}}"
    token_endpoint_auth: client_secret_post
    allow_private_targets: true
    allowed: {{ domains: [corp.example], groups: [admins] }}
    session: {{ cookie_name: corp, key: "${{file:{dir}/key_a}}" }}
  burst: {{ type: rate_limit, key: consumer, average: 4, period: 1m, overrides: {{ vip: {{ average: 100 }} }} }}
  daily: {{ type: quota, limit: 2, window: day }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        issuer = idp.issuer(),
    )
}

fn key_a(dir: &Path) -> String {
    format!("key: \"${{file:{}/key_a}}\"", dir.display())
}

/// Sends a request with the browser's cookies and takes the cookies of the answer.
async fn send(
    port: u16,
    host: &str,
    target: &str,
    browser: &mut Browser,
    html: bool,
) -> client::Reply {
    let mut req = client::get(host, target);
    if html {
        req.headers_mut().insert("accept", HTML.parse().unwrap());
    } else {
        req.headers_mut()
            .insert("accept", "application/json".parse().unwrap());
    }
    req.headers_mut()
        .insert("x-auth-email", "spoofed@example.com".parse().unwrap());
    if let Some(cookie) = browser.header() {
        req.headers_mut().insert("cookie", cookie.parse().unwrap());
    }
    let reply = client::http1(addr(port), req).await;
    browser.absorb(&reply.headers);
    reply
}

/// The path and query of an absolute URL.
fn path_of(url: &str) -> String {
    let uri: http::Uri = url.parse().unwrap();
    uri.path_and_query().unwrap().as_str().to_owned()
}

/// Follows a redirect to the provider and returns its redirect back (the callback URL).
async fn provider(idp: &FakeIdp, location: &str) -> String {
    assert!(location.starts_with(&idp.issuer()), "{location}");
    let idp_addr: SocketAddr = idp.issuer().trim_start_matches("http://").parse().unwrap();
    let reply = client::http1(idp_addr, client::get("idp", &path_of(location))).await;
    assert_eq!(reply.status, 302, "{}", reply.text());
    reply.header("location").unwrap().to_owned()
}

/// Starts a login at `target` and returns the provider's callback URL.
async fn begin(
    port: u16,
    host: &str,
    target: &str,
    browser: &mut Browser,
    idp: &FakeIdp,
) -> String {
    let start = send(port, host, target, browser, true).await;
    assert_eq!(start.status, 302, "{}", start.text());
    assert_eq!(start.header("cache-control"), Some("no-store"));
    let location = start.header("location").unwrap().to_owned();
    for param in [
        "code_challenge_method=S256",
        "response_type=code",
        "state=",
        "nonce=",
        "code_challenge=",
    ] {
        assert!(location.contains(param), "{param} in {location}");
    }
    provider(idp, &location).await
}

/// A whole login; returns the callback's answer.
async fn login(
    port: u16,
    host: &str,
    target: &str,
    browser: &mut Browser,
    idp: &FakeIdp,
) -> client::Reply {
    let callback = begin(port, host, target, browser, idp).await;
    assert!(
        callback.starts_with(&format!("https://{host}/_rdock/oidc/callback?")),
        "{callback}"
    );
    send(port, host, &path_of(&callback), browser, true).await
}

#[tokio::test]
async fn the_login_flow_admits_browsers_and_refuses_api_requests_without_a_session() {
    let idp = FakeIdp::start(CLIENT, Some(SECRET)).await;
    let backend = Backend::start("app").await;
    let dir = tempfile::tempdir().unwrap();
    secrets(dir.path());
    let port = free_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, &idp, dir.path(), &key_a(dir.path()), ""),
    );

    // An API request without a session: 401, never a redirect; nothing reaches the backend.
    let mut anonymous = Browser::default();
    let api = send(port, "app.test", "/api/items", &mut anonymous, false).await;
    assert_eq!(api.status, 401);
    assert!(api.header("location").is_none());
    let mut form_post = client::request("POST", "app.test", "/form", "a=1");
    form_post
        .headers_mut()
        .insert("accept", HTML.parse().unwrap());
    assert_eq!(
        client::http1(addr(port), form_post).await.status,
        401,
        "only GET and HEAD are redirected"
    );
    assert_eq!(backend.requests(), 0);

    // A navigation logs in and comes back to where it started.
    let mut alice = Browser::default();
    let callback = login(port, "app.test", "/dashboard?tab=1", &mut alice, &idp).await;
    assert_eq!(callback.status, 302, "{}", callback.text());
    assert_eq!(callback.header("location"), Some("/dashboard?tab=1"));
    assert!(alice.get(SESSION).is_some(), "{:?}", alice.cookies);
    assert!(
        alice.names("__Host-rdock_oidc_state_").is_empty(),
        "the state cookie is removed"
    );
    let set_cookie: Vec<&str> = callback
        .headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    let session_cookie = set_cookie.iter().find(|c| c.starts_with(SESSION)).unwrap();
    for attribute in ["Path=/", "HttpOnly", "Secure", "SameSite=Lax", "Max-Age="] {
        assert!(
            session_cookie.contains(attribute),
            "{attribute} in {session_cookie}"
        );
    }
    // The token request used PKCE and client_secret_basic.
    let token = idp
        .requests()
        .into_iter()
        .find(|r| r.path == "/token")
        .unwrap();
    assert!(token.header("authorization").unwrap().starts_with("Basic "));
    let form = rdock_testkit::oidc::parse_form(&String::from_utf8_lossy(&token.body));
    assert!(form.contains_key("code_verifier"));
    assert!(!form.contains_key("client_secret"));

    // The backend sees the identity headers and none of rdock's cookies.
    alice.set("theme", "dark");
    let page = send(port, "app.test", "/dashboard?tab=1", &mut alice, true).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let headers = &page.json()["headers"];
    assert_eq!(
        headers["x-auth-email"][0], "alice@example.com",
        "the spoofed copy is replaced"
    );
    assert_eq!(headers["x-auth-groups"][0], "staff");
    assert_eq!(headers["cookie"][0], "theme=dark", "{headers}");
    // API requests with the session pass too.
    assert_eq!(
        send(port, "app.test", "/api/items", &mut alice, false)
            .await
            .status,
        200
    );

    // The access log carries the consumer.
    std::thread::sleep(Duration::from_millis(300));
    let log = rdock.access_log();
    assert!(
        log.iter().any(|r| r["consumer"] == "alice@example.com"),
        "{log:?}"
    );

    // Consumer limits after login: `burst` allows 4 a minute per consumer.
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(
            send(port, "app.test", "/api/items", &mut alice, false)
                .await
                .status,
        );
    }
    assert!(statuses.contains(&429), "{statuses:?}");
    // Another user has their own budget.
    idp.set_user(User::new("user-2", "bob@example.com", &["staff"]));
    let mut bob = Browser::default();
    assert_eq!(
        login(port, "app.test", "/", &mut bob, &idp).await.status,
        302
    );
    assert_eq!(
        send(port, "app.test", "/api/items", &mut bob, false)
            .await
            .status,
        200
    );
    // `quota` counts per consumer: 2 a day.
    let quota: Vec<u16> = {
        let mut out = Vec::new();
        for _ in 0..3 {
            out.push(send(port, "quota.test", "/", &mut bob, false).await.status);
        }
        out
    };
    assert_eq!(quota, [200, 200, 429]);

    // An open-redirect attempt in the original URL ends on a local path.
    let raw = client::raw(
        addr(port),
        b"GET //evil.example/next HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
        Duration::from_secs(5),
    )
    .await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.starts_with("HTTP/1.1 302"), "{text}");
    let mut evil = Browser::default();
    let mut headers = http::HeaderMap::new();
    let mut location = String::new();
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(": ") {
            if name.eq_ignore_ascii_case("set-cookie") {
                headers.append("set-cookie", value.parse().unwrap());
            }
            if name.eq_ignore_ascii_case("location") {
                location = value.to_owned();
            }
        }
    }
    evil.absorb(&headers);
    let callback = provider(&idp, &location).await;
    let back = send(port, "app.test", &path_of(&callback), &mut evil, true).await;
    assert_eq!(back.status, 302);
    // The proxy may normalise the path first; either way the target stays on this host.
    let target = back.header("location").unwrap();
    assert!(
        target.starts_with('/') && !target.starts_with("//") && !target.contains('\\'),
        "{target}"
    );

    // A wrong state, or no login in progress: refused.
    let mut mallory = Browser::default();
    let callback = begin(port, "app.test", "/", &mut mallory, &idp).await;
    // The provider percent-encodes the `.` between the state's ID and its secret.
    let (id, _) = callback
        .split_once("state=")
        .unwrap()
        .1
        .split_once("%2E")
        .unwrap();
    let forged = callback.replace(&format!("state={id}%2E"), &format!("state={id}%2Eforged"));
    let refused = send(port, "app.test", &path_of(&forged), &mut mallory, true).await;
    assert_eq!(refused.status, 401);
    assert!(mallory.get(SESSION).is_none());
    let mut stranger = Browser::default();
    assert_eq!(
        send(port, "app.test", &path_of(&callback), &mut stranger, true)
            .await
            .status,
        401
    );

    // The provider refuses: its description is never echoed.
    idp.knobs(|k| k.authorize_error = Some("access_denied".into()));
    let mut denied = Browser::default();
    let callback = begin(port, "app.test", "/", &mut denied, &idp).await;
    let refused = send(port, "app.test", &path_of(&callback), &mut denied, true).await;
    assert_eq!(refused.status, 401);
    assert!(!refused.text().contains("<script>"), "{}", refused.text());
    idp.knobs(|k| k.authorize_error = None);

    // L1 of the v0.8 review: a logout another site triggers (an `<img>`, a form, a link) is
    // refused and the session stays; other methods are not logouts.
    let logout = async |alice: &mut Browser, method: &str, headers: &[(&str, &str)]| {
        let mut req = client::request(method, "app.test", "/_rdock/oidc/logout", "");
        for (name, value) in headers {
            req.headers_mut().insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        if let Some(cookie) = alice.header() {
            req.headers_mut().insert("cookie", cookie.parse().unwrap());
        }
        let reply = client::http1(addr(port), req).await;
        alice.absorb(&reply.headers);
        reply
    };
    for (method, headers) in [
        ("GET", vec![("sec-fetch-site", "cross-site")]),
        ("GET", vec![("sec-fetch-site", "same-site")]),
        ("POST", vec![("sec-fetch-site", "cross-site")]),
        ("GET", vec![]),
        ("GET", vec![("referer", "https://evil.example/page")]),
        ("GET", vec![("referer", "https://app.test.evil.example/")]),
        ("POST", vec![("origin", "https://evil.example")]),
    ] {
        let out = logout(&mut alice, method, &headers).await;
        assert_eq!(out.status, 403, "{method} {headers:?}");
        assert!(alice.get(SESSION).is_some(), "{method} {headers:?}");
    }
    assert_eq!(
        logout(&mut alice, "DELETE", &[("sec-fetch-site", "same-origin")])
            .await
            .status,
        405
    );
    assert!(alice.get(SESSION).is_some());
    // Older browsers without `Sec-Fetch-Site`: the site's own `Referer` or `Origin` counts.
    let mut via_referer = alice.clone();
    let out = logout(
        &mut via_referer,
        "GET",
        &[("referer", "https://app.test/account")],
    )
    .await;
    assert_eq!(out.status, 302);
    let mut via_origin = alice.clone();
    let out = logout(&mut via_origin, "POST", &[("origin", "https://app.test")]).await;
    assert_eq!(out.status, 302);

    // Logout from the site itself clears the session and goes to the provider's end-session
    // endpoint.
    let out = logout(&mut alice, "GET", &[("sec-fetch-site", "same-origin")]).await;
    assert_eq!(out.status, 302);
    let location = out.header("location").unwrap();
    assert!(
        location.starts_with(&format!("{}/logout?client_id={CLIENT}", idp.issuer())),
        "{location}"
    );
    assert!(
        location.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.test%2F"),
        "{location}"
    );
    assert!(alice.get(SESSION).is_none());
    assert_eq!(
        send(port, "app.test", "/api/items", &mut alice, false)
            .await
            .status,
        401
    );

    // Metrics.
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        metrics.contains("rdock_oidc_logins_total{middleware=\"login\",result=\"success\"} 3"),
        "{metrics}"
    );
    assert!(
        metrics
            .contains("rdock_oidc_logins_total{middleware=\"login\",result=\"provider_error\"} 1")
    );
}

#[tokio::test]
async fn id_tokens_that_fail_a_check_are_refused() {
    let idp = FakeIdp::start(CLIENT, Some(SECRET)).await;
    let backend = Backend::start("app").await;
    let dir = tempfile::tempdir().unwrap();
    secrets(dir.path());
    let port = free_port();
    let _rdock = Rdock::start(
        RDOCK,
        &config(port, backend.addr, &idp, dir.path(), &key_a(dir.path()), ""),
    );

    let attempt = |change: Box<dyn FnOnce(&mut rdock_testkit::oidc::Knobs)>| {
        let idp = idp.clone();
        async move {
            idp.knobs(|k| *k = rdock_testkit::oidc::Knobs::default());
            idp.knobs(change);
            let mut browser = Browser::default();
            let status = login(port, "app.test", "/", &mut browser, &idp)
                .await
                .status;
            (status, browser.get(SESSION).is_some())
        }
    };
    assert_eq!(
        attempt(Box::new(|_| {})).await,
        (302, true),
        "the baseline logs in"
    );
    assert_eq!(
        attempt(Box::new(|k| k.nonce = Some("replayed".into()))).await,
        (401, false),
        "nonce"
    );
    assert_eq!(
        attempt(Box::new(
            |k| k.aud = Some(serde_json::json!("another-client"))
        ))
        .await,
        (401, false),
        "aud"
    );
    assert_eq!(
        attempt(Box::new(
            |k| k.aud = Some(serde_json::json!([CLIENT, "another-client"]))
        ))
        .await,
        (401, false),
        "several audiences without azp"
    );
    assert_eq!(
        attempt(Box::new(|k| k.iss = Some("https://evil.example".into()))).await,
        (401, false),
        "iss"
    );
    assert_eq!(
        attempt(Box::new(|k| k.id_token_lifetime = -3600)).await,
        (401, false),
        "expired"
    );
    assert_eq!(
        attempt(Box::new(|k| k.alg_none = true)).await,
        (401, false),
        "alg none"
    );

    // A rotated signing key: the unknown key ID makes rdock fetch the keys again.
    idp.knobs(|k| *k = rdock_testkit::oidc::Knobs::default());
    idp.knobs(|k| {
        k.published = vec![0, 1];
        k.signing_key = 1;
    });
    let mut first = Browser::default();
    let status = login(port, "app.test", "/", &mut first, &idp).await.status;
    let mut status_after = status;
    for _ in 0..20 {
        if status_after == 302 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut again = Browser::default();
        status_after = login(port, "app.test", "/", &mut again, &idp).await.status;
    }
    assert_eq!(status_after, 302, "logins work once the new key is fetched");

    // `allowed`: only corp.example addresses or the admins group.
    idp.knobs(|k| *k = rdock_testkit::oidc::Knobs::default());
    let mut outsider = Browser::default();
    let callback = begin(port, "corp.test", "/", &mut outsider, &idp).await;
    let refused = send(port, "corp.test", &path_of(&callback), &mut outsider, true).await;
    assert_eq!(refused.status, 403);
    assert!(outsider.get("__Host-corp").is_none());
    let token = idp
        .requests()
        .into_iter()
        .rev()
        .find(|r| r.path == "/token")
        .unwrap();
    assert!(
        token.header("authorization").is_none(),
        "client_secret_post"
    );
    idp.set_user(User::new("user-3", "carol@corp.example", &[]));
    let mut carol = Browser::default();
    let callback = begin(port, "corp.test", "/", &mut carol, &idp).await;
    assert_eq!(
        send(port, "corp.test", &path_of(&callback), &mut carol, true)
            .await
            .status,
        302
    );
    assert_eq!(
        send(port, "corp.test", "/", &mut carol, false).await.status,
        200
    );
    idp.set_user(User::new("user-4", "dave@example.com", &["admins"]));
    let mut dave = Browser::default();
    let callback = begin(port, "corp.test", "/", &mut dave, &idp).await;
    assert_eq!(
        send(port, "corp.test", &path_of(&callback), &mut dave, true)
            .await
            .status,
        302
    );

    // A host the routes do not name never becomes a redirect URI.
    let mut other = Browser::default();
    let mut req = client::get("evil.test", "/");
    req.headers_mut().insert("accept", HTML.parse().unwrap());
    let reply = client::http1(addr(port), req).await;
    assert_ne!(reply.status, 302);
    other.absorb(&reply.headers);
    assert_eq!(other.header(), None);
}

#[tokio::test]
async fn sessions_refresh_expire_rotate_and_work_across_replicas_and_outages() {
    let idp = FakeIdp::start(CLIENT, Some(SECRET)).await;
    let backend = Backend::start("app").await;
    let dir = tempfile::tempdir().unwrap();
    secrets(dir.path());
    let port = free_port();
    let base = config(port, backend.addr, &idp, dir.path(), &key_a(dir.path()), "");
    let rdock = Rdock::start(RDOCK, &base);

    // Refresh: the ID token lives 32 s and refreshes start 30 s before expiry.
    idp.knobs(|k| k.id_token_lifetime = 32);
    let mut alice = Browser::default();
    assert_eq!(
        login(port, "app.test", "/", &mut alice, &idp).await.status,
        302
    );
    let first = send(port, "app.test", "/", &mut alice, false).await;
    assert_eq!(first.status, 200);
    assert!(first.header("set-cookie").is_none());
    let before = alice.get(SESSION).unwrap().to_owned();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let refreshed = send(port, "app.test", "/", &mut alice, false).await;
    assert_eq!(refreshed.status, 200, "{}", refreshed.text());
    assert!(
        refreshed.header("set-cookie").is_some(),
        "the renewed session is stored"
    );
    assert_ne!(alice.get(SESSION).unwrap(), before);
    assert_eq!(idp.hits("/token"), 2);

    // A refresh the provider refuses means a new login.
    idp.knobs(|k| k.refuse_refresh = true);
    let mut bob = Browser::default();
    assert_eq!(
        login(port, "app.test", "/", &mut bob, &idp).await.status,
        302
    );
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        send(port, "app.test", "/", &mut bob, false).await.status,
        401
    );
    assert_eq!(
        send(port, "app.test", "/", &mut bob, true).await.status,
        302,
        "a navigation logs in again"
    );

    // Without a refresh token the session ends with the ID token.
    idp.knobs(|k| {
        k.refuse_refresh = false;
        k.refresh_tokens = false;
        k.id_token_lifetime = 2;
    });
    let mut carol = Browser::default();
    assert_eq!(
        login(port, "app.test", "/", &mut carol, &idp).await.status,
        302
    );
    assert_eq!(
        send(port, "app.test", "/", &mut carol, false).await.status,
        200
    );
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert_eq!(
        send(port, "app.test", "/", &mut carol, false).await.status,
        401,
        "expired"
    );
    let again = send(port, "app.test", "/", &mut carol, true).await;
    assert_eq!(again.status, 302);
    assert!(
        again.header("location").unwrap().starts_with(&idp.issuer()),
        "re-login"
    );

    // A long session for the rest.
    idp.knobs(|k| *k = rdock_testkit::oidc::Knobs::default());
    idp.knobs(|k| k.id_token_lifetime = 3600);
    let mut dave = Browser::default();
    assert_eq!(
        login(port, "app.test", "/", &mut dave, &idp).await.status,
        302
    );
    let cookie = dave.get(SESSION).unwrap().to_owned();

    // Tampered and truncated cookies are refused.
    let mut tampered = dave.clone();
    let mut bytes = cookie.clone().into_bytes();
    let i = bytes.len() / 2;
    bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
    tampered.set(SESSION, std::str::from_utf8(&bytes).unwrap());
    assert_eq!(
        send(port, "app.test", "/", &mut tampered, false)
            .await
            .status,
        401
    );
    let mut truncated = dave.clone();
    truncated.set(SESSION, &cookie[..cookie.len() - 10]);
    assert_eq!(
        send(port, "app.test", "/", &mut truncated, false)
            .await
            .status,
        401
    );

    // A second replica with the same key accepts the session.
    let port_b = free_port();
    let _replica = Rdock::start(
        RDOCK,
        &config(
            port_b,
            backend.addr,
            &idp,
            dir.path(),
            &key_a(dir.path()),
            "",
        ),
    );
    assert_eq!(
        send(port_b, "app.test", "/", &mut dave, false).await.status,
        200
    );

    // The provider goes down: a fresh instance still admits the existing session, but a new
    // login cannot start.
    idp.knobs(|k| k.unavailable = true);
    let port_c = free_port();
    let _isolated = Rdock::start(
        RDOCK,
        &config(
            port_c,
            backend.addr,
            &idp,
            dir.path(),
            &key_a(dir.path()),
            "",
        ),
    );
    assert_eq!(
        send(port_c, "app.test", "/", &mut dave, false).await.status,
        200
    );
    let mut newcomer = Browser::default();
    let unavailable = send(port_c, "app.test", "/", &mut newcomer, true).await;
    assert_eq!(unavailable.status, 503);
    assert!(unavailable.header("location").is_none());
    idp.knobs(|k| k.unavailable = false);

    // Key rotation: `keys: [new, old]` still opens old sessions; without the old key they are
    // refused (a foreign key).
    let rotated = format!(
        "keys: [\"${{file:{d}/key_b}}\", \"${{file:{d}/key_a}}\"]",
        d = dir.path().display()
    );
    rdock.write_config(&config(port, backend.addr, &idp, dir.path(), &rotated, ""));
    assert_eq!(rdock.reload().0, 200);
    assert_eq!(
        send(port, "app.test", "/", &mut dave, false).await.status,
        200
    );
    let only_new = format!("key: \"${{file:{}/key_b}}\"", dir.path().display());
    rdock.write_config(&config(port, backend.addr, &idp, dir.path(), &only_new, ""));
    assert_eq!(rdock.reload().0, 200);
    assert_eq!(
        send(port, "app.test", "/", &mut dave, false).await.status,
        401
    );

    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    assert!(
        metrics.contains("rdock_oidc_refreshes_total{middleware=\"login\",result=\"success\"} 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("rdock_oidc_refreshes_total{middleware=\"login\",result=\"failed\"} 1"),
        "{metrics}"
    );
}

/// H1 of the v0.8 review: an address the provider has not verified never names the consumer
/// (it would share the owner's quota and cache entries), and a consumer name equal to one of
/// `consumers` gets that consumer's groups only with `map_to_consumers`.
#[tokio::test]
async fn consumers_need_a_verified_email_and_an_explicit_mapping() {
    let idp = FakeIdp::start(CLIENT, Some(SECRET)).await;
    let backend = Backend::start("app").await;
    let dir = tempfile::tempdir().unwrap();
    secrets(dir.path());
    let consumers = "consumers:\n  user-7: { groups: [vip] }\n";
    let start = |extra: &str| {
        let port = free_port();
        let mut text = config(
            port,
            backend.addr,
            &idp,
            dir.path(),
            &key_a(dir.path()),
            extra,
        );
        text.push_str(consumers);
        (port, Rdock::start(RDOCK, &text))
    };

    // The owner of the address uses up the daily quota of 2.
    let (port, _default) = start("");
    idp.set_user(User::new("victim", "victim@corp.example", &[]));
    let mut victim = Browser::default();
    assert_eq!(
        login(port, "quota.test", "/", &mut victim, &idp)
            .await
            .status,
        302
    );
    for expected in [200, 200, 429] {
        assert_eq!(
            send(port, "quota.test", "/", &mut victim, false)
                .await
                .status,
            expected
        );
    }
    // Someone whose provider let them claim the same address, unverified or without
    // `email_verified`, is a consumer of their own (`sub`), not the owner.
    for verified in [serde_json::json!(false), serde_json::Value::Null] {
        idp.knobs(|k| k.email_verified = verified.clone());
        idp.set_user(User::new("attacker", "victim@corp.example", &[]));
        let mut attacker = Browser::default();
        assert_eq!(
            login(port, "quota.test", "/", &mut attacker, &idp)
                .await
                .status,
            302
        );
        assert_eq!(
            send(port, "quota.test", "/", &mut attacker, false)
                .await
                .status,
            200,
            "email_verified = {verified}: not the victim's quota"
        );
    }
    idp.knobs(|k| k.email_verified = serde_json::json!(true));

    // `consumer_claim: sub` names `user-7`, a configured consumer in group `vip`: without
    // `map_to_consumers` the session gets nothing from it, so `burst` allows 4 a minute.
    idp.set_user(User::new("user-7", "seven@example.com", &[]));
    let burst = |port: u16, mut browser: Browser| async move {
        let mut out = Vec::new();
        for _ in 0..6 {
            out.push(
                send(port, "app.test", "/api", &mut browser, false)
                    .await
                    .status,
            );
        }
        out
    };
    let (port, _unmapped) = start("    consumer_claim: sub\n");
    let mut seven = Browser::default();
    assert_eq!(
        login(port, "app.test", "/", &mut seven, &idp).await.status,
        302
    );
    let statuses = burst(port, seven).await;
    assert!(statuses.contains(&429), "{statuses:?}");

    // With `map_to_consumers` it is that consumer, with its `vip` override.
    let (port, _mapped) = start("    consumer_claim: sub\n    map_to_consumers: true\n");
    let mut seven = Browser::default();
    assert_eq!(
        login(port, "app.test", "/", &mut seven, &idp).await.status,
        302
    );
    assert_eq!(burst(port, seven).await, [200; 6]);
}

/// `rdock validate` output for a configuration with one `oidc` middleware.
fn validate(dir: &Path, middleware: &str, rule: &str, tls: &str) -> (bool, String) {
    let file = dir.join("rdock.yaml");
    std::fs::write(
        &file,
        format!(
            r#"
listeners:
  web: {{ address: "127.0.0.1:1" }}
defaults: {{ listeners: [web], tls: {tls} }}
routes:
  app: {{ match: "{rule}", service: app, middlewares: [login] }}
middlewares:
  login:
{middleware}
services:
  app: {{ backends: [{{ address: "127.0.0.1:2" }}] }}
"#
        ),
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .arg("validate")
        .arg(&file)
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn validation_refuses_unsafe_settings() {
    let dir = tempfile::tempdir().unwrap();
    secrets(dir.path());
    std::fs::write(dir.path().join("short"), "too-short").unwrap();
    let d = dir.path().display();
    let host = "Host(`app.example.com`)";
    let good = format!(
        "    type: oidc\n    issuer: https://idp.example.com\n    client_id: app\n    session: {{ key: \"${{file:{d}/key_a}}\" }}"
    );
    let (ok, text) = validate(dir.path(), &good, host, "off");
    assert!(ok, "{text}");

    let short = good.replace("key_a", "short");
    let (ok, text) = validate(dir.path(), &short, host, "off");
    assert!(!ok);
    assert!(text.contains("at least 32 bytes"), "{text}");

    let http_issuer = good.replace("https://idp.example.com", "http://idp.example.com");
    let (ok, text) = validate(dir.path(), &http_issuer, host, "off");
    assert!(!ok);
    assert!(text.contains("https://"), "{text}");

    let insecure = good.replace("session: {", "session: { secure: false,");
    let (ok, text) = validate(dir.path(), &insecure, host, "off");
    assert!(!ok);
    assert!(text.contains("without TLS"), "{text}");
    let opted_in = good.replace(
        "session: {",
        "session: { secure: false, allow_insecure_cookies: true,",
    );
    let (ok, text) = validate(dir.path(), &opted_in, host, "off");
    assert!(ok, "plain route with the opt-in: {text}");
    let (ok, text) = validate(dir.path(), &opted_in, host, "auto");
    assert!(!ok, "secure: false on a TLS route");
    assert!(text.contains("plain-HTTP routes only"), "{text}");

    let (ok, text) = validate(dir.path(), &good, "PathPrefix(`/`)", "off");
    assert!(!ok);
    assert!(text.contains("no `Host` matcher"), "{text}");

    let literal = good.replace(
        "client_id: app",
        "client_id: app\n    client_secret: hunter2-literal",
    );
    let (ok, text) = validate(dir.path(), &literal, host, "off");
    assert!(!ok);
    assert!(
        text.contains("a secret is written in the configuration file"),
        "{text}"
    );
    assert!(
        !text.contains("hunter2-literal"),
        "the secret is not echoed: {text}"
    );

    let strict = good.replace("session: {", "session: { same_site: strict,");
    let (ok, text) = validate(dir.path(), &strict, host, "off");
    assert!(!ok);
    assert!(text.contains("strict"), "{text}");

    let no_key =
        "    type: oidc\n    issuer: https://idp.example.com\n    client_id: app\n    session: {}";
    let (ok, text) = validate(dir.path(), no_key, host, "off");
    assert!(!ok);
    assert!(text.contains("needs a key"), "{text}");
}

/// Resolves `location` against `base` (`http://host:port`).
fn absolute(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_owned()
    } else {
        format!("{base}{location}")
    }
}

/// The `action` of the first form in an HTML page, unescaped.
fn form_action(html: &str) -> Option<String> {
    let form = &html[html.find("<form")?..];
    let start = form.find("action=\"")? + "action=\"".len();
    let end = form[start..].find('"')?;
    Some(form[start..start + end].replace("&amp;", "&"))
}

/// A login against a real Dex (`ghcr.io/dexidp/dex`, CI job `oidc-dex`): its local password
/// form, the token exchange with `client_secret_basic`, and the ID token verified with Dex's
/// keys.
#[tokio::test]
#[ignore = "needs a Dex server (CI job `oidc-dex`)"]
async fn a_real_dex_login() {
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let issuer = env("RDOCK_DEX_ISSUER");
    let user = env("RDOCK_DEX_USER");
    let password = env("RDOCK_DEX_PASSWORD");
    let backend = Backend::start("app").await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("key_a"), KEY_A).unwrap();
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "Host(`app.test`)", service: app, middlewares: [login] }}
middlewares:
  login:
    type: oidc
    issuer: "{issuer}"
    client_id: "{client}"
    client_secret: "${{env:RDOCK_DEX_CLIENT_SECRET}}"
    scopes: [openid, email, profile, offline_access]
    allow_private_targets: true
    claims_to_headers: {{ email: X-Auth-Email }}
    session: {{ key: "${{file:{d}/key_a}}" }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        client = env("RDOCK_DEX_CLIENT_ID"),
        d = dir.path().display(),
        backend = backend.addr,
    );
    let rdock = Rdock::start(RDOCK, &config);
    let mut browser = Browser::default();
    let start = send(port, "app.test", "/after-login", &mut browser, true).await;
    assert_eq!(start.status, 302, "{}\n{}", start.text(), rdock.log());
    let mut url = start.header("location").unwrap().to_owned();
    let uri: http::Uri = issuer.parse().unwrap();
    let authority = uri.authority().unwrap().as_str().to_owned();
    let base = format!("http://{authority}");
    let dex: SocketAddr = authority.parse().unwrap();
    // Follow Dex until it redirects back, submitting the password form on the way.
    let mut callback = None;
    for _ in 0..10 {
        if url.starts_with("https://app.test/") {
            callback = Some(url.clone());
            break;
        }
        let reply = client::http1(dex, client::get(&authority, &path_of(&url))).await;
        if let Some(location) = reply.header("location") {
            url = absolute(&base, location);
            continue;
        }
        let html = reply.text();
        assert_eq!(reply.status, 200, "{html}");
        let action = form_action(&html).unwrap_or_else(|| panic!("no form in {html}"));
        let body = format!("login={}&password={}", user.replace('@', "%40"), password);
        let mut login_form = client::request("POST", &authority, &action, body);
        login_form.headers_mut().insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        let reply = client::http1(dex, login_form).await;
        url = absolute(
            &base,
            reply.header("location").expect("Dex accepted the password"),
        );
    }
    let callback = callback.expect("Dex redirected back");
    let back = send(port, "app.test", &path_of(&callback), &mut browser, true).await;
    assert_eq!(back.status, 302, "{}\n{}", back.text(), rdock.log());
    assert_eq!(back.header("location"), Some("/after-login"));
    let page = send(port, "app.test", "/after-login", &mut browser, false).await;
    assert_eq!(page.status, 200);
    assert_eq!(page.json()["headers"]["x-auth-email"][0], user.as_str());
    assert!(page.json()["headers"]["cookie"].is_null());
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        rdock
            .access_log()
            .iter()
            .any(|r| r["consumer"] == user.as_str()),
        "the consumer is the e-mail address"
    );
}
