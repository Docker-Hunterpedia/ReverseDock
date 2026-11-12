//! End-to-end: the HTTP cache (F-WEB-03, ADR-0030) through the real binary against a scripted
//! origin that counts requests. Storing and reuse, revalidation, what is never stored and the
//! explicit opposites, request directives, `Vary`, the query rule, ranges and `HEAD`,
//! invalidation, `stale-if-error`, purges through the admin API, route isolation, the
//! authentication rule, request middlewares on hits, compression, HTTP/2, reloads, request
//! coalescing and the disk store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::io::Read;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use rdock_testkit::client::{self, Reply};
use rdock_testkit::free_port;
use rdock_testkit::origin::{Origin, Script};
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A configuration with one store `mem`, a `cache` middleware with `settings`, and route `app`
/// for `app.test` through `chain` (default `[cache]`); `extra` is appended (more routes,
/// middlewares under their own keys are not allowed: use `middlewares`).
struct Setup<'a> {
    settings: &'a str,
    chain: &'a str,
    middlewares: &'a str,
    caches: &'a str,
    extra_routes: &'a str,
    extra: &'a str,
}

impl Default for Setup<'_> {
    fn default() -> Self {
        Self {
            settings: "",
            chain: "cache",
            middlewares: "",
            caches: "  mem: { type: memory, max_size: 64MiB }\n",
            extra_routes: "",
            extra: "",
        }
    }
}

fn config(port: u16, origin: SocketAddr, setup: &Setup<'_>) -> String {
    format!(
        "acme: false\nlisteners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\n\
         caches:\n{caches}\
         middlewares:\n  cache: {{ type: cache, store: mem{sep}{settings} }}\n{middlewares}\
         routes:\n  app: {{ match: \"Host(`app.test`)\", service: app, middlewares: [{chain}] }}\n{extra_routes}\
         services:\n  app: {{ backends: [{{ address: \"{origin}\" }}] }}\n{extra}",
        caches = setup.caches,
        sep = if setup.settings.is_empty() { "" } else { ", " },
        settings = setup.settings,
        middlewares = setup.middlewares,
        chain = setup.chain,
        extra_routes = setup.extra_routes,
        extra = setup.extra,
    )
}

fn start(origin: &Origin, setup: &Setup<'_>) -> (Rdock, u16) {
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, origin.addr, setup));
    (rdock, port)
}

fn request(
    method: &str,
    host: &str,
    target: &str,
    headers: &[(&str, &str)],
) -> http::Request<Full<Bytes>> {
    let mut req = client::request(method, host, target, Bytes::new());
    for (name, value) in headers {
        req.headers_mut().append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    req
}

async fn get(port: u16, target: &str) -> Reply {
    get_with(port, target, &[]).await
}

async fn get_with(port: u16, target: &str, headers: &[(&str, &str)]) -> Reply {
    client::http1(addr(port), request("GET", "app.test", target, headers)).await
}

fn status(reply: &Reply) -> &str {
    reply.header("cache-status").unwrap_or("<none>")
}

fn is_hit(reply: &Reply) -> bool {
    status(reply).starts_with("rdock; hit")
}

fn cached(cc: &str, body: &str) -> Script {
    Script::ok(body.to_owned()).cache_control(cc)
}

// -- storing and reuse ------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_miss_is_stored_and_hits_carry_a_growing_age() {
    let origin = Origin::start().await;
    origin.set("/a", cached("max-age=60", "alpha"));
    let (rdock, port) = start(&origin, &Setup::default());
    let first = get(port, "/a").await;
    assert_eq!((first.status, first.text().as_str()), (200, "alpha"));
    assert_eq!(
        status(&first),
        "rdock; fwd=uri-miss; fwd-status=200; stored"
    );
    assert!(first.header("age").is_none(), "a fresh response has no Age");
    let second = get(port, "/a").await;
    assert!(is_hit(&second), "{}", status(&second));
    assert_eq!(second.text(), "alpha");
    assert_eq!(origin.count("/a"), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let third = get(port, "/a").await;
    let age: u64 = third.header("age").unwrap().parse().unwrap();
    assert!(age >= 1, "Age grows: {age}");
    assert_eq!(origin.count("/a"), 1);
    // The access log and the metrics say what happened. The miss's line is written when
    // its request ends, which is after the cache fill and can be after the client has the
    // response (and even after the hits' lines): wait for all three, in any order.
    let mut log = rdock.access_log();
    let started = std::time::Instant::now();
    while log.iter().filter(|l| l["cache_status"].is_string()).count() < 3
        && started.elapsed() < Duration::from_secs(5)
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
        log = rdock.access_log();
    }
    let mut statuses: Vec<_> = log
        .iter()
        .filter_map(|l| l["cache_status"].as_str())
        .collect();
    statuses.sort_unstable();
    assert_eq!(statuses, ["hit", "hit", "miss"], "{log:?}");
    let (_, metrics) = rdock.get_admin("/metrics").unwrap();
    assert!(
        metrics
            .contains("rdock_cache_requests_total{route=\"app\",status=\"hit\",store=\"mem\"} 2"),
        "{metrics}"
    );
    assert!(
        metrics.contains("rdock_cache_objects{store=\"mem\"} 1"),
        "{metrics}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_origins_age_counts_towards_freshness() {
    let origin = Origin::start().await;
    origin.set("/aged", cached("max-age=60", "x").header("age", "59"));
    let (_rdock, port) = start(&origin, &Setup::default());
    get(port, "/aged").await;
    let hit = get(port, "/aged").await;
    assert!(is_hit(&hit));
    assert!(hit.header("age").unwrap().parse::<u64>().unwrap() >= 59);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let later = get(port, "/aged").await;
    assert!(!is_hit(&later), "stale after a second: {}", status(&later));
    assert_eq!(origin.count("/aged"), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_revalidates_with_304_updating_headers_and_with_200_replacing() {
    let origin = Origin::start().await;
    origin.set(
        "/e",
        cached("max-age=1", "body-e")
            .etag("\"v1\"")
            .header("x-version", "1")
            .not_modified("x-version", "2"),
    );
    origin.set("/r", cached("max-age=1", "r").numbered());
    let (_rdock, port) = start(&origin, &Setup::default());
    get(port, "/e").await;
    get(port, "/r").await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let revalidated = get(port, "/e").await;
    assert_eq!(revalidated.status, 200);
    assert_eq!(revalidated.text(), "body-e");
    assert!(
        status(&revalidated).starts_with("rdock; fwd=stale; fwd-status=304"),
        "{}",
        status(&revalidated)
    );
    assert_eq!(
        revalidated.header("x-version"),
        Some("2"),
        "every 304 field updates the stored response"
    );
    let sent = origin.last_headers("/e").unwrap();
    assert_eq!(sent.get("if-none-match").unwrap(), "\"v1\"");
    let after = get(port, "/e").await;
    assert!(is_hit(&after));
    assert_eq!(after.header("x-version"), Some("2"));
    assert_eq!(origin.count("/e"), 2);

    let replaced = get(port, "/r").await;
    assert_eq!(replaced.text(), "2:r");
    assert_eq!(
        status(&replaced),
        "rdock; fwd=stale; fwd-status=200; stored"
    );
    let hit = get(port, "/r").await;
    assert!(is_hit(&hit));
    assert_eq!(hit.text(), "2:r");
}

// -- what is never stored, and the explicit opposites -----------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responses_the_origin_or_the_request_forbid_are_not_stored() {
    let origin = Origin::start().await;
    for (path, script) in [
        ("/no-store", cached("max-age=60, no-store", "x")),
        ("/private", cached("max-age=60, private", "x")),
        (
            "/cookie",
            cached("max-age=60", "x").header("set-cookie", "sid=secret"),
        ),
        ("/vary-star", cached("max-age=60", "x").header("vary", "*")),
        ("/no-freshness", Script::ok("x").etag("\"a\"")),
        ("/auth", cached("max-age=60", "x")),
        ("/auth-public", cached("public, max-age=60", "x")),
    ] {
        origin.set(path, script);
    }
    let (_rdock, port) = start(&origin, &Setup::default());
    for (path, detail) in [
        ("/no-store", "no-store"),
        ("/private", "private"),
        ("/cookie", "set-cookie"),
        ("/vary-star", "vary-star"),
        ("/no-freshness", "no-freshness"),
    ] {
        let first = get(port, path).await;
        assert!(
            status(&first).ends_with(&format!("detail={detail}")),
            "{path}: {}",
            status(&first)
        );
        let second = get(port, path).await;
        assert!(!is_hit(&second), "{path}");
        assert_eq!(origin.count(path), 2, "{path}");
    }
    let cookie = get(port, "/cookie").await;
    assert_eq!(
        cookie.header("set-cookie"),
        Some("sid=secret"),
        "passed through, never stored"
    );
    let auth = [("authorization", "Bearer abc")];
    get_with(port, "/auth", &auth).await;
    let again = get_with(port, "/auth", &auth).await;
    assert!(
        status(&again).ends_with("detail=authorization"),
        "{}",
        status(&again)
    );
    assert_eq!(origin.count("/auth"), 2);
    get_with(port, "/auth-public", &auth).await;
    assert!(
        is_hit(&get_with(port, "/auth-public", &auth).await),
        "public may be shared"
    );
    // A request's own no-store keeps its answer out of the store.
    origin.set("/rq", cached("max-age=60", "x"));
    get_with(port, "/rq", &[("cache-control", "no-store")]).await;
    assert!(!is_hit(&get(port, "/rq").await));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_safe_default_has_an_explicit_opposite() {
    let origin = Origin::start().await;
    origin.set(
        "/cookie",
        cached("max-age=60", "c").header("set-cookie", "sid=1"),
    );
    origin.set("/auth", cached("max-age=60", "a"));
    origin.set("/plain", Script::ok("p"));
    origin.set(
        "/lm",
        Script::ok("l").header("last-modified", "Mon, 01 Jan 2024 00:00:00 GMT"),
    );
    origin.set("/created", Script::status(201).cache_control("max-age=60"));
    let setup = Setup {
        settings: "set_cookie: strip, authorization: store, default_ttl: { \"200\": 60s }, heuristic_freshness: true, statuses: [200, 201]",
        ..Setup::default()
    };
    let (_rdock, port) = start(&origin, &setup);
    let filled = get(port, "/cookie").await;
    assert_eq!(
        filled.header("set-cookie"),
        Some("sid=1"),
        "the filling client keeps its cookie"
    );
    let hit = get(port, "/cookie").await;
    assert!(is_hit(&hit));
    assert!(hit.header("set-cookie").is_none(), "stored without it");
    let auth = [("authorization", "Bearer abc")];
    get_with(port, "/auth", &auth).await;
    assert!(is_hit(&get_with(port, "/auth", &auth).await));
    get(port, "/plain").await;
    let ttl = get(port, "/plain").await;
    assert!(is_hit(&ttl), "default_ttl: {}", status(&ttl));
    get(port, "/created").await;
    assert!(is_hit(&get(port, "/created").await), "statuses override");
    // `/lm` takes the default TTL too (an operator's choice wins over the heuristic).
    get(port, "/lm").await;
    assert!(is_hit(&get(port, "/lm").await));
    for path in ["/cookie", "/auth", "/plain", "/created", "/lm"] {
        assert_eq!(origin.count(path), 1, "{path}");
    }
}

// -- request directives -----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_directives_force_revalidation_and_only_if_cached_never_reaches_the_origin() {
    let origin = Origin::start().await;
    origin.set("/d", cached("max-age=60", "d").etag("\"d\""));
    let (_rdock, port) = start(&origin, &Setup::default());
    get(port, "/d").await;
    for cc in ["no-cache", "max-age=0"] {
        let forced = get_with(port, "/d", &[("cache-control", cc)]).await;
        assert!(
            status(&forced).starts_with("rdock; fwd=request; fwd-status=304"),
            "{cc}: {}",
            status(&forced)
        );
    }
    assert_eq!(origin.count("/d"), 3);
    let only = get_with(port, "/d", &[("cache-control", "only-if-cached")]).await;
    assert!(is_hit(&only));
    let absent = get_with(port, "/absent", &[("cache-control", "only-if-cached")]).await;
    assert_eq!(absent.status, 504);
    assert_eq!(
        status(&absent),
        "rdock; fwd=uri-miss; detail=only-if-cached"
    );
    assert_eq!(origin.count("/absent"), 0);

    let origin2 = Origin::start().await;
    origin2.set("/d", cached("max-age=60", "d"));
    let (_rdock2, port2) = start(
        &origin2,
        &Setup {
            settings: "request_directives: ignore",
            ..Setup::default()
        },
    );
    get(port2, "/d").await;
    assert!(is_hit(
        &get_with(port2, "/d", &[("cache-control", "no-cache")]).await
    ));
    assert_eq!(origin2.count("/d"), 1);
}

// -- Vary and the key -------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vary_keeps_one_variant_per_value() {
    let origin = Origin::start().await;
    origin.set(
        "/v",
        cached("max-age=60", "v")
            .header("vary", "Accept-Language")
            .numbered(),
    );
    let (_rdock, port) = start(&origin, &Setup::default());
    let en = [("accept-language", "en")];
    let de = [("accept-language", "de")];
    assert_eq!(get_with(port, "/v", &en).await.text(), "1:v");
    let de_first = get_with(port, "/v", &de).await;
    assert_eq!(de_first.text(), "2:v");
    assert!(
        status(&de_first).contains("fwd=vary-miss"),
        "{}",
        status(&de_first)
    );
    let en_again = get_with(port, "/v", &en).await;
    assert!(is_hit(&en_again));
    assert_eq!(en_again.text(), "1:v");
    let de_again = get_with(port, "/v", &[("accept-language", "DE")]).await;
    assert!(is_hit(&de_again), "language tags compare without case");
    assert_eq!(de_again.text(), "2:v");
    assert_eq!(origin.count("/v"), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_rules_shape_the_key_and_the_forwarded_request() {
    let origin = Origin::start().await;
    origin.set("/q", cached("max-age=60", "q").numbered());
    let setup = Setup {
        middlewares: "  sorted: { type: cache, store: mem, key: { query: sorted } }\n  ignore: { type: cache, store: mem, key: { query: { ignore: [utm_*] } } }\n  only: { type: cache, store: mem, key: { query: { only: [page] } } }\n",
        extra_routes: "  sorted: { match: \"Host(`sorted.test`)\", service: app, middlewares: [sorted] }\n  ignore: { match: \"Host(`ignore.test`)\", service: app, middlewares: [ignore] }\n  only: { match: \"Host(`only.test`)\", service: app, middlewares: [only] }\n",
        ..Setup::default()
    };
    let (_rdock, port) = start(&origin, &setup);
    let on = |host: &'static str, target: &'static str| async move {
        client::http1(addr(port), request("GET", host, target, &[])).await
    };
    // As sent (the default): order matters.
    on("app.test", "/q?a=1&b=2").await;
    assert!(!is_hit(&on("app.test", "/q?b=2&a=1").await));
    on("sorted.test", "/q?a=1&b=2").await;
    assert!(is_hit(&on("sorted.test", "/q?b=2&a=1").await));
    on("ignore.test", "/q?utm_source=x&page=2").await;
    assert!(is_hit(&on("ignore.test", "/q?page=2&utm_medium=y").await));
    assert!(
        origin
            .seen()
            .iter()
            .any(|(target, _)| target == "/q?page=2"),
        "ignored parameters never reach the origin: {:?}",
        origin.seen().iter().map(|s| &s.0).collect::<Vec<_>>()
    );
    on("only.test", "/q?page=3&session=abc").await;
    assert!(is_hit(&on("only.test", "/q?page=3&session=def").await));
    assert!(!is_hit(&on("only.test", "/q?page=4").await));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_routes_sharing_a_store_never_see_each_others_objects() {
    let origin = Origin::start().await;
    origin.set("/same", cached("max-age=60", "same").numbered());
    let setup = Setup {
        extra_routes: "  other: { match: \"Host(`app.test`) && Header(`X-Route`, `other`)\", service: app, middlewares: [cache] }\n",
        ..Setup::default()
    };
    let (_rdock, port) = start(&origin, &setup);
    let other = [("x-route", "other")];
    assert_eq!(get_with(port, "/same", &other).await.text(), "1:same");
    let app = get(port, "/same").await;
    assert_eq!(
        app.text(),
        "2:same",
        "the other route's object is not this route's"
    );
    assert!(is_hit(&get_with(port, "/same", &other).await));
    assert!(is_hit(&get(port, "/same").await));
    assert_eq!(origin.count("/same"), 2);
}

// -- ranges, HEAD, invalidation ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ranges_and_head_are_answered_from_the_stored_object() {
    let origin = Origin::start().await;
    let body: String = (0..1000)
        .map(|i| char::from(b'a' + u8::try_from(i % 26).unwrap()))
        .collect();
    origin.set("/big", cached("max-age=60", &body));
    let (_rdock, port) = start(&origin, &Setup::default());
    let cold = get_with(port, "/big", &[("range", "bytes=0-9")]).await;
    assert_eq!(
        cold.status, 206,
        "a range miss fetches the whole object and answers the range"
    );
    assert_eq!(cold.text(), &body[0..10]);
    let sent = origin.last_headers("/big").unwrap();
    assert!(
        sent.get("range").is_none(),
        "the origin is asked for the whole object"
    );
    let warm = get_with(port, "/big", &[("range", "bytes=990-999")]).await;
    assert_eq!(warm.status, 206);
    assert!(is_hit(&warm));
    assert_eq!(warm.header("content-range"), Some("bytes 990-999/1000"));
    assert_eq!(warm.text(), &body[990..]);
    let head = client::http1(addr(port), request("HEAD", "app.test", "/big", &[])).await;
    assert_eq!(head.status, 200);
    assert!(is_hit(&head));
    assert_eq!(head.header("content-length"), Some("1000"));
    assert!(head.body.is_empty());
    assert_eq!(origin.count("/big"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_successful_unsafe_method_invalidates_the_url_and_its_location() {
    let origin = Origin::start().await;
    origin.set("/item", cached("max-age=60", "item").numbered());
    origin.set("/new", cached("max-age=60", "new").numbered());
    origin.set("/create", Script::status(201).header("location", "/new"));
    origin.set("/fail", cached("max-age=60", "fail").numbered());
    let (_rdock, port) = start(&origin, &Setup::default());
    get(port, "/item").await;
    get(port, "/new").await;
    get(port, "/fail").await;
    let posted = client::http1(addr(port), request("POST", "app.test", "/item", &[])).await;
    assert_eq!(
        status(&posted),
        "rdock; fwd=method; fwd-status=200; detail=method"
    );
    assert_eq!(get(port, "/item").await.text(), "3:item", "invalidated");
    client::http1(addr(port), request("PUT", "app.test", "/create", &[])).await;
    assert_eq!(
        get(port, "/new").await.text(),
        "2:new",
        "Location invalidated"
    );
    // An error answer invalidates nothing.
    origin.set("/fail", Script::status(500));
    client::http1(addr(port), request("DELETE", "app.test", "/fail", &[])).await;
    assert!(is_hit(&get(port, "/fail").await));
}

// -- stale-if-error ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_if_error_serves_the_stored_response_inside_the_window_only() {
    let origin = Origin::start().await;
    origin.set("/s", cached("max-age=1, stale-if-error=3", "stale-body"));
    let (_rdock, port) = start(&origin, &Setup::default());
    get(port, "/s").await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    origin.set("/s", Script::status(503));
    let on_5xx = get(port, "/s").await;
    assert_eq!((on_5xx.status, on_5xx.text().as_str()), (200, "stale-body"));
    assert!(
        status(&on_5xx).contains("detail=stale-if-error"),
        "{}",
        status(&on_5xx)
    );
    origin.stop();
    let on_connect = get(port, "/s").await;
    assert_eq!(
        (on_connect.status, on_connect.text().as_str()),
        (200, "stale-body")
    );
    assert!(status(&on_connect).contains("detail=stale-if-error"));
    tokio::time::sleep(Duration::from_millis(3200)).await;
    let late = get(port, "/s").await;
    assert_eq!(
        late.status,
        502,
        "past the window the error shows: {}",
        status(&late)
    );
}

// -- purges through the admin API -------------------------------------------------------------

async fn admin_tcp(rdock: &Rdock, method: &str, path: &str, token: &str, body: &str) -> Reply {
    let mut req = client::request(method, "127.0.0.1", path, body.to_owned());
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    client::http1(rdock.admin, req).await
}

fn purge(rdock: &Rdock, body: &str) -> (u16, serde_json::Value) {
    let (status, _, body) = rdock
        .admin_send(
            "POST",
            "/api/v1/cache/mem/purge",
            &[("Content-Type", "application/json")],
            body,
        )
        .unwrap();
    (
        status,
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn purges_by_url_prefix_tag_and_all_are_authorised_and_audited() {
    let origin = Origin::start().await;
    origin.set(
        "/p1",
        cached("max-age=60", "p1")
            .header("cache-tag", "Red, shared")
            .numbered(),
    );
    origin.set(
        "/p2",
        cached("max-age=60", "p2")
            .header("surrogate-key", "blue shared")
            .numbered(),
    );
    origin.set("/dir/x", cached("max-age=60", "x").numbered());
    origin.set("/dir/y", cached("max-age=60", "y").numbered());
    let (rdock, port) = start(&origin, &Setup::default());
    let fill = || async {
        for path in ["/p1", "/p2", "/dir/x", "/dir/y"] {
            let reply = get(port, path).await;
            assert!(
                reply.header("cache-tag").is_none() && reply.header("surrogate-key").is_none(),
                "tags are removed"
            );
        }
    };
    fill().await;
    let (code, body) = purge(&rdock, r#"{"url":"http://APP.test:80/p1"}"#);
    assert_eq!((code, body["purged"].as_u64()), (200, Some(1)));
    assert!(!is_hit(&get(port, "/p1").await));
    assert!(is_hit(&get(port, "/p2").await));
    let (_, body) = purge(&rdock, r#"{"prefix":"http://app.test/dir/"}"#);
    assert_eq!(body["purged"].as_u64(), Some(2));
    assert!(!is_hit(&get(port, "/dir/x").await));
    let (_, body) = purge(&rdock, r#"{"tag":"RED"}"#);
    assert_eq!(body["purged"].as_u64(), Some(1));
    assert!(!is_hit(&get(port, "/p1").await));
    assert!(is_hit(&get(port, "/p2").await));
    let (_, body) = purge(&rdock, r#"{"tag":"shared"}"#);
    assert_eq!(body["purged"].as_u64(), Some(2));
    fill().await;
    let (_, body) = purge(&rdock, r#"{"all":true}"#);
    assert_eq!(body["purged"].as_u64(), Some(4));
    // Refusals.
    assert_eq!(purge(&rdock, r#"{"url":"/relative"}"#).0, 400);
    assert_eq!(
        purge(&rdock, r#"{"url":"http://a.test/","tag":"t"}"#).0,
        400
    );
    assert_eq!(purge(&rdock, "{}").0, 400);
    let (code, _, _) = rdock
        .admin_send(
            "POST",
            "/api/v1/cache/nope/purge",
            &[("Content-Type", "application/json")],
            r#"{"all":true}"#,
        )
        .unwrap();
    assert_eq!(code, 404);
    // Statistics.
    let (code, stats) = rdock.get_admin("/api/v1/cache").unwrap();
    assert_eq!(code, 200);
    let stats: serde_json::Value = serde_json::from_str(&stats).unwrap();
    assert_eq!(stats["stores"][0]["name"], "mem");
    assert_eq!(stats["stores"][0]["purged"].as_u64(), Some(10));
    // A viewer may look but not purge.
    let created = rdock.command(&["tokens", "create", "ci", "--role", "viewer", "--days", "1"]);
    let token = String::from_utf8_lossy(&created.stdout)
        .split_whitespace()
        .find(|w| w.starts_with("rdk_pat_"))
        .unwrap_or_default()
        .to_owned();
    assert!(token.starts_with("rdk_pat_"), "{token}");
    let denied = admin_tcp(
        &rdock,
        "POST",
        "/api/v1/cache/mem/purge",
        &token,
        r#"{"all":true}"#,
    )
    .await;
    assert_eq!(denied.status, 403);
    let allowed = admin_tcp(&rdock, "GET", "/api/v1/cache", &token, "").await;
    assert_eq!(allowed.status, 200);
    // The CLI goes through the same endpoint.
    fill().await;
    let cli = rdock.command(&["cache", "purge", "mem", "--tag", "shared"]);
    assert!(cli.status.success(), "{cli:?}");
    assert!(
        String::from_utf8_lossy(&cli.stdout).contains("purged 2 objects from mem"),
        "{cli:?}"
    );
    let listed = rdock.command(&["cache", "list"]);
    assert!(
        String::from_utf8_lossy(&listed.stdout).starts_with("mem "),
        "{listed:?}"
    );
    // Audited, with the selector.
    let audit = rdock.command(&["audit", "list", "--limit", "100"]);
    let audit = String::from_utf8_lossy(&audit.stdout);
    assert!(audit.contains("cache.purge"), "{audit}");
    assert!(audit.contains("mem: tag=shared"), "{audit}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_purge_wins_over_a_fill_still_in_progress() {
    let origin = Origin::start().await;
    origin.set(
        "/slow",
        cached("max-age=60", "chunk-")
            .repeat(10)
            .chunk_delay(Duration::from_millis(100))
            .numbered(),
    );
    let (rdock, port) = start(&origin, &Setup::default());
    let filling = tokio::spawn(async move { get(port, "/slow").await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (code, _) = purge(&rdock, r#"{"url":"http://app.test/slow"}"#);
    assert_eq!(code, 200);
    let filled = filling.await.unwrap();
    assert_eq!(filled.status, 200);
    assert!(filled.text().starts_with("1:"));
    let next = get(port, "/slow").await;
    assert!(
        next.text().starts_with("2:"),
        "the purged fill was discarded: {}",
        status(&next)
    );
}

// -- authentication and request middlewares ---------------------------------------------------

#[test]
fn caching_an_authenticated_route_needs_an_explicit_statement() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, settings: &str| {
        let file = dir.path().join(name);
        std::fs::write(
            &file,
            format!(
                "acme: false\ncaches:\n  mem: {{ type: memory }}\nmiddlewares:\n  auth: {{ type: basic_auth, users: [\"alice:$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/\"] }}\n  cache: {{ type: cache, store: mem{settings} }}\nroutes:\n  app: {{ match: \"Host(`app.test`)\", service: app, middlewares: [auth, cache] }}\nservices:\n  app: {{ backends: [{{ address: \"127.0.0.1:9\" }}] }}\n"
            ),
        )
        .unwrap();
        let output = std::process::Command::new(RDOCK)
            .args(["validate", file.to_str().unwrap()])
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned()
                + &String::from_utf8_lossy(&output.stderr),
        )
    };
    let (ok, text) = write("refused.yaml", "");
    assert!(!ok, "{text}");
    assert!(
        text.contains("`cache` caches the responses of a route that authenticates with `auth`: one user's response could be served to another"),
        "{text}"
    );
    assert!(text.contains("keyed on the user name"), "{text}");
    for settings in [", shared_across_users: true", ", key: { consumer: true }"] {
        let (ok, text) = write("accepted.yaml", settings);
        assert!(ok, "{settings}: {text}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hits_still_pass_authentication_ip_filters_and_rate_limits() {
    let origin = Origin::start().await;
    origin.set("/h", cached("max-age=60", "h"));
    let setup = Setup {
        settings: "shared_across_users: true",
        chain: "deny, auth, limit, cache",
        middlewares: "  auth: { type: basic_auth, users: [\"alice:$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/\"], remove_header: true }\n  deny: { type: ip_deny, cidrs: [10.0.0.0/8] }\n  limit: { type: rate_limit, average: 2, burst: 2, period: 1m }\n",
        extra: "security: { trusted_proxies: [127.0.0.0/8] }\n",
        ..Setup::default()
    };
    let (_rdock, port) = start(&origin, &setup);
    let alice = ("authorization", "Basic YWxpY2U6cGFzc3dvcmQ=");
    assert_eq!(get_with(port, "/h", &[alice]).await.status, 200);
    assert!(is_hit(&get_with(port, "/h", &[alice]).await));
    assert_eq!(get(port, "/h").await.status, 401, "no credentials, no hit");
    assert_eq!(
        get_with(port, "/h", &[alice, ("x-forwarded-for", "10.1.2.3")])
            .await
            .status,
        403
    );
    // Two requests per minute pass the limit (refused requests never reached it): the third
    // is limited although the object is stored.
    let limited = get_with(port, "/h", &[alice]).await;
    assert_eq!(limited.status, 429, "{}", status(&limited));
    assert_eq!(origin.count("/h"), 1);
}

// -- compression, HTTP/2 ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_stored_object_serves_gzip_zstd_and_identity_clients() {
    let origin = Origin::start().await;
    let text = "cacheable text that compresses well. ".repeat(200);
    origin.set(
        "/t",
        cached("max-age=60", &text).header("content-type", "text/plain"),
    );
    let setup = Setup {
        chain: "gz, cache",
        middlewares: "  gz: { type: compress, algorithms: [zstd, gzip] }\n",
        ..Setup::default()
    };
    let (_rdock, port) = start(&origin, &setup);
    let gzip = get_with(port, "/t", &[("accept-encoding", "gzip")]).await;
    assert_eq!(gzip.header("content-encoding"), Some("gzip"));
    assert_eq!(gzip.header("vary"), Some("Accept-Encoding"));
    let mut decoded = String::new();
    flate2::read::GzDecoder::new(&gzip.body[..])
        .read_to_string(&mut decoded)
        .unwrap();
    assert_eq!(decoded, text);
    let zstd = get_with(port, "/t", &[("accept-encoding", "zstd")]).await;
    assert!(is_hit(&zstd));
    assert_eq!(zstd.header("content-encoding"), Some("zstd"));
    assert_eq!(zstd::decode_all(&zstd.body[..]).unwrap(), text.as_bytes());
    let identity = get(port, "/t").await;
    assert!(is_hit(&identity));
    assert!(identity.header("content-encoding").is_none());
    assert_eq!(identity.text(), text);
    assert_eq!(
        origin.count("/t"),
        1,
        "the store holds the origin's representation once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_clients_fill_and_hit() {
    let origin = Origin::start().await;
    origin.set("/h2", cached("max-age=60", "over h2"));
    let (_rdock, port) = start(&origin, &Setup::default());
    let first = client::h2c(addr(port), request("GET", "app.test", "/h2", &[])).await;
    assert_eq!((first.status, first.text().as_str()), (200, "over h2"));
    let second = client::h2c(addr(port), request("GET", "app.test", "/h2", &[])).await;
    assert_eq!(second.version, http::Version::HTTP_2);
    assert!(is_hit(&second), "{}", status(&second));
    assert_eq!(second.text(), "over h2");
    assert_eq!(origin.count("/h2"), 1);
}

// -- reload -----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reloads_keep_objects_apply_policy_and_diagnose_store_changes() {
    let origin = Origin::start().await;
    origin.set("/k", cached("max-age=60", "k"));
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, origin.addr, &Setup::default()));
    get(port, "/k").await;
    // Policy changes apply; the store and its objects stay.
    rdock.write_config(&config(
        port,
        origin.addr,
        &Setup {
            settings: "cache_status: false",
            ..Setup::default()
        },
    ));
    let (code, report) = rdock.reload();
    assert_eq!(code, 200, "{report}");
    let after = get(port, "/k").await;
    assert!(after.header("cache-status").is_none());
    assert_eq!(origin.count("/k"), 1, "the object survived the reload");
    // Changing a store is diagnosed and waits for a restart; the running store keeps serving.
    let changed = Setup {
        caches: "  mem: { type: memory, max_size: 1MiB }\n",
        ..Setup::default()
    };
    rdock.write_config(&config(port, origin.addr, &changed));
    let (code, report) = rdock.reload();
    assert_eq!(code, 200, "{report}");
    assert!(
        report.to_string().contains("takes effect after a restart"),
        "{report}"
    );
    assert!(is_hit(&get(port, "/k").await));
    // A new store applies at once.
    let added = Setup {
        caches: "  mem: { type: memory, max_size: 1MiB }\n  more: { type: memory }\n",
        middlewares: "  more: { type: cache, store: more }\n",
        chain: "more",
        ..Setup::default()
    };
    rdock.write_config(&config(port, origin.addr, &added));
    let (code, report) = rdock.reload();
    assert_eq!(code, 200, "{report}");
    assert!(!is_hit(&get(port, "/k").await), "a new store starts empty");
    assert!(is_hit(&get(port, "/k").await));
    assert_eq!(origin.count("/k"), 2);
}

// -- coalescing -------------------------------------------------------------------------------

async fn burst(port: u16, target: &'static str, n: usize) -> Vec<Reply> {
    let tasks: Vec<_> = (0..n)
        .map(|_| tokio::spawn(async move { get(port, target).await }))
        .collect();
    let mut out = Vec::with_capacity(n);
    for task in tasks {
        out.push(task.await.unwrap());
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn fifty_concurrent_misses_make_one_origin_request() {
    let origin = Origin::start().await;
    origin.set(
        "/stampede",
        cached("max-age=60", "one answer").delay(Duration::from_millis(500)),
    );
    let (rdock, port) = start(&origin, &Setup::default());
    let replies = burst(port, "/stampede", 50).await;
    assert_eq!(origin.count("/stampede"), 1);
    assert!(
        replies
            .iter()
            .all(|r| r.status == 200 && r.text() == "one answer")
    );
    let collapsed = replies
        .iter()
        .filter(|r| status(r).contains("collapsed"))
        .count();
    assert!(collapsed >= 40, "{collapsed} waited for the fill");
    let (_, metrics) = rdock.get_admin("/metrics").unwrap();
    assert!(
        metrics.contains("rdock_cache_lock_waits_total{store=\"mem\"}"),
        "{metrics}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn waiters_go_to_the_origin_themselves_when_the_fill_fails_or_is_not_cacheable() {
    let origin = Origin::start().await;
    origin.set("/fails", Script::close().delay(Duration::from_millis(400)));
    origin.set(
        "/uncacheable",
        cached("no-store", "u").delay(Duration::from_millis(400)),
    );
    let (_rdock, port) = start(&origin, &Setup::default());
    let started = Instant::now();
    let failed = burst(port, "/fails", 50).await;
    assert!(
        failed.iter().all(|r| r.status == 502),
        "every client gets the origin's failure"
    );
    assert!(
        origin.count("/fails") <= 50,
        "never more than one fetch per request"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "no waiter hangs"
    );
    let uncacheable = burst(port, "/uncacheable", 50).await;
    assert!(
        uncacheable
            .iter()
            .all(|r| r.status == 200 && r.text() == "u")
    );
    assert_eq!(
        origin.count("/uncacheable"),
        50,
        "released waiters fetch on their own"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn waiting_is_bounded_by_the_lock_timeout() {
    let origin = Origin::start().await;
    origin.set(
        "/slower",
        cached("max-age=60", "late").delay(Duration::from_millis(2500)),
    );
    let (_rdock, port) = start(
        &origin,
        &Setup {
            settings: "lock: { timeout: 1s }",
            ..Setup::default()
        },
    );
    let started = Instant::now();
    let replies = burst(port, "/slower", 20).await;
    assert!(
        replies
            .iter()
            .all(|r| r.status == 200 && r.text() == "late")
    );
    // After a second the waiters stop waiting: each goes to the origin uncached (one more
    // writer may be elected when the first one's lock ages out).
    assert!(
        origin.count("/slower") > 1,
        "waiters did not wait for the slow fill"
    );
    assert!(
        started.elapsed() < Duration::from_secs(7),
        "{:?}",
        started.elapsed()
    );
    let timed_out = replies
        .iter()
        .filter(|r| status(r).contains("lock-timeout"))
        .count();
    assert!(
        timed_out >= 1,
        "{:?}",
        replies.iter().map(status).collect::<Vec<_>>()
    );
}

// -- the disk store ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_disk_store_survives_restarts_streams_large_objects_and_drops_damage() {
    let origin = Origin::start().await;
    origin.set("/d", cached("max-age=600", "on disk"));
    origin.set("/d2", cached("max-age=600", "second"));
    let big_chunk = "0123456789abcdef".repeat(4096);
    origin.set("/huge", cached("max-age=600", &big_chunk).repeat(512));
    origin.set(
        "/broken",
        cached("max-age=600", "partial-")
            .repeat(20)
            .chunk_delay(Duration::from_millis(50)),
    );
    let setup = Setup {
        caches: "  mem: { type: disk, max_size: 128MiB, max_objects: 100 }\n",
        settings: "max_object_size: 64MiB",
        ..Setup::default()
    };
    let port = free_port();
    let mut rdock = Rdock::start(RDOCK, &config(port, origin.addr, &setup));
    get(port, "/d").await;
    get(port, "/d2").await;
    let huge = get(port, "/huge").await;
    assert_eq!(huge.body.len(), 32 << 20);
    let stored = rdock.data_dir().join("cache").join("mem");
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode, 0o700);
    // Damage one object on disk while rdock is down.
    rdock.stop(Duration::from_secs(10));
    let files: Vec<_> = walk(&stored);
    assert_eq!(files.len(), 3, "{files:?}");
    let victim = files
        .iter()
        .find(|f| {
            std::fs::read(f)
                .unwrap()
                .windows(11)
                .any(|w| w == b"app.test/d2")
        })
        .cloned()
        .unwrap();
    let mut bytes = std::fs::read(&victim).unwrap();
    let last = bytes.len() - 1;
    bytes.truncate(last);
    std::fs::write(&victim, bytes).unwrap();
    rdock.restart().unwrap();
    let hit = get(port, "/huge").await;
    assert!(is_hit(&hit), "{}", status(&hit));
    assert_eq!(hit.body.len(), 32 << 20);
    assert!(
        hit.body
            .chunks(big_chunk.len())
            .all(|c| c == big_chunk.as_bytes())
    );
    let (_, stats) = rdock.get_admin("/api/v1/cache").unwrap();
    let stats: serde_json::Value = serde_json::from_str(&stats).unwrap();
    assert_eq!(stats["stores"][0]["dropped"].as_u64(), Some(1), "{stats}");
    assert_eq!(stats["stores"][0]["objects"].as_u64(), Some(2), "{stats}");
    assert_eq!(origin.count("/huge"), 1);
    let objects = [get(port, "/d").await, get(port, "/d2").await];
    let hits = objects.iter().filter(|r| is_hit(r)).count();
    assert_eq!(hits, 1, "one survived, the damaged one is fetched again");
    // A fill the origin breaks off leaves nothing behind.
    let broken = tokio::spawn(async move {
        client::http1(addr(port), request("GET", "app.test", "/broken", &[])).await
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    origin.stop();
    let _ = broken.await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let leftovers: Vec<_> = walk(&stored)
        .into_iter()
        .filter(|f| f.extension().is_some_and(|e| e == "tmp"))
        .collect();
    assert_eq!(leftovers, Vec::<std::path::PathBuf>::new());
    let (_, stats) = rdock.get_admin("/api/v1/cache").unwrap();
    let stats: serde_json::Value = serde_json::from_str(&stats).unwrap();
    assert_eq!(stats["stores"][0]["objects"].as_u64(), Some(3), "{stats}");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        if entry.file_type().unwrap().is_dir() {
            out.extend(walk(&entry.path()));
        } else {
            out.push(entry.path());
        }
    }
    out
}

// -- retries, mirrors and held bodies ---------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retried_misses_are_stored_once_and_mirrored_requests_skip_the_cache() {
    let origin = Origin::start().await;
    origin.set("/m", cached("max-age=60", "m").numbered());
    let shadow = Origin::start().await;
    shadow.set("/m", cached("max-age=60", "shadow"));
    let dead = free_port();
    let port = free_port();
    let yaml = format!(
        "acme: false\nlisteners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\n\
         caches:\n  mem: {{ type: memory }}\n\
         middlewares:\n  cache: {{ type: cache, store: mem }}\n  hold: {{ type: hold_body }}\n\
         routes:\n  app: {{ match: \"Host(`app.test`)\", service: app, middlewares: [hold, cache] }}\n\
         \x20 mirrored: {{ match: \"Host(`mirror.test`)\", service: app, middlewares: [cache], mirror: {{ service: shadow, percent: 100 }} }}\n\
         services:\n  app: {{ backends: [{{ address: \"127.0.0.1:{dead}\" }}, {{ address: \"{}\" }}], retries: {{ attempts: 2 }} }}\n\
         \x20 shadow: {{ backends: [{{ address: \"{}\" }}] }}\n",
        origin.addr, shadow.addr
    );
    let _rdock = Rdock::start(RDOCK, &yaml);
    for _ in 0..3 {
        let reply = get(port, "/m").await;
        assert_eq!(
            (reply.status, reply.text().as_str()),
            (200, "1:m"),
            "{}",
            status(&reply)
        );
    }
    assert_eq!(origin.count("/m"), 1, "a retried fill is stored once");
    let on_mirror = |n: usize| async move {
        let reply = client::http1(addr(port), request("GET", "mirror.test", "/m", &[])).await;
        assert_eq!(
            status(&reply),
            "rdock; fwd=bypass; fwd-status=200; detail=mirrored",
            "request {n}"
        );
        reply
    };
    on_mirror(1).await;
    on_mirror(2).await;
    assert_eq!(
        origin.count("/m"),
        3,
        "mirrored requests neither read nor fill the cache"
    );
    for _ in 0..50 {
        if shadow.count("/m") == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        shadow.count("/m"),
        2,
        "the mirror sees every request the service sees"
    );
}
