//! The sync against a fake API on localhost.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Mutex;

use http::Response;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use super::*;

/// A fake `/client/v4/ips` answering from a script, then with 500.
struct FakeApi {
    url: String,
    /// The `If-None-Match` of each request received.
    seen: Arc<Mutex<Vec<Option<String>>>>,
}

impl FakeApi {
    async fn start(script: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/client/v4/ips", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(VecDeque::from(script)));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (log, script) = (log.clone(), script.clone());
                let service = service_fn(move |req: http::Request<Incoming>| {
                    let tag = req
                        .headers()
                        .get(header::IF_NONE_MATCH)
                        .map(|v| v.to_str().unwrap().to_owned());
                    log.lock().unwrap().push(tag);
                    let (status, body) = script
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or((500, String::new()));
                    let response = Response::builder()
                        .status(status)
                        .body(Full::new(Bytes::from(body)))
                        .unwrap();
                    async move { Ok::<_, Infallible>(response) }
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service),
                );
            }
        });
        Self { url, seen }
    }

    fn seen(&self) -> Vec<Option<String>> {
        self.seen.lock().unwrap().clone()
    }
}

fn body(etag: &str, v4: &str) -> String {
    format!(
        r#"{{"result":{{"ipv4_cidrs":["{v4}"],"ipv6_cidrs":["2400:cb00::/32"],"etag":"{etag}"}},"success":true,"errors":[],"messages":[]}}"#
    )
}

fn ok(etag: &str, v4: &str) -> (u16, String) {
    (200, body(etag, v4))
}

fn nets(list: &[&str]) -> Vec<IpNet> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

fn options(url: &str, dir: &std::path::Path) -> Options {
    Options {
        url: url.to_owned(),
        dir: dir.to_owned(),
        interval: INTERVAL,
        retry: RETRY,
    }
}

fn empty_ranges() -> Ranges {
    Arc::new(ArcSwap::from_pointee(Vec::new()))
}

const A: &str = "198.41.128.0/17";
const B: &str = "131.0.72.0/22";

#[tokio::test]
async fn refreshes_honour_the_etag_and_keep_the_list_on_bad_answers() {
    let api = FakeApi::start(vec![
        ok("a", A),
        (304, String::new()),
        ok("a", B),
        (503, String::new()),
        (200, "<html>maintenance</html>".to_owned()),
        ok("c", "0.0.0.0/0"),
        ok("b", B),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let ranges = empty_ranges();
    let mut worker = Worker::new(options(&api.url, dir.path()), ranges.clone());
    assert_eq!(**ranges.load(), IpList::builtin().ranges);

    assert!(worker.refresh().await, "first fetch");
    let a = nets(&[A, "2400:cb00::/32"]);
    assert_eq!(**ranges.load(), a);
    // 304, the same etag with other ranges, 503, HTML and a list trusting everyone: all keep A.
    for step in ["304", "same etag", "503", "html", "too wide"] {
        assert!(!worker.refresh().await, "{step}");
        assert_eq!(**ranges.load(), a, "{step}");
    }
    assert!(worker.refresh().await, "new etag");
    assert_eq!(**ranges.load(), nets(&[B, "2400:cb00::/32"]));

    let seen = api.seen();
    assert_eq!(seen[0], None);
    assert!(seen[1..6].iter().all(|t| t.as_deref() == Some("\"a\"")));
    let (cached, _) = Cache::new(dir.path()).load().unwrap().unwrap();
    assert_eq!(cached.etag.as_deref(), Some("b"));
}

#[tokio::test]
async fn starts_from_the_cache_or_the_builtin_list_without_the_network() {
    // Nothing listens on port 1: every fetch fails.
    let unreachable = "http://127.0.0.1:1/client/v4/ips";
    let dir = tempfile::tempdir().unwrap();
    let ranges = empty_ranges();
    let mut worker = Worker::new(options(unreachable, dir.path()), ranges.clone());
    assert_eq!(**ranges.load(), IpList::builtin().ranges);
    assert!(!worker.refresh().await);
    assert_eq!(**ranges.load(), IpList::builtin().ranges);

    let cached = IpList::from_api(body("x", A).as_bytes()).unwrap();
    Cache::new(dir.path()).save(&cached, 0).unwrap();
    let _worker = Worker::new(options(unreachable, dir.path()), ranges.clone());
    assert_eq!(**ranges.load(), cached.ranges);

    std::fs::write(dir.path().join("ips.json"), "not json").unwrap();
    let _worker = Worker::new(options(unreachable, dir.path()), ranges.clone());
    assert_eq!(**ranges.load(), IpList::builtin().ranges);
}

async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn the_task_fetches_only_while_enabled_and_when_due() {
    let api = FakeApi::start(vec![ok("a", A)]).await;
    let dir = tempfile::tempdir().unwrap();
    let ranges = empty_ranges();
    let sync = IpSync::spawn(options(&api.url, dir.path()), ranges.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(api.seen().is_empty(), "fetched while disabled");

    sync.set_enabled(true);
    let a = nets(&[A, "2400:cb00::/32"]);
    eventually("the first fetch", || **ranges.load() == a).await;

    // A fresh cache waits for the interval.
    let fresh = FakeApi::start(vec![ok("b", B)]).await;
    let restarted = IpSync::spawn(options(&fresh.url, dir.path()), ranges.clone());
    restarted.set_enabled(true);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        fresh.seen().is_empty(),
        "fetched although the cache is fresh"
    );
    assert_eq!(**ranges.load(), a);
}
