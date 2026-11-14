//! Which middleware phases run on a cache hit (F-WEB-03, ADR-0030). Pingora 0.9.1 looks the
//! cache up after `request_filter` and answers a hit before `upstream_peer` and
//! `upstream_request_filter`; `response_filter`, `response_body_filter` and `logging` run on
//! hits too. Counting middlewares appended to a cached route's chain prove it on an
//! in-process data plane compiled as `rdock run` does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_middleware::{Capabilities, Context, Flow, LogSummary, Middleware, Phases};
use rdock_proxy::forwarded::CloudflareRanges;
use rdock_proxy::upstream::Dns;
use rdock_proxy::{CompileEnv, DataPlane, Mode, Runtime, compile};
use rdock_testkit::origin::{Origin, Script};
use rdock_testkit::{client, free_port};

#[derive(Debug, Default)]
struct Counts {
    request: AtomicUsize,
    upstream_request: AtomicUsize,
    response: AtomicUsize,
    response_body: AtomicUsize,
    log: AtomicUsize,
}

#[derive(Debug)]
struct Counter(Arc<Counts>);

#[async_trait]
impl Middleware for Counter {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(
            Phases::REQUEST
                | Phases::UPSTREAM_REQUEST
                | Phases::RESPONSE
                | Phases::RESPONSE_BODY
                | Phases::LOG,
        )
    }

    async fn request(&self, _req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        self.0.request.fetch_add(1, Ordering::SeqCst);
        Flow::Next
    }

    async fn upstream_request(&self, _req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        self.0.upstream_request.fetch_add(1, Ordering::SeqCst);
        Flow::Next
    }

    async fn response(&self, resp: &mut ResponseHeader, _cx: &mut Context) {
        self.0.response.fetch_add(1, Ordering::SeqCst);
        resp.insert_header("x-response-phase", "ran").unwrap();
    }

    fn response_body(&self, body: &mut Option<Bytes>, end_of_stream: bool, _cx: &mut Context) {
        if end_of_stream || body.as_ref().is_some_and(|b| !b.is_empty()) {
            self.0.response_body.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn log(&self, _summary: &LogSummary, _cx: &Context) {
        self.0.log.fetch_add(1, Ordering::SeqCst);
    }
}

async fn serve(
    origin: SocketAddr,
    counts: Arc<Counts>,
    registry: &rdock_cache::Registry,
) -> (DataPlane, SocketAddr) {
    let port = free_port();
    let yaml = format!(
        "acme: false\nlisteners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\n\
         caches:\n  mem: {{ type: memory }}\nmiddlewares:\n  cache: {{ type: cache, store: mem }}\n\
         routes:\n  app: {{ match: \"PathPrefix(`/`)\", service: app, middlewares: [cache] }}\n\
         services:\n  app: {{ backends: [{{ address: \"{origin}\" }}] }}\n"
    );
    let loaded = rdock_config::load_str(&yaml, rdock_config::Format::Yaml).unwrap();
    assert!(!loaded.has_errors(), "{:?}", loaded.diagnostics);
    let compiled = compile(
        &loaded.config,
        &CompileEnv {
            mode: Mode::Run,
            generation: 1,
            dns: &Dns::default(),
            client: Arc::new(rdock_middleware::HttpClient::default()),
            previous: None,
            cloudflare: &CloudflareRanges::default(),
            backends: &rdock_balancer::Registry::default(),
            sticky_key: b"test",
            live: &rdock_observability::live::Live::default(),
            caches: Some(registry),
            plugins: &rdock_plugin_api::Registry::new(),
            metrics: None,
            quotas: None,
            abuse: None,
            shared_limits: None,
        },
    );
    let errors: Vec<_> = compiled
        .diagnostics
        .iter()
        .filter(|d| d.is_error())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    let mut runtime = compiled.runtime.unwrap();
    let listener = runtime.listeners.get_mut("web").unwrap();
    let route = Arc::get_mut(&mut listener.routes[0]).expect("a fresh route has one owner");
    assert!(route.cache.is_some(), "the route caches");
    let mut chain: Vec<(Arc<str>, Arc<dyn Middleware>)> = route
        .middlewares
        .names()
        .map(Arc::from)
        .zip(route.middlewares.middlewares().cloned())
        .collect();
    chain.push((Arc::from("counter"), Arc::new(Counter(counts))));
    route.middlewares = rdock_middleware::Chain::new(chain);
    let metrics = rdock_observability::Metrics::new("test", "test").unwrap();
    let plane = DataPlane::new(metrics, Runtime::empty());
    plane
        .apply(runtime, Duration::from_millis(10))
        .await
        .unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (plane, addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hit_runs_request_response_body_and_log_phases_but_not_upstream_request() {
    let origin = Origin::start().await;
    origin.set("/x", Script::ok("cached body").cache_control("max-age=60"));
    let counts = Arc::new(Counts::default());
    let registry = rdock_cache::Registry::new(None);
    let (_plane, addr) = serve(origin.addr, counts.clone(), &registry).await;
    let snapshot = |c: &Counts| {
        [
            c.request.load(Ordering::SeqCst),
            c.upstream_request.load(Ordering::SeqCst),
            c.response.load(Ordering::SeqCst),
            c.response_body.load(Ordering::SeqCst),
            c.log.load(Ordering::SeqCst),
        ]
    };
    let miss = client::http1(addr, client::get("app.test", "/x")).await;
    assert_eq!(miss.text(), "cached body");
    assert_eq!(miss.header("x-response-phase"), Some("ran"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_miss = snapshot(&counts);
    assert_eq!(
        after_miss[..3],
        [1, 1, 1],
        "a miss runs every phase: {after_miss:?}"
    );
    assert!(after_miss[3] >= 1 && after_miss[4] == 1, "{after_miss:?}");

    let hit = client::http1(addr, client::get("app.test", "/x")).await;
    assert!(
        hit.header("cache-status")
            .unwrap()
            .starts_with("rdock; hit")
    );
    assert_eq!(hit.text(), "cached body");
    assert_eq!(
        hit.header("x-response-phase"),
        Some("ran"),
        "response middlewares change hits"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_hit = snapshot(&counts);
    assert_eq!(after_hit[0], 2, "request runs on the hit");
    assert_eq!(
        after_hit[1], 1,
        "upstream_request does not: no backend is chosen"
    );
    assert_eq!(after_hit[2], 2, "response runs on the hit");
    assert!(
        after_hit[3] > after_miss[3],
        "response_body runs on the hit"
    );
    assert_eq!(after_hit[4], 2, "log runs on the hit");
    assert_eq!(origin.count("/x"), 1);
    assert_eq!(registry.get("mem").unwrap().stats().objects, 1);
}
