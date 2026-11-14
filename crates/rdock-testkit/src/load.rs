//! Steady client load for the chaos suite (ADR-0033): an open-model generator that sends
//! requests at a fixed rate whatever the answers do, so a stall shows as late and failed
//! requests instead of slowing the generator down (no coordinated omission).
//!
//! Every request has a deadline ([`Target::deadline`], 5 s by default); a request counts as
//! failed when it is not answered in time, the connection fails, or the status is not one the
//! target expects. Connections are kept alive and reused (HTTP/1.1, optionally over TLS); a
//! request that finds its pooled connection already closed by the server before anything was
//! sent is sent again once on a new connection, as browsers and HTTP clients do (hyper's
//! `is_canceled`); any other error counts.
//!
//! ```no_run
//! # async fn demo(addr: std::net::SocketAddr) {
//! use rdock_testkit::load::{Load, Target};
//! let load = Load::start(vec![Target::http(addr, "app.test", "/")], 50);
//! // … inject a fault, heal it …
//! let report = load.stop().await;
//! report.assert_clean("a backend outage", "");
//! # }
//! ```

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// Requests in flight at most; beyond it a scheduled request counts as failed ("overloaded").
const MAX_IN_FLIGHT: u64 = 512;
/// Failures kept in the report with their reason.
const KEPT_FAILURES: usize = 30;

/// Where requests go and what counts as success.
#[derive(Clone)]
pub struct Target {
    /// The listener.
    pub addr: SocketAddr,
    /// `Host` (and the TLS server name).
    pub host: String,
    /// The request target.
    pub path: String,
    /// Statuses that count as success.
    pub expect: Vec<u16>,
    /// The longest a request may take.
    pub deadline: Duration,
    /// A TLS client configuration, for HTTPS.
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// A name for the report.
    pub name: String,
    /// Each request asks for a path of its own (`?n=<number>`), so a caching route misses
    /// every time and has to store.
    pub unique: bool,
}

impl Target {
    /// Plain HTTP/1.1 expecting `200`.
    pub fn http(addr: SocketAddr, host: &str, path: &str) -> Self {
        Self {
            addr,
            host: host.to_owned(),
            path: path.to_owned(),
            expect: vec![200],
            deadline: Duration::from_secs(5),
            tls: None,
            name: format!("http://{host}{path}"),
            unique: false,
        }
    }

    /// HTTPS (HTTP/1.1 over TLS) expecting `200`.
    pub fn https(addr: SocketAddr, host: &str, path: &str, tls: Arc<rustls::ClientConfig>) -> Self {
        Self {
            tls: Some(tls),
            name: format!("https://{host}{path}"),
            ..Self::http(addr, host, path)
        }
    }

    /// The same target with a query of its own on every request.
    #[must_use]
    pub fn unique_paths(mut self) -> Self {
        self.unique = true;
        self
    }

    /// The same target accepting `statuses` instead.
    #[must_use]
    pub fn expecting(mut self, statuses: &[u16]) -> Self {
        self.expect = statuses.to_vec();
        self
    }
}

/// One failed request.
#[derive(Debug, Clone)]
pub struct Failure {
    /// Since the load started.
    pub at: Duration,
    /// The target's name.
    pub target: String,
    /// What happened.
    pub reason: String,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    ok: AtomicU64,
    failed: AtomicU64,
    in_flight: AtomicU64,
    retried_stale: AtomicU64,
    slowest_ms: AtomicU64,
}

struct Shared {
    started: Instant,
    counters: Counters,
    failures: Mutex<Vec<Failure>>,
    pools: Vec<Mutex<VecDeque<SendRequest<Empty<Bytes>>>>>,
    targets: Vec<Target>,
}

/// What a load run saw.
#[derive(Debug, Clone)]
pub struct Report {
    /// Requests scheduled.
    pub sent: u64,
    /// Answered with an expected status in time.
    pub ok: u64,
    /// Everything else.
    pub failed: u64,
    /// Requests re-sent once because their pooled connection was closed before sending.
    pub retried_stale: u64,
    /// The slowest successful request.
    pub slowest: Duration,
    /// The first failures, with reasons.
    pub failures: Vec<Failure>,
    /// How long the load ran.
    pub elapsed: Duration,
}

impl Report {
    /// Panics with the failures and `log` (the process log) unless no request failed and at
    /// least one succeeded.
    pub fn assert_clean(&self, scenario: &str, log: &str) {
        assert!(
            self.failed == 0 && self.ok > 0,
            "{scenario}: {} of {} requests failed (ok {}); first failures:\n{}\n--- process log ---\n{log}",
            self.failed,
            self.sent,
            self.ok,
            self.failures
                .iter()
                .map(|f| format!("  {:>8.3}s {} {}", f.at.as_secs_f64(), f.target, f.reason))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// A running load.
pub struct Load {
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    scheduler: tokio::task::JoinHandle<()>,
}

impl Load {
    /// Starts sending `rate` requests a second, round-robin over `targets`.
    pub fn start(targets: Vec<Target>, rate: u32) -> Self {
        assert!(!targets.is_empty() && rate > 0);
        let shared = Arc::new(Shared {
            started: Instant::now(),
            counters: Counters::default(),
            failures: Mutex::new(Vec::new()),
            pools: targets.iter().map(|_| Mutex::default()).collect(),
            targets,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let interval = Duration::from_secs(1) / rate;
        let scheduler = {
            let (shared, stop) = (shared.clone(), stop.clone());
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                // Open model: a late tick fires at once, it is not skipped.
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
                let mut n = 0usize;
                while !stop.load(Ordering::Relaxed) {
                    tick.tick().await;
                    let index = n % shared.targets.len();
                    n += 1;
                    shared.counters.sent.fetch_add(1, Ordering::Relaxed);
                    if shared.counters.in_flight.load(Ordering::Relaxed) >= MAX_IN_FLIGHT {
                        fail(
                            &shared,
                            index,
                            "overloaded: too many requests in flight".into(),
                        );
                        continue;
                    }
                    shared.counters.in_flight.fetch_add(1, Ordering::Relaxed);
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        one(&shared, index).await;
                        shared.counters.in_flight.fetch_sub(1, Ordering::Relaxed);
                    });
                }
            })
        };
        Self {
            shared,
            stop,
            scheduler,
        }
    }

    /// The report so far.
    pub fn report(&self) -> Report {
        let c = &self.shared.counters;
        Report {
            sent: c.sent.load(Ordering::Relaxed),
            ok: c.ok.load(Ordering::Relaxed),
            failed: c.failed.load(Ordering::Relaxed),
            retried_stale: c.retried_stale.load(Ordering::Relaxed),
            slowest: Duration::from_millis(c.slowest_ms.load(Ordering::Relaxed)),
            failures: self
                .shared
                .failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            elapsed: self.shared.started.elapsed(),
        }
    }

    /// Successful requests so far.
    pub fn ok(&self) -> u64 {
        self.shared.counters.ok.load(Ordering::Relaxed)
    }

    /// Waits until `more` further requests have succeeded (the load is flowing), at most
    /// `limit`.
    pub async fn wait_for_ok(&self, more: u64, limit: Duration) {
        let target = self.ok() + more;
        let start = Instant::now();
        while self.ok() < target {
            assert!(
                start.elapsed() < limit,
                "the load did not reach {target} successful requests within {limit:?}: {:?}",
                self.report()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Stops scheduling, waits for the requests in flight (each has its deadline) and reports.
    pub async fn stop(self) -> Report {
        self.stop.store(true, Ordering::Relaxed);
        let Self {
            shared,
            stop,
            scheduler,
        } = self;
        let _ = scheduler.await;
        let this = Self {
            shared,
            stop,
            scheduler: tokio::spawn(async {}),
        };
        let shared = &this.shared;
        let longest = shared
            .targets
            .iter()
            .map(|t| t.deadline)
            .max()
            .unwrap_or_default();
        let start = Instant::now();
        while shared.counters.in_flight.load(Ordering::Relaxed) > 0
            && start.elapsed() < longest + Duration::from_secs(5)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        this.report()
    }
}

fn fail(shared: &Shared, index: usize, reason: String) {
    shared.counters.failed.fetch_add(1, Ordering::Relaxed);
    let mut failures = shared
        .failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if failures.len() < KEPT_FAILURES {
        failures.push(Failure {
            at: shared.started.elapsed(),
            target: shared.targets[index].name.clone(),
            reason,
        });
    }
}

async fn one(shared: &Shared, index: usize) {
    let target = &shared.targets[index];
    let started = Instant::now();
    let outcome = tokio::time::timeout(target.deadline, attempt(shared, index)).await;
    match outcome {
        Ok(Ok(status)) if target.expect.contains(&status) => {
            shared.counters.ok.fetch_add(1, Ordering::Relaxed);
            let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            shared.counters.slowest_ms.fetch_max(ms, Ordering::Relaxed);
        }
        Ok(Ok(status)) => fail(shared, index, format!("status {status}")),
        Ok(Err(reason)) => fail(shared, index, reason),
        Err(_) => fail(
            shared,
            index,
            format!("no answer within {:?}", target.deadline),
        ),
    }
}

/// One request: on a pooled connection when one is free, else a new one. A pooled connection
/// the server closed before the request was sent gets one retry on a new connection.
async fn attempt(shared: &Shared, index: usize) -> Result<u16, String> {
    let pooled = loop {
        let candidate = shared.pools[index]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front();
        match candidate {
            Some(sender) if sender.is_closed() => {}
            other => break other,
        }
    };
    if let Some(sender) = pooled {
        match send(shared, index, sender).await {
            Err(SendError::Canceled) => {
                shared
                    .counters
                    .retried_stale
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(SendError::Other(reason)) => return Err(reason),
            Ok(status) => return Ok(status),
        }
    }
    let sender = connect(&shared.targets[index]).await?;
    send(shared, index, sender).await.map_err(|e| match e {
        SendError::Canceled => "the connection closed before the request was sent".to_owned(),
        SendError::Other(reason) => reason,
    })
}

enum SendError {
    Canceled,
    Other(String),
}

async fn send(
    shared: &Shared,
    index: usize,
    mut sender: SendRequest<Empty<Bytes>>,
) -> Result<u16, SendError> {
    let target = &shared.targets[index];
    if sender.ready().await.is_err() {
        return Err(SendError::Canceled);
    }
    let path = if target.unique {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!("{}?n={}", target.path, NEXT.fetch_add(1, Ordering::Relaxed))
    } else {
        target.path.clone()
    };
    let request = Request::builder()
        .uri(path.as_str())
        .header("host", target.host.as_str())
        .body(Empty::<Bytes>::new())
        .map_err(|e| SendError::Other(e.to_string()))?;
    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(e) if e.is_canceled() => return Err(SendError::Canceled),
        Err(e) => return Err(SendError::Other(format!("request: {e}"))),
    };
    let status = response.status().as_u16();
    let keep = !response
        .headers()
        .get(http::header::CONNECTION)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"close"));
    response
        .into_body()
        .collect()
        .await
        .map_err(|e| SendError::Other(format!("body: {e}")))?;
    if keep && !sender.is_closed() {
        shared.pools[index]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(sender);
    }
    Ok(status)
}

async fn connect(target: &Target) -> Result<SendRequest<Empty<Bytes>>, String> {
    let tcp = TcpStream::connect(target.addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let _ = tcp.set_nodelay(true);
    match &target.tls {
        None => handshake(tcp).await,
        Some(config) => {
            let name = rustls_pki_types::ServerName::try_from(target.host.clone())
                .map_err(|e| e.to_string())?;
            let tls = tokio_rustls::TlsConnector::from(config.clone())
                .connect(name, tcp)
                .await
                .map_err(|e| format!("TLS: {e}"))?;
            handshake(tls).await
        }
    }
}

async fn handshake<S>(stream: S) -> Result<SendRequest<Empty<Bytes>>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    tokio::spawn(conn);
    Ok(sender)
}
