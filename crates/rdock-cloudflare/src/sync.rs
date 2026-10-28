//! Keeps Cloudflare's edge ranges current (W-CF-01, ADR-0020): the cache or the built-in list
//! at once, then `GET /client/v4/ips` once a day while a configuration trusts `cloudflare`.
//! A failed or implausible fetch keeps the list in use.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use ipnet::IpNet;
use tokio::sync::watch;
use tokio::time::{Instant, timeout};

use crate::ips::{Cache, InvalidList, IpList};

/// Cloudflare's API endpoint for its IP ranges.
pub const API_URL: &str = "https://api.cloudflare.com/client/v4/ips";
/// How often the ranges are fetched.
pub const INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How soon a failed fetch is tried again.
pub const RETRY: Duration = Duration::from_secs(60 * 60);

/// Limit for one request, connection to last byte.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The real response is about 500 bytes.
const MAX_BODY: usize = 64 * 1024;

/// The ranges shared with the data plane, which only reads them.
pub type Ranges = Arc<ArcSwap<Vec<IpNet>>>;

/// Where and how often to fetch.
#[derive(Debug, Clone)]
pub struct Options {
    /// The API URL; [`API_URL`] except in tests.
    pub url: String,
    /// Directory of the cache file (`$RDOCK_DATA_DIR/cloudflare`).
    pub dir: PathBuf,
    /// Time between fetches.
    pub interval: Duration,
    /// Time before a failed fetch is repeated.
    pub retry: Duration,
}

impl Options {
    /// Cloudflare's API, daily, cached in `dir`.
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            url: API_URL.to_owned(),
            dir,
            interval: INTERVAL,
            retry: RETRY,
        }
    }
}

/// Why a fetch failed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The TLS client could not be set up.
    #[error("TLS setup: {0}")]
    Tls(String),
    /// The request could not be built.
    #[error("request: {0}")]
    Request(#[from] http::Error),
    /// Connecting or exchanging the request failed.
    #[error("{0}")]
    Http(#[from] hyper_util::client::legacy::Error),
    /// The answer took longer than 30 seconds.
    #[error("timed out")]
    Timeout,
    /// The answer was not `200 OK` or `304 Not Modified`.
    #[error("HTTP status {0}")]
    Status(StatusCode),
    /// The body could not be read or was too large.
    #[error("body: {0}")]
    Body(String),
    /// The body is not a plausible list.
    #[error(transparent)]
    Invalid(#[from] InvalidList),
}

/// The result of one fetch.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Fetched {
    /// The list in use is current.
    Unchanged,
    /// A new list.
    Updated(IpList),
}

/// Handle of the sync task.
#[derive(Debug)]
pub struct IpSync {
    enabled: watch::Sender<bool>,
}

impl IpSync {
    /// Puts the cached list (or the built-in one) into `ranges` before returning, so nothing
    /// waits for the network, then starts the task. It fetches only while enabled.
    #[must_use]
    pub fn spawn(options: Options, ranges: Ranges) -> Self {
        let worker = Worker::new(options, ranges);
        let (enabled, rx) = watch::channel(false);
        tokio::spawn(worker.run(rx));
        Self { enabled }
    }

    /// Starts or pauses fetching: on while the applied configuration trusts `cloudflare`.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.send_if_modified(|current| {
            let changed = *current != on;
            *current = on;
            changed
        });
    }
}

type HttpsClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;

pub(crate) struct Worker {
    options: Options,
    cache: Cache,
    ranges: Ranges,
    current: IpList,
    next: Instant,
    client: Option<HttpsClient>,
}

impl Worker {
    /// Loads the cache or the built-in list into `ranges`.
    pub(crate) fn new(options: Options, ranges: Ranges) -> Self {
        let cache = Cache::new(&options.dir);
        let (current, age) = match cache.load() {
            Ok(Some((list, fetched_at))) => (list, Some(unix_now().saturating_sub(fetched_at))),
            Ok(None) => (IpList::builtin(), None),
            Err(err) => {
                tracing::warn!(error = %err, "ignoring the cached Cloudflare IP ranges");
                (IpList::builtin(), None)
            }
        };
        ranges.store(Arc::new(current.ranges.clone()));
        let next = Instant::now()
            + age.map_or(Duration::ZERO, |age| {
                options.interval.saturating_sub(Duration::from_secs(age))
            });
        Self {
            options,
            cache,
            ranges,
            current,
            next,
            client: None,
        }
    }

    async fn run(mut self, mut enabled: watch::Receiver<bool>) {
        loop {
            if enabled.wait_for(|on| *on).await.is_err() {
                return;
            }
            tokio::select! {
                () = tokio::time::sleep_until(self.next) => {
                    self.refresh().await;
                }
                changed = enabled.changed() => if changed.is_err() {
                    return;
                },
            }
        }
    }

    /// Fetches once and applies the result; returns whether the ranges changed.
    pub(crate) async fn refresh(&mut self) -> bool {
        match self.fetch().await {
            Ok(fetched) => {
                self.next = Instant::now() + self.options.interval;
                let changed = matches!(fetched, Fetched::Updated(_));
                if let Fetched::Updated(list) = fetched {
                    tracing::info!(
                        ranges = list.ranges.len(),
                        etag = list.etag.as_deref().unwrap_or_default(),
                        "Cloudflare IP ranges updated"
                    );
                    self.ranges.store(Arc::new(list.ranges.clone()));
                    self.current = list;
                }
                if let Err(err) = self.cache.save(&self.current, unix_now()) {
                    tracing::warn!(error = %err, "cannot cache the Cloudflare IP ranges");
                }
                changed
            }
            Err(err) => {
                self.next = Instant::now() + self.options.retry;
                tracing::warn!(
                    error = %err,
                    retry_in_s = self.options.retry.as_secs(),
                    "cannot fetch Cloudflare's IP ranges; keeping the current list"
                );
                false
            }
        }
    }

    async fn fetch(&mut self) -> Result<Fetched, FetchError> {
        let client = self.client()?;
        let mut request = Request::get(&self.options.url).header(
            header::USER_AGENT,
            concat!("rdock/", env!("CARGO_PKG_VERSION")),
        );
        if let Some(etag) = &self.current.etag {
            request = request.header(header::IF_NONE_MATCH, format!("\"{etag}\""));
        }
        let request = request.body(Empty::new())?;
        let exchange = async {
            let response = client.request(request).await?;
            match response.status() {
                StatusCode::NOT_MODIFIED => return Ok(None),
                StatusCode::OK => {}
                status => return Err(FetchError::Status(status)),
            }
            let body = Limited::new(response.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|e| FetchError::Body(e.to_string()))?;
            Ok(Some(body.to_bytes()))
        };
        let Some(body) = timeout(TIMEOUT, exchange)
            .await
            .map_err(|_| FetchError::Timeout)??
        else {
            return Ok(Fetched::Unchanged);
        };
        let list = IpList::from_api(&body)?;
        // The API does not answer `If-None-Match` with 304 (checked 2026-10-28), so the `etag`
        // in the body decides.
        if list.etag.is_some() && list.etag == self.current.etag {
            return Ok(Fetched::Unchanged);
        }
        Ok(Fetched::Updated(list))
    }

    fn client(&mut self) -> Result<HttpsClient, FetchError> {
        if let Some(client) = &self.client {
            return Ok(client.clone());
        }
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|e| FetchError::Tls(e.to_string()))?
            // `http://` only reaches the fake API of the tests: the URL is not configurable.
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        self.client = Some(client.clone());
        Ok(client)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests;
