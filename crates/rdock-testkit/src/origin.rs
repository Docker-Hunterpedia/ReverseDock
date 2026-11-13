//! A scripted origin for cache tests: each path answers what its [`Script`] says, and every
//! request is counted and recorded.
//!
//! - an unscripted path answers `404` without caching headers;
//! - a script with an `etag` answers `304` (with `not_modified` headers) to a matching
//!   `If-None-Match`;
//! - `delay` waits before the head, `chunk_delay` between body chunks (a slow fill);
//! - `close` drops the connection without answering (an origin failure);
//! - [`Origin::stop`] closes the listener and every connection, so connects are refused.

#![allow(
    clippy::return_self_not_must_use,
    reason = "builder methods of a test fixture"
)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use http_body_util::{BodyExt, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

type Body = BoxBody<Bytes, Infallible>;

/// What a path answers.
#[derive(Debug, Clone)]
pub struct Script {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Repeat `body` this many times (large objects without a large script).
    pub repeat: usize,
    pub delay: Duration,
    pub chunk_delay: Duration,
    pub etag: Option<String>,
    pub not_modified: Vec<(String, String)>,
    pub close: bool,
    /// Prefix the body with the request count for this path (to tell answers apart).
    pub numbered: bool,
}

impl Script {
    /// `200` with `body`.
    pub fn ok(body: impl Into<Bytes>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
            repeat: 1,
            delay: Duration::ZERO,
            chunk_delay: Duration::ZERO,
            etag: None,
            not_modified: Vec::new(),
            close: false,
            numbered: false,
        }
    }

    /// `status` with a short body.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::ok(format!("status {status}\n"))
        }
    }

    /// Drops the connection without an answer.
    pub fn close() -> Self {
        Self {
            close: true,
            ..Self::ok("")
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn cache_control(self, value: &str) -> Self {
        self.header("cache-control", value)
    }

    pub fn etag(mut self, etag: &str) -> Self {
        self.etag = Some(etag.to_owned());
        self.header("etag", etag)
    }

    /// A header added to `304` answers.
    pub fn not_modified(mut self, name: &str, value: &str) -> Self {
        self.not_modified.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn repeat(mut self, times: usize) -> Self {
        self.repeat = times;
        self
    }

    pub fn chunk_delay(mut self, delay: Duration) -> Self {
        self.chunk_delay = delay;
        self
    }

    pub fn numbered(mut self) -> Self {
        self.numbered = true;
        self
    }
}

#[derive(Default)]
struct State {
    scripts: HashMap<String, Script>,
    counts: HashMap<String, usize>,
    seen: Vec<(String, HeaderMap)>,
}

/// A running scripted origin.
pub struct Origin {
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

impl Origin {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state: Arc<Mutex<State>> = Arc::default();
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let mut stopping = stopped.clone();
                let accepted = tokio::select! {
                    a = listener.accept() => a,
                    _ = stopping.changed() => return,
                };
                let Ok((tcp, _)) = accepted else {
                    continue;
                };
                let state = shared.clone();
                let mut stopping = stopped.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = state.clone();
                        async move { handle(&state, req).await }
                    });
                    let builder =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    let conn = builder.serve_connection(TokioIo::new(tcp), service);
                    tokio::select! {
                        _ = conn => {}
                        _ = stopping.changed() => {}
                    }
                });
            }
        });
        Self {
            addr,
            state,
            stop,
            task,
        }
    }

    /// Scripts `path` (without the query).
    pub fn set(&self, path: &str, script: Script) {
        self.state
            .lock()
            .unwrap()
            .scripts
            .insert(path.to_owned(), script);
    }

    /// Requests received for `path` (without the query).
    pub fn count(&self, path: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .counts
            .get(path)
            .copied()
            .unwrap_or(0)
    }

    /// Request targets (with the query) and headers received, in order.
    pub fn seen(&self) -> Vec<(String, HeaderMap)> {
        self.state.lock().unwrap().seen.clone()
    }

    /// The headers of the last request for `path`.
    pub fn last_headers(&self, path: &str) -> Option<HeaderMap> {
        self.seen()
            .into_iter()
            .rev()
            .find(|(target, _)| target.split('?').next() == Some(path))
            .map(|(_, h)| h)
    }

    /// Closes the listener and every open connection: further connects are refused.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

async fn handle(
    state: &Mutex<State>,
    req: Request<Incoming>,
) -> Result<Response<Body>, std::io::Error> {
    let path = req.uri().path().to_owned();
    let target = req
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let (script, count) = {
        let mut state = state.lock().unwrap();
        let count = {
            let c = state.counts.entry(path.clone()).or_default();
            *c += 1;
            *c
        };
        state.seen.push((target, req.headers().clone()));
        (state.scripts.get(&path).cloned(), count)
    };
    let headers = req.headers().clone();
    let _ = req.into_body().collect().await;
    let Some(script) = script else {
        return Ok(Response::builder()
            .status(404)
            .body(BodyExt::boxed(http_body_util::Full::new(
                Bytes::from_static(b"no script\n"),
            )))
            .unwrap());
    };
    if !script.delay.is_zero() {
        tokio::time::sleep(script.delay).await;
    }
    if script.close {
        // A failed service makes hyper close the connection without an answer.
        return Err(std::io::Error::other("closed by the script"));
    }
    let matches = script.etag.as_deref().is_some_and(|etag| {
        headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|t| t.trim() == etag))
    });
    if matches {
        let mut resp = Response::builder().status(304);
        for (n, v) in script
            .headers
            .iter()
            .filter(|(n, _)| n == "etag" || n == "cache-control")
        {
            resp = resp.header(n, v);
        }
        for (n, v) in &script.not_modified {
            resp = resp.header(n, v);
        }
        return Ok(resp
            .body(BodyExt::boxed(http_body_util::Empty::new()))
            .unwrap());
    }
    let mut resp = Response::builder().status(script.status);
    for (n, v) in &script.headers {
        resp = resp.header(n, v);
    }
    let prefix = if script.numbered {
        Bytes::from(format!("{count}:"))
    } else {
        Bytes::new()
    };
    let length = prefix.len() + script.body.len() * script.repeat;
    resp = resp.header("content-length", length.to_string());
    let chunks: Vec<Bytes> = std::iter::once(prefix)
        .chain(std::iter::repeat_n(script.body.clone(), script.repeat))
        .filter(|c| !c.is_empty())
        .collect();
    let delay = script.chunk_delay;
    let stream = futures_util::stream::unfold(
        (chunks.into_iter(), true),
        move |(mut it, first)| async move {
            let chunk = it.next()?;
            if !first && !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            Some((Ok::<_, Infallible>(Frame::data(chunk)), (it, false)))
        },
    );
    Ok(resp.body(BodyExt::boxed(StreamBody::new(stream))).unwrap())
}
