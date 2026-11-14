//! A fake Docker Engine API on a Unix socket for tests without Docker (the chaos suite,
//! ADR-0033): the three read calls the Docker provider makes (`containers/json`,
//! `containers/{id}/json`, `events`), and the ways a socket fails.
//!
//! [`DockerMode`] switches between a working daemon, a socket that is gone (the file is
//! removed), one that accepts connections and never answers, and one that answers every call
//! with `500`. A switch closes the connections open at that moment, as a daemon restart does.
//! [`FakeDocker::requests`] counts the calls, so a test can bound reconnect attempts.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// What the socket does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerMode {
    /// Answers like a daemon.
    Up,
    /// The socket file is gone: connecting fails.
    Down,
    /// Accepts connections and never answers.
    Hang,
    /// Answers every call with `500`.
    Error,
}

/// A running container the fake lists.
#[derive(Debug, Clone)]
pub struct FakeContainer {
    /// The name, without the leading `/`.
    pub name: String,
    /// Its labels.
    pub labels: BTreeMap<String, String>,
    /// The address its network reaches it at.
    pub ip: String,
}

impl FakeContainer {
    /// A container exposed as `host` that forwards to `127.0.0.1:port` (`rdock.port`).
    pub fn routed(name: &str, host: &str, port: u16) -> Self {
        let labels = [
            ("rdock.enable", "true".to_owned()),
            ("rdock.host", host.to_owned()),
            ("rdock.tls", "off".to_owned()),
            ("rdock.port", port.to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        Self {
            name: name.to_owned(),
            labels,
            ip: "127.0.0.1".to_owned(),
        }
    }
}

struct State {
    mode: DockerMode,
    containers: Vec<FakeContainer>,
    connections: Vec<JoinHandle<()>>,
    accept: Option<JoinHandle<()>>,
}

/// A fake Docker daemon.
pub struct FakeDocker {
    path: PathBuf,
    state: Arc<Mutex<State>>,
    events: broadcast::Sender<String>,
    requests: Arc<AtomicU64>,
}

fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Drop for FakeDocker {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        close(&mut state);
        let _ = std::fs::remove_file(&self.path);
    }
}

fn close(state: &mut State) {
    if let Some(accept) = state.accept.take() {
        accept.abort();
    }
    for connection in state.connections.drain(..) {
        connection.abort();
    }
}

type Body = UnsyncBoxBody<Bytes, Infallible>;

fn full(status: StatusCode, body: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("api-version", "1.47")
        .body(Full::new(Bytes::from(body.to_string())).boxed_unsync())
        .unwrap()
}

fn inspect(id: usize, c: &FakeContainer) -> Value {
    json!({
        "Id": format!("{id:064x}"),
        "Name": format!("/{}", c.name),
        "State": { "Status": "running", "Running": true },
        "Config": { "Labels": c.labels },
        "HostConfig": { "NetworkMode": "bridge" },
        "NetworkSettings": { "Networks": { "bridge": { "IPAddress": c.ip } } }
    })
}

impl FakeDocker {
    /// Starts a working daemon at `path`.
    pub fn start(path: &Path) -> Self {
        let (events, _) = broadcast::channel(64);
        let docker = Self {
            path: path.to_owned(),
            state: Arc::new(Mutex::new(State {
                mode: DockerMode::Down,
                containers: Vec::new(),
                connections: Vec::new(),
                accept: None,
            })),
            events,
            requests: Arc::new(AtomicU64::new(0)),
        };
        docker.set_mode(DockerMode::Up);
        docker
    }

    /// A fake whose socket does not exist yet ([`DockerMode::Down`]).
    pub fn absent(path: &Path) -> Self {
        let docker = Self::start(path);
        docker.set_mode(DockerMode::Down);
        docker
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Calls answered or held since the start.
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Replaces the running containers and sends a `start` event.
    pub fn set_containers(&self, containers: Vec<FakeContainer>) {
        let name = containers
            .first()
            .map(|c| c.name.clone())
            .unwrap_or_default();
        lock(&self.state).containers = containers;
        let event = json!({
            "Type": "container", "Action": "start",
            "Actor": { "ID": "0", "Attributes": { "name": name } },
            "time": 0
        });
        let _ = self.events.send(format!("{event}\n"));
    }

    /// Switches the mode; the connections open now are closed.
    pub fn set_mode(&self, mode: DockerMode) {
        let mut state = lock(&self.state);
        close(&mut state);
        state.mode = mode;
        let _ = std::fs::remove_file(&self.path);
        if mode == DockerMode::Down {
            return;
        }
        let listener = UnixListener::bind(&self.path).unwrap();
        let (shared, events, requests) = (
            self.state.clone(),
            self.events.clone(),
            self.requests.clone(),
        );
        state.accept = Some(tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (state, events, requests) = (shared.clone(), events.clone(), requests.clone());
                let task = tokio::spawn(async move {
                    if lock(&state).mode == DockerMode::Hang {
                        requests.fetch_add(1, Ordering::Relaxed);
                        // Accepted, never answered: hold the stream until closed.
                        let _held = stream;
                        std::future::pending::<()>().await;
                        return;
                    }
                    let service = service_fn(move |request: Request<Incoming>| {
                        let (state, events) = (state.clone(), events.clone());
                        requests.fetch_add(1, Ordering::Relaxed);
                        async move { Ok::<_, Infallible>(answer(&request, &state, &events)) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
                let mut state = lock(&shared);
                state.connections.retain(|t| !t.is_finished());
                state.connections.push(task);
            }
        }));
    }
}

fn answer(
    request: &Request<Incoming>,
    state: &Mutex<State>,
    events: &broadcast::Sender<String>,
) -> Response<Body> {
    let state = lock(state);
    if state.mode == DockerMode::Error {
        return full(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({ "message": "fake daemon error" }),
        );
    }
    // Paths carry the API version: `/v1.47/containers/json`.
    let path = request.uri().path();
    let path = path
        .strip_prefix("/v")
        .and_then(|p| p.split_once('/'))
        .map_or(path, |(_, rest)| rest);
    let path = path.trim_start_matches('/');
    match path.split('/').collect::<Vec<_>>().as_slice() {
        ["_ping"] => full(StatusCode::OK, &json!("OK")),
        ["containers", "json"] => {
            let list: Vec<Value> = (0..state.containers.len())
                .map(|i| json!({ "Id": format!("{i:064x}"), "State": "running" }))
                .collect();
            full(StatusCode::OK, &Value::Array(list))
        }
        ["containers", id, "json"] => {
            let found = state
                .containers
                .iter()
                .enumerate()
                .find(|(i, _)| format!("{i:064x}") == *id);
            match found {
                Some((i, c)) => full(StatusCode::OK, &inspect(i, c)),
                None => full(
                    StatusCode::NOT_FOUND,
                    &json!({ "message": "no such container" }),
                ),
            }
        }
        ["events"] => {
            let stream = tokio_stream_of(events.subscribe());
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("api-version", "1.47")
                .body(BodyExt::boxed_unsync(StreamBody::new(stream)))
                .unwrap()
        }
        _ => full(StatusCode::NOT_FOUND, &json!({ "message": "not faked" })),
    }
}

/// The events channel as a body stream: one JSON line per event, never ending by itself.
fn tokio_stream_of(
    receiver: broadcast::Receiver<String>,
) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + 'static {
    futures_util::stream::unfold(receiver, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(line) => return Some((Ok(Frame::data(Bytes::from(line))), receiver)),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
        }
    })
    .boxed()
}
