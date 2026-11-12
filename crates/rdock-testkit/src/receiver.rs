//! A fake event receiver for metering and webhook tests: an HTTP/1 server on `127.0.0.1:0`
//! that records every request and answers by its current mode: accept (`204`), refuse with a
//! status (`429`, `503`…), or hang without answering.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

/// How the receiver answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `204 No Content`.
    Accept,
    /// This status.
    Status(u16),
    /// Never answers (the connection stays open).
    Hang,
}

/// One request received.
#[derive(Debug, Clone)]
pub struct Received {
    /// Request path.
    pub path: String,
    /// Headers.
    pub headers: HeaderMap,
    /// Body.
    pub body: Bytes,
    /// The mode it was answered in.
    pub answered: Mode,
}

impl Received {
    /// The body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    /// A header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

#[derive(Default)]
struct State {
    modes: Vec<Mode>,
    default: Option<Mode>,
    received: Vec<Received>,
}

/// The running receiver.
#[derive(Clone)]
pub struct Receiver {
    url: String,
    state: Arc<Mutex<State>>,
}

impl Receiver {
    /// Starts a receiver that accepts everything.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state: Arc<Mutex<State>> = Arc::default();
        let shared = state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = shared.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| serve(request, state.clone()));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { url, state }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Answers every following request in `mode`.
    pub fn set(&self, mode: Mode) {
        let mut state = self.state.lock().unwrap();
        state.default = Some(mode);
        state.modes.clear();
    }

    /// Answers the next requests in these modes, one each, then the default mode again.
    pub fn then(&self, modes: &[Mode]) {
        self.state.lock().unwrap().modes.extend_from_slice(modes);
    }

    /// Every request so far.
    pub fn received(&self) -> Vec<Received> {
        self.state.lock().unwrap().received.clone()
    }
}

async fn serve(
    request: Request<Incoming>,
    state: Arc<Mutex<State>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let mode = {
        let mut state = state.lock().unwrap();
        let mode = if state.modes.is_empty() {
            state.default.unwrap_or(Mode::Accept)
        } else {
            state.modes.remove(0)
        };
        state.received.push(Received {
            path: parts.uri.path().to_owned(),
            headers: parts.headers,
            body,
            answered: mode,
        });
        mode
    };
    let status = match mode {
        Mode::Accept => StatusCode::NO_CONTENT,
        Mode::Status(code) => StatusCode::from_u16(code).unwrap(),
        Mode::Hang => {
            std::future::pending::<()>().await;
            StatusCode::NO_CONTENT
        }
    };
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    Ok(response)
}
