//! A test backend speaking HTTP/1.1 and h2c on one port (optionally TLS with h2 by ALPN).
//!
//! - `GET /sse?n=3&ms=200`: `n` server-sent events, one every `ms` milliseconds.
//! - `GET /status/<code>`: that status with a short body.
//! - `GET /bytes/<n>`: `n` bytes of text.
//! - `GET /slow/<ms>`: answers after `ms` milliseconds.
//! - `GET /ws`: WebSocket echo.
//! - `POST /grpc` with `content-type: application/grpc`: echoes the messages, then the
//!   `grpc-status: 0` trailer.
//! - `GET /healthz`: `200` while healthy, `503` after [`Backend::set_healthy`]`(false)`.
//! - `POST /grpc.health.v1.Health/Check`: `SERVING` or `NOT_SERVING` the same way.
//! - `/flaky`: the JSON echo while healthy; `503` with `Retry-After: 30` otherwise.
//! - anything else: a JSON echo of method, target, version, headers and body length.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;

type Body = BoxBody<Bytes, Infallible>;

/// A running backend.
pub struct Backend {
    pub addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    targets: Arc<std::sync::Mutex<Vec<String>>>,
    healthy: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Backend {
    /// A plain backend (HTTP/1.1 and h2c).
    pub async fn start(name: &str) -> Self {
        Self::start_with(name, None).await
    }

    /// A TLS backend offering h2 and HTTP/1.1.
    pub async fn start_tls(name: &str, cert_pem: &str, key_pem: &str) -> Self {
        use rustls_pki_types::pem::PemObject;
        let certs = rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Self::start_with(
            name,
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))),
        )
        .await
    }

    async fn start_with(name: &str, tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let targets: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let seen = targets.clone();
        let name: Arc<str> = Arc::from(name);
        let healthy = Arc::new(AtomicBool::new(true));
        let health = healthy.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let name = name.clone();
                let counter = counter.clone();
                let seen = seen.clone();
                let health = health.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        counter.fetch_add(1, Ordering::SeqCst);
                        seen.lock().unwrap().push(
                            req.uri()
                                .path_and_query()
                                .map_or("/", |p| p.as_str())
                                .to_owned(),
                        );
                        handle(name.clone(), health.load(Ordering::SeqCst), req)
                    });
                    let builder =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    match tls {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(tcp).await {
                                let _ = builder
                                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                                    .await;
                            }
                        }
                        None => {
                            let _ = builder
                                .serve_connection_with_upgrades(TokioIo::new(tcp), service)
                                .await;
                        }
                    }
                });
            }
        });
        Self {
            addr,
            requests,
            targets,
            healthy,
            task,
        }
    }

    /// Makes the health endpoints report healthy or not.
    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::SeqCst);
    }

    /// Requests received so far that were not health probes.
    pub fn traffic(&self) -> usize {
        self.targets()
            .iter()
            .filter(|t| *t != "/healthz" && !t.starts_with("/grpc.health"))
            .count()
    }

    /// Requests received so far.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// Request targets received so far, in order.
    pub fn targets(&self) -> Vec<String> {
        self.targets.lock().unwrap().clone()
    }
}

fn full(body: impl Into<Bytes>) -> Body {
    Full::new(body.into()).boxed()
}

fn query(req: &Request<Incoming>, key: &str) -> Option<u64> {
    req.uri().query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.parse().ok()).flatten()
    })
}

async fn handle(
    name: Arc<str>,
    healthy: bool,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_owned();
    if path == "/healthz" {
        let status = if healthy { 200 } else { 503 };
        return Ok(Response::builder()
            .status(status)
            .body(full(if healthy { "ok\n" } else { "sick\n" }))
            .unwrap());
    }
    if path == "/grpc.health.v1.Health/Check" {
        return Ok(grpc_health(healthy));
    }
    if path == "/flaky" && !healthy {
        return Ok(Response::builder()
            .status(503)
            .header("retry-after", "30")
            .body(full(format!("status 503 from {name}\n")))
            .unwrap());
    }
    if let Some(code) = path.strip_prefix("/status/") {
        let status = StatusCode::from_u16(code.parse().unwrap_or(500)).unwrap_or(StatusCode::OK);
        return Ok(Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .body(full(format!("status {code} from {name}\n")))
            .unwrap());
    }
    if let Some(n) = path.strip_prefix("/bytes/") {
        let n: usize = n.parse().unwrap_or(0);
        return Ok(Response::builder()
            .header("content-type", "text/plain; charset=utf-8")
            .header("etag", "\"bytes\"")
            .body(full("a".repeat(n)))
            .unwrap());
    }
    if let Some(ms) = path.strip_prefix("/slow/") {
        tokio::time::sleep(Duration::from_millis(ms.parse().unwrap_or(0))).await;
        return Ok(Response::new(full(format!("slow from {name}\n"))));
    }
    match path.as_str() {
        "/sse" => Ok(sse(
            query(&req, "n").unwrap_or(3),
            query(&req, "ms").unwrap_or(200),
        )),
        "/ws" => Ok(websocket(req)),
        "/grpc" => Ok(grpc(req).await),
        _ => Ok(echo(&name, req).await),
    }
}

async fn echo(name: &str, req: Request<Incoming>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in &parts.headers {
        headers
            .entry(k.as_str().to_owned())
            .or_default()
            .push(String::from_utf8_lossy(v.as_bytes()).into_owned());
    }
    let json = serde_json::json!({
        "backend": name,
        "method": parts.method.as_str(),
        "target": parts.uri.path_and_query().map_or("/", http::uri::PathAndQuery::as_str),
        "version": format!("{:?}", parts.version),
        "headers": headers,
        "body_len": body.len(),
    });
    Response::builder()
        .header("content-type", "application/json")
        .header("x-backend", name)
        .body(full(json.to_string()))
        .unwrap()
}

fn sse(n: u64, ms: u64) -> Response<Body> {
    let stream = futures_util::stream::unfold(0, move |i| async move {
        if i >= n {
            return None;
        }
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let frame: Result<Frame<Bytes>, Infallible> =
            Ok(Frame::data(Bytes::from(format!("data: event {i}\n\n"))));
        Some((frame, i + 1))
    });
    Response::builder()
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(BodyExt::boxed(StreamBody::new(stream)))
        .unwrap()
}

fn websocket(req: Request<Incoming>) -> Response<Body> {
    let key = req
        .headers()
        .get("sec-websocket-key")
        .map(|k| tokio_tungstenite::tungstenite::handshake::derive_accept_key(k.as_bytes()));
    let Some(accept) = key else {
        return Response::builder()
            .status(400)
            .body(full("not a websocket"))
            .unwrap();
    };
    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(req).await else {
            return;
        };
        let mut ws =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
        while let Some(Ok(message)) = ws.next().await {
            if message.is_close() || ws.send(message).await.is_err() {
                break;
            }
        }
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-accept", accept)
        .body(full(Bytes::new()))
        .unwrap()
}

/// Echoes gRPC frames (length-prefixed messages) and ends with the status trailer.
/// A `HealthCheckResponse` with `SERVING` (1) or `NOT_SERVING` (2).
fn grpc_health(healthy: bool) -> Response<Body> {
    let status = if healthy { 1 } else { 2 };
    let message = Bytes::from(vec![0, 0, 0, 0, 2, 0x08, status]);
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    let frames = vec![
        Ok::<_, Infallible>(Frame::data(message)),
        Ok(Frame::trailers(trailers)),
    ];
    Response::builder()
        .header("content-type", "application/grpc")
        .body(BodyExt::boxed(StreamBody::new(futures_util::stream::iter(
            frames,
        ))))
        .unwrap()
}

async fn grpc(req: Request<Incoming>) -> Response<Body> {
    let body = req
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    trailers.insert("grpc-message", HeaderValue::from_static("ok"));
    let frames = vec![
        Ok::<_, Infallible>(Frame::data(body)),
        Ok(Frame::trailers(trailers)),
    ];
    Response::builder()
        .header("content-type", "application/grpc")
        .body(BodyExt::boxed(StreamBody::new(futures_util::stream::iter(
            frames,
        ))))
        .unwrap()
}
