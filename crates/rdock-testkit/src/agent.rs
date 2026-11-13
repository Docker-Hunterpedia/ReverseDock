//! A scriptable out-of-process agent for the `agent` middleware's tests: records every request
//! it receives (method, target, headers, body, time) and answers what its handler returns,
//! optionally after a delay. Plain HTTP/1.1 and h2c, or TLS.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

/// A request the agent received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    /// When the request was complete.
    pub at: Instant,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The body as JSON (`protocol: rdock` documents).
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// What the agent answers.
#[derive(Debug, Clone)]
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub delay: Duration,
}

impl Answer {
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
            delay: Duration::ZERO,
        }
    }

    /// `200` with a JSON body (a `protocol: rdock` verdict).
    pub fn json(value: &serde_json::Value) -> Self {
        Self::status(200)
            .header("content-type", "application/json")
            .body(value.to_string())
    }

    /// `{"action":"allow"}`.
    pub fn allow() -> Self {
        Self::json(&serde_json::json!({ "action": "allow" }))
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    #[must_use]
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    #[must_use]
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Answer + Send + Sync>;

/// A running stub agent.
pub struct StubAgent {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    handler: Arc<Mutex<Handler>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for StubAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl StubAgent {
    /// A plain agent answering with `handler`.
    pub async fn start(handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static) -> Self {
        Self::start_with(Arc::new(handler), None).await
    }

    /// A TLS agent (HTTP/1.1) with the given certificate.
    pub async fn start_tls(
        handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static,
        cert_pem: &str,
        key_pem: &str,
    ) -> Self {
        use rustls_pki_types::pem::PemObject;
        let certs = rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        Self::start_with(
            Arc::new(handler),
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))),
        )
        .await
    }

    async fn start_with(handler: Handler, tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let handler = Arc::new(Mutex::new(handler));
        let (log, current) = (seen.clone(), handler.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let (log, current, tls) = (log.clone(), current.clone(), tls.clone());
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let (log, current) = (log.clone(), current.clone());
                        async move {
                            let (parts, body) = req.into_parts();
                            let body = body
                                .collect()
                                .await
                                .map(http_body_util::Collected::to_bytes)
                                .unwrap_or_default();
                            let seen = Seen {
                                method: parts.method.to_string(),
                                target: parts
                                    .uri
                                    .path_and_query()
                                    .map_or("/", |p| p.as_str())
                                    .to_owned(),
                                headers: parts.headers,
                                body,
                                at: Instant::now(),
                            };
                            let handler = current.lock().unwrap().clone();
                            let answer = handler(&seen);
                            log.lock().unwrap().push(seen);
                            if !answer.delay.is_zero() {
                                tokio::time::sleep(answer.delay).await;
                            }
                            let mut response = Response::new(Full::new(answer.body));
                            *response.status_mut() = StatusCode::from_u16(answer.status).unwrap();
                            for (name, value) in &answer.headers {
                                response.headers_mut().append(
                                    http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                                    value.parse().unwrap(),
                                );
                            }
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let builder =
                        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    match tls {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(tcp).await {
                                let _ = builder
                                    .serve_connection(TokioIo::new(stream), service)
                                    .await;
                            }
                        }
                        None => {
                            let _ = builder.serve_connection(TokioIo::new(tcp), service).await;
                        }
                    }
                });
            }
        });
        Self {
            addr,
            seen,
            handler,
            task,
        }
    }

    /// Replaces the handler.
    pub fn set(&self, handler: impl Fn(&Seen) -> Answer + Send + Sync + 'static) {
        *self.handler.lock().unwrap() = Arc::new(handler);
    }

    /// Requests received so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Number of requests received so far.
    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// Stops accepting connections (the port is closed).
    pub fn stop(&self) {
        self.task.abort();
    }
}
