#![doc = include_str!("../README.md")]

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use http::{Method, Response, StatusCode, header};
use pingora::apps::ServerApp;
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::{GetSocketDigest, SocketDigest};
use subtle::ConstantTimeEq;
use tokio::sync::watch;

/// What the admin API reads from and asks of the running process.
#[async_trait]
pub trait Control: Send + Sync {
    /// Whether a configuration is applied and listeners are bound (and no shutdown started).
    fn ready(&self) -> bool;
    /// Prometheus text exposition, or `None` when metrics are disabled.
    fn metrics(&self) -> Option<String>;
    /// Status document for `GET /api/v1/status`.
    async fn status(&self) -> serde_json::Value;
    /// Reloads the configuration; returns whether it was applied, and the report.
    async fn reload(&self) -> (bool, serde_json::Value);
}

/// The admin HTTP application.
struct Admin {
    token: String,
    control: Arc<dyn Control>,
}

fn respond(status: StatusCode, content_type: &str, body: impl Into<Vec<u8>>) -> Response<Vec<u8>> {
    let body = body.into();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    if let Ok(value) = content_type.parse() {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    let length = response.body().len();
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, length.into());
    response
}

fn json(status: StatusCode, value: &serde_json::Value) -> Response<Vec<u8>> {
    respond(status, "application/json", format!("{value}\n"))
}

impl Admin {
    fn authorized(&self, session: &ServerSession) -> bool {
        let presented = session
            .req_header()
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        !self.token.is_empty() && bool::from(presented.as_bytes().ct_eq(self.token.as_bytes()))
    }
}

#[async_trait]
impl ServeHttp for Admin {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let method = session.req_header().method.clone();
        let path = session.req_header().uri.path().to_owned();
        match (method, path.as_str()) {
            (Method::GET | Method::HEAD, "/healthz") => {
                respond(StatusCode::OK, "text/plain", "ok\n")
            }
            (Method::GET | Method::HEAD, "/readyz") => {
                if self.control.ready() {
                    respond(StatusCode::OK, "text/plain", "ready\n")
                } else {
                    respond(StatusCode::SERVICE_UNAVAILABLE, "text/plain", "not ready\n")
                }
            }
            (Method::GET, "/metrics") => match self.control.metrics() {
                Some(text) => respond(StatusCode::OK, "text/plain; version=0.0.4", text),
                None => json(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({ "error": "metrics are disabled" }),
                ),
            },
            (_, "/api/v1/status" | "/api/v1/config/reload") if !self.authorized(session) => {
                let mut response = json(
                    StatusCode::UNAUTHORIZED,
                    &serde_json::json!({ "error": "a valid admin token is required" }),
                );
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    http::HeaderValue::from_static("Bearer"),
                );
                response
            }
            (Method::GET, "/api/v1/status") => json(StatusCode::OK, &self.control.status().await),
            (Method::POST, "/api/v1/config/reload") => {
                let (applied, report) = self.control.reload().await;
                let status = if applied {
                    StatusCode::OK
                } else {
                    StatusCode::UNPROCESSABLE_ENTITY
                };
                json(status, &report)
            }
            _ => json(
                StatusCode::NOT_FOUND,
                &serde_json::json!({ "error": "not found" }),
            ),
        }
    }
}

/// Binds the admin listener and serves it until `stop` changes. Binding errors are returned
/// immediately.
pub fn serve(
    address: SocketAddr,
    token: String,
    control: Arc<dyn Control>,
    mut stop: watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let std_listener = std::net::TcpListener::bind(address)?;
    std_listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    let app = Arc::new(Admin { token, control });
    let (closing, closing_rx) = watch::channel(false);
    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                accepted = listener.accept() => match accepted {
                    Ok((tcp, _)) => {
                        let app = app.clone();
                        let closing = closing_rx.clone();
                        tokio::spawn(async move {
                            #[cfg(unix)]
                            let fd = std::os::unix::io::AsRawFd::as_raw_fd(&tcp);
                            let mut stream: L4Stream = tcp.into();
                            #[cfg(unix)]
                            stream.set_socket_digest(SocketDigest::from_raw_fd(fd));
                            app.process_new(Box::new(stream), &closing).await;
                        });
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "admin accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                },
            }
        }
        let _ = closing.send(true);
    }))
}
