//! Clients for tests: HTTP/1.1, h2c, TLS (h2 or HTTP/1.1 by ALPN) and raw bytes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Request, Version};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// A complete response.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub trailers: Option<HeaderMap>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }
}

/// A request with an empty body.
pub fn get(host: &str, target: &str) -> Request<Full<Bytes>> {
    request("GET", host, target, Bytes::new())
}

pub fn request(
    method: &str,
    host: &str,
    target: &str,
    body: impl Into<Bytes>,
) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(target)
        .header("host", host)
        .body(Full::new(body.into()))
        .unwrap()
}

async fn finish(response: http::Response<hyper::body::Incoming>) -> Reply {
    let (parts, body) = response.into_parts();
    let collected = body.collect().await.unwrap();
    let trailers = collected.trailers().cloned();
    Reply {
        status: parts.status.as_u16(),
        version: parts.version,
        headers: parts.headers,
        body: collected.to_bytes(),
        trailers,
    }
}

async fn http1_on<S>(stream: S, req: Request<Full<Bytes>>) -> Reply
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    finish(sender.send_request(req).await.unwrap()).await
}

async fn http2_on<S>(stream: S, mut req: Request<Full<Bytes>>) -> Reply
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // HTTP/2 carries the host in :authority.
    if req.uri().authority().is_none()
        && let Some(host) = req.headers_mut().remove("host")
    {
        let target = req
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_owned();
        *req.uri_mut() = format!("http://{}{target}", host.to_str().unwrap())
            .parse()
            .unwrap();
    }
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    finish(sender.send_request(req).await.unwrap()).await
}

/// One HTTP/1.1 request on a new connection.
pub async fn http1(addr: SocketAddr, req: Request<Full<Bytes>>) -> Reply {
    http1_on(TcpStream::connect(addr).await.unwrap(), req).await
}

/// One HTTP/2 request with prior knowledge (h2c) on a new connection.
pub async fn h2c(addr: SocketAddr, req: Request<Full<Bytes>>) -> Reply {
    http2_on(TcpStream::connect(addr).await.unwrap(), req).await
}

/// One request over TLS; the protocol follows the negotiated ALPN.
pub async fn tls(
    addr: SocketAddr,
    server_name: &str,
    config: Arc<rustls::ClientConfig>,
    req: Request<Full<Bytes>>,
) -> Reply {
    let stream = tls_connect(addr, server_name, config).await.unwrap();
    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    if h2 {
        http2_on(stream, req).await
    } else {
        http1_on(stream, req).await
    }
}

/// A TLS connection, or the handshake error.
pub async fn tls_connect(
    addr: SocketAddr,
    server_name: &str,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let name = rustls_pki_types::ServerName::try_from(server_name.to_owned()).unwrap();
    tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await
}

/// Sends raw bytes and returns everything received until the server closes the connection or
/// `wait` passes without data.
pub async fn raw(addr: SocketAddr, bytes: &[u8], wait: Duration) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tokio::time::timeout(wait, stream.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return out,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// Status codes of every HTTP/1 response in a raw byte stream.
pub fn statuses(raw: &[u8]) -> Vec<u16> {
    let text = String::from_utf8_lossy(raw);
    text.match_indices("HTTP/1.")
        .filter_map(|(i, _)| text.get(i + 9..i + 12)?.parse().ok())
        .collect()
}
