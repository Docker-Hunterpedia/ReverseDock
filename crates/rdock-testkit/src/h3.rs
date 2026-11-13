//! An HTTP/3 client on quinn and h3 for the end-to-end tests of the experimental HTTP/3 ingress
//! (ADR-0032), plus a raw mode that writes request frames byte by byte, for requests h3's own
//! client would refuse to build.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{HeaderMap, Request, Response};
use rustls_pki_types::CertificateDer;
use tokio::io::AsyncWriteExt;

/// The QUIC and HTTP/3 crates, for tests that need their types without depending on them.
pub use ::h3 as h3_crate;
pub use quinn;

/// An answer read over HTTP/3.
#[derive(Debug)]
pub struct H3Reply {
    /// Status and headers.
    pub head: Response<()>,
    /// The whole body.
    pub body: Bytes,
    /// Trailers, if any were sent.
    pub trailers: Option<HeaderMap>,
}

impl H3Reply {
    /// The status code.
    pub fn status(&self) -> u16 {
        self.head.status().as_u16()
    }

    /// A header's value as text.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// The body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// How a raw request stream ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RawOutcome {
    /// The server reset the stream with this HTTP/3 error code.
    Reset(u64),
    /// The server answered: the payload of the first HEADERS frame (QPACK-encoded).
    Answered(Vec<u8>),
    /// The connection closed with this error code.
    ConnectionClosed(u64),
    /// Nothing within the time allowed.
    Timeout,
}

/// One HTTP/3 connection.
pub struct H3Client {
    /// The QUIC endpoint (one per client, an ephemeral UDP port).
    pub endpoint: quinn::Endpoint,
    /// The QUIC connection.
    pub conn: quinn::Connection,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    /// Resolves with the reason the HTTP/3 connection ended (GOAWAY or close).
    pub closed: tokio::sync::oneshot::Receiver<String>,
    authority: String,
}

/// The rustls client configuration for HTTP/3 that trusts `roots`.
pub fn client_tls(
    roots: &[CertificateDer<'static>],
    early_data: bool,
) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store.add(root.clone()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(store)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.enable_early_data = early_data;
    Arc::new(config)
}

/// The quinn client configuration for `tls`.
pub fn quic_client(tls: Arc<rustls::ClientConfig>) -> quinn::ClientConfig {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
    ));
    config.transport_config(Arc::new(transport));
    config
}

/// A client endpoint on an ephemeral loopback port.
pub fn endpoint() -> quinn::Endpoint {
    quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap()
}

impl H3Client {
    /// Connects to `addr` for `server_name`, trusting `roots`.
    pub async fn connect(
        addr: SocketAddr,
        server_name: &str,
        roots: &[CertificateDer<'static>],
    ) -> Result<Self, String> {
        Self::connect_with(
            endpoint(),
            quic_client(client_tls(roots, false)),
            addr,
            server_name,
        )
        .await
    }

    /// Connects with a client configuration of the caller's (to keep TLS sessions between
    /// connections).
    pub async fn connect_with(
        endpoint: quinn::Endpoint,
        config: quinn::ClientConfig,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Self, String> {
        let connecting = endpoint
            .connect_with(config, addr, server_name)
            .map_err(|e| e.to_string())?;
        let conn = tokio::time::timeout(Duration::from_secs(10), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|e| e.to_string())?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|e| e.to_string())?;
        let (tx, closed) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            let _ = tx.send(err.to_string());
        });
        Ok(Self {
            endpoint,
            conn,
            send,
            closed,
            authority: server_name.to_owned(),
        })
    }

    /// A request builder for `path` with this connection's authority.
    pub fn request(&self, method: &str, path: &str) -> http::request::Builder {
        Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", self.authority))
    }

    /// Sends `req` with `body` (each piece a DATA frame) and reads the whole answer.
    pub async fn send(&mut self, req: Request<()>, body: Vec<Bytes>) -> Result<H3Reply, String> {
        let mut stream = self
            .send
            .send_request(req)
            .await
            .map_err(|e| e.to_string())?;
        for chunk in body {
            stream.send_data(chunk).await.map_err(|e| e.to_string())?;
        }
        stream.finish().await.map_err(|e| e.to_string())?;
        read_reply(&mut stream).await
    }

    /// GET `path`.
    pub async fn get(&mut self, path: &str) -> Result<H3Reply, String> {
        let req = self.request("GET", path).body(()).unwrap();
        self.send(req, Vec::new()).await
    }

    /// Starts a request and sends `body` without finishing it: the caller keeps the stream.
    pub async fn start(
        &mut self,
        req: Request<()>,
        body: Vec<Bytes>,
    ) -> Result<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>, String> {
        let mut stream = self
            .send
            .send_request(req)
            .await
            .map_err(|e| e.to_string())?;
        for chunk in body {
            stream.send_data(chunk).await.map_err(|e| e.to_string())?;
        }
        Ok(stream)
    }

    /// Opens a request stream and writes `bytes` (whole frames) on it; with `finish` the stream
    /// ends after them. Then waits up to `wait` for what the server does.
    pub async fn raw(&self, bytes: &[u8], finish: bool, wait: Duration) -> RawOutcome {
        let (mut send, mut recv) = match self.conn.open_bi().await {
            Ok(pair) => pair,
            Err(err) => return closed_outcome(&err),
        };
        if send.write_all(bytes).await.is_err() {
            return self.after_failure().await;
        }
        if finish {
            let _ = send.finish();
        } else {
            let _ = send.flush().await;
        }
        let read = tokio::time::timeout(wait, async {
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match recv.read(&mut chunk).await {
                    Ok(Some(n)) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(headers) = first_headers(&buf) {
                            return RawOutcome::Answered(headers);
                        }
                    }
                    Ok(None) => {
                        return first_headers(&buf)
                            .map_or(RawOutcome::Reset(0), RawOutcome::Answered);
                    }
                    Err(quinn::ReadError::Reset(code)) => {
                        return RawOutcome::Reset(code.into_inner());
                    }
                    Err(quinn::ReadError::ConnectionLost(err)) => return closed_outcome(&err),
                    Err(_) => return RawOutcome::Reset(0),
                }
            }
        })
        .await;
        read.unwrap_or(RawOutcome::Timeout)
    }

    /// Opens a request stream, writes `bytes`, and resets it at once with `code`.
    pub async fn raw_reset(&self, bytes: &[u8], code: u32) -> Result<(), String> {
        let (mut send, _recv) = self.conn.open_bi().await.map_err(|e| e.to_string())?;
        send.write_all(bytes).await.map_err(|e| e.to_string())?;
        send.reset(quinn::VarInt::from_u32(code))
            .map_err(|e| e.to_string())
    }

    async fn after_failure(&self) -> RawOutcome {
        match tokio::time::timeout(Duration::from_secs(5), self.conn.closed()).await {
            Ok(err) => closed_outcome(&err),
            Err(_) => RawOutcome::Timeout,
        }
    }
}

fn closed_outcome(err: &quinn::ConnectionError) -> RawOutcome {
    match err {
        quinn::ConnectionError::ApplicationClosed(close) => {
            RawOutcome::ConnectionClosed(close.error_code.into_inner())
        }
        _ => RawOutcome::ConnectionClosed(0),
    }
}

/// Reads a QUIC variable-length integer (RFC 9000 §16).
fn varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for b in &buf[1..len] {
        value = (value << 8) | u64::from(*b);
    }
    Some((value, len))
}

/// Writes a QUIC variable-length integer.
pub fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 64 {
        out.push(u8::try_from(value).unwrap());
    } else if value < 16_384 {
        out.extend_from_slice(&(u16::try_from(value).unwrap() | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&(u32::try_from(value).unwrap() | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// An HTTP/3 frame of `kind` with `payload` (RFC 9114 §7.1): 0x0 DATA, 0x1 HEADERS.
pub fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, kind);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

/// The payload of the first HEADERS frame in `buf`, once complete.
fn first_headers(buf: &[u8]) -> Option<Vec<u8>> {
    let mut at = 0;
    loop {
        let (kind, n) = varint(&buf[at..])?;
        let (len, m) = varint(&buf[at + n..])?;
        let start = at + n + m;
        let end = start + usize::try_from(len).ok()?;
        if buf.len() < end {
            return None;
        }
        if kind == 1 {
            return Some(buf[start..end].to_vec());
        }
        at = end;
    }
}

/// Reads the response, body and trailers of `stream`.
pub async fn read_reply(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<H3Reply, String> {
    let head = stream.recv_response().await.map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
        let n = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(n));
    }
    let trailers = stream.recv_trailers().await.map_err(|e| e.to_string())?;
    Ok(H3Reply {
        head,
        body: Bytes::from(body),
        trailers,
    })
}
