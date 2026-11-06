//! A plain TCP backend for TCP-route tests: it echoes every byte and, when the client ends its
//! side, answers `EOF` and closes. It can first read a PROXY protocol header and keep what it
//! said.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use proxy_header::{ParseConfig, ProxyHeader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the end of the echo is.
pub const EOF_REPLY: &[u8] = b"EOF";

/// What a PROXY header told the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// 1 or 2.
    pub version: u8,
    /// The client the header named (`None` for LOCAL).
    pub source: Option<SocketAddr>,
    /// The ALPN TLV.
    pub alpn: Option<Vec<u8>>,
    /// The AUTHORITY TLV.
    pub authority: Option<String>,
    /// The SSL TLV's version sub-TLV, when the TLV is present.
    pub ssl_version: Option<String>,
}

/// A running echo backend.
pub struct EchoBackend {
    pub addr: SocketAddr,
    headers: Arc<Mutex<Vec<Received>>>,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for EchoBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl EchoBackend {
    /// An echo backend that expects no PROXY header.
    pub async fn start() -> Self {
        Self::start_with(false).await
    }

    /// An echo backend that reads a PROXY header (v1 or v2) first on every connection.
    pub async fn start_proxy_protocol() -> Self {
        Self::start_with(true).await
    }

    async fn start_with(proxy_protocol: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let headers = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (seen, count) = (headers.clone(), connections.clone());
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let seen = seen.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, proxy_protocol, &seen).await;
                });
            }
        });
        Self {
            addr,
            headers,
            connections,
            task,
        }
    }

    /// The PROXY headers received so far, in order.
    pub fn headers(&self) -> Vec<Received> {
        self.headers.lock().unwrap().clone()
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

async fn serve(
    mut stream: TcpStream,
    proxy_protocol: bool,
    seen: &Mutex<Vec<Received>>,
) -> std::io::Result<()> {
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];
    if proxy_protocol {
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            pending.extend_from_slice(&buf[..n]);
            let config = ParseConfig {
                include_tlvs: true,
                ..ParseConfig::default()
            };
            match ProxyHeader::parse(&pending, config) {
                Ok((header, len)) => {
                    seen.lock().unwrap().push(Received {
                        version: if pending.starts_with(b"PROXY ") { 1 } else { 2 },
                        source: header.proxied_address().map(|a| a.source),
                        alpn: header.alpn().map(<[u8]>::to_vec),
                        authority: header.authority().map(str::to_owned),
                        ssl_version: header.ssl().and_then(|s| s.version().map(str::to_owned)),
                    });
                    pending.drain(..len);
                    break;
                }
                Err(proxy_header::Error::BufferTooShort) => {}
                Err(_) => return Ok(()),
            }
        }
    }
    stream.write_all(&pending).await?;
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            stream.write_all(EOF_REPLY).await?;
            return stream.shutdown().await;
        }
        stream.write_all(&buf[..n]).await?;
    }
}
