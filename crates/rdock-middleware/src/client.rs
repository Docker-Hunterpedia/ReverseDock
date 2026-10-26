//! A small HTTP client on Pingora's connector, for subrequests (forward authentication, error
//! pages from a service). Connections are pooled; host names are resolved with a short cache.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use pingora::connectors::http::Connector;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::upstreams::peer::HttpPeer;
use url::{Host, Url};

const DNS_TTL: Duration = Duration::from_secs(10);
const POOL_IDLE: Duration = Duration::from_secs(60);

/// A response read completely into memory.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// Status and headers.
    pub header: ResponseHeader,
    /// Body.
    pub body: Bytes,
}

/// Why a subrequest failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The host name could not be resolved.
    #[error("cannot resolve `{0}`")]
    Resolve(String),
    /// Connecting or exchanging the request failed.
    #[error("{0}")]
    Connect(String),
    /// The whole exchange took too long.
    #[error("timed out")]
    Timeout,
    /// The response body was too large.
    #[error("the response body is larger than {0} bytes")]
    TooLarge(usize),
}

/// Resolved addresses by host and port, with the time of the lookup.
type DnsCache = HashMap<(String, u16), (Vec<SocketAddr>, Instant)>;

/// The HTTP client.
pub struct HttpClient {
    connector: Connector,
    dns: Mutex<DnsCache>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpClient")
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self {
            connector: Connector::new(None),
            dns: Mutex::new(HashMap::new()),
        }
    }
}

impl HttpClient {
    /// Sends `req` to `peer` and reads the response, all within `timeout`.
    pub async fn send(
        &self,
        peer: &HttpPeer,
        req: RequestHeader,
        timeout: Duration,
        max_body: usize,
    ) -> Result<Fetched, FetchError> {
        tokio::time::timeout(timeout, self.exchange(peer, req, max_body))
            .await
            .map_err(|_| FetchError::Timeout)?
    }

    async fn exchange(
        &self,
        peer: &HttpPeer,
        req: RequestHeader,
        max_body: usize,
    ) -> Result<Fetched, FetchError> {
        let failed = |e: Box<pingora::Error>| FetchError::Connect(e.to_string());
        let (mut session, _reused) = self
            .connector
            .get_http_session(peer)
            .await
            .map_err(failed)?;
        session
            .write_request_header(Box::new(req))
            .await
            .map_err(failed)?;
        session.finish_request_body().await.map_err(failed)?;
        session.read_response_header().await.map_err(failed)?;
        let header = session
            .response_header()
            .cloned()
            .ok_or_else(|| FetchError::Connect("no response header".to_owned()))?;
        let mut body = BytesMut::new();
        while let Some(chunk) = session.read_response_body().await.map_err(failed)? {
            if body.len() + chunk.len() > max_body {
                return Err(FetchError::TooLarge(max_body));
            }
            body.extend_from_slice(&chunk);
        }
        self.connector
            .release_http_session(session, peer, Some(POOL_IDLE))
            .await;
        Ok(Fetched {
            header,
            body: body.freeze(),
        })
    }

    /// A peer for an `http://` or `https://` URL; certificates are verified against the system
    /// roots.
    pub async fn peer_for(&self, url: &Url, timeout: Duration) -> Result<HttpPeer, FetchError> {
        let host = url
            .host()
            .ok_or_else(|| FetchError::Resolve(url.to_string()))?;
        let tls = url.scheme() == "https";
        let port = url
            .port_or_known_default()
            .unwrap_or(if tls { 443 } else { 80 });
        let (address, sni) = match host {
            Host::Ipv4(ip) => (SocketAddr::from((ip, port)), ip.to_string()),
            Host::Ipv6(ip) => (SocketAddr::from((ip, port)), ip.to_string()),
            Host::Domain(name) => (self.resolve(name, port).await?, name.to_owned()),
        };
        let mut peer = HttpPeer::new(address, tls, sni);
        peer.options.connection_timeout = Some(timeout);
        peer.options.read_timeout = Some(timeout);
        peer.options.write_timeout = Some(timeout);
        Ok(peer)
    }

    async fn resolve(&self, name: &str, port: u16) -> Result<SocketAddr, FetchError> {
        let key = (name.to_owned(), port);
        let cached = {
            let dns = self.dns.lock().unwrap_or_else(PoisonError::into_inner);
            dns.get(&key)
                .filter(|(_, at)| at.elapsed() < DNS_TTL)
                .and_then(|(addrs, _)| addrs.first().copied())
        };
        if let Some(addr) = cached {
            return Ok(addr);
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name, port))
            .await
            .map_err(|_| FetchError::Resolve(name.to_owned()))?
            .collect();
        let first = *addrs
            .first()
            .ok_or_else(|| FetchError::Resolve(name.to_owned()))?;
        self.dns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, (addrs, Instant::now()));
        Ok(first)
    }
}
