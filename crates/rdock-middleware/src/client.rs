//! A small HTTP client on Pingora's connector, for subrequests (forward authentication, error
//! pages from a service). Connections are pooled; host names are resolved with a short cache.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use pingora::connectors::http::Connector;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::upstreams::peer::HttpPeer;
use url::{Host, Url};

const DNS_TTL: Duration = Duration::from_secs(10);
const POOL_IDLE: Duration = Duration::from_secs(60);

/// TLS settings for a subrequest peer (agents): verification, the name to verify, a CA bundle
/// instead of the system roots, and a client certificate.
#[derive(Clone, Default)]
pub struct ClientTls {
    /// Skip certificate and host-name verification (unsafe; validation warns).
    pub insecure: bool,
    /// SNI and verification name, when it differs from the URL's host.
    pub server_name: Option<String>,
    /// CA certificates used instead of the system roots.
    pub ca: Option<Arc<[pingora::utils::tls::WrappedX509]>>,
    /// Client certificate and key for mutual TLS.
    pub client_cert: Option<Arc<pingora::utils::tls::CertKey>>,
}

impl std::fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTls")
            .field("insecure", &self.insecure)
            .field("server_name", &self.server_name)
            .field("ca", &self.ca.is_some())
            .field("client_cert", &self.client_cert.is_some())
            .finish()
    }
}

impl ClientTls {
    /// Loads the files named by `tls`.
    ///
    /// # Errors
    ///
    /// A file cannot be read or is invalid.
    pub fn load(tls: &rdock_model::service::UpstreamTls) -> Result<Self, String> {
        Ok(Self {
            insecure: !tls.verify,
            server_name: tls.server_name.clone(),
            ca: match &tls.ca_file {
                Some(file) => Some(load_ca(file)?),
                None => None,
            },
            client_cert: match (&tls.cert_file, &tls.key_file) {
                (Some(cert), Some(key)) => Some(load_client_cert(cert, key)?),
                _ => None,
            },
        })
    }
}

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

    /// Sends `req` with `body` and returns the response with its trailers (HTTP/2 only), for
    /// protocols such as the gRPC health check that report results in trailers.
    pub async fn send_with_body(
        &self,
        peer: &HttpPeer,
        req: RequestHeader,
        body: Bytes,
        timeout: Duration,
        max_body: usize,
    ) -> Result<(Fetched, Option<http::HeaderMap>), FetchError> {
        tokio::time::timeout(timeout, self.exchange_full(peer, req, Some(body), max_body))
            .await
            .map_err(|_| FetchError::Timeout)?
    }

    async fn exchange(
        &self,
        peer: &HttpPeer,
        req: RequestHeader,
        max_body: usize,
    ) -> Result<Fetched, FetchError> {
        self.exchange_full(peer, req, None, max_body)
            .await
            .map(|(fetched, _)| fetched)
    }

    async fn exchange_full(
        &self,
        peer: &HttpPeer,
        req: RequestHeader,
        request_body: Option<Bytes>,
        max_body: usize,
    ) -> Result<(Fetched, Option<http::HeaderMap>), FetchError> {
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
        match request_body {
            Some(data) => session
                .write_request_body(data, true)
                .await
                .map_err(failed)?,
            None => session.finish_request_body().await.map_err(failed)?,
        }
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
        let trailers = match &mut session {
            pingora::protocols::http::client::HttpSession::H2(h2) => {
                h2.read_trailers().await.map_err(failed)?
            }
            _ => None,
        };
        self.connector
            .release_http_session(session, peer, Some(POOL_IDLE))
            .await;
        Ok((
            Fetched {
                header,
                body: body.freeze(),
            },
            trailers,
        ))
    }

    /// A peer for an `http://` or `https://` URL; certificates are verified against the system
    /// roots.
    pub async fn peer_for(&self, url: &Url, timeout: Duration) -> Result<HttpPeer, FetchError> {
        self.peer_with(url, timeout, &ClientTls::default()).await
    }

    /// A peer for an `http://` or `https://` URL with `tls` settings for `https://`.
    pub async fn peer_with(
        &self,
        url: &Url,
        timeout: Duration,
        tls: &ClientTls,
    ) -> Result<HttpPeer, FetchError> {
        let mut peer = self
            .plain_peer(url, timeout, tls.server_name.as_deref())
            .await?;
        if peer.is_tls() {
            peer.options.verify_cert = !tls.insecure;
            peer.options.verify_hostname = !tls.insecure;
            peer.options.ca.clone_from(&tls.ca);
            peer.client_cert_key.clone_from(&tls.client_cert);
        }
        Ok(peer)
    }

    async fn plain_peer(
        &self,
        url: &Url,
        timeout: Duration,
        server_name: Option<&str>,
    ) -> Result<HttpPeer, FetchError> {
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
        let sni = server_name.map_or(sni, str::to_owned);
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

/// Reads the client certificate chain and key that a service presents to its backends. They
/// are checked here because Pingora asserts a non-empty chain and unwraps the key conversion.
///
/// # Errors
///
/// A file cannot be read or holds no usable certificate or key.
pub fn load_client_cert(
    cert_file: &std::path::Path,
    key_file: &std::path::Path,
) -> Result<Arc<pingora::utils::tls::CertKey>, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use x509_parser::prelude::FromDer;

    let chain = CertificateDer::pem_file_iter(cert_file)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("cannot read `{}`: {e}", cert_file.display()))?;
    if chain.is_empty() {
        return Err(format!("`{}` holds no certificate", cert_file.display()));
    }
    for der in &chain {
        x509_parser::certificate::X509Certificate::from_der(der.as_ref())
            .map_err(|e| format!("invalid certificate in `{}`: {e}", cert_file.display()))?;
    }
    let key = PrivateKeyDer::from_pem_file(key_file)
        .map_err(|e| format!("cannot read the key `{}`: {e}", key_file.display()))?;
    rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("unusable key `{}`: {e}", key_file.display()))?;
    let key = key.secret_der().to_vec();
    if PrivateKeyDer::try_from(key.clone()).is_err() {
        return Err(format!(
            "unsupported key format in `{}`",
            key_file.display()
        ));
    }
    Ok(Arc::new(pingora::utils::tls::CertKey::new(
        chain.into_iter().map(|c| c.to_vec()).collect(),
        key,
    )))
}

/// Reads a PEM bundle of CA certificates for backend verification.
///
/// # Errors
///
/// The file cannot be read or holds no valid certificate.
pub fn load_ca(file: &std::path::Path) -> Result<Arc<[pingora::utils::tls::WrappedX509]>, String> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    use x509_parser::prelude::FromDer;

    let bytes =
        std::fs::read(file).map_err(|e| format!("cannot read `{}`: {e}", file.display()))?;
    let mut certs = Vec::new();
    for der in CertificateDer::pem_slice_iter(&bytes) {
        let der = der.map_err(|e| format!("invalid PEM in `{}`: {e}", file.display()))?;
        // Pingora's parser panics on invalid DER, so check it first.
        x509_parser::certificate::X509Certificate::from_der(der.as_ref())
            .map_err(|e| format!("invalid certificate in `{}`: {e}", file.display()))?;
        certs.push(pingora::utils::tls::WrappedX509::new(
            der.as_ref().to_vec(),
            pingora::utils::tls::parse_x509,
        ));
    }
    if certs.is_empty() {
        return Err(format!("`{}` contains no certificate", file.display()));
    }
    Ok(certs.into())
}
