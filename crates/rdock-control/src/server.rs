//! The cluster listener: TLS with an optional client certificate from the cluster CA, HTTP/2 or
//! HTTP/1.1, the calls of `rdock_cluster::protocol`. Runs on the control plane's runtime; the
//! data planes never wait on it to serve traffic (ADR-0009, ADR-0012).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use rdock_cluster::protocol::{
    BUNDLE_MEDIA_TYPE, EnrollRequest, RenewRequest, Report, StoreRequest,
};
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use tokio::sync::{Semaphore, watch};
use tracing::{debug, warn};

use crate::plane::ControlPlane;
use crate::{Error, ca};

/// Largest request body: a store write of a certificate chain and key is a few KiB.
const MAX_BODY: usize = 1 << 20;
/// Largest enrolment or renewal body: a token, a signing request and a name.
const MAX_SMALL_BODY: usize = 64 << 10;
/// Longest a bundle request may wait.
const MAX_WAIT: Duration = Duration::from_secs(300);
/// Connections at once (review finding M5).
const MAX_CONNECTIONS: usize = 4096;
/// Connections without a client certificate at once: they can only enrol.
const MAX_ANONYMOUS: usize = 64;
/// Enrolments handled at once; more get `503`.
const MAX_ENROLMENTS: usize = 8;
/// The longest a connection without a client certificate stays open.
const ANONYMOUS_LIFETIME: Duration = Duration::from_secs(60);
/// The longest a client may take to send a request's headers, and its body.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// The header every answer carries: the control plane's clock in milliseconds since the Unix
/// epoch, which a data plane compares with its own on its first call (review finding M6).
pub const TIME_HEADER: &str = rdock_cluster::protocol::TIME_HEADER;

/// The names on the server certificate: the configured ones, the listener's IP, and loopback.
#[must_use]
pub fn server_names(plane: &ControlPlane) -> Vec<String> {
    let settings = plane.settings();
    let mut names = settings.names.clone();
    if let Some(ip) = settings.listener.ip()
        && !ip.is_unspecified()
    {
        names.push(ip.to_string());
    }
    for name in ["localhost", "127.0.0.1", "::1"] {
        names.push(name.to_owned());
    }
    names.sort();
    names.dedup();
    names
}

/// The TLS configuration of the cluster listener.
pub fn tls_config(plane: &ControlPlane) -> Result<Arc<rustls::ServerConfig>, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (cert_pem, key_pem) = plane.ca().server_certificate(&server_names(plane))?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| Error::Certificate(e.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| Error::Certificate(e.to_string()))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(plane.ca().der().clone())
        .map_err(|e| Error::Certificate(e.to_string()))?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|e| Error::Certificate(e.to_string()))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Certificate(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| Error::Certificate(e.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Serves the cluster listener on `listener` until `stop` turns true.
///
/// Bounded against slow or many clients (review finding M5): at most 4,096 connections, of
/// which 64 without a client certificate, each of those closed after 60 s; the TLS handshake
/// (10 s), a request's headers (10 s) and its body (30 s) each have a deadline; bodies are capped
/// per call; at most 8 enrolments run at once.
pub async fn serve(
    plane: Arc<ControlPlane>,
    listener: std::net::TcpListener,
    mut stop: watch::Receiver<bool>,
) -> Result<(), Error> {
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::State(e.to_string()))?;
    let listener =
        tokio::net::TcpListener::from_std(listener).map_err(|e| Error::State(e.to_string()))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config(&plane)?);
    let limits = Arc::new(Limits {
        connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        anonymous: Arc::new(Semaphore::new(MAX_ANONYMOUS)),
        enrolments: Arc::new(Semaphore::new(MAX_ENROLMENTS)),
        builder: http_builder(),
    });
    loop {
        let (tcp, peer) = tokio::select! {
            _ = stop.changed() => return Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    warn!(error = %e, "cluster listener: accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(slot) = limits.connections.clone().try_acquire_owned() else {
            debug!(%peer, "cluster listener: too many connections; closing one");
            continue;
        };
        // Small request and answer frames (store operations): no Nagle delay.
        let _ = tcp.set_nodelay(true);
        let (acceptor, plane, stop, limits) = (
            acceptor.clone(),
            plane.clone(),
            stop.clone(),
            limits.clone(),
        );
        tokio::spawn(async move {
            let _slot = slot;
            connection(tcp, peer, acceptor, plane, stop, &limits).await;
        });
    }
}

/// What every connection shares: the caps and the HTTP settings.
struct Limits {
    connections: Arc<Semaphore>,
    anonymous: Arc<Semaphore>,
    enrolments: Arc<Semaphore>,
    builder: Builder<TokioExecutor>,
}

/// HTTP/1.1 and HTTP/2 with deadlines and small buffers.
fn http_builder() -> Builder<TokioExecutor> {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(64 << 10);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .max_concurrent_streams(64)
        .max_header_list_size(16 << 10);
    builder
}

/// One connection: the TLS handshake, then HTTP until it ends, the server stops, or (without a
/// client certificate) its time is up.
async fn connection(
    tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    plane: Arc<ControlPlane>,
    mut stop: watch::Receiver<bool>,
    limits: &Limits,
) {
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            debug!(%peer, error = %e, "cluster listener: TLS handshake failed");
            return;
        }
        Err(_) => return,
    };
    let identity = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .and_then(|leaf| ca::identity_of(leaf, plane.cluster_id()));
    let anonymous_slot = if identity.is_none() {
        let Ok(slot) = limits.anonymous.clone().try_acquire_owned() else {
            debug!(%peer, "cluster listener: too many connections without a client certificate");
            return;
        };
        Some(slot)
    } else {
        None
    };
    let enrolments = limits.enrolments.clone();
    let service = service_fn(move |request| {
        let (plane, identity, enrolments) = (plane.clone(), identity.clone(), enrolments.clone());
        async move {
            let caller = identity.as_ref().map(|(i, s)| (i.as_str(), s.as_str()));
            let mut response = route(&plane, caller, &enrolments, request).await;
            if let Ok(value) = http::HeaderValue::from_str(
                &rdock_cluster::Clock::now_ms(&rdock_cluster::SystemClock).to_string(),
            ) {
                response.headers_mut().insert(TIME_HEADER, value);
            }
            Ok::<_, Infallible>(response)
        }
    });
    let serving = limits.builder.serve_connection(TokioIo::new(tls), service);
    let lifetime = if anonymous_slot.is_some() {
        ANONYMOUS_LIFETIME
    } else {
        Duration::MAX
    };
    tokio::select! {
        _ = serving => {}
        _ = stop.changed() => {}
        () = sleep_for(lifetime) => {
            debug!(%peer, "cluster listener: closing a connection without a client certificate after its time");
        }
    }
    drop(anonymous_slot);
}

async fn sleep_for(duration: Duration) {
    if duration == Duration::MAX {
        std::future::pending::<()>().await;
    } else {
        tokio::time::sleep(duration).await;
    }
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_default()
}

fn error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, &json!({ "error": message }))
}

fn from_error(e: &Error) -> Response<Full<Bytes>> {
    match e {
        Error::Refused(message) => error(StatusCode::FORBIDDEN, message),
        Error::Forbidden => error(
            StatusCode::FORBIDDEN,
            "this instance is not enrolled or was revoked",
        ),
        other => {
            warn!(error = %other, "cluster listener: request failed");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the control plane failed",
            )
        }
    }
}

async fn body<T: serde::de::DeserializeOwned>(
    request: Request<Incoming>,
    limit: usize,
) -> Result<T, Box<Response<Full<Bytes>>>> {
    let collected = tokio::time::timeout(
        BODY_TIMEOUT,
        Limited::new(request.into_body(), limit).collect(),
    )
    .await
    .map_err(|_| {
        Box::new(error(
            StatusCode::REQUEST_TIMEOUT,
            "the request body did not arrive in time",
        ))
    })?;
    let bytes = collected
        .map_err(|_| {
            error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body is too large or broken",
            )
        })?
        .to_bytes();
    serde_json::from_slice(&bytes)
        .map_err(|e| Box::new(error(StatusCode::BAD_REQUEST, &e.to_string())))
}

fn query(request: &Request<Incoming>, name: &str) -> Option<u64> {
    request.uri().query()?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

async fn route(
    plane: &ControlPlane,
    caller: Option<(&str, &str)>,
    enrolments: &Semaphore,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    if method == Method::POST && path == "/cluster/v1/enroll" {
        let Ok(_permit) = enrolments.try_acquire() else {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many enrolments at once; try again",
            );
        };
        let enroll: EnrollRequest = match body(request, MAX_SMALL_BODY).await {
            Ok(enroll) => enroll,
            Err(response) => return *response,
        };
        return match plane.enroll(&enroll, caller).await {
            Ok(answer) => json_response(StatusCode::OK, &json!(answer)),
            Err(e) => from_error(&e),
        };
    }
    let Some((instance, serial)) = caller else {
        return error(
            StatusCode::UNAUTHORIZED,
            "a client certificate from the cluster CA is required",
        );
    };
    if !plane.admit(instance, serial).await {
        return error(
            StatusCode::FORBIDDEN,
            "this instance is not enrolled, was revoked, or presents a certificate that was replaced",
        );
    }
    match (method, path.as_str()) {
        (Method::POST, "/cluster/v1/renew") => {
            let renew: RenewRequest = match body(request, MAX_SMALL_BODY).await {
                Ok(renew) => renew,
                Err(response) => return *response,
            };
            match plane.renew(instance, &renew.csr_pem).await {
                Ok(answer) => json_response(StatusCode::OK, &json!(answer)),
                Err(e) => from_error(&e),
            }
        }
        (Method::GET, "/cluster/v1/bundle") => {
            let after = query(&request, "after").unwrap_or(0);
            let wait = Duration::from_secs(query(&request, "wait").unwrap_or(30)).min(MAX_WAIT);
            let bundle = plane.bundle_after(instance, after, wait).await;
            // A revocation while the request waited ends it without a bundle.
            if !plane.admit(instance, serial).await {
                return error(StatusCode::FORBIDDEN, "this instance was revoked");
            }
            match bundle {
                Some(bytes) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", BUNDLE_MEDIA_TYPE)
                    .body(Full::new(Bytes::from(bytes)))
                    .unwrap_or_default(),
                None => Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_default(),
            }
        }
        (Method::POST, "/cluster/v1/report") => {
            let report: Report = match body(request, MAX_BODY).await {
                Ok(report) => report,
                Err(response) => return *response,
            };
            match plane.report(instance, report).await {
                Ok(()) => Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_default(),
                Err(e) => from_error(&e),
            }
        }
        (Method::POST, "/cluster/v1/store") => {
            let op: StoreRequest = match body(request, MAX_BODY).await {
                Ok(op) => op,
                Err(response) => return *response,
            };
            json_response(StatusCode::OK, &json!(plane.store_op(instance, op).await))
        }
        _ => error(StatusCode::NOT_FOUND, "no such cluster call"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn connect(
        plane: &ControlPlane,
        addr: std::net::SocketAddr,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(plane.ca().der().clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        connector
            .connect(
                rustls_pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap()
    }

    /// Review finding M5: a client without a certificate that sends half a request is
    /// disconnected after the header deadline instead of holding the connection for ever; a
    /// complete request is answered, with the control plane's clock.
    #[tokio::test]
    async fn a_slow_client_is_disconnected() {
        let dir = tempfile::tempdir().unwrap();
        let plane =
            ControlPlane::open(dir.path(), rdock_model::cluster::ControlPlane::default()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (_stop, stop_rx) = watch::channel(false);
        tokio::spawn(serve(plane.clone(), listener, stop_rx));
        // A complete request without a client certificate: 401, with the clock header.
        let mut tls = connect(&plane, addr).await;
        tls.write_all(
            b"GET /cluster/v1/bundle HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut answer = String::new();
        tls.read_to_string(&mut answer).await.unwrap_or_default();
        assert!(answer.starts_with("HTTP/1.1 401"), "{answer}");
        assert!(answer.contains(TIME_HEADER), "{answer}");
        // Half a request line: closed within the header deadline (and some slack).
        let mut slow = connect(&plane, addr).await;
        slow.write_all(b"GET /cluster/v1/bun").await.unwrap();
        let started = std::time::Instant::now();
        let mut buffer = Vec::new();
        let read = tokio::time::timeout(
            HEADER_TIMEOUT + Duration::from_secs(10),
            slow.read_to_end(&mut buffer),
        )
        .await;
        assert!(read.is_ok(), "the connection stayed open");
        assert!(started.elapsed() + Duration::from_secs(1) >= HEADER_TIMEOUT);
    }
}
