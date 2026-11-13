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
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rdock_cluster::protocol::{
    BUNDLE_MEDIA_TYPE, EnrollRequest, RenewRequest, Report, StoreRequest,
};
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::plane::ControlPlane;
use crate::{Error, ca};

/// Largest request body: a store write of a certificate chain and key is a few KiB.
const MAX_BODY: usize = 1 << 20;
/// Longest a bundle request may wait.
const MAX_WAIT: Duration = Duration::from_secs(300);

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
        let (acceptor, plane, stop) = (acceptor.clone(), plane.clone(), stop.clone());
        tokio::spawn(async move {
            let tls =
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(e)) => {
                        debug!(%peer, error = %e, "cluster listener: TLS handshake failed");
                        return;
                    }
                    Err(_) => return,
                };
            let instance = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .and_then(|leaf| ca::instance_of(leaf, plane.cluster_id()));
            let service = service_fn(move |request| {
                let (plane, instance) = (plane.clone(), instance.clone());
                async move { Ok::<_, Infallible>(route(&plane, instance.as_deref(), request).await) }
            });
            let builder = Builder::new(TokioExecutor::new());
            let connection = builder.serve_connection(TokioIo::new(tls), service);
            let mut stop = stop;
            tokio::select! {
                _ = connection => {}
                _ = stop.changed() => {}
            }
        });
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
) -> Result<T, Box<Response<Full<Bytes>>>> {
    let bytes = Limited::new(request.into_body(), MAX_BODY)
        .collect()
        .await
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
    instance: Option<&str>,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    if method == Method::POST && path == "/cluster/v1/enroll" {
        let enroll: EnrollRequest = match body(request).await {
            Ok(enroll) => enroll,
            Err(response) => return *response,
        };
        return match plane.enroll(&enroll).await {
            Ok(answer) => json_response(StatusCode::OK, &json!(answer)),
            Err(e) => from_error(&e),
        };
    }
    let Some(instance) = instance else {
        return error(
            StatusCode::UNAUTHORIZED,
            "a client certificate from the cluster CA is required",
        );
    };
    if !plane.admit(instance).await {
        return error(
            StatusCode::FORBIDDEN,
            "this instance is not enrolled or was revoked",
        );
    }
    match (method, path.as_str()) {
        (Method::POST, "/cluster/v1/renew") => {
            let renew: RenewRequest = match body(request).await {
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
            let bundle = plane.bundle_after(after, wait).await;
            // A revocation while the request waited ends it without a bundle.
            if !plane.admit(instance).await {
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
            let report: Report = match body(request).await {
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
            let op: StoreRequest = match body(request).await {
                Ok(op) => op,
                Err(response) => return *response,
            };
            json_response(StatusCode::OK, &json!(plane.store_op(instance, op).await))
        }
        _ => error(StatusCode::NOT_FOUND, "no such cluster call"),
    }
}
