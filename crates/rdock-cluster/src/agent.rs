//! The data-plane agent (ADR-0031): enrolment, the mutual-TLS client, the long poll for bundles
//! with ACK/NACK, certificate renewal, and the control plane's store as a [`ClusterStore`].
//!
//! The agent is a background service like a provider: the request path never waits on it
//! (ADR-0009, ADR-0012). While the control plane is away the data plane serves its stored
//! bundle and the agent retries with backoff.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::protocol::{
    Bundle, EnrollRequest, EnrollResponse, Report, StoreRequest, StoreResponse, Verdict,
};
use crate::store::{ClusterStore, Entry, Expect, Fencing, Lease, StoreError};

/// Why the agent cannot do something.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// The control plane could not be reached or answered with an error.
    #[error("control plane: {0}")]
    Unreachable(String),
    /// The control plane refused (a bad join token, a revoked instance).
    #[error("refused by the control plane: {0}")]
    Refused(String),
    /// The identity on disk or the configuration cannot be used.
    #[error("{0}")]
    Identity(String),
}

/// What the agent needs to know (from `cluster.control`).
#[derive(Debug, Clone)]
pub struct AgentSettings {
    /// The control plane's address, `https://host:port`.
    pub url: String,
    /// The cluster CA, PEM, when `ca_file` is set.
    pub ca_pem: Option<String>,
    /// `sha256:<hex>`, when `ca_pin` is set.
    pub ca_pin: Option<String>,
    /// Where the identity is kept.
    pub identity_dir: PathBuf,
    /// The join token, resolved (only used while there is no identity).
    pub join_token: Option<String>,
    /// The name to ask for.
    pub instance: Option<String>,
    /// How long one bundle request waits.
    pub poll_timeout: Duration,
    /// This binary's version.
    pub version: String,
}

/// `identity.json`: who this instance is, with its key, certificate and the cluster CA in one
/// file, so a crash while it is written leaves the previous identity or the new one, never a
/// key that does not match its certificate (review finding L4). Identities written before held
/// the PEM files beside it (`key.pem`, `cert.pem`, `ca.pem`); those still load.
#[derive(Clone, Serialize, Deserialize)]
struct IdentityFile {
    cluster_id: String,
    instance: String,
    not_after: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_pem: Option<String>,
}

/// The key an enrolment is made with, kept until the identity is saved, so a retry after a
/// lost answer or a crash asks with the same key and gets the same instance (review finding
/// L2).
const ENROLMENT_KEY: &str = "enroll-key.pem";

/// The enrolled identity: who this instance is in which cluster, with its key and certificate.
#[derive(Clone)]
pub struct Identity {
    /// The cluster's id.
    pub cluster_id: String,
    /// This instance's name.
    pub instance: String,
    /// When the client certificate expires (Unix seconds).
    pub not_after: i64,
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("cluster_id", &self.cluster_id)
            .field("instance", &self.instance)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

impl Identity {
    fn load(dir: &Path) -> Result<Option<Self>, AgentError> {
        let read = |name: &str| std::fs::read_to_string(dir.join(name));
        let file = match read("identity.json") {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AgentError::Identity(format!("{}: {e}", dir.display()))),
        };
        let meta: IdentityFile = serde_json::from_str(&file)
            .map_err(|e| AgentError::Identity(format!("{}/identity.json: {e}", dir.display())))?;
        let pems = match (meta.ca_pem, meta.cert_pem, meta.key_pem) {
            (Some(ca), Some(cert), Some(key)) => Ok((ca, cert, key)),
            // An identity written by an earlier version: the PEM files beside it.
            _ => match (read("ca.pem"), read("cert.pem"), read("key.pem")) {
                (Ok(ca), Ok(cert), Ok(key)) => Ok((ca, cert, key)),
                _ => Err(()),
            },
        };
        match pems {
            Ok((ca_pem, cert_pem, key_pem)) => Ok(Some(Self {
                cluster_id: meta.cluster_id,
                instance: meta.instance,
                not_after: meta.not_after,
                ca_pem,
                cert_pem,
                key_pem,
            })),
            Err(()) => Err(AgentError::Identity(format!(
                "the identity in {} is incomplete; remove the directory and enrol again",
                dir.display()
            ))),
        }
    }

    /// Writes the identity as one file, mode 0600, replaced atomically.
    fn save(&self, dir: &Path) -> Result<(), AgentError> {
        let fail = |e: std::io::Error| AgentError::Identity(format!("{}: {e}", dir.display()));
        let file = IdentityFile {
            cluster_id: self.cluster_id.clone(),
            instance: self.instance.clone(),
            not_after: self.not_after,
            ca_pem: Some(self.ca_pem.clone()),
            cert_pem: Some(self.cert_pem.clone()),
            key_pem: Some(self.key_pem.clone()),
        };
        let json =
            serde_json::to_vec_pretty(&file).map_err(|e| AgentError::Identity(e.to_string()))?;
        crate::dir::write_private(&dir.join("identity.json"), &json).map_err(fail)?;
        // The files of earlier versions and the enrolment key are no longer needed.
        for old in ["key.pem", "cert.pem", "ca.pem", ENROLMENT_KEY] {
            let _ = std::fs::remove_file(dir.join(old));
        }
        Ok(())
    }

    /// Whether the client certificate has expired: the control plane refuses it in the TLS
    /// handshake, which a data plane would otherwise see as an unreachable control plane.
    fn expired(&self, now: i64) -> bool {
        self.not_after <= now
    }

    /// Whether a third or less of the certificate's life is left.
    fn wants_renewal(&self, now: i64) -> bool {
        let Ok(der) = CertificateDer::from_pem_slice(self.cert_pem.as_bytes()) else {
            return true;
        };
        let Ok((_, cert)) = x509_parser::parse_x509_certificate(der.as_ref()) else {
            return true;
        };
        let (from, to) = (
            cert.validity().not_before.timestamp(),
            cert.validity().not_after.timestamp(),
        );
        now >= to - (to - from) / 3
    }
}

/// A new key and a signing request for it.
fn key_and_csr() -> Result<(String, String), AgentError> {
    let key = rcgen::KeyPair::generate().map_err(|e| AgentError::Identity(e.to_string()))?;
    csr_for(&key.serialize_pem())
}

/// A signing request for the key `key_pem`.
fn csr_for(key_pem: &str) -> Result<(String, String), AgentError> {
    let key = rcgen::KeyPair::from_pem(key_pem).map_err(|e| AgentError::Identity(e.to_string()))?;
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .and_then(|p| p.serialize_request(&key))
        .and_then(|r| r.pem())
        .map_err(|e| AgentError::Identity(e.to_string()))?;
    Ok((key_pem.to_owned(), csr))
}

/// The enrolment key: the one kept from an earlier attempt, or a new one, written (mode 0600)
/// before anything is sent.
fn enrolment_key(dir: &Path) -> Result<String, AgentError> {
    let path = dir.join(ENROLMENT_KEY);
    if let Ok(pem) = std::fs::read_to_string(&path)
        && rcgen::KeyPair::from_pem(&pem).is_ok()
    {
        return Ok(pem);
    }
    let key = rcgen::KeyPair::generate().map_err(|e| AgentError::Identity(e.to_string()))?;
    let pem = key.serialize_pem();
    crate::dir::write_private(&path, pem.as_bytes())
        .map_err(|e| AgentError::Identity(format!("{}: {e}", path.display())))?;
    Ok(pem)
}

/// Warns once when this instance's clock differs from the control plane's (the
/// [`crate::protocol::TIME_HEADER`] of an answer received at `now_ms`) by more than
/// [`crate::protocol::CLOCK_SKEW_WARNING`]: leases on a shared directory, limit windows and
/// member counts assume clocks within a few seconds (review finding M6).
fn check_clock(server_ms: Option<u64>, checked: &AtomicBool) {
    let Some(server_ms) = server_ms else {
        return;
    };
    if checked.swap(true, Ordering::Relaxed) {
        return;
    }
    let now = crate::clock::Clock::now_ms(&crate::clock::SystemClock);
    let skew = now.abs_diff(server_ms);
    let limit = u64::try_from(crate::protocol::CLOCK_SKEW_WARNING.as_millis()).unwrap_or(0);
    if skew > limit {
        let direction = if now > server_ms {
            "ahead of"
        } else {
            "behind"
        };
        warn!(
            skew_ms = skew,
            "this instance's clock is {} s {direction} the control plane's; cluster-scoped limits, member counts and leases on a shared directory assume clocks within a few seconds of each other: synchronise the clocks (NTP)",
            skew / 1000
        );
    }
}

/// Accepts the control plane when its chain holds a CA certificate with the pinned digest
/// and the leaf is valid under that CA for the name in the URL.
#[derive(Debug)]
struct PinVerifier {
    pin: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let expected = self.pin.strip_prefix("sha256:").unwrap_or(&self.pin);
        let ca = intermediates
            .iter()
            .find(|c| sha256_hex(c.as_ref()) == expected)
            .ok_or_else(|| {
                rustls::Error::General(
                    "the control plane's chain has no CA with the pinned digest".to_owned(),
                )
            })?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca.clone().into_owned())
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            self.provider.clone(),
        )
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
        inner.verify_server_cert(end_entity, &[], server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client that trusts only the cluster CA (`ca_pem`), or the pinned CA, and presents
/// `client` when given.
fn https_client(
    ca_pem: Option<&str>,
    pin: Option<&str>,
    client: Option<(&str, &str)>,
) -> Result<HttpsClient, AgentError> {
    let fail = |e: &dyn std::fmt::Display| AgentError::Identity(format!("TLS: {e}"));
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| fail(&e))?;
    let builder = if let Some(ca_pem) = ca_pem {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots
                .add(cert.map_err(|e| fail(&e))?)
                .map_err(|e| fail(&e))?;
        }
        builder.with_root_certificates(roots)
    } else if let Some(pin) = pin {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                pin: pin.to_owned(),
                provider: provider(),
            }))
    } else {
        return Err(AgentError::Identity(
            "`cluster.control` needs `ca_file` or `ca_pin`".to_owned(),
        ));
    };
    let config = match client {
        Some((cert_pem, key_pem)) => {
            let chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|e| fail(&e))?;
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| fail(&e))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| fail(&e))?
        }
        None => builder.with_no_client_auth(),
    };
    // Store operations are small requests in quick succession: no Nagle delay.
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

/// One call: status, body and the control plane's clock, within `limit`.
async fn call(
    client: &HttpsClient,
    method: Method,
    url: &str,
    body: Option<Vec<u8>>,
    limit: Duration,
) -> Result<(StatusCode, Bytes, Option<u64>), AgentError> {
    let mut builder = Request::builder().method(method).uri(url);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let request = builder
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|e| AgentError::Unreachable(e.to_string()))?;
    let response = tokio::time::timeout(limit, client.request(request))
        .await
        .map_err(|_| AgentError::Unreachable("timed out".to_owned()))?
        .map_err(|e| {
            let text = format!("{e:?}");
            // A control plane whose certificate does not verify (another CA, a wrong pin) is
            // not one to keep retrying against.
            if text.contains("pinned digest") || text.contains("InvalidCertificate") {
                AgentError::Refused(format!(
                    "the control plane's certificate is not trusted: {text}"
                ))
            } else {
                AgentError::Unreachable(text)
            }
        })?;
    let status = response.status();
    let server_ms = response
        .headers()
        .get(crate::protocol::TIME_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let bytes = tokio::time::timeout(limit, response.into_body().collect())
        .await
        .map_err(|_| AgentError::Unreachable("timed out reading the answer".to_owned()))?
        .map_err(|e| AgentError::Unreachable(e.to_string()))?
        .to_bytes();
    Ok((status, bytes, server_ms))
}

fn refusal(status: StatusCode, body: &Bytes) -> AgentError {
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or_else(|| status.to_string());
    if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
        AgentError::Refused(message)
    } else {
        AgentError::Unreachable(format!("{status}: {message}"))
    }
}

/// The connection to the control plane once enrolled.
#[derive(Clone)]
pub struct Channel {
    url: String,
    client: Arc<Mutex<HttpsClient>>,
    identity: Arc<Mutex<Identity>>,
    settings: AgentSettings,
    /// Whether the clocks were compared (on the first answer).
    clock_checked: Arc<AtomicBool>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// Loads the identity, or enrols with the join token (retrying with backoff while the control
/// plane cannot be reached; a refused token is final).
pub async fn connect(settings: AgentSettings) -> Result<Channel, AgentError> {
    let clock_checked = Arc::new(AtomicBool::new(false));
    let identity = if let Some(identity) = Identity::load(&settings.identity_dir)? {
        identity
    } else {
        let mut delay = Duration::from_millis(500);
        loop {
            match enroll(&settings, &clock_checked).await {
                Ok(identity) => break identity,
                Err(AgentError::Unreachable(e)) => {
                    warn!(error = %e, retry_in = ?delay, "cannot reach the control plane to enrol; trying again");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
                Err(e) => return Err(e),
            }
        }
    };
    let client = https_client(
        Some(&identity.ca_pem),
        None,
        Some((&identity.cert_pem, &identity.key_pem)),
    )?;
    Ok(Channel {
        url: settings.url.trim_end_matches('/').to_owned(),
        client: Arc::new(Mutex::new(client)),
        identity: Arc::new(Mutex::new(identity)),
        settings,
        clock_checked,
    })
}

async fn enroll(settings: &AgentSettings, clock: &AtomicBool) -> Result<Identity, AgentError> {
    let token = settings.join_token.clone().ok_or_else(|| {
        AgentError::Identity(
            "this instance is not enrolled: set `cluster.control.join_token` (from `rdock control token create`)".to_owned(),
        )
    })?;
    let client = https_client(settings.ca_pem.as_deref(), settings.ca_pin.as_deref(), None)?;
    let (key_pem, csr_pem) = csr_for(&enrolment_key(&settings.identity_dir)?)?;
    let request = EnrollRequest {
        token,
        csr_pem,
        name: settings.instance.clone(),
        version: settings.version.clone(),
    };
    let body = serde_json::to_vec(&request).map_err(|e| AgentError::Identity(e.to_string()))?;
    drop(request);
    let url = format!("{}/cluster/v1/enroll", settings.url.trim_end_matches('/'));
    let (status, bytes, server_ms) = call(
        &client,
        Method::POST,
        &url,
        Some(body),
        Duration::from_secs(30),
    )
    .await?;
    check_clock(server_ms, clock);
    if status == StatusCode::SERVICE_UNAVAILABLE {
        return Err(AgentError::Unreachable(refusal(status, &bytes).to_string()));
    }
    if !status.is_success() {
        return Err(refusal(status, &bytes));
    }
    let answer: EnrollResponse =
        serde_json::from_slice(&bytes).map_err(|e| AgentError::Unreachable(e.to_string()))?;
    if let Some(pin) = &settings.ca_pin {
        let ca = CertificateDer::from_pem_slice(answer.ca_pem.as_bytes())
            .map_err(|e| AgentError::Identity(e.to_string()))?;
        if format!("sha256:{}", sha256_hex(ca.as_ref())) != *pin {
            return Err(AgentError::Refused(
                "the control plane sent a CA that does not match `ca_pin`".to_owned(),
            ));
        }
    }
    let identity = Identity {
        cluster_id: answer.cluster_id,
        instance: answer.instance,
        not_after: answer.not_after,
        ca_pem: answer.ca_pem,
        cert_pem: answer.certificate_pem,
        key_pem,
    };
    identity.save(&settings.identity_dir)?;
    info!(instance = %identity.instance, cluster = %identity.cluster_id, "enrolled with the control plane");
    Ok(identity)
}

/// What the data plane does with a bundle.
#[async_trait]
pub trait BundleSink: Send + Sync {
    /// The revision served now, `0` before the first bundle.
    fn serving(&self) -> u64;
    /// Validates and compiles `bundle` like any configuration, **stores it**, then applies it.
    /// `Ok` (warnings) is an ACK; `Err` (diagnostics) a NACK, with the running configuration
    /// left as it was.
    async fn apply(&self, bundle: Bundle)
    -> Result<Vec<serde_json::Value>, Vec<serde_json::Value>>;
    /// The channel's state changed (connected or not, a refusal).
    fn connection(&self, connected: bool, error: Option<String>);
    /// Counts a bundle by result (`ack`, `nack`, `refused`).
    fn counted(&self, result: &str) {
        let _ = result;
    }
}

/// Why a bundle is refused before it is even tried: another cluster's, not newer than what
/// is served, empty, or not matching its digest.
#[must_use]
pub fn refuse(bundle: &Bundle, cluster_id: &str, serving: u64) -> Option<String> {
    if bundle.cluster_id != cluster_id {
        return Some(format!(
            "the bundle belongs to cluster `{}`, not `{cluster_id}`",
            bundle.cluster_id
        ));
    }
    if bundle.revision <= serving {
        return Some(format!(
            "revision {} is not newer than revision {serving}, which is served",
            bundle.revision
        ));
    }
    if bundle.is_empty() {
        return Some("the bundle is empty; an empty configuration never replaces one".to_owned());
    }
    if Bundle::digest(&bundle.document) != bundle.sha256 {
        return Some("the bundle does not match its SHA-256".to_owned());
    }
    None
}

fn diagnostic(message: &str) -> serde_json::Value {
    serde_json::json!({ "severity": "error", "path": "", "message": message })
}

impl Channel {
    /// The identity in use.
    #[must_use]
    pub fn identity(&self) -> Identity {
        self.identity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn client(&self) -> HttpsClient {
        self.client
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The control plane's store over this channel.
    #[must_use]
    pub fn store(&self) -> Arc<dyn ClusterStore> {
        Arc::new(RemoteStore {
            channel: self.clone(),
        })
    }

    async fn post<T: Serialize>(
        &self,
        path: &str,
        value: &T,
        limit: Duration,
    ) -> Result<(StatusCode, Bytes), AgentError> {
        let body = serde_json::to_vec(value).map_err(|e| AgentError::Identity(e.to_string()))?;
        let (status, bytes, server_ms) = call(
            &self.client(),
            Method::POST,
            &format!("{}{path}", self.url),
            Some(body),
            limit,
        )
        .await?;
        check_clock(server_ms, &self.clock_checked);
        Ok((status, bytes))
    }

    /// Renews the client certificate when a third of its life or less is left.
    async fn renew_if_due(&self) -> Result<(), AgentError> {
        if !self.identity().wants_renewal(unix_now()) {
            return Ok(());
        }
        let (key_pem, csr_pem) = key_and_csr()?;
        let (status, bytes) = self
            .post(
                "/cluster/v1/renew",
                &crate::protocol::RenewRequest { csr_pem },
                Duration::from_secs(30),
            )
            .await?;
        if !status.is_success() {
            return Err(refusal(status, &bytes));
        }
        let answer: EnrollResponse =
            serde_json::from_slice(&bytes).map_err(|e| AgentError::Unreachable(e.to_string()))?;
        let mut identity = self.identity();
        identity.cert_pem = answer.certificate_pem;
        identity.key_pem = key_pem;
        identity.not_after = answer.not_after;
        identity.save(&self.settings.identity_dir)?;
        let client = https_client(
            Some(&identity.ca_pem),
            None,
            Some((&identity.cert_pem, &identity.key_pem)),
        )?;
        *self.client.lock().unwrap_or_else(PoisonError::into_inner) = client;
        *self.identity.lock().unwrap_or_else(PoisonError::into_inner) = identity;
        info!(
            not_after = answer.not_after,
            "renewed the cluster certificate"
        );
        Ok(())
    }

    /// Runs the bundle loop until `stop` turns true: long-polls for the bundle after the one
    /// served, hands it to `sink`, and reports the verdict. Backs off while the control plane
    /// is away; a revoked instance asks again once a minute and keeps serving.
    pub async fn run(
        self,
        sink: Arc<dyn BundleSink>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut delay = Duration::from_millis(500);
        let mut connected: Option<bool> = None;
        loop {
            let result = tokio::select! {
                _ = stop.changed() => return,
                result = self.once(sink.as_ref()) => result,
            };
            let pause = match result {
                Ok(()) => {
                    if connected != Some(true) {
                        info!("connected to the control plane");
                        sink.connection(true, None);
                        connected = Some(true);
                    }
                    delay = Duration::from_millis(500);
                    Duration::ZERO
                }
                Err(AgentError::Refused(e)) => {
                    warn!(error = %e, "the control plane refuses this instance; serving the last bundle");
                    sink.connection(false, Some(format!("refused: {e}")));
                    connected = Some(false);
                    Duration::from_secs(60)
                }
                Err(e) => {
                    if connected != Some(false) {
                        warn!(error = %e, "the control plane is unreachable; serving the last bundle and trying again");
                    }
                    sink.connection(false, Some(e.to_string()));
                    connected = Some(false);
                    let pause = delay;
                    delay = (delay * 2).min(Duration::from_secs(30));
                    pause
                }
            };
            if !pause.is_zero() {
                tokio::select! {
                    _ = stop.changed() => return,
                    () = tokio::time::sleep(pause) => {}
                }
            }
        }
    }

    async fn once(&self, sink: &dyn BundleSink) -> Result<(), AgentError> {
        let identity = self.identity();
        if identity.expired(unix_now()) {
            return Err(AgentError::Refused(format!(
                "the cluster certificate of `{}` expired (Unix time {}); this instance must enrol again: remove the identity in {} and set `cluster.control.join_token` to a new token from `rdock control token create`",
                identity.instance,
                identity.not_after,
                self.settings.identity_dir.display()
            )));
        }
        if let Err(e) = self.renew_if_due().await {
            warn!(error = %e, "cannot renew the cluster certificate");
            if matches!(e, AgentError::Refused(_)) {
                return Err(e);
            }
        }
        let wait = self.settings.poll_timeout;
        let url = format!(
            "{}/cluster/v1/bundle?after={}&wait={}",
            self.url,
            sink.serving(),
            wait.as_secs()
        );
        let (status, bytes, server_ms) = call(
            &self.client(),
            Method::GET,
            &url,
            None,
            wait + Duration::from_secs(15),
        )
        .await?;
        check_clock(server_ms, &self.clock_checked);
        if status == StatusCode::NO_CONTENT {
            return Ok(());
        }
        if !status.is_success() {
            return Err(refusal(status, &bytes));
        }
        let bundle = decompress(&bytes).map_err(AgentError::Unreachable)?;
        let identity = self.identity();
        let serving = sink.serving();
        let (verdict, diagnostics) =
            if let Some(reason) = refuse(&bundle, &identity.cluster_id, serving) {
                warn!(revision = bundle.revision, %reason, "refusing a bundle");
                sink.counted("refused");
                (Verdict::Nack, vec![diagnostic(&reason)])
            } else {
                match sink.apply(bundle.clone()).await {
                    Ok(warnings) => {
                        sink.counted("ack");
                        (Verdict::Ack, warnings)
                    }
                    Err(diagnostics) => {
                        sink.counted("nack");
                        (Verdict::Nack, diagnostics)
                    }
                }
            };
        let report = Report {
            revision: bundle.revision,
            verdict,
            serving: sink.serving(),
            diagnostics,
            version: self.settings.version.clone(),
        };
        let (status, bytes) = self
            .post("/cluster/v1/report", &report, Duration::from_secs(30))
            .await?;
        if !status.is_success() {
            return Err(refusal(status, &bytes));
        }
        if verdict == Verdict::Nack {
            // The same revision would come back at once; wait for a newer one without busy
            // polling: the control plane answers the next poll only for a newer revision.
            self.wait_for_newer(bundle.revision, sink).await?;
        }
        Ok(())
    }

    /// After a NACK of `revision`: polls for a revision above it.
    async fn wait_for_newer(&self, revision: u64, sink: &dyn BundleSink) -> Result<(), AgentError> {
        let wait = self.settings.poll_timeout;
        loop {
            let url = format!(
                "{}/cluster/v1/bundle?after={revision}&wait={}",
                self.url,
                wait.as_secs()
            );
            let (status, bytes, _) = call(
                &self.client(),
                Method::GET,
                &url,
                None,
                wait + Duration::from_secs(15),
            )
            .await?;
            if status == StatusCode::NO_CONTENT {
                continue;
            }
            if !status.is_success() {
                return Err(refusal(status, &bytes));
            }
            let _ = sink;
            return Ok(());
        }
    }
}

/// Decompresses a bundle (at most 64 MiB of JSON).
pub fn decompress(bytes: &[u8]) -> Result<Bundle, String> {
    use std::io::Read as _;
    let mut json = Vec::new();
    zstd::Decoder::new(bytes)
        .map_err(|e| e.to_string())?
        .take(64 << 20)
        .read_to_end(&mut json)
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&json).map_err(|e| e.to_string())
}

/// The control plane's store, over the channel (`POST /cluster/v1/store`).
#[derive(Debug, Clone)]
struct RemoteStore {
    channel: Channel,
}

impl RemoteStore {
    async fn op(&self, request: StoreRequest) -> Result<StoreResponse, StoreError> {
        let (status, bytes) = self
            .channel
            .post("/cluster/v1/store", &request, Duration::from_secs(15))
            .await
            .map_err(|e| StoreError::Unavailable(e.to_string()))?;
        if !status.is_success() {
            return Err(StoreError::Unavailable(refusal(status, &bytes).to_string()));
        }
        let response: StoreResponse =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Unavailable(e.to_string()))?;
        match response {
            StoreResponse::Error {
                kind,
                message,
                current,
            } => Err(match kind.as_str() {
                "conflict" => StoreError::Conflict {
                    key: message,
                    current,
                },
                "fenced" => StoreError::Fenced {
                    lease: message,
                    token: 0,
                },
                "lost" => StoreError::Lost(message),
                "invalid_key" => StoreError::InvalidKey(message),
                "forbidden" => StoreError::Forbidden(message),
                _ => StoreError::Backend(message),
            }),
            other => Ok(other),
        }
    }
}

fn unexpected(response: &StoreResponse) -> StoreError {
    StoreError::Backend(format!(
        "unexpected answer from the control plane: {response:?}"
    ))
}

fn ttl_ms(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX)
}

#[async_trait]
impl ClusterStore for RemoteStore {
    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError> {
        match self
            .op(StoreRequest::Get {
                key: key.to_owned(),
            })
            .await?
        {
            StoreResponse::Entry {
                value: Some(value),
                version,
            } => Ok(Some(Entry {
                value: STANDARD
                    .decode(value)
                    .map_err(|e| StoreError::Backend(e.to_string()))?,
                version,
            })),
            StoreResponse::Entry { value: None, .. } => Ok(None),
            other => Err(unexpected(&other)),
        }
    }

    async fn put(
        &self,
        key: &str,
        value: Vec<u8>,
        expect: Expect,
        fence: Option<&Lease>,
    ) -> Result<u64, StoreError> {
        let request = StoreRequest::Put {
            key: key.to_owned(),
            value: STANDARD.encode(value),
            expect,
            fence: fence.cloned(),
        };
        match self.op(request).await? {
            StoreResponse::Version { version } => Ok(version),
            other => Err(unexpected(&other)),
        }
    }

    async fn delete(
        &self,
        key: &str,
        expect: Expect,
        fence: Option<&Lease>,
    ) -> Result<(), StoreError> {
        let request = StoreRequest::Delete {
            key: key.to_owned(),
            expect,
            fence: fence.cloned(),
        };
        match self.op(request).await? {
            StoreResponse::Done => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        match self
            .op(StoreRequest::List {
                prefix: prefix.to_owned(),
            })
            .await?
        {
            StoreResponse::Keys { keys } => Ok(keys),
            other => Err(unexpected(&other)),
        }
    }

    async fn acquire(
        &self,
        name: &str,
        _holder: &str,
        ttl: Duration,
    ) -> Result<Option<Lease>, StoreError> {
        // The control plane names the holder after the calling instance.
        match self
            .op(StoreRequest::Acquire {
                name: name.to_owned(),
                ttl_ms: ttl_ms(ttl),
            })
            .await?
        {
            StoreResponse::Lease { lease } => Ok(lease),
            other => Err(unexpected(&other)),
        }
    }

    async fn renew(&self, lease: &Lease, ttl: Duration) -> Result<Lease, StoreError> {
        match self
            .op(StoreRequest::Renew {
                lease: lease.clone(),
                ttl_ms: ttl_ms(ttl),
            })
            .await?
        {
            StoreResponse::Lease { lease: Some(lease) } => Ok(lease),
            other => Err(unexpected(&other)),
        }
    }

    async fn release(&self, lease: &Lease) -> Result<(), StoreError> {
        match self
            .op(StoreRequest::Release {
                lease: lease.clone(),
            })
            .await?
        {
            StoreResponse::Done => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    async fn lease(&self, name: &str) -> Result<Option<Lease>, StoreError> {
        match self
            .op(StoreRequest::Lease {
                name: name.to_owned(),
            })
            .await?
        {
            StoreResponse::Lease { lease } => Ok(lease),
            other => Err(unexpected(&other)),
        }
    }

    fn fencing(&self) -> Fencing {
        Fencing::Enforced
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn bundle(cluster: &str, revision: u64, document: serde_json::Value) -> Bundle {
        Bundle {
            format: 1,
            cluster_id: cluster.to_owned(),
            revision,
            sha256: Bundle::digest(&document),
            published_at: String::new(),
            published_by: None,
            rollback_of: None,
            document,
        }
    }

    /// Review findings L4 and L2: the identity is one file, mode 0600, replacing the previous
    /// one atomically; an identity of the earlier layout (PEM files beside `identity.json`)
    /// still loads; the enrolment key is kept until the identity is saved.
    #[test]
    fn the_identity_is_one_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = enrolment_key(dir.path()).unwrap();
        assert_eq!(enrolment_key(dir.path()).unwrap(), key, "kept for a retry");
        let identity = Identity {
            cluster_id: "c1".into(),
            instance: "edge-1".into(),
            not_after: 4_000_000_000,
            ca_pem: "ca".into(),
            cert_pem: "cert".into(),
            key_pem: key,
        };
        identity.save(dir.path()).unwrap();
        assert!(!dir.path().join(ENROLMENT_KEY).exists());
        let loaded = Identity::load(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.cert_pem, "cert");
        assert_eq!(loaded.instance, "edge-1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("identity.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // The earlier layout.
        let old = tempfile::tempdir().unwrap();
        std::fs::write(
            old.path().join("identity.json"),
            br#"{"cluster_id": "c1", "instance": "edge-2", "not_after": 1}"#,
        )
        .unwrap();
        for (name, text) in [("ca.pem", "ca"), ("cert.pem", "c"), ("key.pem", "k")] {
            std::fs::write(old.path().join(name), text).unwrap();
        }
        let loaded = Identity::load(old.path()).unwrap().unwrap();
        assert_eq!(
            (loaded.cert_pem.as_str(), loaded.key_pem.as_str()),
            ("c", "k")
        );
        assert!(
            loaded.expired(2),
            "expired: reported as such, not as unreachable"
        );
        std::fs::remove_file(old.path().join("key.pem")).unwrap();
        assert!(Identity::load(old.path()).is_err());
    }

    #[test]
    fn the_safety_rules_refuse_before_anything_is_tried() {
        let doc = json!({ "routes": {} });
        assert!(refuse(&bundle("c1", 3, doc.clone()), "c1", 2).is_none());
        assert!(
            refuse(&bundle("c2", 3, doc.clone()), "c1", 2)
                .unwrap()
                .contains("cluster `c2`")
        );
        assert!(
            refuse(&bundle("c1", 2, doc.clone()), "c1", 2)
                .unwrap()
                .contains("not newer")
        );
        assert!(
            refuse(&bundle("c1", 1, doc.clone()), "c1", 2)
                .unwrap()
                .contains("not newer")
        );
        assert!(
            refuse(&bundle("c1", 3, json!({})), "c1", 2)
                .unwrap()
                .contains("empty")
        );
        let mut tampered = bundle("c1", 3, doc);
        tampered.document = json!({ "routes": { "x": {} } });
        assert!(refuse(&tampered, "c1", 2).unwrap().contains("SHA-256"));
    }
}
