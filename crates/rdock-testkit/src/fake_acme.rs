//! A small ACME CA for tests that run without Docker (RFC 8555, the parts instant-acme uses):
//! accounts, orders, HTTP-01 and TLS-ALPN-01 validation, finalisation and download, served over
//! HTTPS on `127.0.0.1:0` with a certificate from a throw-away CA ([`FakeAcme::root_pem`]).
//!
//! It counts what a test needs to count at the CA: orders created per set of names and
//! certificates issued. Validation asks **every** target address for the answer (like a CA
//! with several vantage points that may each reach a different instance) and fails when one
//! of them does not have it, so a test proves that answers were on every instance before the
//! CA was told to validate. JWS signatures are not verified (a test CA, never a real one).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, CertifiedIssuer, KeyPair};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::certs::TestCa;

#[derive(Debug, Clone)]
struct Challenge {
    kind: &'static str,
    token: String,
    status: &'static str,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct Authz {
    name: String,
    status: &'static str,
    challenges: Vec<Challenge>,
    thumbprint: String,
}

#[derive(Debug, Clone)]
struct Order {
    names: Vec<String>,
    status: &'static str,
    authzs: Vec<usize>,
    certificate: Option<String>,
}

#[derive(Default)]
struct State {
    nonce: u64,
    accounts: Vec<String>,
    orders: Vec<Order>,
    authzs: Vec<Authz>,
    certs: Vec<String>,
    /// Orders created, by their names joined with `,`.
    created: BTreeMap<String, usize>,
    /// Certificates issued, by their names joined with `,`.
    issued: BTreeMap<String, usize>,
    targets: Vec<SocketAddr>,
    tls_targets: Vec<SocketAddr>,
    validation_delay: Duration,
    lifetime: Duration,
    failures: Vec<String>,
    /// How the CA's port behaves (the chaos suite).
    mode: CaMode,
    /// The next new-order requests answered with an error: how many, status, `Retry-After`.
    fail_orders: Option<(usize, u16, Option<u64>)>,
    /// HTTP requests received.
    requests: u64,
    /// TCP connections accepted.
    connections: u64,
    /// The tasks serving open connections, cut when the mode changes.
    open: Vec<tokio::task::JoinHandle<()>>,
}

/// How the fake CA's port behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaMode {
    /// Answers.
    #[default]
    Up,
    /// Accepts and closes at once (a CA that is down behind a load balancer).
    Down,
    /// Accepts and never answers (a CA that hangs).
    Hang,
}

/// A running fake ACME CA.
pub struct FakeAcme {
    state: Arc<Mutex<State>>,
    root_pem: String,
    issuing_pem: String,
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeAcme {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeAcme {
    /// Starts the CA. `http_targets` are the addresses HTTP-01 validation fetches from (every
    /// one must answer), `tls_targets` the addresses TLS-ALPN-01 validation connects to.
    pub async fn start(http_targets: Vec<SocketAddr>, tls_targets: Vec<SocketAddr>) -> Self {
        let tls_ca = TestCa::new();
        let dir = tempfile::tempdir().unwrap();
        let server = tls_ca.issue(dir.path(), "acme", &["127.0.0.1", "localhost"]);
        let chain = vec![
            rustls_pki_types::CertificateDer::from_pem_slice(server.cert_pem.as_bytes()).unwrap(),
        ];
        let key =
            rustls_pki_types::PrivateKeyDer::from_pem_slice(server.key_pem.as_bytes()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fake ACME issuing CA");
        let issuer =
            Arc::new(CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap());
        let issuing_pem = issuer.pem();
        let state = Arc::new(Mutex::new(State {
            targets: http_targets,
            tls_targets,
            lifetime: Duration::from_secs(90 * 24 * 3600),
            ..State::default()
        }));
        let shared = state.clone();
        let base = format!("https://{addr}");
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let mode = {
                    let mut state = lock(&shared);
                    state.connections += 1;
                    state.mode
                };
                match mode {
                    CaMode::Up => {}
                    CaMode::Down => {
                        drop(tcp);
                        continue;
                    }
                    CaMode::Hang => {
                        let task = tokio::spawn(async move {
                            let _held = tcp;
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                        });
                        lock(&shared).open.push(task);
                        continue;
                    }
                }
                let (acceptor, state, issuer, base) = (
                    acceptor.clone(),
                    shared.clone(),
                    issuer.clone(),
                    base.clone(),
                );
                let registry = state.clone();
                let task = tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = service_fn(move |request| {
                        let (state, issuer, base) = (state.clone(), issuer.clone(), base.clone());
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                handle(request, &state, &issuer, &base).await,
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
                let mut held = lock(&registry);
                held.open.retain(|t| !t.is_finished());
                held.open.push(task);
            }
        });
        let root_pem = tls_ca.pem();
        drop(dir);
        Self {
            state,
            root_pem,
            issuing_pem,
            addr,
            task,
        }
    }

    /// The directory URL.
    pub fn directory(&self) -> String {
        format!("https://{}/dir", self.addr)
    }

    /// The root that signed the CA's own HTTPS certificate (for `acme.ca_root`).
    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }

    /// The CA certificates are issued from (what a client trusts).
    pub fn issuing_pem(&self) -> &str {
        &self.issuing_pem
    }

    /// Orders created, by their names joined with `,`.
    pub fn orders_created(&self) -> BTreeMap<String, usize> {
        lock(&self.state).created.clone()
    }

    /// Certificates issued, by their names joined with `,`.
    pub fn issued(&self) -> BTreeMap<String, usize> {
        lock(&self.state).issued.clone()
    }

    /// Why validations failed so far.
    pub fn failures(&self) -> Vec<String> {
        lock(&self.state).failures.clone()
    }

    /// Validation starts this long after a challenge is answered (a test kills the instance
    /// that ordered meanwhile).
    pub fn set_validation_delay(&self, delay: Duration) {
        lock(&self.state).validation_delay = delay;
    }

    /// Lifetime of the certificates issued from now on (default 90 days).
    pub fn set_lifetime(&self, lifetime: Duration) {
        lock(&self.state).lifetime = lifetime;
    }

    /// How the CA's port behaves from now on; the connections open now are cut, as when
    /// the CA goes away.
    pub fn set_mode(&self, mode: CaMode) {
        let mut state = lock(&self.state);
        state.mode = mode;
        for task in state.open.drain(..) {
            task.abort();
        }
    }

    /// Answers the next `count` new-order requests with `status` (a `429` or `503` with
    /// `Retry-After: retry_after` seconds when given, as a rate-limited or overloaded CA does).
    pub fn fail_new_orders(&self, count: usize, status: u16, retry_after: Option<u64>) {
        lock(&self.state).fail_orders = Some((count, status, retry_after));
    }

    /// HTTP requests the CA received so far.
    pub fn requests(&self) -> u64 {
        lock(&self.state).requests
    }

    /// TCP connections the CA accepted so far (whatever its mode).
    pub fn connections(&self) -> u64 {
        lock(&self.state).connections
    }

    /// Replaces the addresses validation reaches.
    pub fn set_targets(&self, http: Vec<SocketAddr>, tls: Vec<SocketAddr>) {
        let mut state = lock(&self.state);
        state.targets = http;
        state.tls_targets = tls;
    }
}

fn reply(
    status: StatusCode,
    nonce: u64,
    body: &Value,
    location: Option<String>,
) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(status)
        .header("replay-nonce", format!("n{nonce:016}"))
        .header("cache-control", "no-store");
    builder = builder.header(
        "content-type",
        if status.is_success() {
            "application/json"
        } else {
            "application/problem+json"
        },
    );
    if let Some(location) = location {
        builder = builder.header("location", location);
    }
    builder
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn next_nonce(state: &Mutex<State>) -> u64 {
    let mut state = lock(state);
    state.nonce += 1;
    state.nonce
}

/// RFC 7638 thumbprint of an EC or RSA JWK.
fn thumbprint(jwk: &Value) -> String {
    let canonical = match jwk["kty"].as_str() {
        Some("EC") => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["crv"].as_str().unwrap_or_default(),
            jwk["x"].as_str().unwrap_or_default(),
            jwk["y"].as_str().unwrap_or_default()
        ),
        Some("RSA") => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            jwk["e"].as_str().unwrap_or_default(),
            jwk["n"].as_str().unwrap_or_default()
        ),
        _ => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            jwk["crv"].as_str().unwrap_or_default(),
            jwk["x"].as_str().unwrap_or_default()
        ),
    };
    B64.encode(ring::digest::digest(
        &ring::digest::SHA256,
        canonical.as_bytes(),
    ))
}

fn order_json(order: &Order, base: &str, id: usize) -> Value {
    json!({
        "status": order.status,
        "identifiers": order.names.iter().map(|n| json!({ "type": "dns", "value": n })).collect::<Vec<_>>(),
        "authorizations": order.authzs.iter().map(|a| format!("{base}/authz/{a}")).collect::<Vec<_>>(),
        "finalize": format!("{base}/finalize/{id}"),
        "certificate": order.certificate,
    })
}

fn challenge_json(c: &Challenge, base: &str, authz: usize, index: usize) -> Value {
    let mut value = json!({
        "type": c.kind,
        "url": format!("{base}/chall/{authz}/{index}"),
        "token": c.token,
        "status": c.status,
    });
    if let Some(error) = &c.error {
        value["error"] =
            json!({ "type": "urn:ietf:params:acme:error:unauthorized", "detail": error });
    }
    value
}

fn authz_json(a: &Authz, base: &str, id: usize) -> Value {
    json!({
        "identifier": { "type": "dns", "value": a.name },
        "status": a.status,
        "challenges": a.challenges.iter().enumerate().map(|(i, c)| challenge_json(c, base, id, i)).collect::<Vec<_>>(),
    })
}

fn token() -> String {
    let mut bytes = [0u8; 24];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).unwrap();
    B64.encode(bytes)
}

#[allow(clippy::too_many_lines)]
async fn handle(
    request: Request<Incoming>,
    state: &Arc<Mutex<State>>,
    issuer: &Arc<CertifiedIssuer<'static, KeyPair>>,
    base: &str,
) -> Response<Full<Bytes>> {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let nonce = next_nonce(state);
    lock(state).requests += 1;
    if path == "/dir" {
        return reply(
            StatusCode::OK,
            nonce,
            &json!({
                "newNonce": format!("{base}/nonce"),
                "newAccount": format!("{base}/account/new"),
                "newOrder": format!("{base}/order/new"),
                "revokeCert": format!("{base}/revoke"),
                "keyChange": format!("{base}/key-change"),
            }),
            None,
        );
    }
    if path == "/nonce" {
        let mut response = reply(StatusCode::OK, nonce, &json!({}), None);
        if method == Method::HEAD {
            *response.body_mut() = Full::new(Bytes::new());
        }
        return response;
    }
    let body = request
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    let jws: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let protected: Value = jws["protected"]
        .as_str()
        .and_then(|p| B64.decode(p).ok())
        .and_then(|p| serde_json::from_slice(&p).ok())
        .unwrap_or(Value::Null);
    let payload: Value = jws["payload"]
        .as_str()
        .filter(|p| !p.is_empty())
        .and_then(|p| B64.decode(p).ok())
        .and_then(|p| serde_json::from_slice(&p).ok())
        .unwrap_or(Value::Null);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let mut s = lock(state);
    match parts.as_slice() {
        ["account", "new"] => {
            let thumb = thumbprint(&protected["jwk"]);
            s.accounts.push(thumb);
            let id = s.accounts.len() - 1;
            reply(
                StatusCode::CREATED,
                nonce,
                &json!({ "status": "valid", "contact": payload["contact"] }),
                Some(format!("{base}/account/{id}")),
            )
        }
        ["order", "new"] if s.fail_orders.is_some_and(|(n, _, _)| n > 0) => {
            let Some((count, status, retry_after)) = s.fail_orders else {
                unreachable!()
            };
            s.fail_orders = Some((count - 1, status, retry_after));
            let status = StatusCode::from_u16(status).unwrap();
            let kind = if status == StatusCode::TOO_MANY_REQUESTS {
                "urn:ietf:params:acme:error:rateLimited"
            } else {
                "urn:ietf:params:acme:error:serverInternal"
            };
            let mut response = reply(
                status,
                nonce,
                &json!({ "type": kind, "detail": "the fake CA refuses this order", "status": status.as_u16() }),
                None,
            );
            if let Some(seconds) = retry_after {
                response
                    .headers_mut()
                    .insert("retry-after", seconds.to_string().parse().unwrap());
            }
            response
        }
        ["order", "new"] => {
            let account: usize = protected["kid"]
                .as_str()
                .and_then(|k| k.rsplit('/').next())
                .and_then(|k| k.parse().ok())
                .unwrap_or(0);
            let thumb = s.accounts.get(account).cloned().unwrap_or_default();
            let names: Vec<String> = payload["identifiers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i["value"].as_str().map(str::to_owned))
                .collect();
            let mut authzs = Vec::new();
            for name in &names {
                s.authzs.push(Authz {
                    name: name.clone(),
                    status: "pending",
                    challenges: vec![
                        Challenge {
                            kind: "http-01",
                            token: token(),
                            status: "pending",
                            error: None,
                        },
                        Challenge {
                            kind: "tls-alpn-01",
                            token: token(),
                            status: "pending",
                            error: None,
                        },
                    ],
                    thumbprint: thumb.clone(),
                });
                authzs.push(s.authzs.len() - 1);
            }
            *s.created.entry(names.join(",")).or_default() += 1;
            s.orders.push(Order {
                names,
                status: "pending",
                authzs,
                certificate: None,
            });
            let id = s.orders.len() - 1;
            let order = s.orders[id].clone();
            reply(
                StatusCode::CREATED,
                nonce,
                &order_json(&order, base, id),
                Some(format!("{base}/order/{id}")),
            )
        }
        ["order", id] => match id
            .parse::<usize>()
            .ok()
            .and_then(|i| s.orders.get(i).cloned().map(|o| (i, o)))
        {
            Some((i, order)) => reply(StatusCode::OK, nonce, &order_json(&order, base, i), None),
            None => reply(
                StatusCode::NOT_FOUND,
                nonce,
                &json!({ "type": "urn:ietf:params:acme:error:malformed", "detail": "no such order" }),
                None,
            ),
        },
        ["authz", id] => match id
            .parse::<usize>()
            .ok()
            .and_then(|i| s.authzs.get(i).cloned().map(|a| (i, a)))
        {
            Some((i, authz)) => reply(StatusCode::OK, nonce, &authz_json(&authz, base, i), None),
            None => reply(
                StatusCode::NOT_FOUND,
                nonce,
                &json!({ "type": "urn:ietf:params:acme:error:malformed" }),
                None,
            ),
        },
        ["chall", authz, index] => {
            let (Ok(authz), Ok(index)) = (authz.parse::<usize>(), index.parse::<usize>()) else {
                return reply(StatusCode::NOT_FOUND, nonce, &json!({}), None);
            };
            let Some(a) = s.authzs.get_mut(authz) else {
                return reply(StatusCode::NOT_FOUND, nonce, &json!({}), None);
            };
            let Some(c) = a.challenges.get_mut(index) else {
                return reply(StatusCode::NOT_FOUND, nonce, &json!({}), None);
            };
            if c.status == "pending" && payload.is_object() {
                c.status = "processing";
                let (kind, token, name, thumb) = (
                    c.kind,
                    c.token.clone(),
                    a.name.clone(),
                    a.thumbprint.clone(),
                );
                let shared = state.clone();
                tokio::spawn(async move {
                    validate(shared, authz, index, kind, token, name, thumb).await;
                });
            }
            let c = s.authzs[authz].challenges[index].clone();
            reply(
                StatusCode::OK,
                nonce,
                &challenge_json(&c, base, authz, index),
                None,
            )
        }
        ["finalize", id] => {
            let Some(i) = id.parse::<usize>().ok().filter(|i| *i < s.orders.len()) else {
                return reply(StatusCode::NOT_FOUND, nonce, &json!({}), None);
            };
            if s.orders[i].status != "ready" {
                return reply(
                    StatusCode::FORBIDDEN,
                    nonce,
                    &json!({ "type": "urn:ietf:params:acme:error:orderNotReady", "detail": "not ready" }),
                    None,
                );
            }
            let csr = payload["csr"]
                .as_str()
                .and_then(|c| B64.decode(c).ok())
                .unwrap_or_default();
            let der = rustls_pki_types::CertificateSigningRequestDer::from(csr);
            let Ok(mut params) = rcgen::CertificateSigningRequestParams::from_der(&der) else {
                return reply(
                    StatusCode::BAD_REQUEST,
                    nonce,
                    &json!({ "type": "urn:ietf:params:acme:error:badCSR" }),
                    None,
                );
            };
            let now = time::OffsetDateTime::now_utc();
            params.params.not_before = now - time::Duration::seconds(1);
            params.params.not_after =
                now + time::Duration::try_from(s.lifetime).unwrap_or(time::Duration::days(90));
            let Ok(cert) = params.signed_by(issuer) else {
                return reply(
                    StatusCode::BAD_REQUEST,
                    nonce,
                    &json!({ "type": "urn:ietf:params:acme:error:badCSR" }),
                    None,
                );
            };
            s.certs.push(format!("{}{}", cert.pem(), issuer.pem()));
            let cert_id = s.certs.len() - 1;
            let key = s.orders[i].names.join(",");
            *s.issued.entry(key).or_default() += 1;
            s.orders[i].status = "valid";
            s.orders[i].certificate = Some(format!("{base}/cert/{cert_id}"));
            let order = s.orders[i].clone();
            reply(
                StatusCode::OK,
                nonce,
                &order_json(&order, base, i),
                Some(format!("{base}/order/{i}")),
            )
        }
        ["cert", id] => match id
            .parse::<usize>()
            .ok()
            .and_then(|i| s.certs.get(i).cloned())
        {
            Some(pem) => Response::builder()
                .status(StatusCode::OK)
                .header("replay-nonce", format!("n{nonce:016}"))
                .header("content-type", "application/pem-certificate-chain")
                .body(Full::new(Bytes::from(pem)))
                .unwrap(),
            None => reply(StatusCode::NOT_FOUND, nonce, &json!({}), None),
        },
        ["account", _] => reply(StatusCode::OK, nonce, &json!({ "status": "valid" }), None),
        _ => reply(
            StatusCode::NOT_FOUND,
            nonce,
            &json!({ "type": "urn:ietf:params:acme:error:malformed", "detail": "no such resource" }),
            None,
        ),
    }
}

async fn validate(
    state: Arc<Mutex<State>>,
    authz: usize,
    index: usize,
    kind: &'static str,
    token: String,
    name: String,
    thumbprint: String,
) {
    let (delay, http, tls) = {
        let s = lock(&state);
        (s.validation_delay, s.targets.clone(), s.tls_targets.clone())
    };
    tokio::time::sleep(delay).await;
    let key_authorization = format!("{token}.{thumbprint}");
    let mut error = None;
    if kind == "http-01" {
        for target in &http {
            match fetch_http01(*target, &name, &token).await {
                Ok(body) if body.trim() == key_authorization => {}
                Ok(body) => error = Some(format!("{target}: wrong answer `{body}`")),
                Err(e) => error = Some(format!("{target}: {e}")),
            }
        }
    } else {
        let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
        for target in &tls {
            if let Err(e) = check_tls_alpn01(*target, &name, digest.as_ref()).await {
                error = Some(format!("{target}: {e}"));
            }
        }
    }
    let mut s = lock(&state);
    if let Some(e) = &error {
        s.failures.push(format!("{name} {kind}: {e}"));
    }
    let Some(a) = s.authzs.get_mut(authz) else {
        return;
    };
    a.challenges[index].status = if error.is_none() { "valid" } else { "invalid" };
    a.challenges[index].error.clone_from(&error);
    a.status = if error.is_none() { "valid" } else { "invalid" };
    let orders: Vec<usize> = (0..s.orders.len())
        .filter(|o| s.orders[*o].authzs.contains(&authz))
        .collect();
    for o in orders {
        let statuses: Vec<&str> = s.orders[o]
            .authzs
            .iter()
            .map(|a| s.authzs[*a].status)
            .collect();
        if statuses.contains(&"invalid") {
            s.orders[o].status = "invalid";
        } else if statuses.iter().all(|st| *st == "valid") && s.orders[o].status == "pending" {
            s.orders[o].status = "ready";
        }
    }
}

/// Connects to a validation target. A refused connection is retried for a while: it means the
/// instance is not listening yet, which says nothing about whether the answer was replicated.
/// An instance that listens and lacks the answer fails the validation: a cluster member copies
/// the answers in the store before its listeners accept.
async fn connect(target: SocketAddr) -> Result<tokio::net::TcpStream, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let attempt = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(target),
        )
        .await
        .map_err(|_| "connect timed out".to_owned())?;
        match attempt {
            Ok(tcp) => return Ok(tcp),
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

async fn fetch_http01(target: SocketAddr, host: &str, token: &str) -> Result<String, String> {
    let tcp = connect(target).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(connection);
    let request = Request::get(format!("/.well-known/acme-challenge/{token}"))
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    if status != StatusCode::OK {
        return Err(format!("status {status}"));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Accepts any certificate: a TLS-ALPN-01 validation certificate is self-signed by design.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    // webpki refuses the critical acmeIdentifier extension, so signatures are not checked
    // through it; a test CA only reads the certificate.
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn check_tls_alpn01(target: SocketAddr, name: &str, digest: &[u8]) -> Result<(), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = connect(target).await?;
    let server_name =
        rustls_pki_types::ServerName::try_from(name.to_owned()).map_err(|e| e.to_string())?;
    let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .map_err(|_| "handshake timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    let (_, connection) = tls.get_ref();
    let leaf = connection
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or("no certificate")?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|e| e.to_string())?;
    let acme_identifier = x509_parser::der_parser::oid!(1.3.6.1.5.5.7.1.31);
    let extension = cert
        .extensions()
        .iter()
        .find(|e| e.oid == acme_identifier)
        .ok_or("no acmeIdentifier extension")?;
    // An OCTET STRING of 32 bytes: 0x04 0x20 and the digest.
    if extension.value.len() == 34 && extension.value[2..] == *digest {
        Ok(())
    } else {
        Err("the acmeIdentifier does not match".to_owned())
    }
}

use rustls_pki_types::pem::PemObject as _;
