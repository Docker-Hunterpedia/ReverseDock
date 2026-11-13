//! The OpenID provider as seen from the data plane: its discovery document and signing keys,
//! fetched lazily and refreshed in the background (so a reload never waits for the provider,
//! ADR-0009/0012), and its token endpoint.
//!
//! Every request goes through the shared [`HttpClient`]; the address actually connected is
//! checked against private ranges unless `allow_private_targets` is on, and redirects are
//! never followed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use pingora::http::RequestHeader;
use rdock_model::middleware::JwtAlgorithm;
use serde::Deserialize;
use tokio::sync::Notify;
use url::Url;

use crate::client::HttpClient;
use crate::jwt::keys::{self, Key};

/// Keys are fetched again after this long.
const JWKS_EVERY: Duration = Duration::from_secs(600);
/// The discovery document is fetched again after this long.
const DISCOVERY_EVERY: Duration = Duration::from_secs(3600);
/// Wait after a failed fetch.
const RETRY: Duration = Duration::from_secs(30);
/// An unknown key ID triggers a fetch at most this often.
const EARLY_REFRESH: Duration = Duration::from_secs(30);
/// Time for one request to the provider.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);
/// Largest discovery document, key set or token response read.
const MAX_BODY: usize = 1024 * 1024;

/// Algorithms an ID token may use without explicit configuration (no `none`, no HMAC).
pub(crate) const SAFE: [JwtAlgorithm; 9] = [
    JwtAlgorithm::Rs256,
    JwtAlgorithm::Rs384,
    JwtAlgorithm::Rs512,
    JwtAlgorithm::Ps256,
    JwtAlgorithm::Ps384,
    JwtAlgorithm::Ps512,
    JwtAlgorithm::Es256,
    JwtAlgorithm::Es384,
    JwtAlgorithm::EdDsa,
];

/// What the provider published.
#[derive(Debug)]
pub(crate) struct Discovered {
    /// The issuer as the provider writes it (the expected `iss`).
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: Url,
    pub(crate) token_endpoint: Url,
    pub(crate) end_session_endpoint: Option<Url>,
    jwks_uri: Url,
    /// Advertised ID-token algorithms that are also configured.
    pub(crate) algorithms: Vec<JwtAlgorithm>,
    /// Signing keys for those algorithms.
    pub(crate) keys: Vec<Key>,
    fetched: Instant,
}

#[derive(Deserialize)]
struct Document {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    end_session_endpoint: Option<String>,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
}

/// Why a request to the provider failed. The text goes to logs; it never names a secret.
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum ProviderError {
    #[error("{0}")]
    Fetch(String),
    #[error("refused: {0} resolves to a private address; set allow_private_targets: true")]
    Private(String),
    #[error("status {0}")]
    Status(u16),
    #[error("{0}")]
    Invalid(String),
}

/// One provider for one middleware, kept across reloads while the configuration is the same.
pub(crate) struct Provider {
    pub(crate) middleware: Arc<str>,
    issuer: Url,
    client: Arc<HttpClient>,
    allow_private: bool,
    algorithms: Vec<JwtAlgorithm>,
    current: ArcSwapOption<Discovered>,
    started: AtomicBool,
    loaded: Notify,
    refresh: Arc<Notify>,
    last_early: Mutex<Option<Instant>>,
    metrics: Option<rdock_observability::Metrics>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("issuer", &self.issuer.as_str())
            .field("loaded", &self.current.load().is_some())
            .finish_non_exhaustive()
    }
}

type Registry = Mutex<HashMap<String, Weak<Provider>>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}

impl Provider {
    /// The provider of middleware `name`: the one the previous configuration used when its
    /// settings are unchanged (so a reload keeps the fetched keys), otherwise a new one.
    pub(crate) fn shared(
        name: &str,
        issuer: &Url,
        allow_private: bool,
        algorithms: &[JwtAlgorithm],
        client: Arc<HttpClient>,
        metrics: Option<rdock_observability::Metrics>,
    ) -> Arc<Self> {
        let algs: Vec<&str> = algorithms.iter().map(|a| a.name()).collect();
        let key = format!("{name}\0{issuer}\0{allow_private}\0{}", algs.join(","));
        let mut map = registry().lock().unwrap_or_else(PoisonError::into_inner);
        map.retain(|_, weak| weak.strong_count() > 0);
        if let Some(existing) = map.get(&key).and_then(Weak::upgrade) {
            return existing;
        }
        let provider = Arc::new(Self {
            middleware: Arc::from(name),
            issuer: issuer.clone(),
            client,
            allow_private,
            algorithms: algorithms
                .iter()
                .copied()
                .filter(|a| !a.is_hmac())
                .collect(),
            current: ArcSwapOption::empty(),
            started: AtomicBool::new(false),
            loaded: Notify::new(),
            refresh: Arc::new(Notify::new()),
            last_early: Mutex::new(None),
            metrics,
        });
        map.insert(key, Arc::downgrade(&provider));
        provider
    }

    fn count_error(&self, operation: &str) {
        if let Some(m) = &self.metrics {
            m.oidc_provider_errors
                .with_label_values(&[&*self.middleware, operation])
                .inc();
        }
    }

    /// What the provider published, waiting at most `wait` for the first fetch.
    pub(crate) async fn ready(self: &Arc<Self>, wait: Duration) -> Option<Arc<Discovered>> {
        self.start();
        if let Some(current) = self.current.load_full() {
            return Some(current);
        }
        let loaded = self.loaded.notified();
        if let Some(current) = self.current.load_full() {
            return Some(current);
        }
        let _ = tokio::time::timeout(wait, loaded).await;
        self.current.load_full()
    }

    /// What is known now, without waiting.
    pub(crate) fn known(&self) -> Option<Arc<Discovered>> {
        self.current.load_full()
    }

    fn start(self: &Arc<Self>) {
        if !self.started.swap(true, Ordering::AcqRel) {
            tokio::spawn(refresh_loop(Arc::downgrade(self)));
        }
    }

    /// Asks for an early key fetch (an ID token named an unknown key).
    pub(crate) fn refresh_early(&self) {
        let mut last = self
            .last_early
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_none_or(|t| t.elapsed() >= EARLY_REFRESH) {
            *last = Some(Instant::now());
            self.refresh.notify_one();
        }
    }

    /// The well-known URL: the issuer with `/.well-known/openid-configuration` appended to
    /// its path (OpenID Connect Discovery §4.1).
    fn discovery_url(&self) -> Url {
        let mut url = self.issuer.clone();
        let path = format!(
            "{}/.well-known/openid-configuration",
            url.path().trim_end_matches('/')
        );
        url.set_path(&path);
        url
    }

    /// Whether `issuer` from the document is the configured issuer (exactly, allowing only
    /// the trailing `/` a bare host gains when parsed).
    fn same_issuer(&self, issuer: &str) -> bool {
        let configured = self.issuer.as_str();
        issuer == configured || (self.issuer.path() == "/" && format!("{issuer}/") == configured)
    }

    /// An endpoint from the document: https, or http to a loopback address.
    fn endpoint(name: &str, value: &str) -> Result<Url, ProviderError> {
        let url = Url::parse(value)
            .map_err(|_| ProviderError::Invalid(format!("`{name}` is not a URL")))?;
        let loopback = match url.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if url.scheme() == "https" || (url.scheme() == "http" && loopback) {
            Ok(url)
        } else {
            Err(ProviderError::Invalid(format!(
                "`{name}` must be an https:// URL"
            )))
        }
    }

    async fn fetch_discovery(&self) -> Result<Document, ProviderError> {
        let url = self.discovery_url();
        let body = self.get(&url).await?;
        let doc: Document = serde_json::from_slice(&body).map_err(|e| {
            ProviderError::Invalid(format!("not an OpenID provider configuration: {e}"))
        })?;
        if !self.same_issuer(&doc.issuer) {
            return Err(ProviderError::Invalid(
                "the document's `issuer` is not the configured issuer".to_owned(),
            ));
        }
        if let Some(methods) = &doc.code_challenge_methods_supported
            && !methods.iter().any(|m| m == "S256")
        {
            tracing::warn!(middleware = %self.middleware, "the provider does not advertise PKCE S256; rdock sends it anyway");
        }
        Ok(doc)
    }

    async fn load(
        &self,
        previous: Option<&Discovered>,
    ) -> Result<Discovered, (ProviderError, &'static str)> {
        let reuse = previous.filter(|p| p.fetched.elapsed() < DISCOVERY_EVERY);
        let (issuer, authorization, token, end_session, jwks_uri, algorithms) =
            if let Some(p) = reuse {
                (
                    p.issuer.clone(),
                    p.authorization_endpoint.clone(),
                    p.token_endpoint.clone(),
                    p.end_session_endpoint.clone(),
                    p.jwks_uri.clone(),
                    p.algorithms.clone(),
                )
            } else {
                {
                    let doc = self.fetch_discovery().await.map_err(|e| (e, "discovery"))?;
                    let checked = (|| {
                        let authorization =
                            Self::endpoint("authorization_endpoint", &doc.authorization_endpoint)?;
                        let token = Self::endpoint("token_endpoint", &doc.token_endpoint)?;
                        let jwks = Self::endpoint("jwks_uri", &doc.jwks_uri)?;
                        let end = match &doc.end_session_endpoint {
                            Some(v) => Some(Self::endpoint("end_session_endpoint", v)?),
                            None => None,
                        };
                        let algorithms: Vec<JwtAlgorithm> = self
                            .algorithms
                            .iter()
                            .copied()
                            .filter(|a| {
                                doc.id_token_signing_alg_values_supported
                                    .iter()
                                    .any(|n| n == a.name())
                            })
                            .collect();
                        Ok::<_, ProviderError>((authorization, token, jwks, end, algorithms))
                    })()
                    .map_err(|e| (e, "discovery"))?;
                    (
                        doc.issuer, checked.0, checked.1, checked.3, checked.2, checked.4,
                    )
                }
            };
        let body = self.get(&jwks_uri).await.map_err(|e| (e, "jwks"))?;
        let text = std::str::from_utf8(&body).map_err(|_| {
            (
                ProviderError::Invalid("the key set is not UTF-8".to_owned()),
                "jwks",
            )
        })?;
        let keys =
            keys::parse_set(text, &algorithms).map_err(|e| (ProviderError::Invalid(e), "jwks"))?;
        Ok(Discovered {
            issuer,
            authorization_endpoint: authorization,
            token_endpoint: token,
            end_session_endpoint: end_session,
            jwks_uri,
            algorithms,
            keys,
            fetched: reuse.map_or_else(Instant::now, |p| p.fetched),
        })
    }

    /// A peer for `url`, refused when it resolves to a private address and that is not
    /// allowed.
    async fn peer(&self, url: &Url) -> Result<pingora::upstreams::peer::HttpPeer, ProviderError> {
        let peer = self
            .client
            .peer_for(url, TIMEOUT)
            .await
            .map_err(|e| ProviderError::Fetch(e.to_string()))?;
        let private = peer
            ._address
            .as_inet()
            .is_some_and(|a| rdock_observability::is_private_address(a.ip()));
        if !self.allow_private && private {
            return Err(ProviderError::Private(
                url.host_str().unwrap_or_default().to_owned(),
            ));
        }
        Ok(peer)
    }

    fn head(method: http::Method, url: &Url) -> Result<RequestHeader, ProviderError> {
        let target = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        let mut req = RequestHeader::build(method, target.as_bytes(), None)
            .map_err(|e| ProviderError::Fetch(e.to_string()))?;
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let fail = |e: Box<pingora::Error>| ProviderError::Fetch(e.to_string());
        req.insert_header(http::header::HOST, host).map_err(fail)?;
        req.insert_header(http::header::ACCEPT, "application/json")
            .map_err(fail)?;
        req.insert_header(
            http::header::USER_AGENT,
            concat!("rdock/", env!("CARGO_PKG_VERSION")),
        )
        .map_err(fail)?;
        Ok(req)
    }

    async fn get(&self, url: &Url) -> Result<Bytes, ProviderError> {
        let peer = self.peer(url).await?;
        let req = Self::head(http::Method::GET, url)?;
        let reply = self
            .client
            .send(&peer, req, TIMEOUT, MAX_BODY)
            .await
            .map_err(|e| ProviderError::Fetch(e.to_string()))?;
        if reply.header.status != 200 {
            return Err(ProviderError::Status(reply.header.status.as_u16()));
        }
        Ok(reply.body)
    }

    /// POSTs a form to the token endpoint and returns the status and the JSON body.
    pub(crate) async fn token_request(
        &self,
        endpoint: &Url,
        form: &str,
        basic: Option<&str>,
        operation: &'static str,
    ) -> Result<serde_json::Value, ProviderError> {
        let result = async {
            let peer = self.peer(endpoint).await?;
            let mut req = Self::head(http::Method::POST, endpoint)?;
            let fail = |e: Box<pingora::Error>| ProviderError::Fetch(e.to_string());
            req.insert_header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .map_err(fail)?;
            req.insert_header(http::header::CONTENT_LENGTH, form.len())
                .map_err(fail)?;
            req.insert_header(http::header::CACHE_CONTROL, "no-store")
                .map_err(fail)?;
            if let Some(basic) = basic {
                req.insert_header(http::header::AUTHORIZATION, basic)
                    .map_err(fail)?;
            }
            let (reply, _) = self
                .client
                .send_with_body(
                    &peer,
                    req,
                    Bytes::copy_from_slice(form.as_bytes()),
                    TIMEOUT,
                    MAX_BODY,
                )
                .await
                .map_err(|e| ProviderError::Fetch(e.to_string()))?;
            let status = reply.header.status.as_u16();
            let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap_or_default();
            if status != 200 {
                // `error` is a registered code (RFC 6749 §5.2); keep only its safe characters.
                let code: String = body
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .take(64)
                    .collect();
                return Err(ProviderError::Invalid(format!("status {status} {code}")));
            }
            Ok(body)
        }
        .await;
        if result.is_err() {
            self.count_error(operation);
        }
        result
    }
}

/// Fetches the document and keys until the provider is dropped: keys every
/// [`JWKS_EVERY`] (or early on request), the document every [`DISCOVERY_EVERY`]. A failed fetch
/// keeps what is known.
async fn refresh_loop(provider: Weak<Provider>) {
    loop {
        let Some(this) = provider.upgrade() else {
            return;
        };
        let previous = this.current.load_full();
        let wait = match this.load(previous.as_deref()).await {
            Ok(found) => {
                if found.algorithms.is_empty() {
                    tracing::warn!(middleware = %this.middleware, "the provider advertises none of the configured ID-token algorithms");
                }
                tracing::debug!(middleware = %this.middleware, keys = found.keys.len(), "fetched the OpenID provider configuration");
                this.current.store(Some(Arc::new(found)));
                this.loaded.notify_waiters();
                JWKS_EVERY
            }
            Err((error, operation)) => {
                tracing::warn!(middleware = %this.middleware, operation, %error, "cannot read the OpenID provider");
                this.count_error(operation);
                this.loaded.notify_waiters();
                RETRY
            }
        };
        let refresh = this.refresh.clone();
        drop(this);
        let _ = tokio::time::timeout(wait, refresh.notified()).await;
    }
}
