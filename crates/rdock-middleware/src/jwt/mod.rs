//! `jwt`: verify JSON Web Tokens on ring, with keys from a JWKS URL (fetched in the
//! background), a JWKS file or a shared HMAC secret (M-SEC-01, ADR-0022).
//!
//! Rules from RFC 8725: the configuration fixes the algorithms, each key verifies one
//! algorithm only, `none` does not exist, `iss` and `aud` are checked unless the configuration
//! says `any`, `exp` is required, and `jku`/`x5u` headers are never followed.

mod keys;
mod token;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use pingora::http::RequestHeader;
use rdock_model::middleware::{JwtAlgorithm, JwtConfig, TokenSource};
use serde_json::Value;
use tokio::sync::Notify;

use crate::client::HttpClient;
use crate::{BuildError, Context, Flow, Middleware, Reply};
use keys::Key;
use token::{Invalid, Rules};

/// How long fetched keys are used before they are fetched again (Envoy's `jwt_authn` default).
const JWKS_CACHE: Duration = Duration::from_secs(600);
/// A token with an unknown `kid` triggers an early fetch at most this often.
const EARLY_REFRESH: Duration = Duration::from_secs(30);
/// Wait before fetching again after a failure.
const RETRY: Duration = Duration::from_secs(30);
/// Only the very first requests wait this long for the first key set.
const FIRST_FETCH: Duration = Duration::from_secs(5);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_JWKS: usize = 1024 * 1024;

/// The `jwt` middleware.
#[derive(Debug)]
pub(crate) struct Jwt {
    name: String,
    issuer: Option<String>,
    audiences: Option<Vec<String>>,
    leeway: Duration,
    source: TokenSource,
    claims_to_headers: Vec<(String, HeaderName)>,
    forward_token: bool,
    local: Vec<Key>,
    remote: Option<Arc<Remote>>,
}

/// Keys fetched from `jwks_url`.
#[derive(Debug)]
struct Remote {
    url: url::Url,
    allowed: Vec<JwtAlgorithm>,
    client: Arc<HttpClient>,
    keys: ArcSwap<Vec<Key>>,
    loaded: Notify,
    has_keys: AtomicBool,
    started: AtomicBool,
    /// Shared with the refresh task, which must not keep the rest alive while it waits.
    refresh: Arc<Notify>,
    last_early: Mutex<Option<Instant>>,
}

impl Jwt {
    pub(crate) fn new(
        name: &str,
        config: &JwtConfig,
        client: Arc<HttpClient>,
    ) -> Result<Self, BuildError> {
        let invalid =
            |message: String| BuildError::Invalid(format!("middleware `{name}`: {message}"));
        let mut local = Vec::new();
        if let Some(reference) = &config.hmac_secret {
            let secret = rdock_config::interpolate::expand(reference, &rdock_config::System)
                .map_err(|e| invalid(e.to_string()))?;
            if secret.len() < 32 {
                return Err(invalid(
                    "`hmac_secret` must be at least 32 bytes (RFC 7518 §3.2)".into(),
                ));
            }
            for alg in config.algorithms.iter().filter(|a| a.is_hmac()) {
                local.push(Key::hmac(*alg, secret.as_bytes()));
            }
        }
        let public: Vec<JwtAlgorithm> = config
            .algorithms
            .iter()
            .copied()
            .filter(|a| !a.is_hmac())
            .collect();
        if let Some(file) = &config.jwks_file {
            let text = std::fs::read_to_string(file)
                .map_err(|e| invalid(format!("cannot read `{}`: {e}", file.display())))?;
            let keys = keys::parse_set(&text, &public).map_err(invalid)?;
            if keys.is_empty() {
                return Err(invalid(format!(
                    "`{}` has no key for the listed algorithms",
                    file.display()
                )));
            }
            local.extend(keys);
        }
        let remote = config.jwks_url.as_ref().map(|url| {
            Arc::new(Remote {
                url: url.as_url().clone(),
                allowed: public.clone(),
                client,
                keys: ArcSwap::from_pointee(Vec::new()),
                loaded: Notify::new(),
                has_keys: AtomicBool::new(false),
                started: AtomicBool::new(false),
                refresh: Arc::new(Notify::new()),
                last_early: Mutex::new(None),
            })
        });
        let claims_to_headers = config
            .claims_to_headers
            .iter()
            .map(|(claim, header)| {
                HeaderName::try_from(header.as_str())
                    .map(|h| (claim.clone(), h))
                    .map_err(|_| invalid(format!("`{header}` is not a header name")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            name: name.to_owned(),
            issuer: (config.issuer != "any").then(|| config.issuer.clone()),
            audiences: (!config.audiences.iter().any(|a| a == "any"))
                .then(|| config.audiences.clone()),
            leeway: config.leeway.as_std(),
            source: config.token.clone(),
            claims_to_headers,
            forward_token: config.forward_token,
            local,
            remote,
        })
    }

    /// The token and, for header tokens, the header it came from.
    fn token<'a>(&self, req: &'a RequestHeader) -> Token<'a> {
        let source = &self.source;
        let header = source
            .header
            .as_deref()
            .map_or(http::header::AUTHORIZATION, |h| {
                HeaderName::try_from(h).unwrap_or(http::header::AUTHORIZATION)
            });
        let defaulted =
            source.header.is_none() && source.cookie.is_none() && source.query.is_none();
        if defaulted || source.header.is_some() {
            let values = req.headers.get_all(&header);
            if values.iter().nth(1).is_some() {
                return Token::Repeated;
            }
            if let Some(value) = values.iter().next().and_then(|v| v.to_str().ok()) {
                let token = if header == http::header::AUTHORIZATION {
                    match value
                        .strip_prefix("Bearer ")
                        .or_else(|| value.strip_prefix("bearer "))
                    {
                        Some(token) => token,
                        None => return Token::Missing,
                    }
                } else {
                    value
                };
                return Token::Found(token.trim(), Some(header));
            }
        }
        if let Some(name) = &source.cookie {
            let mut values = crate::limits::cookies(req, name);
            if let Some(value) = values.next() {
                if values.next().is_some() {
                    return Token::Repeated;
                }
                return Token::Found(value, None);
            }
        }
        let (Some(name), Some(query)) = (source.query.as_deref(), req.uri.query()) else {
            return Token::Missing;
        };
        let mut values = query.split('&').filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == name).then_some(v)
        });
        match (values.next(), values.next()) {
            (Some(value), None) => Token::Found(value, None),
            (Some(_), Some(_)) => Token::Repeated,
            (None, _) => Token::Missing,
        }
    }

    async fn keys(&self) -> Vec<Arc<Vec<Key>>> {
        let Some(remote) = &self.remote else {
            return Vec::new();
        };
        remote.start();
        if !remote.has_keys.load(Ordering::Acquire) {
            let loaded = remote.loaded.notified();
            if !remote.has_keys.load(Ordering::Acquire) {
                let _ = tokio::time::timeout(FIRST_FETCH, loaded).await;
            }
        }
        vec![remote.keys.load_full()]
    }
}

impl Remote {
    fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(refresh_loop(weak));
    }

    fn refresh_early(&self) {
        let mut last = self
            .last_early
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_none_or(|t| t.elapsed() >= EARLY_REFRESH) {
            *last = Some(Instant::now());
            self.refresh.notify_one();
        }
    }

    async fn fetch(&self) -> Result<Vec<Key>, String> {
        let peer = self
            .client
            .peer_for(&self.url, FETCH_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        let target = match self.url.query() {
            Some(q) => format!("{}?{q}", self.url.path()),
            None => self.url.path().to_owned(),
        };
        let mut req = RequestHeader::build(http::Method::GET, target.as_bytes(), None)
            .map_err(|e| e.to_string())?;
        let host = self.url.host_str().unwrap_or_default().to_owned();
        req.insert_header(http::header::HOST, host)
            .map_err(|e| e.to_string())?;
        req.insert_header(http::header::ACCEPT, "application/json")
            .map_err(|e| e.to_string())?;
        let reply = self
            .client
            .send(&peer, req, FETCH_TIMEOUT, MAX_JWKS)
            .await
            .map_err(|e| e.to_string())?;
        if reply.header.status != 200 {
            return Err(format!("status {}", reply.header.status.as_u16()));
        }
        let text = std::str::from_utf8(&reply.body).map_err(|e| e.to_string())?;
        keys::parse_set(text, &self.allowed)
    }
}

/// Fetches the key set every [`JWKS_CACHE`], or earlier when asked, until the middleware is
/// gone. A failed fetch keeps the keys already known.
async fn refresh_loop(remote: Weak<Remote>) {
    loop {
        let Some(this) = remote.upgrade() else {
            return;
        };
        let wait = match this.fetch().await {
            Ok(keys) => {
                tracing::debug!(url = %this.url, keys = keys.len(), "fetched the JWT keys");
                this.keys.store(Arc::new(keys));
                this.has_keys.store(true, Ordering::Release);
                this.loaded.notify_waiters();
                JWKS_CACHE
            }
            Err(error) => {
                tracing::warn!(url = %this.url, %error, "cannot fetch the JWT keys");
                this.loaded.notify_waiters();
                RETRY
            }
        };
        // Wait without holding the keys, so a configuration that drops this middleware ends
        // the task at its next wake-up.
        let refresh = this.refresh.clone();
        drop(this);
        let _ = tokio::time::timeout(wait, refresh.notified()).await;
    }
}

/// Where the token of a request is.
enum Token<'a> {
    /// The only token, and for header tokens the header it came from.
    Found(&'a str, Option<HeaderName>),
    /// No token where the middleware looks.
    Missing,
    /// The token header, cookie or query parameter appears more than once.
    Repeated,
}

/// `400` for a request that repeats its token (RFC 6750 §3.1, `invalid_request`).
fn invalid_request() -> Flow {
    Flow::Reply(Reply::status(400).header(
        http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_request\""),
    ))
}

fn unauthorized(error: Option<&str>) -> Flow {
    let challenge = match error {
        None => "Bearer".to_owned(),
        Some(error) => format!("Bearer error=\"{error}\""),
    };
    let mut reply = Reply::status(401);
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        reply = reply.header(http::header::WWW_AUTHENTICATE, value);
    }
    Flow::Reply(reply)
}

/// A claim as header text: strings as they are, other values as JSON, arrays joined by `,`.
fn claim_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(claim_text).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

#[async_trait]
impl Middleware for Jwt {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        // Claim headers are only ever set from a verified token.
        for (_, header) in &self.claims_to_headers {
            req.remove_header(header);
        }
        let (token, header) = match self.token(req) {
            Token::Found(token, header) => (token.to_owned(), header),
            Token::Missing => return unauthorized(None),
            Token::Repeated => {
                // The backend could read another copy than the one verified here.
                tracing::debug!(middleware = %self.name, "JWT refused: more than one token");
                return invalid_request();
            }
        };
        let remote = self.keys().await;
        let keys: Vec<&Key> = self
            .local
            .iter()
            .chain(remote.iter().flat_map(|k| k.iter()))
            .collect();
        let rules = Rules {
            issuer: self.issuer.as_deref(),
            audiences: self.audiences.as_deref(),
            leeway: self.leeway,
            now: SystemTime::now(),
        };
        let claims = match token::verify(&token, &keys, &rules) {
            Ok(claims) => claims,
            Err(why) => {
                if why == Invalid::UnknownKey
                    && let Some(remote) = &self.remote
                {
                    remote.refresh_early();
                }
                tracing::debug!(middleware = %self.name, reason = %why, "JWT refused");
                return unauthorized(Some("invalid_token"));
            }
        };
        for (claim, name) in &self.claims_to_headers {
            if let Some(value) = claims.get(claim)
                && let Ok(value) = HeaderValue::from_str(&claim_text(value))
            {
                let _ = req.insert_header(name.clone(), value);
            }
        }
        if !self.forward_token
            && let Some(header) = header
        {
            req.remove_header(&header);
        }
        if cx.user.is_none() {
            cx.user = claims.get("sub").and_then(Value::as_str).map(str::to_owned);
        }
        cx.claims = Some(Arc::new(claims));
        Flow::Next
    }
}

/// Fuzzing entry point: verifies `token` against a fixed HMAC key and an EC and RSA key set,
/// with `alg`s chosen by the token. It must only ever return.
#[doc(hidden)]
pub fn fuzz_verify(token: &str) {
    use std::sync::OnceLock;
    static KEYS: OnceLock<Vec<Key>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        let set = r#"{"keys":[
            {"kty":"EC","crv":"P-256","kid":"ec","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
            {"kty":"OKP","crv":"Ed25519","kid":"ed","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
            {"kty":"RSA","kid":"rsa","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}
        ]}"#;
        let mut keys = keys::parse_set(set, &[JwtAlgorithm::Es256, JwtAlgorithm::EdDsa, JwtAlgorithm::Rs256, JwtAlgorithm::Ps256])
            .unwrap_or_default();
        keys.push(Key::hmac(JwtAlgorithm::Hs256, b"fuzzing-secret-fuzzing-secret-32"));
        keys
    });
    let refs: Vec<&Key> = keys.iter().collect();
    let audiences = vec!["api".to_owned()];
    let rules = Rules {
        issuer: Some("https://idp.test"),
        audiences: Some(&audiences),
        leeway: Duration::from_secs(60),
        now: SystemTime::now(),
    };
    let _ = token::verify(token, &refs, &rules);
}

#[cfg(test)]
mod tests;
