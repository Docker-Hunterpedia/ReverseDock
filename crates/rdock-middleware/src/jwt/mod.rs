//! `jwt`: verify JSON Web Tokens on ring, with keys from a JWKS URL (fetched in the
//! background), a JWKS file or a shared HMAC secret (M-SEC-01, ADR-0022).
//!
//! Rules from RFC 8725: the configuration fixes the algorithms, each key verifies one
//! algorithm only, `none` does not exist, `iss` and `aud` are checked unless the configuration
//! says `any`, `exp` is required, and `jku`/`x5u` headers are never followed.

pub(crate) mod keys;
pub(crate) mod token;

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
use crate::{BuildError, ConsumerIndex, Context, Flow, Middleware, Reply};
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
#[allow(clippy::struct_excessive_bools)] // independent settings of the configuration
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
    /// `cloudflare_access`: the consumer is the token's `email`, or a service token's
    /// `common_name`.
    access: bool,
    /// The claim that names the consumer, and the one that lists its groups.
    consumer_claim: Option<String>,
    groups_claim: Option<String>,
    /// `trusted_groups`: token groups that count for group keys and overrides.
    trusted_groups: Vec<String>,
    /// `map_to_consumers`: the claim names a consumer of `consumers`.
    map_to_consumers: bool,
    /// `unverified_emails`: an `email` without `email_verified` names the consumer.
    unverified_emails: bool,
    /// The configuration's consumers, for `map_to_consumers`.
    consumers: Arc<ConsumerIndex>,
}

/// The group a Cloudflare Access service token's consumer is in.
pub(crate) const SERVICE_TOKEN_GROUP: &str = "service-token";

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
        consumers: Arc<ConsumerIndex>,
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
            access: false,
            consumer_claim: config.consumer_claim.clone(),
            groups_claim: config.groups_claim.clone(),
            trusted_groups: config.trusted_groups.clone(),
            map_to_consumers: config.map_to_consumers,
            unverified_emails: config.unverified_emails,
            consumers,
        })
    }

    /// The `cloudflare_access` preset (W-CF-06): `jwt` with the team's certs URL, issuer,
    /// RS256 and the Access header, then cookie, and the consumer set from the identity.
    pub(crate) fn cloudflare_access(
        name: &str,
        config: &rdock_model::middleware::CloudflareAccessConfig,
        client: Arc<HttpClient>,
        consumers: Arc<ConsumerIndex>,
    ) -> Result<Self, BuildError> {
        if !config.team_is_valid() {
            return Err(BuildError::Invalid(format!(
                "middleware `{name}`: `{}` is not a Cloudflare Zero Trust team name",
                config.team
            )));
        }
        let jwt = config.to_jwt().ok_or_else(|| {
            BuildError::Invalid(format!("middleware `{name}`: the certs URL is invalid"))
        })?;
        let mut this = Self::new(name, &jwt, client, consumers)?;
        this.access = true;
        Ok(this)
    }

    /// The issuer that namespaces the token's consumer: the configured one, or the token's
    /// `iss` with `issuer: any`, or the middleware's name when the token has none.
    fn token_issuer(&self, claims: &serde_json::Map<String, Value>) -> Arc<str> {
        match (
            self.issuer.as_deref(),
            claims.get("iss").and_then(Value::as_str),
        ) {
            (Some(issuer), _) | (None, Some(issuer)) => Arc::from(issuer),
            (None, None) => Arc::from(format!("jwt:{}", self.name)),
        }
    }

    /// With `map_to_consumers` and a consumer of `consumers` with the same name, adds its
    /// groups and shares its identity; otherwise keys the consumer on the token's issuer, so
    /// it never shares a configured consumer's identity (H1 of the v0.8 review).
    fn place(&self, consumer: &mut crate::Consumer, claims: &serde_json::Map<String, Value>) {
        let defined = self
            .map_to_consumers
            .then(|| self.consumers.consumer(&consumer.name))
            .flatten();
        // Token groups listed in `trusted_groups` count as configured ones; they go first.
        let (mut groups, claimed): (Vec<Arc<str>>, Vec<Arc<str>>) = consumer
            .groups
            .iter()
            .cloned()
            .partition(|g| self.trusted_groups.iter().any(|t| **t == **g));
        let Some(defined) = defined else {
            consumer.issuer = Some(self.token_issuer(claims));
            consumer.trusted_groups = groups.len();
            groups.extend(claimed);
            consumer.groups = Arc::from(groups);
            return;
        };
        consumer.issuer = None;
        // The configured consumer's groups first: they are its primary group.
        let mut ordered: Vec<Arc<str>> = defined.groups.to_vec();
        for group in groups {
            if !ordered.contains(&group) {
                ordered.push(group);
            }
        }
        consumer.trusted_groups = ordered.len();
        for group in claimed {
            if !ordered.contains(&group) {
                ordered.push(group);
            }
        }
        consumer.groups = Arc::from(ordered);
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
        // `url` leaves out the scheme's default port, so this is the authority as it should be.
        let host = match self.url.port() {
            Some(port) => format!("{}:{port}", self.url.host_str().unwrap_or_default()),
            None => self.url.host_str().unwrap_or_default().to_owned(),
        };
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

/// The consumer of a Cloudflare Access token: a user's `email`, or for a service token (whose
/// `sub` is empty) its `common_name`, the Client ID, in the group [`SERVICE_TOKEN_GROUP`].
/// Both are keyed on the team's `issuer`, service tokens on `<issuer> service-token`, so a
/// service token never shares the identity of a user or of a consumer of `consumers`.
fn access_consumer(
    claims: &serde_json::Map<String, Value>,
    issuer: &str,
) -> Option<crate::Consumer> {
    let text = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty())
    };
    if text("sub").is_none()
        && let Some(common_name) = text("common_name")
    {
        return Some(crate::Consumer {
            name: Arc::from(common_name),
            groups: Arc::from([Arc::from(SERVICE_TOKEN_GROUP)]),
            // A fixed group the middleware assigns, not a value of the token.
            trusted_groups: 1,
            issuer: Some(Arc::from(format!("{issuer} {SERVICE_TOKEN_GROUP}"))),
        });
    }
    // Cloudflare Access verifies the address before it issues a user token.
    text("email").map(|email| crate::Consumer {
        issuer: Some(Arc::from(issuer)),
        ..crate::Consumer::named(email)
    })
}

/// The consumer named by `claim` (a non-empty string, or a number), with the groups listed in
/// `groups` (a string or an array of strings). With `claim` `email`, the address counts only
/// with `email_verified: true` (or without `email_verified` when `unverified_emails`), and
/// `sub` names the consumer otherwise. The consumer is not yet placed (`issuer` is `None`).
fn claim_consumer(
    claims: &serde_json::Map<String, Value>,
    claim: &str,
    groups: Option<&str>,
    unverified_emails: bool,
) -> Option<crate::Consumer> {
    let verified = email_verified(claims);
    let claim =
        if claim == "email" && verified != Some(true) && !(unverified_emails && verified.is_none())
        {
            "sub"
        } else {
            claim
        };
    let name = match claims.get(claim)? {
        Value::String(s) if !s.trim().is_empty() => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    let groups: Vec<Arc<str>> = match groups.and_then(|g| claims.get(g)) {
        Some(Value::String(s)) => vec![Arc::from(s.as_str())],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(Arc::from)
            .collect(),
        _ => Vec::new(),
    };
    Some(crate::Consumer {
        name: Arc::from(name.as_str()),
        groups: Arc::from(groups),
        trusted_groups: 0,
        issuer: None,
    })
}

/// The `email_verified` claim: `true`/`false` (also as strings), `None` when absent or of
/// another type.
pub(crate) fn email_verified(claims: &serde_json::Map<String, Value>) -> Option<bool> {
    claims.get("email_verified").and_then(|v| match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => Some(s == "true"),
        _ => None,
    })
}

/// A claim as header text: strings as they are, other values as JSON, arrays joined by `,`.
pub(crate) fn claim_text(value: &Value) -> String {
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
                cx.auth_failed = true;
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
        if self.access {
            let issuer = self.token_issuer(&claims);
            let Some(consumer) = access_consumer(&claims, &issuer) else {
                tracing::debug!(middleware = %self.name, "Access token without email or common_name");
                cx.auth_failed = true;
                return unauthorized(Some("invalid_token"));
            };
            cx.user = Some(consumer.name.to_string());
            cx.consumer = Some(consumer);
        } else if let Some(claim) = &self.consumer_claim {
            let Some(mut consumer) = claim_consumer(
                &claims,
                claim,
                self.groups_claim.as_deref(),
                self.unverified_emails,
            ) else {
                tracing::debug!(middleware = %self.name, claim = %claim, "JWT without the consumer claim");
                cx.auth_failed = true;
                return unauthorized(Some("invalid_token"));
            };
            self.place(&mut consumer, &claims);
            cx.user = Some(consumer.name.to_string());
            cx.consumer = Some(consumer);
        } else if cx.user.is_none() {
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
