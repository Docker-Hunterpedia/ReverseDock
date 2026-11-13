//! `oidc`: an OpenID Connect relying party for browsers (F-GW-01, ADR-0030).
//!
//! The authorization code flow with PKCE (S256) always on, `state` and `nonce`, the ID-token
//! checks of OpenID Connect Core §3.1.3.7 on the ring JWT code shared with `jwt`, and a
//! stateless session in a sealed cookie (see [`cookie`]). Requests that are not page
//! navigations get `401` instead of a redirect. The backend never sees rdock's cookies, and
//! client-sent copies of the identity headers are removed before they are set.

pub(crate) mod cookie;
mod provider;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::{HeaderName, HeaderValue};
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_model::middleware::JwtAlgorithm;
use rdock_model::oidc::{OidcConfig, OidcSameSite, TokenEndpointAuth, Unauthenticated};
use ring::rand::SystemRandom;
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;
use tokio::sync::OnceCell;

use crate::jwt::keys::Key;
use crate::jwt::token::{self, Invalid, Rules};
use crate::{
    BuildError, Capabilities, ConsumerIndex, Context, Flow, Middleware, ProblemKind, Reply,
};
use cookie::{LoginState, Purpose, Sealer, Session};
use provider::{Discovered, Provider};

/// How long a login may take, from the redirect to the provider to the callback.
const LOGIN_TTL: u64 = 600;
/// Logins in progress at once per browser; older state cookies are dropped.
const MAX_LOGINS: usize = 4;
/// How long a request waits for the provider's configuration before answering `503`.
const PROVIDER_WAIT: Duration = Duration::from_secs(3);
/// Refresh this long before the tokens expire.
const REFRESH_EARLY: u64 = 30;
/// Refresh results are shared by parallel requests for this long.
const REFRESH_SHARED: Duration = Duration::from_secs(30);
/// Header the access token is passed in with `forward_access_token`.
const ACCESS_TOKEN_HEADER: &str = "x-forwarded-access-token";
/// Longest post-login target kept.
const MAX_TARGET: usize = 2048;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One refresh in flight or just finished, shared by requests with the same refresh token.
type Refreshing = HashMap<[u8; 32], (Instant, Arc<OnceCell<Option<Session>>>)>;

/// The `oidc` middleware.
#[allow(clippy::struct_excessive_bools)] // independent settings of the configuration
pub(crate) struct Oidc {
    name: Arc<str>,
    provider: Arc<Provider>,
    client_id: String,
    client_secret: Option<String>,
    token_auth: TokenEndpointAuth,
    scopes: String,
    callback_path: String,
    redirect_url: Option<String>,
    logout_path: String,
    post_logout_path: String,
    cookie_base: String,
    state_prefix: String,
    session_attributes: String,
    state_attributes: String,
    session: Sealer,
    state: Sealer,
    ttl: u64,
    refresh: bool,
    secure: bool,
    claims_to_headers: Vec<(String, HeaderName)>,
    consumer_claim: String,
    /// `map_to_consumers`: the consumer is a consumer of `consumers`.
    map_to_consumers: bool,
    /// The configured issuer, which namespaces the consumer otherwise.
    issuer: Arc<str>,
    groups_claim: String,
    allowed_emails: Vec<String>,
    allowed_domains: Vec<String>,
    allowed_groups: Vec<String>,
    unverified_emails: bool,
    unauthenticated: Unauthenticated,
    forward_access_token: bool,
    hmac_keys: Vec<Key>,
    leeway: Duration,
    hosts: Vec<String>,
    consumers: Arc<ConsumerIndex>,
    metrics: Option<rdock_observability::Metrics>,
    random: SystemRandom,
    refreshing: Mutex<Refreshing>,
}

impl std::fmt::Debug for Oidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oidc")
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Cookies to set on the response after a refresh.
struct SetCookies(Vec<HeaderValue>);

/// Resolves a secret reference (`${file:…}`, `${env:…}`, `${vault:…}`).
fn resolve(reference: &str) -> Result<String, String> {
    rdock_config::interpolate::expand(reference, &rdock_config::System)
        .map(std::borrow::Cow::into_owned)
        .map_err(|e| e.to_string())
}

impl Oidc {
    #[allow(clippy::too_many_lines)] // one field after another
    pub(crate) fn new(
        name: &str,
        config: &OidcConfig,
        env: &crate::BuildEnv<'_>,
    ) -> Result<Self, BuildError> {
        let invalid =
            |message: String| BuildError::Invalid(format!("middleware `{name}`: {message}"));
        let mut secrets: Vec<Vec<u8>> = Vec::new();
        for reference in config.key_references() {
            secrets.push(resolve(&reference).map_err(invalid)?.into_bytes());
        }
        if let Some(file) = &config.session.key_file {
            let text = std::fs::read_to_string(file)
                .map_err(|e| invalid(format!("cannot read `{}`: {e}", file.display())))?;
            secrets.push(text.trim_end_matches(['\r', '\n']).as_bytes().to_vec());
        }
        if secrets.is_empty() {
            return Err(invalid("`session.key` is required".to_owned()));
        }
        if secrets.iter().any(|s| s.len() < cookie::MIN_KEY) {
            return Err(invalid(format!(
                "a session key must be at least {} bytes (e.g. `openssl rand -base64 48`)",
                cookie::MIN_KEY
            )));
        }
        let binding = format!("{}\0{}", config.issuer, config.client_id);
        let session = Sealer::new(&secrets, Purpose::Session, &binding)
            .ok_or_else(|| invalid("cannot derive the session keys".to_owned()))?;
        let state = Sealer::new(&secrets, Purpose::State, &binding)
            .ok_or_else(|| invalid("cannot derive the state keys".to_owned()))?;
        let client_secret = match &config.client_secret {
            Some(reference) => Some(resolve(reference).map_err(invalid)?.trim().to_owned()),
            None => None,
        };
        let mut hmac_keys = Vec::new();
        for alg in config.algorithms.iter().filter(|a| a.is_hmac()) {
            let Some(secret) = &client_secret else {
                return Err(invalid(
                    "HMAC ID-token algorithms need `client_secret`".to_owned(),
                ));
            };
            if secret.len() < 32 {
                return Err(invalid(
                    "HMAC ID tokens need a client secret of at least 32 bytes (RFC 7518 §3.2)"
                        .to_owned(),
                ));
            }
            hmac_keys.push(Key::hmac(*alg, secret.as_bytes()));
        }
        let claims_to_headers = config
            .claims_to_headers
            .iter()
            .map(|(claim, header)| {
                HeaderName::try_from(header.as_str())
                    .map(|h| (claim.clone(), h))
                    .map_err(|_| invalid(format!("`{header}` is not a header name")))
            })
            .collect::<Result<_, _>>()?;
        let cookie_base = config.cookie_base();
        let mut common = "; Path=/; HttpOnly".to_owned();
        if config.session.secure {
            common.push_str("; Secure");
        }
        if let Some(domain) = &config.session.domain {
            common.push_str("; Domain=");
            common.push_str(domain);
        }
        let same_site = match config.session.same_site {
            OidcSameSite::None => "; SameSite=None",
            OidcSameSite::Strict => "; SameSite=Strict",
            OidcSameSite::Lax => "; SameSite=Lax",
        };
        // The state cookie must come back on the provider's cross-site redirect.
        let state_same_site = match config.session.same_site {
            OidcSameSite::None => "; SameSite=None",
            _ => "; SameSite=Lax",
        };
        let lower = |list: &[String]| list.iter().map(|v| v.to_ascii_lowercase()).collect();
        let provider = Provider::shared(
            name,
            config.issuer.as_url(),
            config.allow_private_targets,
            &config.algorithms,
            env.client.clone(),
            env.metrics.cloned(),
        );
        Ok(Self {
            name: Arc::from(name),
            provider,
            client_id: config.client_id.clone(),
            client_secret,
            token_auth: config.token_endpoint_auth,
            scopes: config.scopes.join(" "),
            callback_path: config.callback_path(),
            redirect_url: config.redirect_url.as_ref().map(|u| u.as_url().to_string()),
            logout_path: config.logout_path.clone(),
            post_logout_path: config.post_logout_path.clone(),
            state_prefix: format!("{cookie_base}_state_"),
            cookie_base,
            session_attributes: format!("{common}{same_site}"),
            state_attributes: format!("{common}{state_same_site}"),
            session,
            state,
            ttl: config.session.ttl.as_std().as_secs(),
            refresh: config.session.refresh,
            secure: config.session.secure,
            claims_to_headers,
            consumer_claim: config.consumer_claim.clone(),
            map_to_consumers: config.map_to_consumers,
            issuer: Arc::from(config.issuer.as_url().as_str()),
            groups_claim: config.groups_claim.clone(),
            allowed_emails: lower(&config.allowed.emails),
            allowed_domains: lower(&config.allowed.domains),
            allowed_groups: config.allowed.groups.clone(),
            unverified_emails: config.allowed.unverified_emails,
            unauthenticated: config.unauthenticated,
            forward_access_token: config.forward_access_token,
            hmac_keys,
            leeway: config.leeway.as_std(),
            hosts: env
                .route_hosts
                .get(name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            consumers: env.consumers.clone(),
            metrics: env.metrics.cloned(),
            random: SystemRandom::new(),
            refreshing: Mutex::new(HashMap::new()),
        })
    }

    fn count_login(&self, result: &str) {
        if let Some(m) = &self.metrics {
            m.oidc_logins
                .with_label_values(&[&*self.name, result])
                .inc();
        }
    }

    fn count_refresh(&self, result: &str) {
        if let Some(m) = &self.metrics {
            m.oidc_refreshes
                .with_label_values(&[&*self.name, result])
                .inc();
        }
    }

    /// `Set-Cookie` for `name=value` with these attributes and lifetime.
    fn set_cookie(name: &str, value: &str, attributes: &str, max_age: u64) -> Option<HeaderValue> {
        HeaderValue::from_str(&format!("{name}={value}{attributes}; Max-Age={max_age}")).ok()
    }

    /// `Set-Cookie` that removes cookie `name`.
    fn clear_cookie(name: &str, attributes: &str) -> Option<HeaderValue> {
        HeaderValue::from_str(&format!(
            "{name}={attributes}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        ))
        .ok()
    }

    fn is_own_cookie(&self, name: &str) -> bool {
        name == self.cookie_base
            || name.starts_with(&self.state_prefix)
            || name
                .strip_prefix(&self.cookie_base)
                .and_then(|rest| rest.strip_prefix('_'))
                .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit())
    }

    /// Removes rdock's cookies from the request, keeping every other cookie.
    fn strip_cookies(&self, req: &mut RequestHeader) {
        let mut own = false;
        let kept: Vec<String> = req
            .headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
            .filter(|pair| {
                let name = pair.split_once('=').map_or(*pair, |(n, _)| n.trim());
                let mine = self.is_own_cookie(name);
                own |= mine;
                !mine
            })
            .map(str::to_owned)
            .collect();
        if !own {
            return;
        }
        req.remove_header(&http::header::COOKIE);
        if !kept.is_empty()
            && let Ok(value) = HeaderValue::from_str(&kept.join("; "))
        {
            let _ = req.insert_header(http::header::COOKIE, value);
        }
    }

    /// The session cookie names the request carries.
    fn present_session_names(&self, req: &RequestHeader) -> Vec<String> {
        let names = cookie::session_names(&self.cookie_base);
        cookie::pairs(req)
            .into_iter()
            .map(|(n, _)| n)
            .filter(|n| names.iter().any(|m| m == n))
            .map(str::to_owned)
            .collect()
    }

    fn read_session(&self, req: &RequestHeader) -> Option<Session> {
        let value = cookie::read_split(&cookie::pairs(req), &self.cookie_base)?;
        cookie::open_json(&self.session, &value)
    }

    /// `Set-Cookie` headers that store `session` and remove the session cookies the request
    /// had that are not rewritten. `None` when the session is too large.
    fn session_cookies(&self, session: &Session, present: &[String]) -> Option<Vec<HeaderValue>> {
        let sealed = cookie::seal_json(&self.session, session)?;
        let parts = cookie::split(&self.cookie_base, &sealed)?;
        let max_age = session.expires.saturating_sub(now());
        let mut out = Vec::new();
        for (name, value) in &parts {
            out.push(Self::set_cookie(
                name,
                value,
                &self.session_attributes,
                max_age,
            )?);
        }
        for name in present {
            if !parts.iter().any(|(n, _)| n == name) {
                out.extend(Self::clear_cookie(name, &self.session_attributes));
            }
        }
        Some(out)
    }

    /// Whether the session's user may use this route.
    fn allowed(&self, session: &Session) -> bool {
        if self.allowed_emails.is_empty()
            && self.allowed_domains.is_empty()
            && self.allowed_groups.is_empty()
        {
            return true;
        }
        if let Some(email) = &session.email {
            let email = email.to_ascii_lowercase();
            if self.allowed_emails.contains(&email) {
                return true;
            }
            if let Some((_, domain)) = email.rsplit_once('@')
                && self.allowed_domains.iter().any(|d| d == domain)
            {
                return true;
            }
        }
        session
            .groups
            .iter()
            .any(|g| self.allowed_groups.contains(g))
    }

    /// Whether an unauthenticated request is sent to the login rather than refused.
    fn wants_redirect(&self, req: &RequestHeader) -> bool {
        let fetch = req.method == http::Method::GET || req.method == http::Method::HEAD;
        match self.unauthenticated {
            Unauthenticated::Deny => false,
            Unauthenticated::Redirect => fetch,
            Unauthenticated::Auto => fetch && is_navigation(req),
        }
    }

    /// `scheme://authority` of the request when its host is one the routes name.
    fn origin(&self, cx: &Context) -> Option<String> {
        let authority = cx.authority.to_ascii_lowercase();
        if authority.is_empty()
            || !authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        {
            return None;
        }
        let host = match authority.strip_prefix('[') {
            Some(rest) => rest.split(']').next().unwrap_or_default(),
            None => authority
                .rsplit_once(':')
                .map_or(authority.as_str(), |(h, _)| h),
        };
        let matches = self
            .hosts
            .iter()
            .any(|pattern| match pattern.strip_prefix("*.") {
                Some(suffix) => host
                    .strip_suffix(suffix)
                    .and_then(|label| label.strip_suffix('.'))
                    .is_some_and(|label| !label.is_empty() && !label.contains('.')),
                None => pattern.trim_matches(['[', ']']) == host,
            });
        if !matches {
            return None;
        }
        let scheme = if self.secure || cx.tls {
            "https"
        } else {
            "http"
        };
        Some(format!("{scheme}://{authority}"))
    }

    fn redirect_uri(&self, cx: &Context) -> Option<String> {
        if let Some(url) = &self.redirect_url {
            return Some(url.clone());
        }
        Some(format!("{}{}", self.origin(cx)?, self.callback_path))
    }

    /// Sets the identity on the request and the context from `session`.
    fn admit(&self, req: &mut RequestHeader, cx: &mut Context, session: &Session) {
        for (claim, header) in &self.claims_to_headers {
            if let Some((_, text)) = session.claims.iter().find(|(c, _)| c == claim)
                && let Ok(value) = HeaderValue::from_str(text)
            {
                let _ = req.insert_header(header.clone(), value);
            }
        }
        if self.forward_access_token
            && let Some(token) = &session.access_token
            && let Ok(value) = HeaderValue::from_str(token)
        {
            let _ = req.insert_header(ACCESS_TOKEN_HEADER, value);
        }
        let mut groups: Vec<Arc<str>> = session
            .groups
            .iter()
            .map(|g| Arc::from(g.as_str()))
            .collect();
        // Only with `map_to_consumers` is the name one of `consumers` (H1 of the v0.8
        // review): otherwise a user whose claim equals a configured name would get its groups
        // and share its quota. A name that is not configured stays keyed on the issuer.
        let defined = self
            .map_to_consumers
            .then(|| self.consumers.consumer(&session.consumer))
            .flatten();
        if let Some(defined) = defined {
            for group in defined.groups.iter() {
                if !groups.contains(group) {
                    groups.push(group.clone());
                }
            }
        }
        cx.user = Some(session.consumer.clone());
        cx.consumer = Some(crate::Consumer {
            name: Arc::from(session.consumer.as_str()),
            groups: Arc::from(groups),
            issuer: defined.is_none().then(|| self.issuer.clone()),
        });
        self.strip_cookies(req);
    }

    /// The claims of a valid ID token (Core §3.1.3.7): signature with an allowed algorithm,
    /// `iss`, `aud`, `azp`, `exp`, `iat`, `nonce` when expected, `sub`, and `at_hash` when
    /// present with an access token.
    fn verify_id_token(
        &self,
        found: &Discovered,
        id_token: &str,
        nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<Map<String, Value>, String> {
        let keys: Vec<&Key> = found.keys.iter().chain(self.hmac_keys.iter()).collect();
        let audiences = [self.client_id.clone()];
        let now_time = SystemTime::now();
        let rules = Rules {
            issuer: Some(&found.issuer),
            audiences: Some(&audiences),
            leeway: self.leeway,
            now: now_time,
        };
        let claims = token::verify(id_token, &keys, &rules).map_err(|why| {
            if why == Invalid::UnknownKey {
                self.provider.refresh_early();
            }
            why.to_string()
        })?;
        if let Some(Value::Array(list)) = claims.get("aud")
            && list.len() > 1
            && claims.get("azp").is_none()
        {
            return Err("several audiences and no `azp`".to_owned());
        }
        if let Some(azp) = claims.get("azp")
            && azp.as_str() != Some(self.client_id.as_str())
        {
            return Err("`azp` is another client".to_owned());
        }
        let latest = now().saturating_add(self.leeway.as_secs());
        match claims.get("iat").and_then(Value::as_f64) {
            Some(iat) if iat <= f64::from(u32::try_from(latest).unwrap_or(u32::MAX)) => {}
            Some(_) => return Err("`iat` is in the future".to_owned()),
            None => return Err("no `iat`".to_owned()),
        }
        if claims
            .get("sub")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err("no `sub`".to_owned());
        }
        if let Some(expected) = nonce {
            let got = claims
                .get("nonce")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !bool::from(got.as_bytes().ct_eq(expected.as_bytes())) {
                return Err("wrong `nonce`".to_owned());
            }
        }
        if let (Some(at_hash), Some(access_token)) =
            (claims.get("at_hash").and_then(Value::as_str), access_token)
        {
            let alg = token_alg(id_token).ok_or_else(|| "malformed header".to_owned())?;
            if !at_hash_matches(alg, access_token, at_hash) {
                return Err("`at_hash` does not match the access token".to_owned());
            }
        }
        Ok(claims)
    }

    /// A session for the verified `claims` and token response.
    fn new_session(
        &self,
        claims: &Map<String, Value>,
        tokens: &Value,
        login: u64,
        previous: Option<&Session>,
    ) -> Session {
        let now = now();
        let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
        let sub = text("sub").unwrap_or_default();
        let verified = crate::jwt::email_verified(claims);
        let trusted_email =
            verified == Some(true) || (self.unverified_emails && verified.is_none());
        let consumer = match claims.get(&self.consumer_claim) {
            // An address the provider has not verified could be anyone's (H1 of the v0.8
            // review): it names the consumer only when verified, `sub` otherwise.
            _ if self.consumer_claim == "email" && !trusted_email => sub.clone(),
            Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => sub.clone(),
        };
        let groups = match claims.get(&self.groups_claim) {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        };
        let email = text("email").filter(|_| trusted_email);
        let claims_out = self
            .claims_to_headers
            .iter()
            .filter_map(|(claim, _)| {
                claims
                    .get(claim)
                    .map(|v| (claim.clone(), crate::jwt::claim_text(v)))
            })
            .collect();
        let id_exp = claims.get("exp").and_then(Value::as_u64).unwrap_or(now);
        let access_exp = tokens
            .get("expires_in")
            .and_then(Value::as_u64)
            .map(|s| now + s);
        let refresh_at = match access_exp {
            Some(at) if self.forward_access_token => at.min(id_exp),
            _ => id_exp,
        };
        let refresh_token = if self.refresh {
            tokens
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| previous.and_then(|p| p.refresh_token.clone()))
        } else {
            None
        };
        let mut expires = login.saturating_add(self.ttl);
        match &refresh_token {
            Some(_) => {
                if let Some(idle) = tokens.get("refresh_expires_in").and_then(Value::as_u64)
                    && idle > 0
                {
                    expires = expires.min(now + idle);
                }
            }
            None => expires = expires.min(refresh_at),
        }
        let access_token = if self.forward_access_token {
            tokens
                .get("access_token")
                .and_then(Value::as_str)
                .map(str::to_owned)
        } else {
            None
        };
        Session {
            sub,
            consumer,
            groups,
            email,
            claims: claims_out,
            login,
            expires,
            refresh_at,
            refresh_token,
            access_token,
        }
    }

    /// The token endpoint form for `pairs`, with client authentication, and the `Authorization`
    /// header for `client_secret_basic`.
    fn token_form(&self, pairs: &[(&str, &str)]) -> (String, Option<String>) {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            form.append_pair(k, v);
        }
        let mut basic = None;
        match (&self.client_secret, self.token_auth) {
            (Some(secret), TokenEndpointAuth::ClientSecretBasic) => {
                // RFC 6749 §2.3.1: both parts form-encoded before Basic.
                let enc = |s: &str| {
                    url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
                };
                let creds = format!("{}:{}", enc(&self.client_id), enc(secret));
                basic = Some(format!("Basic {}", STANDARD.encode(creds)));
            }
            (Some(secret), TokenEndpointAuth::ClientSecretPost) => {
                form.append_pair("client_id", &self.client_id);
                form.append_pair("client_secret", secret);
            }
            (None, _) => {
                form.append_pair("client_id", &self.client_id);
            }
        }
        (form.finish(), basic)
    }

    async fn refresh_session(&self, session: &Session) -> Option<Session> {
        let token = session.refresh_token.as_deref()?;
        let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(digest.as_ref());
        let cell = {
            let mut map = self
                .refreshing
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            map.retain(|_, (at, _)| at.elapsed() < REFRESH_SHARED);
            map.entry(key)
                .or_insert_with(|| (Instant::now(), Arc::new(OnceCell::new())))
                .1
                .clone()
        };
        cell.get_or_init(|| self.do_refresh(session, token))
            .await
            .clone()
    }

    async fn do_refresh(&self, session: &Session, refresh_token: &str) -> Option<Session> {
        let found = self.provider.ready(PROVIDER_WAIT).await?;
        let (form, basic) = self.token_form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ]);
        let tokens = match self
            .provider
            .token_request(&found.token_endpoint, &form, basic.as_deref(), "refresh")
            .await
        {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::debug!(middleware = %self.name, %error, "OIDC refresh failed");
                self.count_refresh("failed");
                return None;
            }
        };
        let access = tokens.get("access_token").and_then(Value::as_str);
        let renewed = if let Some(id_token) = tokens.get("id_token").and_then(Value::as_str) {
            {
                let claims = match self.verify_id_token(&found, id_token, None, access) {
                    Ok(claims) => claims,
                    Err(why) => {
                        tracing::debug!(middleware = %self.name, reason = %why, "refreshed ID token refused");
                        self.count_refresh("failed");
                        return None;
                    }
                };
                if claims.get("sub").and_then(Value::as_str) != Some(session.sub.as_str()) {
                    tracing::debug!(middleware = %self.name, "refreshed ID token names another subject");
                    self.count_refresh("failed");
                    return None;
                }
                self.new_session(&claims, &tokens, session.login, Some(session))
            }
        } else {
            {
                // No new ID token (Core §12.2 allows it): keep the identity, renew the times.
                let now = now();
                let mut next = session.clone();
                next.refresh_at = tokens
                    .get("expires_in")
                    .and_then(Value::as_u64)
                    .map_or(now + 300, |s| now + s);
                if let Some(token) = tokens.get("refresh_token").and_then(Value::as_str) {
                    next.refresh_token = Some(token.to_owned());
                }
                if self.forward_access_token {
                    next.access_token = access.map(str::to_owned);
                }
                next.expires = session.login.saturating_add(self.ttl);
                if let Some(idle) = tokens.get("refresh_expires_in").and_then(Value::as_u64)
                    && idle > 0
                {
                    next.expires = next.expires.min(now + idle);
                }
                next
            }
        };
        self.count_refresh("success");
        Some(renewed)
    }

    /// Redirects to the provider's login, with a new state cookie.
    async fn start_login(&self, req: &RequestHeader, cx: &Context) -> Flow {
        let Some(found) = self.provider.ready(PROVIDER_WAIT).await else {
            self.count_login("unavailable");
            return Flow::Reply(
                Reply::problem(ProblemKind::IdentityProviderUnavailable)
                    .header(http::header::RETRY_AFTER, HeaderValue::from_static("30")),
            );
        };
        if found.algorithms.is_empty() && self.hmac_keys.is_empty() {
            self.count_login("unavailable");
            tracing::warn!(middleware = %self.name, "no ID-token algorithm in common with the provider");
            return Flow::Reply(
                Reply::problem(ProblemKind::IdentityProviderUnavailable)
                    .header(http::header::RETRY_AFTER, HeaderValue::from_static("30")),
            );
        }
        let Some(redirect_uri) = self.redirect_uri(cx) else {
            tracing::debug!(middleware = %self.name, "login refused: the request's host is not one the routes name");
            return Flow::Reply(Reply::problem(ProblemKind::BadRequest));
        };
        let random = |n| cookie::random_token(&self.random, n);
        let (Some(id), Some(secret), Some(nonce), Some(verifier)) =
            (random(6), random(32), random(32), random(32))
        else {
            return Flow::Reply(Reply::problem(ProblemKind::InternalError));
        };
        let state = format!("{id}.{secret}");
        let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
            &ring::digest::SHA256,
            verifier.as_bytes(),
        ));
        let login = LoginState {
            state: state.clone(),
            nonce: nonce.clone(),
            verifier,
            redirect_uri: redirect_uri.clone(),
            target: login_target(req),
            expires: now() + LOGIN_TTL,
        };
        let Some(sealed) = cookie::seal_json(&self.state, &login) else {
            return Flow::Reply(Reply::problem(ProblemKind::InternalError));
        };
        let mut location = found.authorization_endpoint.clone();
        location
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &self.scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let Ok(location) = HeaderValue::from_str(location.as_str()) else {
            return Flow::Reply(Reply::problem(ProblemKind::InternalError));
        };
        let mut reply = redirect(location);
        // Drop the oldest logins in progress beyond the cap.
        let mut pending: Vec<(u64, String)> = cookie::pairs(req)
            .into_iter()
            .filter(|(n, _)| n.starts_with(&self.state_prefix))
            .map(|(n, v)| {
                let expires =
                    cookie::open_json::<LoginState>(&self.state, v).map_or(0, |s| s.expires);
                (expires, n.to_owned())
            })
            .collect();
        pending.sort();
        let excess = pending.len().saturating_sub(MAX_LOGINS - 1);
        for (_, name) in pending.into_iter().take(excess) {
            if let Some(clear) = Self::clear_cookie(&name, &self.state_attributes) {
                reply = reply.header(http::header::SET_COOKIE, clear);
            }
        }
        match Self::set_cookie(
            &format!("{}{id}", self.state_prefix),
            &sealed,
            &self.state_attributes,
            LOGIN_TTL,
        ) {
            Some(cookie) => Flow::Reply(reply.header(http::header::SET_COOKIE, cookie)),
            None => Flow::Reply(Reply::problem(ProblemKind::InternalError)),
        }
    }

    /// A failed login: `kind`'s page, with the login's state cookie removed.
    fn login_failed(&self, kind: ProblemKind, result: &str, state_cookie: Option<&str>) -> Flow {
        self.count_login(result);
        let mut reply = Reply::problem(kind).header(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        if kind == ProblemKind::IdentityProviderUnavailable {
            reply = reply.header(http::header::RETRY_AFTER, HeaderValue::from_static("30"));
        }
        if let Some(name) = state_cookie
            && let Some(clear) = Self::clear_cookie(name, &self.state_attributes)
        {
            reply = reply.header(http::header::SET_COOKIE, clear);
        }
        Flow::Reply(reply)
    }

    /// The provider's redirect back: checks the state, exchanges the code, verifies the ID
    /// token and starts the session.
    #[allow(clippy::too_many_lines)] // the checks in the order of Core §3.1.2.7 and §3.1.3.7
    async fn callback(&self, req: &RequestHeader) -> Flow {
        let params: HashMap<String, String> = req
            .uri
            .query()
            .map(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .into_owned()
                    .collect()
            })
            .unwrap_or_default();
        let Some(state) = params.get("state") else {
            return self.login_failed(ProblemKind::LoginFailed, "failed", None);
        };
        let id = state.split('.').next().unwrap_or_default();
        if id.is_empty()
            || id.len() > 16
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return self.login_failed(ProblemKind::LoginFailed, "failed", None);
        }
        let cookie_name = format!("{}{id}", self.state_prefix);
        let found_cookie = cookie::pairs(req)
            .into_iter()
            .find(|(n, _)| *n == cookie_name)
            .map(|(_, v)| v.to_owned());
        let login = found_cookie
            .and_then(|v| cookie::open_json::<LoginState>(&self.state, &v))
            .filter(|l| l.expires >= now());
        let Some(login) = login else {
            tracing::debug!(middleware = %self.name, "callback without a matching login in progress");
            return self.login_failed(ProblemKind::LoginFailed, "failed", Some(&cookie_name));
        };
        if !bool::from(login.state.as_bytes().ct_eq(state.as_bytes())) {
            tracing::debug!(middleware = %self.name, "callback with a wrong state");
            return self.login_failed(ProblemKind::LoginFailed, "failed", Some(&cookie_name));
        }
        if let Some(error) = params.get("error") {
            // A registered code (RFC 6749 §4.1.2.1); `error_description` is never echoed.
            let code: String = error
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(64)
                .collect();
            tracing::info!(middleware = %self.name, error = %code, "the provider refused the login");
            return self.login_failed(
                ProblemKind::LoginFailed,
                "provider_error",
                Some(&cookie_name),
            );
        }
        let Some(found) = self.provider.ready(PROVIDER_WAIT).await else {
            return self.login_failed(
                ProblemKind::IdentityProviderUnavailable,
                "unavailable",
                Some(&cookie_name),
            );
        };
        if let Some(iss) = params.get("iss")
            && *iss != found.issuer
        {
            tracing::debug!(middleware = %self.name, "callback from another issuer (RFC 9207)");
            return self.login_failed(ProblemKind::LoginFailed, "failed", Some(&cookie_name));
        }
        let Some(code) = params.get("code") else {
            return self.login_failed(ProblemKind::LoginFailed, "failed", Some(&cookie_name));
        };
        let (form, basic) = self.token_form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &login.redirect_uri),
            ("code_verifier", &login.verifier),
        ]);
        let tokens = match self
            .provider
            .token_request(&found.token_endpoint, &form, basic.as_deref(), "token")
            .await
        {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::warn!(middleware = %self.name, %error, "the token request failed");
                return self.login_failed(
                    ProblemKind::LoginFailed,
                    "provider_error",
                    Some(&cookie_name),
                );
            }
        };
        let access = tokens.get("access_token").and_then(Value::as_str);
        if access.is_some()
            && !tokens
                .get("token_type")
                .and_then(Value::as_str)
                .is_some_and(|t| t.eq_ignore_ascii_case("bearer"))
        {
            tracing::debug!(middleware = %self.name, "the token type is not Bearer");
            return self.login_failed(ProblemKind::LoginFailed, "failed", Some(&cookie_name));
        }
        let Some(id_token) = tokens.get("id_token").and_then(Value::as_str) else {
            tracing::debug!(middleware = %self.name, "the token response has no ID token");
            return self.login_failed(ProblemKind::LoginFailed, "failed", Some(&cookie_name));
        };
        let claims = match self.verify_id_token(&found, id_token, Some(&login.nonce), access) {
            Ok(claims) => claims,
            Err(why) => {
                tracing::info!(middleware = %self.name, reason = %why, "ID token refused");
                return self.login_failed(ProblemKind::LoginFailed, "failed", Some(&cookie_name));
            }
        };
        let session = self.new_session(&claims, &tokens, now(), None);
        if !self.allowed(&session) {
            tracing::info!(middleware = %self.name, consumer = %session.consumer, "login denied by `allowed`");
            return self.login_failed(ProblemKind::Forbidden, "denied", Some(&cookie_name));
        }
        let Some(cookies) = self.session_cookies(&session, &self.present_session_names(req)) else {
            tracing::warn!(middleware = %self.name, "the session does not fit in the cookies; pass fewer claims or turn off `forward_access_token`");
            return self.login_failed(ProblemKind::LoginFailed, "failed", Some(&cookie_name));
        };
        self.count_login("success");
        tracing::debug!(middleware = %self.name, consumer = %session.consumer, "OIDC login");
        let Ok(location) = HeaderValue::from_str(&login.target) else {
            return Flow::Reply(Reply::problem(ProblemKind::InternalError));
        };
        let mut reply = redirect(location);
        for cookie in cookies {
            reply = reply.header(http::header::SET_COOKIE, cookie);
        }
        if let Some(clear) = Self::clear_cookie(&cookie_name, &self.state_attributes) {
            reply = reply.header(http::header::SET_COOKIE, clear);
        }
        Flow::Reply(reply)
    }

    /// Whether a logout request comes from the site itself (L1 of the v0.8 review): otherwise
    /// any page could log the user out with an `<img>` or a form. `Sec-Fetch-Site` decides
    /// when the browser sends it (`same-origin`, or `none` for a typed URL or a bookmark);
    /// without it, an `Origin` or else a `Referer` of the request's own origin is needed.
    /// `same-site` is refused: a sibling subdomain may serve other people's content.
    fn same_origin(&self, req: &RequestHeader, cx: &Context) -> bool {
        let header = |name: &str| req.headers.get(name).and_then(|v| v.to_str().ok());
        if let Some(site) = header("sec-fetch-site") {
            return site.eq_ignore_ascii_case("same-origin") || site.eq_ignore_ascii_case("none");
        }
        let Some(origin) = self.origin(cx) else {
            return false;
        };
        if let Some(sent) = header("origin") {
            return sent.eq_ignore_ascii_case(&origin);
        }
        header("referer").is_some_and(|referer| {
            referer
                .get(..origin.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(&origin))
                && matches!(referer.as_bytes().get(origin.len()), None | Some(b'/'))
        })
    }

    /// Ends the session, and at the provider when it supports RP-initiated logout.
    fn logout(&self, req: &RequestHeader, cx: &Context) -> Flow {
        let landing = self
            .origin(cx)
            .map(|o| format!("{o}{}", self.post_logout_path));
        let target = match self
            .provider
            .known()
            .and_then(|f| f.end_session_endpoint.clone())
        {
            Some(mut end) => {
                {
                    let mut query = end.query_pairs_mut();
                    query.append_pair("client_id", &self.client_id);
                    if let Some(landing) = &landing {
                        query.append_pair("post_logout_redirect_uri", landing);
                    }
                }
                end.to_string()
            }
            None => self.post_logout_path.clone(),
        };
        let Ok(location) = HeaderValue::from_str(&target) else {
            return Flow::Reply(Reply::problem(ProblemKind::InternalError));
        };
        let mut reply = redirect(location);
        let mut names = self.present_session_names(req);
        if names.is_empty() {
            names.push(self.cookie_base.clone());
        }
        for name in names {
            if let Some(clear) = Self::clear_cookie(&name, &self.session_attributes) {
                reply = reply.header(http::header::SET_COOKIE, clear);
            }
        }
        Flow::Reply(reply)
    }
}

/// A `302` to `location` that is never cached.
fn redirect(location: HeaderValue) -> Reply {
    Reply {
        status: 302,
        headers: vec![
            (http::header::LOCATION, location),
            (
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ),
        ],
        body: Some(bytes::Bytes::new().into()),
        problem: None,
        extensions: None,
    }
}

/// Whether the request is a page navigation: `Sec-Fetch-Mode: navigate` when the browser
/// sends it, otherwise an `Accept` that names `text/html` and no `X-Requested-With`.
fn is_navigation(req: &RequestHeader) -> bool {
    let header = |name: &str| req.headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(mode) = header("sec-fetch-mode") {
        return mode.eq_ignore_ascii_case("navigate");
    }
    if header("x-requested-with").is_some() {
        return false;
    }
    req.headers
        .get_all(http::header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("text/html"))
}

/// Where to return after the login: the request's own path and query, and `/` for anything
/// that could be read as another origin (`//evil.example`, `/\evil.example`) — the target is
/// never taken from a parameter, so the callback cannot redirect elsewhere.
pub(crate) fn login_target(req: &RequestHeader) -> String {
    let target = req
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let safe = target.starts_with('/')
        && !target.starts_with("//")
        && !target.starts_with("/\\")
        && !target.contains('\\')
        && target.len() <= MAX_TARGET
        && !target.chars().any(char::is_control);
    if safe {
        target.to_owned()
    } else {
        "/".to_owned()
    }
}

/// The `alg` of a compact JWS.
fn token_alg(token: &str) -> Option<JwtAlgorithm> {
    let header = URL_SAFE_NO_PAD.decode(token.split('.').next()?).ok()?;
    let header: Value = serde_json::from_slice(&header).ok()?;
    let name = header.get("alg")?.as_str()?;
    provider::SAFE
        .into_iter()
        .chain([
            JwtAlgorithm::Hs256,
            JwtAlgorithm::Hs384,
            JwtAlgorithm::Hs512,
        ])
        .find(|a| a.name() == name)
}

/// `at_hash` (Core §3.1.3.6): the left half of the access token's hash with the ID token's
/// algorithm's hash (SHA-512 for `EdDSA` with Ed25519), base64url.
pub(crate) fn at_hash_matches(alg: JwtAlgorithm, access_token: &str, at_hash: &str) -> bool {
    use JwtAlgorithm as A;
    let algorithm = match alg {
        A::Rs256 | A::Ps256 | A::Es256 | A::Hs256 => &ring::digest::SHA256,
        A::Rs384 | A::Ps384 | A::Es384 | A::Hs384 => &ring::digest::SHA384,
        A::Rs512 | A::Ps512 | A::Hs512 | A::EdDsa => &ring::digest::SHA512,
    };
    let digest = ring::digest::digest(algorithm, access_token.as_bytes());
    let half = &digest.as_ref()[..digest.as_ref().len() / 2];
    let expected = URL_SAFE_NO_PAD.encode(half);
    bool::from(expected.as_bytes().ct_eq(at_hash.as_bytes()))
}

#[async_trait]
impl Middleware for Oidc {
    fn capabilities(&self) -> Capabilities {
        Capabilities::DEFAULT.with_state()
    }

    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        // Identity headers are only ever set from a verified session.
        for (_, header) in &self.claims_to_headers {
            req.remove_header(header);
        }
        req.remove_header(ACCESS_TOKEN_HEADER);
        let path = req.uri.path();
        if path == self.callback_path {
            return self.callback(req).await;
        }
        if path == self.logout_path {
            if !matches!(
                req.method,
                http::Method::GET | http::Method::HEAD | http::Method::POST
            ) {
                return Flow::Reply(Reply::problem(ProblemKind::MethodNotAllowed).header(
                    http::header::ALLOW,
                    HeaderValue::from_static("GET, HEAD, POST"),
                ));
            }
            if !self.same_origin(req, cx) {
                tracing::debug!(middleware = %self.name, "cross-site logout refused");
                return Flow::Reply(Reply::problem(ProblemKind::Forbidden));
            }
            return self.logout(req, cx);
        }
        let now = now();
        if let Some(session) = self.read_session(req).filter(|s| s.expires > now) {
            let session = if session.refresh_at > now + REFRESH_EARLY {
                Some(session)
            } else if session.refresh_token.is_some() {
                match self.refresh_session(&session).await {
                    Some(renewed) => {
                        let present = self.present_session_names(req);
                        if let Some(cookies) = self.session_cookies(&renewed, &present) {
                            cx.set_state(SetCookies(cookies));
                        }
                        Some(renewed)
                    }
                    None => None,
                }
            } else if session.refresh_at > now {
                Some(session)
            } else {
                None
            };
            if let Some(session) = session {
                if !self.allowed(&session) {
                    self.strip_cookies(req);
                    return Flow::Reply(Reply::problem(ProblemKind::Forbidden));
                }
                self.admit(req, cx, &session);
                return Flow::Next;
            }
        }
        if self.wants_redirect(req) {
            return self.start_login(req, cx).await;
        }
        Flow::Reply(Reply::problem(ProblemKind::Unauthenticated))
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        if let Some(SetCookies(cookies)) = cx.take_state::<SetCookies>() {
            for cookie in cookies {
                let _ = resp.append_header(http::header::SET_COOKIE, cookie);
            }
        }
    }
}

#[cfg(test)]
mod tests;
