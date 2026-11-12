//! A fake OpenID provider for the `oidc` middleware: discovery, an authorization endpoint that
//! approves at once as a configurable user, a token endpoint (authorization code with PKCE
//! S256, refresh tokens with optional rotation, `client_secret_basic` and
//! `client_secret_post`), a JWKS with two RSA keys from `testdata` (one or both published),
//! and an end-session endpoint. Knobs script the faults the relying party must refuse: a wrong
//! `nonce`, `aud` or `iss`, an expired token, `alg: none`, an authorization error, and an
//! unavailable provider.
//!
//! The keys are throw-away test keys; they protect nothing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, RsaKeyPair};
use serde_json::{Value, json};

use crate::cloudflare_access::now;
use crate::fake_api::{FakeApi, Recorded, Reply};

const KEYS: [&[u8]; 2] = [
    include_bytes!("../testdata/access-test-rsa-1.pk8"),
    include_bytes!("../testdata/access-test-rsa-2.pk8"),
];

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random() -> String {
    let mut buf = [0u8; 18];
    SystemRandom::new().fill(&mut buf).unwrap();
    b64(&buf)
}

/// The user the authorization endpoint logs in.
#[derive(Debug, Clone)]
pub struct User {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
    pub name: String,
}

impl User {
    pub fn new(sub: &str, email: &str, groups: &[&str]) -> Self {
        Self {
            sub: sub.to_owned(),
            email: email.to_owned(),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            name: format!("User {sub}"),
        }
    }
}

/// Faults and settings, changed between requests.
#[allow(clippy::struct_excessive_bools)] // independent switches, set one at a time
#[derive(Debug, Clone)]
pub struct Knobs {
    /// Sign with this key (0 or 1).
    pub signing_key: usize,
    /// Keys the JWKS publishes.
    pub published: Vec<usize>,
    /// Put this `nonce` in ID tokens instead of the requested one.
    pub nonce: Option<String>,
    /// Put this `aud` in ID tokens instead of the client ID.
    pub aud: Option<Value>,
    /// Put this `iss` in ID tokens instead of the issuer.
    pub iss: Option<String>,
    /// ID-token lifetime in seconds (negative: already expired).
    pub id_token_lifetime: i64,
    /// `expires_in` of access tokens.
    pub access_token_lifetime: u64,
    /// Issue unsigned tokens (`alg: none`).
    pub alg_none: bool,
    /// Issue refresh tokens.
    pub refresh_tokens: bool,
    /// Replace the refresh token on every refresh (the old one stops working).
    pub rotate_refresh_tokens: bool,
    /// Answer authorization requests with this `error` (and a hostile description).
    pub authorize_error: Option<String>,
    /// Answer every request with `503`.
    pub unavailable: bool,
    /// Refuse every refresh.
    pub refuse_refresh: bool,
    /// The `email_verified` claim of ID tokens; `Null` leaves it out.
    pub email_verified: Value,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            signing_key: 0,
            published: vec![0],
            nonce: None,
            aud: None,
            iss: None,
            id_token_lifetime: 300,
            access_token_lifetime: 300,
            alg_none: false,
            refresh_tokens: true,
            rotate_refresh_tokens: true,
            authorize_error: None,
            unavailable: false,
            refuse_refresh: false,
            email_verified: Value::Bool(true),
        }
    }
}

struct Grant {
    client_id: String,
    redirect_uri: String,
    nonce: Option<String>,
    challenge: Option<String>,
    user: User,
}

struct State {
    user: User,
    knobs: Knobs,
    codes: HashMap<String, Grant>,
    refresh: HashMap<String, (String, User)>,
}

/// The fake provider.
#[derive(Clone)]
pub struct FakeIdp {
    api: FakeApi,
    client_id: String,
    client_secret: Option<String>,
    keys: Arc<Vec<RsaKeyPair>>,
    state: Arc<Mutex<State>>,
}

impl FakeIdp {
    /// A provider with one confidential client.
    pub async fn start(client_id: &str, client_secret: Option<&str>) -> Self {
        let keys: Arc<Vec<RsaKeyPair>> = Arc::new(
            KEYS.iter()
                .map(|der| RsaKeyPair::from_pkcs8(der).unwrap())
                .collect(),
        );
        let api = FakeApi::start().await;
        let state = Arc::new(Mutex::new(State {
            user: User::new("user-1", "alice@example.com", &["staff"]),
            knobs: Knobs::default(),
            codes: HashMap::new(),
            refresh: HashMap::new(),
        }));
        let idp = Self {
            api,
            client_id: client_id.to_owned(),
            client_secret: client_secret.map(str::to_owned),
            keys,
            state,
        };
        idp.install();
        idp
    }

    /// `http://127.0.0.1:<port>`, also the issuer.
    pub fn issuer(&self) -> String {
        self.api.url().to_owned()
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<Recorded> {
        self.api.requests()
    }

    /// Requests to `path` so far.
    pub fn hits(&self, path: &str) -> usize {
        self.requests().iter().filter(|r| r.path == path).count()
    }

    /// The user logged in from now on.
    pub fn set_user(&self, user: User) {
        self.state.lock().unwrap().user = user;
    }

    /// Changes the knobs.
    pub fn knobs(&self, change: impl FnOnce(&mut Knobs)) {
        change(&mut self.state.lock().unwrap().knobs);
    }

    fn install(&self) {
        let state = self.state.clone();
        self.api.guard(move |_| {
            state
                .lock()
                .unwrap()
                .knobs
                .unavailable
                .then(Reply::server_error)
        });
        let issuer = self.issuer();
        self.api
            .route("GET", "/.well-known/openid-configuration", move |_, _| {
                Reply::json(
                    200,
                    json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{issuer}/authorize"),
                        "token_endpoint": format!("{issuer}/token"),
                        "jwks_uri": format!("{issuer}/jwks"),
                        "userinfo_endpoint": format!("{issuer}/userinfo"),
                        "end_session_endpoint": format!("{issuer}/logout"),
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                    }),
                )
            });
        let (keys, state) = (self.keys.clone(), self.state.clone());
        self.api.route("GET", "/jwks", move |_, _| {
            let published = state.lock().unwrap().knobs.published.clone();
            let jwks: Vec<Value> = published
                .iter()
                .map(|&i| {
                    let public: signature::RsaPublicKeyComponents<Vec<u8>> =
                        keys[i].public().into();
                    json!({ "kid": kid(i), "kty": "RSA", "alg": "RS256", "use": "sig", "e": b64(&public.e), "n": b64(&public.n) })
                })
                .collect();
            Reply::json(200, json!({ "keys": jwks }))
        });
        let (state, issuer) = (self.state.clone(), self.issuer());
        self.api.route("GET", "/authorize", move |req, _| {
            let mut state = state.lock().unwrap();
            let q = |name: &str| req.query_param(name);
            let (Some(redirect_uri), Some(client_id)) = (q("redirect_uri"), q("client_id")) else {
                return Reply::json(400, json!({ "error": "invalid_request" }));
            };
            if q("response_type").as_deref() != Some("code") {
                return Reply::json(400, json!({ "error": "unsupported_response_type" }));
            }
            let sep = if redirect_uri.contains('?') { '&' } else { '?' };
            let state_param = encode(&q("state").unwrap_or_default());
            if let Some(error) = state.knobs.authorize_error.clone() {
                let location = format!(
                    "{redirect_uri}{sep}error={}&error_description={}&state={state_param}",
                    encode(&error),
                    encode("<script>alert(1)</script>")
                );
                return Reply::status(302).header("location", &location);
            }
            let code = random();
            let user = state.user.clone();
            state.codes.insert(
                code.clone(),
                Grant {
                    client_id,
                    redirect_uri: redirect_uri.clone(),
                    nonce: q("nonce"),
                    challenge: (q("code_challenge_method").as_deref() == Some("S256"))
                        .then(|| q("code_challenge"))
                        .flatten(),
                    user,
                },
            );
            let location = format!(
                "{redirect_uri}{sep}code={code}&state={state_param}&iss={}",
                encode(&issuer)
            );
            Reply::status(302).header("location", &location)
        });
        let this = self.clone();
        self.api
            .route("POST", "/token", move |req, _| this.token(req));
        self.api.route("GET", "/logout", move |req, _| {
            match req.query_param("post_logout_redirect_uri") {
                Some(target) => Reply::status(302).header("location", &target),
                None => Reply::json(200, json!({ "logged_out": true })),
            }
        });
    }

    /// Whether the request authenticates the client.
    fn client_ok(&self, req: &Recorded, form: &HashMap<String, String>) -> bool {
        let Some(secret) = &self.client_secret else {
            return form.get("client_id") == Some(&self.client_id);
        };
        if let Some(basic) = req
            .header("authorization")
            .and_then(|h| h.strip_prefix("Basic "))
        {
            let decoded =
                String::from_utf8(STANDARD.decode(basic).unwrap_or_default()).unwrap_or_default();
            let (id, pass) = decoded.split_once(':').unwrap_or_default();
            return decode(id) == self.client_id && decode(pass) == *secret;
        }
        form.get("client_id") == Some(&self.client_id) && form.get("client_secret") == Some(secret)
    }

    fn token(&self, req: &Recorded) -> Reply {
        let form = parse_form(&String::from_utf8_lossy(&req.body));
        if !self.client_ok(req, &form) {
            return Reply::json(401, json!({ "error": "invalid_client" }));
        }
        let mut state = self.state.lock().unwrap();
        let knobs = state.knobs.clone();
        let (user, nonce) = match form.get("grant_type").map(String::as_str) {
            Some("authorization_code") => {
                let Some(grant) = form.get("code").and_then(|c| state.codes.remove(c)) else {
                    return Reply::json(400, json!({ "error": "invalid_grant" }));
                };
                if form.get("redirect_uri") != Some(&grant.redirect_uri)
                    || grant.client_id != self.client_id
                {
                    return Reply::json(400, json!({ "error": "invalid_grant" }));
                }
                let verifier = form.get("code_verifier").cloned().unwrap_or_default();
                let computed =
                    b64(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
                if grant.challenge.as_deref() != Some(computed.as_str()) {
                    return Reply::json(
                        400,
                        json!({ "error": "invalid_grant", "error_description": "PKCE" }),
                    );
                }
                (grant.user, grant.nonce)
            }
            Some("refresh_token") => {
                if knobs.refuse_refresh {
                    return Reply::json(400, json!({ "error": "invalid_grant" }));
                }
                let Some(token) = form.get("refresh_token") else {
                    return Reply::json(400, json!({ "error": "invalid_request" }));
                };
                let entry = if knobs.rotate_refresh_tokens {
                    state.refresh.remove(token)
                } else {
                    state.refresh.get(token).cloned()
                };
                let Some((_, user)) = entry else {
                    return Reply::json(400, json!({ "error": "invalid_grant" }));
                };
                (user, None)
            }
            _ => return Reply::json(400, json!({ "error": "unsupported_grant_type" })),
        };
        let access_token = random();
        let mut body = json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": knobs.access_token_lifetime,
        });
        let refresh = form.get("refresh_token").cloned();
        if knobs.refresh_tokens {
            let token = match (&refresh, knobs.rotate_refresh_tokens) {
                (Some(old), false) => old.clone(),
                _ => random(),
            };
            state
                .refresh
                .insert(token.clone(), (self.client_id.clone(), user.clone()));
            body["refresh_token"] = json!(token);
        }
        let now = now().cast_signed();
        let mut claims = json!({
            "iss": knobs.iss.clone().unwrap_or_else(|| self.issuer()),
            "sub": user.sub,
            "aud": knobs.aud.clone().unwrap_or_else(|| json!(self.client_id)),
            "exp": now + knobs.id_token_lifetime,
            "iat": now,
            "auth_time": now,
            "email": user.email,
            "email_verified": knobs.email_verified,
            "name": user.name,
            "groups": user.groups,
            "at_hash": b64(&ring::digest::digest(&ring::digest::SHA256, access_token.as_bytes()).as_ref()[..16]),
        });
        if let Some(nonce) = knobs.nonce.clone().or(nonce) {
            claims["nonce"] = json!(nonce);
        }
        if knobs.email_verified.is_null()
            && let Some(map) = claims.as_object_mut()
        {
            map.remove("email_verified");
        }
        body["id_token"] = json!(self.sign(&knobs, &claims));
        drop(state);
        Reply::json(200, body).header("cache-control", "no-store")
    }

    /// A token with `claims`: signed RS256 with the signing key, or unsigned with `alg_none`.
    fn sign(&self, knobs: &Knobs, claims: &Value) -> String {
        let header = if knobs.alg_none {
            json!({ "alg": "none", "typ": "JWT" })
        } else {
            json!({ "alg": "RS256", "kid": kid(knobs.signing_key), "typ": "JWT" })
        };
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        if knobs.alg_none {
            return format!("{input}.");
        }
        let pair = &self.keys[knobs.signing_key];
        let mut sig = vec![0; pair.public().modulus_len()];
        pair.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{input}.{}", b64(&sig))
    }
}

fn kid(index: usize) -> String {
    format!("oidc-test-key-{index}")
}

fn encode(text: &str) -> String {
    percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn decode(text: &str) -> String {
    percent_encoding::percent_decode_str(&text.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

/// An `application/x-www-form-urlencoded` body.
pub fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(k), decode(v))
        })
        .collect()
}

/// A cookie-keeping browser for driving logins against rdock: it remembers `Set-Cookie`
/// values (ignoring `Secure`, `Domain` and `Path`, which the tests do not need) and removes
/// those set with `Max-Age=0`.
#[derive(Debug, Default, Clone)]
pub struct Browser {
    pub cookies: Vec<(String, String)>,
}

impl Browser {
    /// Takes the cookies of a response.
    pub fn absorb(&mut self, headers: &http::HeaderMap) {
        for value in headers.get_all("set-cookie") {
            let Ok(text) = value.to_str() else { continue };
            let mut parts = text.split(';');
            let Some((name, value)) = parts.next().and_then(|p| p.trim().split_once('=')) else {
                continue;
            };
            let expired = parts.any(|a| a.trim().eq_ignore_ascii_case("max-age=0"));
            self.cookies.retain(|(n, _)| n != name);
            if !expired {
                self.cookies.push((name.to_owned(), value.to_owned()));
            }
        }
    }

    /// The `Cookie` header to send, if any.
    pub fn header(&self) -> Option<String> {
        (!self.cookies.is_empty()).then(|| {
            self.cookies
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    /// The value of cookie `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Sets or replaces a cookie by hand.
    pub fn set(&mut self, name: &str, value: &str) {
        self.cookies.retain(|(n, _)| n != name);
        self.cookies.push((name.to_owned(), value.to_owned()));
    }

    /// Names of the cookies starting with `prefix`.
    pub fn names(&self, prefix: &str) -> Vec<String> {
        self.cookies
            .iter()
            .filter(|(n, _)| n.starts_with(prefix))
            .map(|(n, _)| n.clone())
            .collect()
    }
}
