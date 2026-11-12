//! OpenID Connect login (`type: oidc`, F-GW-01, ADR-0030): a relying party with the
//! authorization code flow and PKCE, and a stateless session in an encrypted cookie.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::middleware::JwtAlgorithm;
use crate::values::{Duration, HttpUrl};

/// OpenID Connect login (`type: oidc`).
///
/// Browsers without a session are sent to the provider's login page (authorization code flow
/// with PKCE S256, `state` and `nonce`); the ID token is verified and the identity kept in an
/// encrypted, authenticated cookie, so no session store is needed and any number of replicas
/// that share `session.keys` accept it. Requests that are not page navigations get `401`
/// instead of a redirect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(inline)]
pub struct OidcConfig {
    /// The provider's issuer URL; its configuration is read from
    /// `<issuer>/.well-known/openid-configuration`. `https://` (or a loopback address).
    pub issuer: HttpUrl,
    /// The client ID registered at the provider.
    pub client_id: String,
    /// The client secret, as a `${file:…}`, `${env:…}` or `${vault:…}` reference. Without it
    /// rdock is a public client and relies on PKCE alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// How the client authenticates at the token endpoint when it has a secret.
    #[serde(default)]
    pub token_endpoint_auth: TokenEndpointAuth,
    /// Scopes requested; must include `openid`. Add `offline_access` where the provider needs
    /// it for refresh tokens.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Path of the callback the provider redirects back to. The route must match it.
    #[serde(default = "default_redirect_path")]
    pub redirect_path: String,
    /// The full redirect URI registered at the provider, when it cannot be built from the
    /// request (a route without a `Host` rule, a port the browser does not see). Its path
    /// replaces `redirect_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<HttpUrl>,
    /// Path that ends the session; the provider's `end_session_endpoint` is called when it
    /// advertises one (RP-initiated logout).
    #[serde(default = "default_logout_path")]
    pub logout_path: String,
    /// Where the browser lands after logging out (a path on the same host).
    #[serde(default = "default_post_logout_path")]
    pub post_logout_path: String,
    /// The session cookie.
    pub session: OidcSession,
    /// Request headers set from ID-token claims (`claim: header`). Client-sent copies are
    /// always removed first.
    #[serde(default)]
    pub claims_to_headers: BTreeMap<String, String>,
    /// The claim that becomes the request's consumer (rate limits, quotas, the cache key,
    /// the access log). `sub` is used when the token lacks it.
    #[serde(default = "default_consumer_claim")]
    pub consumer_claim: String,
    /// The claim that lists the user's groups (a string or an array of strings).
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Who may log in. Everyone the provider authenticates when all lists are empty;
    /// otherwise a user matching any one entry.
    #[serde(default)]
    pub allowed: OidcAllowed,
    /// Requests without a valid session: `auto` redirects page navigations (`GET`/`HEAD`
    /// asking for `text/html`) to the login and answers `401` to everything else, so API
    /// and XHR clients never get a redirect; `redirect` always redirects `GET` and `HEAD`;
    /// `deny` always answers `401`.
    #[serde(default)]
    pub unauthenticated: Unauthenticated,
    /// Pass the access token to the backend in `X-Forwarded-Access-Token`. It is then kept
    /// in the session cookie, which grows.
    #[serde(default)]
    pub forward_access_token: bool,
    /// Allow the provider's endpoints to resolve to private, loopback or link-local
    /// addresses (an in-cluster Keycloak or Dex). Off by default.
    #[serde(default)]
    pub allow_private_targets: bool,
    /// ID-token algorithms accepted: those the provider advertises in
    /// `id_token_signing_alg_values_supported` and that are listed here. HS256/384/512 use
    /// the client secret as key and are accepted only when listed explicitly.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<JwtAlgorithm>,
    /// Clock skew allowed for `exp`, `iat` and `nbf`.
    #[serde(default = "sixty_seconds")]
    pub leeway: Duration,
}

/// Token endpoint client authentication (OpenID Connect Core §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuth {
    /// HTTP Basic with the client ID and secret.
    #[default]
    ClientSecretBasic,
    /// The client ID and secret in the form body.
    ClientSecretPost,
}

/// What `oidc` does with a request that has no valid session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Unauthenticated {
    /// Redirect page navigations to the login; `401` for everything else.
    #[default]
    Auto,
    /// Redirect every `GET` and `HEAD` to the login; `401` for other methods.
    Redirect,
    /// Always `401`.
    Deny,
}

/// The `SameSite` attribute of the session cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OidcSameSite {
    /// Sent on same-site requests and top-level navigations from other sites.
    #[default]
    Lax,
    /// Sent only on same-site requests. Refused: the browser would not send it on the
    /// redirect back from the provider, and the login would loop.
    Strict,
    /// Sent on every request (needs `secure`).
    None,
}

/// The session cookie of `oidc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcSession {
    /// Name of the cookie, without prefix. `__Host-` is prepended when `secure` is on and no
    /// `domain` is set, `__Secure-` when `secure` is on with a `domain`.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    /// The key that encrypts the cookie (at least 32 bytes), as a `${file:…}`, `${env:…}` or
    /// `${vault:…}` reference. Every replica needs the same key. Use `keys` to rotate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Keys for rotation: the first encrypts, all decrypt. References, as `key`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// A file holding the key (read on every reload), instead of `key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_file: Option<std::path::PathBuf>,
    /// Longest session, from login. Without a refresh token the session also ends when the
    /// ID token expires.
    #[serde(default = "eight_hours")]
    pub ttl: Duration,
    /// The cookie's `SameSite` attribute.
    #[serde(default)]
    pub same_site: OidcSameSite,
    /// Send the cookie over HTTPS only. Turning it off is refused unless every route using
    /// the middleware is plain HTTP and `allow_insecure_cookies` is set.
    #[serde(default = "crate::defaults::yes")]
    pub secure: bool,
    /// Explicit opt-in for `secure: false` (local development without TLS).
    #[serde(default)]
    pub allow_insecure_cookies: bool,
    /// Share the cookie with subdomains of this domain. Host-only (and `__Host-`) when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Use the refresh token, when the provider issues one, to renew the session before the
    /// tokens expire; a failed refresh means a new login.
    #[serde(default = "crate::defaults::yes")]
    pub refresh: bool,
}

/// Who may log in.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct OidcAllowed {
    /// E-mail addresses (the verified `email` claim), compared without case.
    pub emails: Vec<String>,
    /// E-mail domains (the part after `@` of the verified `email` claim).
    pub domains: Vec<String>,
    /// Groups from `groups_claim`.
    pub groups: Vec<String>,
    /// Also match `emails` and `domains` against an `email` claim that comes without
    /// `email_verified` (some providers never send it). Off: only `email_verified: true`
    /// counts.
    pub unverified_emails: bool,
}

impl OidcAllowed {
    /// Whether no list restricts the login.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.emails.is_empty() && self.domains.is_empty() && self.groups.is_empty()
    }
}

impl OidcConfig {
    /// The cookie name with its prefix.
    #[must_use]
    pub fn cookie_base(&self) -> String {
        let prefix = match (self.session.secure, &self.session.domain) {
            (true, None) => "__Host-",
            (true, Some(_)) => "__Secure-",
            (false, _) => "",
        };
        format!("{prefix}{}", self.session.cookie_name)
    }

    /// The callback path: `redirect_url`'s path when set, otherwise `redirect_path`.
    #[must_use]
    pub fn callback_path(&self) -> String {
        self.redirect_url.as_ref().map_or_else(
            || self.redirect_path.clone(),
            |u| u.as_url().path().to_owned(),
        )
    }

    /// The key references in rotation order (current first).
    #[must_use]
    pub fn key_references(&self) -> Vec<String> {
        let mut out: Vec<String> = self.session.key.iter().cloned().collect();
        out.extend(self.session.keys.iter().cloned());
        out
    }
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "email".to_owned(),
        "profile".to_owned(),
    ]
}

fn default_redirect_path() -> String {
    "/_rdock/oidc/callback".to_owned()
}

fn default_logout_path() -> String {
    "/_rdock/oidc/logout".to_owned()
}

fn default_post_logout_path() -> String {
    "/".to_owned()
}

fn default_cookie_name() -> String {
    "rdock_oidc".to_owned()
}

fn default_consumer_claim() -> String {
    "email".to_owned()
}

fn default_groups_claim() -> String {
    "groups".to_owned()
}

fn default_algorithms() -> Vec<JwtAlgorithm> {
    vec![
        JwtAlgorithm::Rs256,
        JwtAlgorithm::Rs384,
        JwtAlgorithm::Rs512,
        JwtAlgorithm::Ps256,
        JwtAlgorithm::Ps384,
        JwtAlgorithm::Ps512,
        JwtAlgorithm::Es256,
        JwtAlgorithm::Es384,
        JwtAlgorithm::EdDsa,
    ]
}

const fn sixty_seconds() -> Duration {
    Duration::from_secs(60)
}

const fn eight_hours() -> Duration {
    Duration::from_secs(8 * 3600)
}
