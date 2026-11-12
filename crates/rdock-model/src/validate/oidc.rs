//! `oidc` (F-GW-01, ADR-0030): the settings of the relying party and how routes use it.

use std::collections::BTreeMap;

use rdock_rules::Expr;

use super::{Validator, reference_key};
use crate::diagnostics::{Diagnostic, path_index};
use crate::middleware::Middleware;
use crate::oidc::{OidcConfig, OidcSameSite};
use crate::route::{Route, RouteTls, TlsMode};
use crate::values::is_token;

/// Headers `oidc` sets itself, which `claims_to_headers` cannot name.
const RESERVED_HEADERS: [&str; 4] = [
    "cookie",
    "authorization",
    "host",
    "x-forwarded-access-token",
];

/// Whether `path` is an absolute path that cannot be read as another origin.
fn is_local_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && !path.contains(['?', '#'])
        && !path.chars().any(char::is_control)
}

impl Validator<'_> {
    pub(super) fn check_oidc(&mut self, path: &str, oidc: &OidcConfig) {
        if !oidc.issuer.is_https_or_loopback() {
            self.push(
                Diagnostic::error(
                    format!("{path}.issuer"),
                    "the issuer must be an https:// URL (http:// only to a loopback address)",
                )
                .with_hint("tokens and the provider's keys would travel unprotected"),
            );
        }
        if oidc.issuer.as_url().query().is_some() || oidc.issuer.as_url().fragment().is_some() {
            self.error(
                format!("{path}.issuer"),
                "an issuer has no query or fragment (OpenID Connect Discovery §2)",
            );
        }
        if oidc.client_id.trim().is_empty() {
            self.error(format!("{path}.client_id"), "the client ID is empty");
        }
        if let Some(secret) = &oidc.client_secret {
            self.check_secret_reference(
                &format!("{path}.client_secret"),
                secret,
                "oidc_client_secret",
            );
        }
        if !oidc.scopes.iter().any(|s| s == "openid") {
            self.error(format!("{path}.scopes"), "the scopes must include `openid`");
        }
        for (i, scope) in oidc.scopes.iter().enumerate() {
            if scope.is_empty()
                || scope
                    .chars()
                    .any(|c| c.is_whitespace() || c == '"' || c == '\\')
            {
                self.error(
                    path_index(&format!("{path}.scopes"), i),
                    "a scope is one word without spaces or quotes",
                );
            }
        }
        for (field, value) in [
            ("redirect_path", &oidc.redirect_path),
            ("logout_path", &oidc.logout_path),
            ("post_logout_path", &oidc.post_logout_path),
        ] {
            if !is_local_path(value) {
                self.error(
                    format!("{path}.{field}"),
                    "use an absolute path such as `/_rdock/oidc/callback` (no query, no `//`)",
                );
            }
        }
        let callback = oidc.callback_path();
        if callback == oidc.logout_path {
            self.error(
                format!("{path}.logout_path"),
                "the logout path is the same as the callback path",
            );
        }
        if let Some(url) = &oidc.redirect_url {
            if !url.is_https_or_loopback() && oidc.session.secure {
                self.error(
                    format!("{path}.redirect_url"),
                    "the redirect URL must be https:// (the authorization code travels in it)",
                );
            }
            if url.as_url().query().is_some() || url.as_url().fragment().is_some() {
                self.error(
                    format!("{path}.redirect_url"),
                    "a redirect URI has no query or fragment",
                );
            }
        }
        self.check_oidc_session(path, oidc);
        self.check_oidc_identity(path, oidc);
    }

    fn check_oidc_identity(&mut self, path: &str, oidc: &OidcConfig) {
        for (claim, header) in &oidc.claims_to_headers {
            let at = format!("{path}.claims_to_headers.{claim}");
            if !is_token(header) {
                self.error(&at, format!("`{header}` is not a header name"));
            } else if RESERVED_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
                self.error(&at, format!("`{header}` cannot be set from a claim"));
            }
        }
        if oidc.consumer_claim.trim().is_empty() {
            self.error(format!("{path}.consumer_claim"), "name a claim");
        }
        if oidc.groups_claim.trim().is_empty() {
            self.error(format!("{path}.groups_claim"), "name a claim");
        }
        for (i, domain) in oidc.allowed.domains.iter().enumerate() {
            if domain.is_empty() || domain.contains('@') || domain.starts_with('.') {
                self.error(
                    path_index(&format!("{path}.allowed.domains"), i),
                    "an e-mail domain such as `example.com`",
                );
            }
        }
        for (i, email) in oidc.allowed.emails.iter().enumerate() {
            if !email.contains('@') {
                self.error(
                    path_index(&format!("{path}.allowed.emails"), i),
                    "an e-mail address",
                );
            }
        }
        if oidc.algorithms.is_empty() {
            self.error(format!("{path}.algorithms"), "list at least one algorithm");
        }
        if oidc.algorithms.iter().any(|a| a.is_hmac()) {
            if oidc.client_secret.is_none() {
                self.error(
                    format!("{path}.algorithms"),
                    "HS256/HS384/HS512 ID tokens are verified with the client secret, and there is none",
                );
            } else {
                self.warning(
                    format!("{path}.algorithms"),
                    "HMAC-signed ID tokens are accepted: anyone who knows the client secret can make one",
                );
            }
        }
        if oidc.leeway.as_std() > std::time::Duration::from_secs(300) {
            self.warning(
                format!("{path}.leeway"),
                "a leeway above 5 minutes accepts expired tokens for long",
            );
        }
        if oidc.allow_private_targets {
            self.warning(
                format!("{path}.allow_private_targets"),
                "the provider may be reached on private addresses; make sure the issuer is trusted",
            );
        }
    }

    fn check_oidc_session(&mut self, path: &str, oidc: &OidcConfig) {
        let session = &oidc.session;
        let at = format!("{path}.session");
        let sources = usize::from(session.key.is_some())
            + usize::from(!session.keys.is_empty())
            + usize::from(session.key_file.is_some());
        if sources == 0 {
            self.push(
                Diagnostic::error(
                    format!("{at}.key"),
                    "the session cookie needs a key of at least 32 bytes",
                )
                .with_hint("e.g. `key: \"${file:/run/secrets/oidc_session_key}\"` with the output of `openssl rand -base64 48`; every replica needs the same key"),
            );
        } else if sources > 1 {
            self.error(
                format!("{at}.key"),
                "set one of `key`, `keys` and `key_file`",
            );
        }
        if let Some(key) = &session.key {
            self.check_secret_reference(&format!("{at}.key"), key, "oidc_session_key");
        }
        for (i, key) in session.keys.iter().enumerate() {
            self.check_secret_reference(
                &path_index(&format!("{at}.keys"), i),
                key,
                "oidc_session_key",
            );
        }
        if !is_token(&session.cookie_name) || session.cookie_name.starts_with("__") {
            self.error(
                format!("{at}.cookie_name"),
                "a cookie name of letters, digits, `-`, `_` and `.`, without the `__Host-`/`__Secure-` prefix (rdock adds it)",
            );
        }
        let ttl = session.ttl.as_std();
        if ttl < std::time::Duration::from_secs(60) {
            self.error(format!("{at}.ttl"), "use at least 1m");
        } else if ttl > std::time::Duration::from_secs(30 * 24 * 3600) {
            self.warning(
                format!("{at}.ttl"),
                "a session longer than 30 days cannot be revoked before it ends (sessions are stateless)",
            );
        }
        match session.same_site {
            OidcSameSite::Strict => self.push(
                Diagnostic::error(
                    format!("{at}.same_site"),
                    "`strict` cookies are not sent on the redirect back from the provider, so every login would start again",
                )
                .with_hint("use `lax` (the default)"),
            ),
            OidcSameSite::None if !session.secure => self.error(
                format!("{at}.same_site"),
                "`same_site: none` needs `secure: true` (browsers drop such cookies otherwise)",
            ),
            _ => {}
        }
        if !session.secure && !session.allow_insecure_cookies {
            self.push(
                Diagnostic::error(
                    format!("{at}.secure"),
                    "the session cookie would be sent without TLS, where anyone on the network can copy it",
                )
                .with_hint("keep `secure: true`; for local development over plain HTTP also set `allow_insecure_cookies: true`"),
            );
        } else if !session.secure {
            self.warning(
                format!("{at}.secure"),
                "the session cookie is sent over plain HTTP; use this for local development only",
            );
        }
        if session.secure && session.allow_insecure_cookies {
            self.warning(
                format!("{at}.allow_insecure_cookies"),
                "unused: `secure` is on",
            );
        }
        if let Some(domain) = &session.domain
            && (domain.is_empty() || domain.contains(['/', ':', ' ', ';']))
        {
            self.error(format!("{at}.domain"), "a domain such as `example.com`");
        }
    }

    /// Two `oidc` middlewares with the same cookie name would read each other's sessions
    /// (and refuse them) on a host they share.
    pub(super) fn check_oidc_cookie_names(&mut self) {
        let mut seen: BTreeMap<String, &str> = BTreeMap::new();
        for (name, middleware) in &self.config.middlewares {
            let Middleware::Oidc(oidc) = middleware else {
                continue;
            };
            if let Some(other) = seen.insert(oidc.session.cookie_name.clone(), name) {
                self.warning(
                    format!("{}.session.cookie_name", crate::diagnostics::path_key("middlewares", name)),
                    format!("`{other}` uses the same cookie name; on a host both serve, each would refuse the other's session"),
                );
            }
        }
    }

    /// A route using `oidc`: the redirect URI is built only from hosts the route's rule names
    /// (never from an unchecked `Host` header), and `secure: false` only on plain routes.
    pub(super) fn check_route_oidc(&mut self, path: &str, route: &Route, expr: Option<&Expr>) {
        let mut count = 0;
        for (i, reference) in route.middlewares.iter().enumerate() {
            let Some(Middleware::Oidc(oidc)) =
                self.config.middlewares.get(reference_key(reference))
            else {
                continue;
            };
            count += 1;
            let at = path_index(&format!("{path}.middlewares"), i);
            if count == 2 {
                self.error(&at, "a route logs in with one `oidc` middleware");
            }
            if oidc.redirect_url.is_none()
                && let Some(expr) = expr
            {
                let hosts = expr.positive_hosts();
                if hosts.is_empty() || hosts.contains(&"*") {
                    self.push(
                        Diagnostic::error(
                            &at,
                            format!("`{reference}` needs the hosts its redirect URI may use: this route's rule has no `Host` matcher"),
                        )
                        .with_hint(format!("add `Host(`app.example.com`)` to the rule, or set `redirect_url` on `{reference}`")),
                    );
                }
            }
            let plain = match &route.tls {
                None => self.config.defaults.tls == TlsMode::Off,
                Some(RouteTls::Mode(mode)) => *mode == TlsMode::Off,
                Some(RouteTls::Options(_)) => false,
            };
            if !oidc.session.secure && !plain {
                self.error(
                    &at,
                    format!("`{reference}` has `session.secure: false`, which is allowed on plain-HTTP routes only"),
                );
            }
        }
    }
}
