//! Ingress annotations (ADR-0029, "Ingress"; research §4.2).
//!
//! [`parse`] reads the annotations of one Ingress into [`Annotations`] and a list of
//! [`Note`]s (what was refused or ignored, and why). It is pure and knows nothing about the
//! cluster; the translator turns the result into middlewares.
//!
//! The ingress-nginx annotations (prefix `nginx.ingress.kubernetes.io/`, only while
//! `ingress.nginx_annotations` is on) that map one to one onto the model, with the
//! documentation of each at
//! <https://github.com/kubernetes/ingress-nginx/blob/main/docs/user-guide/nginx-configuration/annotations.md>
//! (read 2026-11-11):
//!
//! | annotation | becomes |
//! |---|---|
//! | `ssl-redirect`, `force-ssl-redirect` | `redirect` to `https` (see the translator) |
//! | `rewrite-target` (no capture groups) | `rewrite` (prefix) or `replace_path` (exact) |
//! | `backend-protocol` | the service's `scheme` |
//! | `proxy-body-size` | the route's `max_body` |
//! | `whitelist-source-range` | `ip_allow` |
//! | `enable-cors`, `cors-allow-origin`, `-methods`, `-headers`, `-credentials`, `-max-age` | `cors` |
//! | `app-root` | `redirect` of `/` |
//! | `permanent-redirect` (+ `-code`), `temporal-redirect` | `redirect` with `regex` |
//!
//! Every other annotation of that prefix gets one warning, every one ending in `-snippet`
//! (raw NGINX configuration) is refused, and `traefik.ingress.kubernetes.io/*` annotations
//! are reported as not supported.

use std::collections::BTreeMap;

use rdock_model::middleware::CorsConfig;
use rdock_model::service::Scheme;
use rdock_model::values::{ByteSize, Duration, IpNetwork};

/// Prefix of the ingress-nginx annotations.
pub const NGINX_PREFIX: &str = "nginx.ingress.kubernetes.io/";
/// Prefix of Traefik's Ingress annotations.
pub const TRAEFIK_PREFIX: &str = "traefik.ingress.kubernetes.io/";
/// The deprecated class annotation.
pub const CLASS_ANNOTATION: &str = "kubernetes.io/ingress.class";

/// What the annotations of one Ingress ask for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Annotations {
    /// `ssl-redirect`: `Some(false)` turns the redirect of TLS hosts off (it is on when the
    /// Ingress has a certificate for the host).
    pub ssl_redirect: Option<bool>,
    /// `force-ssl-redirect`: redirect to HTTPS even for hosts without a certificate.
    pub force_ssl_redirect: bool,
    /// `rewrite-target`, literal.
    pub rewrite_target: Option<String>,
    /// `backend-protocol`.
    pub scheme: Option<Scheme>,
    /// `proxy-body-size`.
    pub max_body: Option<ByteSize>,
    /// `whitelist-source-range`: the allowed networks.
    pub allow: Vec<IpNetwork>,
    /// `whitelist-source-range` was given but no entry is usable: nothing may pass.
    pub deny_all: bool,
    /// `enable-cors` and its settings.
    pub cors: Option<CorsConfig>,
    /// `app-root`.
    pub app_root: Option<String>,
    /// `permanent-redirect` or `temporal-redirect`.
    pub redirect: Option<Redirect>,
}

/// A redirect of the whole Ingress to a fixed URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// The target, `http://…`, `https://…` or a path.
    pub url: String,
    /// 301, 302, 307 or 308.
    pub status: u16,
}

/// A problem with an annotation, for a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The full annotation key.
    pub annotation: String,
    /// What happened to it.
    pub message: String,
}

fn note(annotation: &str, message: impl Into<String>) -> Note {
    Note {
        annotation: annotation.to_owned(),
        message: message.into(),
    }
}

/// The size `proxy-body-size: 0` stands for ("unlimited"): the model has no switch to lift
/// `security.limits.max_body_bytes` on one route, so the largest value is used.
#[must_use]
pub fn unlimited() -> ByteSize {
    "18446744073709551615"
        .parse()
        .unwrap_or_else(|_| ByteSize::mib(u64::from(u32::MAX)))
}

/// Parses an NGINX size (`ngx_parse_size`): digits with an optional `k`, `m` or `g` (either
/// case, powers of 1024); `0` is unlimited ([`unlimited`]).
///
/// # Errors
///
/// When the value is empty, has another unit or a fraction, or does not fit 64 bits.
pub fn parse_size(value: &str) -> Result<ByteSize, String> {
    let value = value.trim();
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let (digits, unit) = value.split_at(split);
    let factor: u64 = match unit {
        "" => 1,
        "k" | "K" => 1 << 10,
        "m" | "M" => 1 << 20,
        "g" | "G" => 1 << 30,
        _ => {
            return Err(format!(
                "`{value}` is not an NGINX size: use digits with an optional k, m or g"
            ));
        }
    };
    let number: u64 = digits.parse().map_err(|_| {
        format!("`{value}` is not an NGINX size: use digits with an optional k, m or g")
    })?;
    if number == 0 {
        return Ok(unlimited());
    }
    let bytes = number
        .checked_mul(factor)
        .ok_or_else(|| format!("size `{value}` is too large"))?;
    format!("{bytes}")
        .parse()
        .map_err(|_| format!("size `{value}` is too large"))
}

fn parse_bool(key: &str, value: &str, notes: &mut Vec<Note>) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => {
            notes.push(note(
                key,
                format!("`{value}` is not `true` or `false`; the annotation is ignored"),
            ));
            None
        }
    }
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|v| !v.is_empty())
}

/// What the `cors-*` annotations say (before `enable-cors` decides).
#[derive(Default)]
struct CorsInput<'a> {
    origin: Option<&'a str>,
    methods: Option<&'a str>,
    headers: Option<&'a str>,
    credentials: Option<&'a str>,
    max_age: Option<&'a str>,
}

/// ingress-nginx's defaults for the CORS annotations (`cors-allow-methods`,
/// `cors-allow-headers`; the origin is `*`).
const DEFAULT_CORS_METHODS: &str = "GET, PUT, POST, DELETE, PATCH, OPTIONS";
const DEFAULT_CORS_HEADERS: &str = "DNT,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization";

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

/// `http://host[:port]` or `https://host[:port]`: no path, query, fragment or wildcard.
fn is_origin(value: &str) -> bool {
    let Some(authority) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    !authority.is_empty()
        && !authority.starts_with(['.', ':'])
        && authority
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

fn cors(input: &CorsInput<'_>, notes: &mut Vec<Note>) -> Option<CorsConfig> {
    let origins_key = format!("{NGINX_PREFIX}cors-allow-origin");
    let mut origins = Vec::new();
    for origin in list(input.origin.unwrap_or("*")) {
        let valid = origin == "*" || is_origin(origin);
        if valid {
            origins.push(origin.to_owned());
        } else {
            notes.push(note(
                &origins_key,
                format!("`{origin}` is not an origin like `https://app.example.com` (regular expressions are not supported); it is left out"),
            ));
        }
    }
    if origins.is_empty() {
        notes.push(note(&origins_key, "no usable origin: CORS is not applied"));
        return None;
    }
    let tokens = |key: &str, value: &str, notes: &mut Vec<Note>| -> Vec<String> {
        let mut out = Vec::new();
        for item in list(value) {
            if is_token(item) {
                out.push(item.to_owned());
            } else {
                notes.push(note(
                    key,
                    format!("`{item}` is not a valid token; it is left out"),
                ));
            }
        }
        out
    };
    let allowed_methods = tokens(
        &format!("{NGINX_PREFIX}cors-allow-methods"),
        input.methods.unwrap_or(DEFAULT_CORS_METHODS),
        notes,
    );
    let allowed_headers = tokens(
        &format!("{NGINX_PREFIX}cors-allow-headers"),
        input.headers.unwrap_or(DEFAULT_CORS_HEADERS),
        notes,
    );
    // ingress-nginx defaults to credentials on; the model refuses them with `*`, and the
    // browsers do too. Credentials are on only when asked for.
    let credentials_key = format!("{NGINX_PREFIX}cors-allow-credentials");
    let mut allow_credentials = input
        .credentials
        .and_then(|v| parse_bool(&credentials_key, v, notes))
        .unwrap_or(false);
    if allow_credentials && origins.iter().any(|o| o == "*") {
        notes.push(note(
            &credentials_key,
            "browsers reject credentials with the `*` origin; list the origins in cors-allow-origin. Credentials are not allowed",
        ));
        allow_credentials = false;
    }
    let max_age_key = format!("{NGINX_PREFIX}cors-max-age");
    let max_age = input.max_age.and_then(|v| {
        let seconds = v.trim().parse::<u64>().ok();
        if seconds.is_none() {
            notes.push(note(
                &max_age_key,
                format!("`{v}` is not a number of seconds; the annotation is ignored"),
            ));
        }
        seconds.map(Duration::from_secs)
    });
    Some(CorsConfig {
        allowed_origins: origins,
        allowed_methods,
        allowed_headers,
        exposed_headers: Vec::new(),
        allow_credentials,
        max_age,
    })
}

/// `whitelist-source-range`: the usable entries are the allow list; with none the Ingress
/// refuses everyone rather than everyone passing.
fn whitelist(key: &str, value: &str, out: &mut Annotations, notes: &mut Vec<Note>) {
    for entry in list(value) {
        match entry.parse::<IpNetwork>() {
            Ok(network) => out.allow.push(network),
            Err(_) => notes.push(note(
                key,
                format!("`{entry}` is not an IP address or CIDR range; it is left out"),
            )),
        }
    }
    out.deny_all = out.allow.is_empty();
    if out.deny_all {
        notes.push(note(
            key,
            "no usable range: every request to this Ingress is refused (403)",
        ));
    }
}

/// `rewrite-target`: a literal path only.
fn rewrite_target(key: &str, value: &str, out: &mut Annotations, notes: &mut Vec<Note>) {
    if value.contains('$') {
        notes.push(note(
            key,
            "rewrite targets with capture groups ($1…) are not supported and the rewrite is not applied; ingress2gateway can convert them",
        ));
    } else if !value.starts_with('/') {
        notes.push(note(
            key,
            format!("`{value}` is not a path starting with `/`; the rewrite is not applied"),
        ));
    } else {
        out.rewrite_target = Some(value.to_owned());
    }
}

/// The whole-Ingress redirect from `permanent-redirect` (with its `-code`) and
/// `temporal-redirect`; the permanent one wins.
fn redirect(
    permanent: Option<(&str, &str)>,
    permanent_code: Option<(&str, &str)>,
    temporal: Option<(&str, &str)>,
    notes: &mut Vec<Note>,
) -> Option<Redirect> {
    let target = |key: &str, value: &str, notes: &mut Vec<Note>| -> Option<String> {
        if value.starts_with("http://") || value.starts_with("https://") || value.starts_with('/') {
            Some(value.to_owned())
        } else {
            notes.push(note(
                key,
                format!("`{value}` is not a URL (http:// or https://) or a path; the redirect is not applied"),
            ));
            None
        }
    };
    if let Some((key, value)) = permanent {
        let mut status = 301;
        if let Some((code_key, code)) = permanent_code {
            match code.trim().parse::<u16>() {
                Ok(c @ (301 | 302 | 307 | 308)) => status = c,
                _ => notes.push(note(
                    code_key,
                    format!("`{code}` is not 301, 302, 307 or 308; 301 is used"),
                )),
            }
        }
        if let Some((temporal_key, _)) = temporal {
            notes.push(note(
                temporal_key,
                "permanent-redirect is also set and takes precedence; this annotation is ignored",
            ));
        }
        return target(key, value, notes).map(|url| Redirect { url, status });
    }
    let (key, value) = temporal?;
    target(key, value, notes).map(|url| Redirect { url, status: 302 })
}

/// Reads the annotations of one Ingress. With `nginx` off the ingress-nginx annotations are
/// ignored, except `*-snippet`, which is always reported.
#[must_use]
pub fn parse(annotations: &BTreeMap<String, String>, nginx: bool) -> (Annotations, Vec<Note>) {
    let mut out = Annotations::default();
    let mut notes = Vec::new();
    let mut cors_enabled = false;
    let mut cors_input = CorsInput::default();
    let mut permanent: Option<(&str, &str)> = None;
    let mut permanent_code: Option<(&str, &str)> = None;
    let mut temporal: Option<(&str, &str)> = None;
    for (key, value) in annotations {
        if let Some(rest) = key.strip_prefix(TRAEFIK_PREFIX) {
            notes.push(note(
                key,
                format!(
                    "Traefik annotation `{rest}` is not supported; use the rdock.* configuration or the Gateway API"
                ),
            ));
            continue;
        }
        let Some(name) = key.strip_prefix(NGINX_PREFIX) else {
            continue;
        };
        if name.ends_with("-snippet") {
            notes.push(note(
                key,
                "raw NGINX configuration is refused; the Ingress is served without it",
            ));
            continue;
        }
        if !nginx {
            continue;
        }
        match name {
            "ssl-redirect" => out.ssl_redirect = parse_bool(key, value, &mut notes),
            "force-ssl-redirect" => {
                out.force_ssl_redirect = parse_bool(key, value, &mut notes).unwrap_or(false);
            }
            "rewrite-target" => rewrite_target(key, value, &mut out, &mut notes),
            "backend-protocol" => match value.trim().to_ascii_uppercase().as_str() {
                "HTTP" => out.scheme = Some(Scheme::Http),
                "HTTPS" | "GRPCS" => out.scheme = Some(Scheme::Https),
                "GRPC" => out.scheme = Some(Scheme::H2c),
                other => notes.push(note(
                    key,
                    format!("backend protocol `{other}` is not supported (use HTTP, HTTPS, GRPC or GRPCS); the Service's appProtocol or HTTP is used"),
                )),
            },
            "proxy-body-size" => match parse_size(value) {
                Ok(size) => out.max_body = Some(size),
                Err(message) => notes.push(note(key, format!("{message}; the annotation is ignored"))),
            },
            "whitelist-source-range" => whitelist(key, value, &mut out, &mut notes),
            "enable-cors" => cors_enabled = parse_bool(key, value, &mut notes).unwrap_or(false),
            "cors-allow-origin" => cors_input.origin = Some(value),
            "cors-allow-methods" => cors_input.methods = Some(value),
            "cors-allow-headers" => cors_input.headers = Some(value),
            "cors-allow-credentials" => cors_input.credentials = Some(value),
            "cors-max-age" => cors_input.max_age = Some(value),
            "app-root" => {
                if value.starts_with('/') {
                    out.app_root = Some(value.clone());
                } else {
                    notes.push(note(
                        key,
                        format!("`{value}` is not a path starting with `/`; the annotation is ignored"),
                    ));
                }
            }
            "permanent-redirect" => permanent = Some((key, value)),
            "permanent-redirect-code" => permanent_code = Some((key, value)),
            "temporal-redirect" => temporal = Some((key, value)),
            other => notes.push(note(
                key,
                format!(
                    "annotation `{other}` is not supported and is ignored; ingress2gateway can convert ingress-nginx annotations to Gateway API resources"
                ),
            )),
        }
    }
    if cors_enabled {
        out.cors = cors(&cors_input, &mut notes);
    }
    out.redirect = redirect(permanent, permanent_code, temporal, &mut notes);
    (out, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(k, v)| (format!("{NGINX_PREFIX}{k}"), (*v).to_owned()))
            .collect()
    }

    fn size(value: &str) -> u64 {
        parse_size(value).unwrap().as_u64()
    }

    #[test]
    fn nginx_sizes() {
        assert_eq!(size("1024"), 1024);
        assert_eq!(size("8m"), 8 << 20);
        assert_eq!(size("8M"), 8 << 20);
        assert_eq!(size("100k"), 100 << 10);
        assert_eq!(size("1g"), 1 << 30);
        assert_eq!(size("0"), u64::MAX);
        assert_eq!(size("0m"), u64::MAX);
        assert_eq!(size(" 2m "), 2 << 20);
        for bad in [
            "",
            "m",
            "1.5m",
            "8mb",
            "-1",
            "1t",
            "99999999999999999999",
            "18446744073709551615g",
        ] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn supported_annotations_are_read() {
        let (a, notes) = parse(
            &map(&[
                ("ssl-redirect", "false"),
                ("force-ssl-redirect", "True"),
                ("rewrite-target", "/new"),
                ("backend-protocol", "grpc"),
                ("proxy-body-size", "16m"),
                ("whitelist-source-range", "10.0.0.0/8, 192.0.2.7,"),
                ("app-root", "/app"),
                ("permanent-redirect", "https://example.org/x"),
            ]),
            true,
        );
        assert_eq!(notes, Vec::new());
        assert_eq!(a.ssl_redirect, Some(false));
        assert!(a.force_ssl_redirect);
        assert_eq!(a.rewrite_target.as_deref(), Some("/new"));
        assert_eq!(a.scheme, Some(Scheme::H2c));
        assert_eq!(a.max_body.map(ByteSize::as_u64), Some(16 << 20));
        assert_eq!(a.allow.len(), 2);
        assert!(!a.deny_all);
        assert_eq!(a.app_root.as_deref(), Some("/app"));
        assert_eq!(
            a.redirect,
            Some(Redirect {
                url: "https://example.org/x".into(),
                status: 301
            })
        );
    }

    #[test]
    fn backend_protocols() {
        for (value, scheme) in [
            ("HTTP", Some(Scheme::Http)),
            ("https", Some(Scheme::Https)),
            ("GRPC", Some(Scheme::H2c)),
            ("GRPCS", Some(Scheme::Https)),
            ("FCGI", None),
            ("AUTO_HTTP", None),
        ] {
            let (a, notes) = parse(&map(&[("backend-protocol", value)]), true);
            assert_eq!(a.scheme, scheme, "{value}");
            assert_eq!(notes.len(), usize::from(scheme.is_none()), "{value}");
        }
    }

    #[test]
    fn rewrite_targets_without_groups_only() {
        let (a, notes) = parse(&map(&[("rewrite-target", "/$2")]), true);
        assert_eq!(a.rewrite_target, None);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].message.contains("capture groups"));
        let (a, notes) = parse(&map(&[("rewrite-target", "relative")]), true);
        assert_eq!((a.rewrite_target, notes.len()), (None, 1));
    }

    #[test]
    fn cors_defaults_and_credentials() {
        let (a, notes) = parse(&map(&[("enable-cors", "true")]), true);
        assert_eq!(notes, Vec::new());
        let cors = a.cors.unwrap();
        assert_eq!(cors.allowed_origins, ["*"]);
        assert_eq!(cors.allowed_methods.len(), 6);
        assert!(cors.allowed_headers.contains(&"Authorization".to_owned()));
        assert!(!cors.allow_credentials);
        assert_eq!(cors.max_age, None);

        let (a, notes) = parse(
            &map(&[
                ("enable-cors", "true"),
                (
                    "cors-allow-origin",
                    "https://a.example.com, https://b.example.com",
                ),
                ("cors-allow-methods", "GET,POST"),
                ("cors-allow-headers", "X-A, X-B"),
                ("cors-allow-credentials", "true"),
                ("cors-max-age", "600"),
            ]),
            true,
        );
        assert_eq!(notes, Vec::new());
        let cors = a.cors.unwrap();
        assert_eq!(cors.allowed_origins.len(), 2);
        assert_eq!(cors.allowed_methods, ["GET", "POST"]);
        assert_eq!(cors.allowed_headers, ["X-A", "X-B"]);
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age, Some(Duration::from_secs(600)));

        // Credentials with `*` are refused; an origin that is a regex is left out.
        let (a, notes) = parse(
            &map(&[("enable-cors", "true"), ("cors-allow-credentials", "true")]),
            true,
        );
        assert!(!a.cors.unwrap().allow_credentials);
        assert_eq!(notes.len(), 1);
        let (a, notes) = parse(
            &map(&[
                ("enable-cors", "true"),
                ("cors-allow-origin", "https://.*\\.example\\.com"),
            ]),
            true,
        );
        assert!(a.cors.is_none());
        assert_eq!(notes.len(), 2);
        // Without enable-cors the cors-* annotations mean nothing and say nothing.
        let (a, notes) = parse(
            &map(&[("cors-allow-origin", "https://a.example.com")]),
            true,
        );
        assert_eq!((a.cors, notes), (None, Vec::new()));
    }

    #[test]
    fn whitelists_fail_closed() {
        let (a, notes) = parse(&map(&[("whitelist-source-range", "10.0.0.0/8,nope")]), true);
        assert_eq!(a.allow.len(), 1);
        assert!(!a.deny_all);
        assert_eq!(notes.len(), 1);
        let (a, notes) = parse(&map(&[("whitelist-source-range", "nope")]), true);
        assert!(a.allow.is_empty() && a.deny_all);
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn redirects() {
        let (a, _) = parse(&map(&[("temporal-redirect", "/elsewhere")]), true);
        assert_eq!(
            a.redirect,
            Some(Redirect {
                url: "/elsewhere".into(),
                status: 302
            })
        );
        let (a, notes) = parse(
            &map(&[
                ("permanent-redirect", "https://x.example.com"),
                ("permanent-redirect-code", "308"),
                ("temporal-redirect", "https://y.example.com"),
            ]),
            true,
        );
        assert_eq!(
            a.redirect.map(|r| (r.url, r.status)),
            Some(("https://x.example.com".to_owned(), 308))
        );
        assert_eq!(notes.len(), 1);
        let (a, notes) = parse(&map(&[("permanent-redirect", "ftp://x")]), true);
        assert_eq!((a.redirect, notes.len()), (None, 1));
        let (a, notes) = parse(
            &map(&[
                ("permanent-redirect", "/x"),
                ("permanent-redirect-code", "200"),
            ]),
            true,
        );
        assert_eq!(a.redirect.map(|r| r.status), Some(301));
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn unsupported_snippets_and_traefik() {
        let mut annotations = map(&[
            ("limit-rps", "5"),
            ("configuration-snippet", "more_set_headers x;"),
            ("server-snippet", "x"),
        ]);
        annotations.insert(
            "traefik.ingress.kubernetes.io/router.entrypoints".into(),
            "websecure".into(),
        );
        annotations.insert("cert-manager.io/cluster-issuer".into(), "le".into());
        let (a, notes) = parse(&annotations, true);
        assert_eq!(a, Annotations::default());
        let messages: Vec<&str> = notes.iter().map(|n| n.annotation.as_str()).collect();
        assert_eq!(
            messages,
            [
                "nginx.ingress.kubernetes.io/configuration-snippet",
                "nginx.ingress.kubernetes.io/limit-rps",
                "nginx.ingress.kubernetes.io/server-snippet",
                "traefik.ingress.kubernetes.io/router.entrypoints",
            ]
        );
        assert!(notes[1].message.contains("ingress2gateway"));
        assert!(notes[0].message.contains("refused"));

        // nginx annotations off: only snippets and Traefik annotations are reported.
        let (a, notes) = parse(&annotations, false);
        assert_eq!(a, Annotations::default());
        assert_eq!(notes.len(), 3);
        let (a, notes) = parse(
            &map(&[("ssl-redirect", "true"), ("proxy-body-size", "1m")]),
            false,
        );
        assert_eq!((a, notes), (Annotations::default(), Vec::new()));
    }
}
