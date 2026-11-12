//! `redirect`: redirects built from the request (scheme, host name, port, full path or path
//! prefix, as the Gateway API's `RequestRedirect`) and regular-expression redirects, with
//! Traefik's status codes (301/308 permanent, 302/307 temporary; the second code for methods
//! other than GET) unless a status is configured.

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Method};
use pingora::http::RequestHeader;
use rdock_model::middleware::{RedirectConfig, RedirectScheme};
use regex::Regex;

use crate::{BuildError, Context, Flow, Middleware, Reply};

#[derive(Debug)]
enum Target {
    /// A URL built from the request with some parts replaced.
    Built(Parts),
    Regex {
        regex: Regex,
        replacement: String,
    },
}

/// The parts of the target URL that replace the request's.
#[derive(Debug)]
struct Parts {
    scheme: Option<RedirectScheme>,
    /// Redirect even when the request already uses `scheme`.
    always: bool,
    hostname: Option<String>,
    port: Option<u16>,
    path: Option<PathChange>,
}

#[derive(Debug)]
enum PathChange {
    Full(String),
    Prefix { from: String, to: String },
}

/// The `redirect` middleware.
#[derive(Debug)]
pub(crate) struct Redirect {
    target: Target,
    permanent: bool,
    status: Option<u16>,
}

impl Redirect {
    pub(crate) fn new(config: &RedirectConfig) -> Result<Self, BuildError> {
        let path = match (&config.path, &config.prefix) {
            (Some(full), None) => Some(PathChange::Full(full.clone())),
            (None, Some(prefix)) => Some(PathChange::Prefix {
                from: prefix.from.clone(),
                to: prefix.to.clone(),
            }),
            (None, None) => None,
            (Some(_), Some(_)) => {
                return Err(BuildError::Invalid(
                    "set `path` or `prefix`, not both".to_owned(),
                ));
            }
        };
        let built = config.scheme.is_some()
            || config.hostname.is_some()
            || config.port.is_some()
            || path.is_some();
        let target = match (built, &config.regex, &config.replacement) {
            (true, None, None) => Target::Built(Parts {
                scheme: config.scheme,
                always: config.always,
                hostname: config.hostname.clone(),
                port: config.port,
                path,
            }),
            (false, Some(regex), Some(replacement)) => Target::Regex {
                regex: Regex::new(regex).map_err(|e| BuildError::Invalid(e.to_string()))?,
                replacement: replacement.clone(),
            },
            _ => {
                return Err(BuildError::Invalid(
                    "set `scheme`, `hostname`, `port`, `path` or `prefix`, or `regex` with `replacement`"
                        .to_owned(),
                ));
            }
        };
        if let Some(status) = config.status
            && !matches!(status, 301 | 302 | 303 | 307 | 308)
        {
            return Err(BuildError::Invalid(format!(
                "`{status}` is not a redirect status"
            )));
        }
        Ok(Self {
            target,
            permanent: config.permanent,
            status: config.status,
        })
    }

    fn location(&self, req: &RequestHeader, cx: &Context) -> Option<String> {
        let path_and_query = req.uri.path_and_query().map_or("/", |p| p.as_str());
        match &self.target {
            Target::Built(parts) => {
                let current = current_scheme(req, cx);
                let scheme = match parts.scheme {
                    Some(RedirectScheme::Http) => "http",
                    Some(RedirectScheme::Https) => "https",
                    None => current,
                };
                // A scheme redirect alone leaves requests that already use the scheme alone,
                // unless it is `always` sent (the Gateway API's `RequestRedirect`).
                if parts.scheme.is_some()
                    && !parts.always
                    && scheme == current
                    && parts.hostname.is_none()
                    && parts.path.is_none()
                {
                    return None;
                }
                let host = parts
                    .hostname
                    .as_deref()
                    .unwrap_or_else(|| host_without_port(&cx.authority));
                // Gateway API `RequestRedirect`: without a port, a new scheme uses its default
                // port and an unchanged scheme keeps the request's port.
                let port = match (parts.port, parts.scheme) {
                    (Some(port), _) => Some(port),
                    (None, Some(_)) => None,
                    (None, None) => port_of(&cx.authority),
                };
                let default_port = if scheme == "https" { 443 } else { 80 };
                let authority = match port {
                    Some(p) if p != default_port => format!("{host}:{p}"),
                    _ => host.to_owned(),
                };
                let path = req.uri.path();
                let new_path = match &parts.path {
                    None => path.to_owned(),
                    Some(PathChange::Full(full)) => full.clone(),
                    Some(PathChange::Prefix { from, to }) => {
                        replace_prefix(path, from, to).unwrap_or_else(|| path.to_owned())
                    }
                };
                let query = req
                    .uri
                    .query()
                    .map_or_else(String::new, |q| format!("?{q}"));
                if parts.path.is_none() {
                    return Some(format!("{scheme}://{authority}{path_and_query}"));
                }
                Some(format!("{scheme}://{authority}{new_path}{query}"))
            }
            Target::Regex { regex, replacement } => {
                let scheme = if cx.tls { "https" } else { "http" };
                let url = format!("{scheme}://{}{path_and_query}", cx.authority);
                let captures = regex.captures(&url)?;
                let mut target = String::new();
                captures.expand(replacement, &mut target);
                (target != url).then_some(target)
            }
        }
    }
}

/// `path` with its leading `from` replaced by `to`, matching whole path segments (the Gateway
/// API's `ReplacePrefixMatch`): `/a` → `/b` turns `/a/x` into `/b/x` and `/a` into `/b`; a
/// trailing `/` on either side never doubles a slash, and an empty result is `/`. `None` when
/// `from` is not a prefix of `path`.
pub(crate) fn replace_prefix(path: &str, from: &str, to: &str) -> Option<String> {
    let from = from.trim_end_matches('/');
    let rest = if from.is_empty() {
        path
    } else if path == from {
        ""
    } else {
        let rest = path.strip_prefix(from)?;
        if !rest.starts_with('/') {
            return None;
        }
        rest
    };
    let replaced = format!("{}{rest}", to.trim_end_matches('/'));
    Some(if replaced.is_empty() {
        "/".to_owned()
    } else {
        replaced
    })
}

/// The port of a `Host` value, when it has one.
fn port_of(authority: &str) -> Option<u16> {
    let after_host = match authority.strip_prefix('[') {
        Some(v6) => v6.split_once(']').map_or("", |(_, rest)| rest),
        None => authority.rsplit_once(':').map_or("", |(_, port)| port),
    };
    let port = after_host.strip_prefix(':').unwrap_or(after_host);
    port.parse().ok()
}

/// `https` for TLS connections, then `X-Forwarded-Proto` (already sanitised for untrusted
/// peers) decides, as in Traefik.
fn current_scheme(req: &RequestHeader, cx: &Context) -> &'static str {
    let forwarded = req
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok());
    match forwarded {
        Some(p) if p.eq_ignore_ascii_case("https") || p.eq_ignore_ascii_case("wss") => "https",
        Some(p) if p.eq_ignore_ascii_case("http") || p.eq_ignore_ascii_case("ws") => "http",
        _ if cx.tls => "https",
        _ => "http",
    }
}

/// The host part of a `Host` value (IPv6 brackets kept).
pub(crate) fn host_without_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority
            .find(']')
            .map_or(authority, |end| &authority[..=end]);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// The redirect status for `method`.
pub(crate) fn status(permanent: bool, method: &Method) -> u16 {
    match (permanent, method == Method::GET) {
        (true, true) => 301,
        (true, false) => 308,
        (false, true) => 302,
        (false, false) => 307,
    }
}

#[async_trait]
impl Middleware for Redirect {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let Some(location) = self.location(req, cx) else {
            return Flow::Next;
        };
        let Ok(value) = HeaderValue::from_str(&location) else {
            return Flow::Next;
        };
        Flow::Reply(Reply {
            status: self
                .status
                .unwrap_or_else(|| status(self.permanent, &req.method)),
            headers: vec![(http::header::LOCATION, value)],
            body: Some(Bytes::new().into()),
            problem: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use rdock_model::middleware::RedirectPrefix;

    use super::*;
    use crate::test_support::{block_on, cx, reply_header, request};

    fn scheme(scheme: RedirectScheme, port: Option<u16>, permanent: bool) -> Redirect {
        Redirect::new(&RedirectConfig {
            scheme: Some(scheme),
            permanent,
            port,
            ..config()
        })
        .unwrap()
    }

    fn config() -> RedirectConfig {
        RedirectConfig {
            scheme: None,
            hostname: None,
            path: None,
            prefix: None,
            regex: None,
            replacement: None,
            permanent: false,
            status: None,
            port: None,
            always: false,
        }
    }

    fn run(mw: &Redirect, method: &str, target: &str, tls: bool) -> Flow {
        let mut req = request(method, target, &[]);
        let mut c = cx();
        c.tls = tls;
        c.authority = "app.example.com:8080".to_owned();
        block_on(mw.request(&mut req, &mut c))
    }

    #[test]
    fn an_always_redirect_is_sent_on_the_same_scheme() {
        // The Gateway API's `RequestRedirect` on an HTTPS listener: `scheme: https` (with or
        // without a port) is a redirect, not a no-op.
        let gateway = |port| {
            Redirect::new(&RedirectConfig {
                scheme: Some(RedirectScheme::Https),
                port,
                status: Some(302),
                always: true,
                ..config()
            })
            .unwrap()
        };
        let Flow::Reply(reply) = run(&gateway(Some(8443)), "GET", "/a?b=1", true) else {
            panic!("expected a redirect")
        };
        assert_eq!(reply.status, 302);
        assert_eq!(
            reply_header(&reply, "location"),
            Some("https://app.example.com:8443/a?b=1")
        );
        let Flow::Reply(reply) = run(&gateway(None), "GET", "/", true) else {
            panic!("expected a redirect")
        };
        assert_eq!(
            reply_header(&reply, "location"),
            Some("https://app.example.com/")
        );
        // The legacy scheme form (file configuration, Ingress `ssl-redirect`) still leaves a
        // request on that scheme alone, with a port or a status.
        let legacy = Redirect::new(&RedirectConfig {
            scheme: Some(RedirectScheme::Https),
            port: Some(8443),
            status: Some(308),
            ..config()
        })
        .unwrap();
        assert_eq!(run(&legacy, "GET", "/", true), Flow::Next);
    }

    #[test]
    fn scheme_redirects_drop_the_port_and_keep_the_path() {
        let mw = scheme(RedirectScheme::Https, None, true);
        let Flow::Reply(reply) = run(&mw, "GET", "/a?b=1", false) else {
            panic!("expected a redirect")
        };
        assert_eq!(reply.status, 301);
        assert_eq!(
            reply_header(&reply, "location"),
            Some("https://app.example.com/a?b=1")
        );
        assert_eq!(run(&mw, "GET", "/", true), Flow::Next, "already https");
        let Flow::Reply(post) = run(&mw, "POST", "/", false) else {
            panic!("expected a redirect")
        };
        assert_eq!(post.status, 308);
        let ported = scheme(RedirectScheme::Https, Some(8443), false);
        let Flow::Reply(reply) = run(&ported, "GET", "/", false) else {
            panic!("expected a redirect")
        };
        assert_eq!(reply.status, 302);
        assert_eq!(
            reply_header(&reply, "location"),
            Some("https://app.example.com:8443/")
        );
    }

    #[test]
    fn regex_redirects_expand_groups() {
        let mw = Redirect::new(&RedirectConfig {
            regex: Some("^http://app\\.example\\.com:8080/(.*)$".into()),
            replacement: Some("https://www.example.com/${1}".into()),
            ..config()
        })
        .unwrap();
        let Flow::Reply(reply) = run(&mw, "PUT", "/x/y?z", false) else {
            panic!("expected a redirect")
        };
        assert_eq!(reply.status, 307);
        assert_eq!(
            reply_header(&reply, "location"),
            Some("https://www.example.com/x/y?z")
        );
        assert_eq!(run(&mw, "GET", "/", true), Flow::Next, "no match");
    }

    /// `(status, Location)` of a redirect on `authority`, or `None` when it passes.
    fn answer(
        mw: &Redirect,
        method: &str,
        authority: &str,
        target: &str,
        tls: bool,
    ) -> Option<(u16, String)> {
        let mut req = request(method, target, &[]);
        let mut c = cx();
        c.tls = tls;
        c.authority = authority.to_owned();
        match block_on(mw.request(&mut req, &mut c)) {
            Flow::Reply(reply) => Some((
                reply.status,
                reply_header(&reply, "location").unwrap().to_owned(),
            )),
            Flow::Next => None,
        }
    }

    fn prefix(from: &str, to: &str) -> RedirectPrefix {
        RedirectPrefix {
            from: from.into(),
            to: to.into(),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one table of cases, read top to bottom
    fn built_redirects_follow_the_gateway_api() {
        let host = |hostname: &str| RedirectConfig {
            hostname: Some(hostname.into()),
            status: Some(302),
            ..config()
        };
        // (config, request method, Host, target, tls) → (status, Location)
        let cases: Vec<(RedirectConfig, &str, &str, &str, bool, u16, &str)> = vec![
            // Hostname only: scheme and the request's port are kept, the query too.
            (
                host("example.org"),
                "GET",
                "a.test",
                "/x?y=1",
                false,
                302,
                "http://example.org/x?y=1",
            ),
            (
                host("example.org"),
                "GET",
                "a.test:8080",
                "/",
                false,
                302,
                "http://example.org:8080/",
            ),
            (
                host("example.org"),
                "GET",
                "a.test:443",
                "/",
                true,
                302,
                "https://example.org/",
            ),
            // A new scheme without a port uses its default port, which is left out.
            (
                RedirectConfig {
                    scheme: Some(RedirectScheme::Https),
                    hostname: Some("example.org".into()),
                    ..config()
                },
                "GET",
                "a.test:8080",
                "/p",
                false,
                302,
                "https://example.org/p",
            ),
            (
                RedirectConfig {
                    scheme: Some(RedirectScheme::Http),
                    status: Some(301),
                    ..config()
                },
                "GET",
                "a.test:8443",
                "/p",
                true,
                301,
                "http://a.test/p",
            ),
            // An explicit port is written unless it is the scheme's default.
            (
                RedirectConfig {
                    port: Some(8443),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test",
                "/p",
                true,
                302,
                "https://a.test:8443/p",
            ),
            (
                RedirectConfig {
                    port: Some(80),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test:8080",
                "/p",
                false,
                302,
                "http://a.test/p",
            ),
            (
                RedirectConfig {
                    scheme: Some(RedirectScheme::Https),
                    port: Some(443),
                    hostname: Some("b.test".into()),
                    ..config()
                },
                "GET",
                "a.test",
                "/",
                false,
                302,
                "https://b.test/",
            ),
            // Full path replacement keeps the query.
            (
                RedirectConfig {
                    path: Some("/full-path-replacement".into()),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test",
                "/full/path/original?q=1",
                false,
                302,
                "http://a.test/full-path-replacement?q=1",
            ),
            // Prefix replacement by segment (ReplacePrefixMatch).
            (
                RedirectConfig {
                    prefix: Some(prefix("/original-prefix", "/replacement-prefix")),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test",
                "/original-prefix/lemon",
                false,
                302,
                "http://a.test/replacement-prefix/lemon",
            ),
            (
                RedirectConfig {
                    prefix: Some(prefix("/a", "/b")),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test",
                "/a",
                false,
                302,
                "http://a.test/b",
            ),
            (
                RedirectConfig {
                    prefix: Some(prefix("/a", "/")),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test",
                "/a/x",
                false,
                302,
                "http://a.test/x",
            ),
            (
                RedirectConfig {
                    prefix: Some(prefix("/a", "/")),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test",
                "/a",
                false,
                302,
                "http://a.test/",
            ),
            (
                RedirectConfig {
                    prefix: Some(prefix("/a", "")),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test",
                "/a/",
                false,
                302,
                "http://a.test/",
            ),
            // A path outside the prefix is kept.
            (
                RedirectConfig {
                    prefix: Some(prefix("/a", "/b")),
                    status: Some(302),
                    ..config()
                },
                "GET",
                "a.test",
                "/ab",
                false,
                302,
                "http://a.test/ab",
            ),
            // Path and host together; a status for every method.
            (
                RedirectConfig {
                    hostname: Some("example.org".into()),
                    prefix: Some(prefix("/path-and-host", "/replacement-prefix")),
                    status: Some(303),
                    ..config()
                },
                "POST",
                "a.test",
                "/path-and-host?k=v",
                false,
                303,
                "http://example.org/replacement-prefix?k=v",
            ),
            (
                RedirectConfig {
                    hostname: Some("example.org".into()),
                    status: Some(308),
                    ..config()
                },
                "GET",
                "a.test",
                "/",
                false,
                308,
                "http://example.org/",
            ),
            // Without a status, Traefik's codes by method.
            (
                RedirectConfig {
                    hostname: Some("example.org".into()),
                    ..config()
                },
                "PUT",
                "a.test",
                "/",
                false,
                307,
                "http://example.org/",
            ),
            (
                RedirectConfig {
                    hostname: Some("example.org".into()),
                    permanent: true,
                    ..config()
                },
                "GET",
                "[::1]:8080",
                "/",
                false,
                301,
                "http://example.org:8080/",
            ),
        ];
        for (config, method, authority, target, tls, status, location) in cases {
            let mw = Redirect::new(&config).unwrap();
            assert_eq!(
                answer(&mw, method, authority, target, tls),
                Some((status, location.to_owned())),
                "{config:?} {method} {authority}{target}"
            );
        }
        // A scheme redirect alone, with a status, still leaves requests on that scheme alone.
        let https = Redirect::new(&RedirectConfig {
            scheme: Some(RedirectScheme::Https),
            status: Some(301),
            ..config()
        })
        .unwrap();
        assert_eq!(answer(&https, "GET", "a.test", "/", true), None);
    }

    #[test]
    fn replaces_prefixes_like_the_gateway_api_table() {
        // httproute_types.go, HTTPPathModifier.ReplacePrefixMatch (Gateway API v1.7.0).
        let table = [
            ("/foo/bar", "/foo", "/xyz", "/xyz/bar"),
            ("/foo/bar", "/foo", "/xyz/", "/xyz/bar"),
            ("/foo/bar", "/foo/", "/xyz", "/xyz/bar"),
            ("/foo/bar", "/foo/", "/xyz/", "/xyz/bar"),
            ("/foo", "/foo", "/xyz", "/xyz"),
            ("/foo/", "/foo", "/xyz", "/xyz/"),
            ("/foo/bar", "/foo", "", "/bar"),
            ("/foo/", "/foo", "", "/"),
            ("/foo", "/foo", "", "/"),
            ("/foo/", "/foo", "/", "/"),
            ("/foo", "/foo", "/", "/"),
            ("/x", "/", "/y", "/y/x"),
        ];
        for (path, from, to, want) in table {
            assert_eq!(
                replace_prefix(path, from, to).as_deref(),
                Some(want),
                "{path} {from} {to}"
            );
        }
        assert_eq!(replace_prefix("/foobar", "/foo", "/x"), None);
        assert_eq!(replace_prefix("/bar", "/foo", "/x"), None);
    }

    #[test]
    fn refuses_invalid_combinations() {
        let both = RedirectConfig {
            path: Some("/a".into()),
            prefix: Some(prefix("/b", "/c")),
            ..config()
        };
        assert!(Redirect::new(&both).is_err());
        let mixed = RedirectConfig {
            hostname: Some("a.test".into()),
            regex: Some(".*".into()),
            replacement: Some("x".into()),
            ..config()
        };
        assert!(Redirect::new(&mixed).is_err());
        let status = RedirectConfig {
            hostname: Some("a.test".into()),
            status: Some(200),
            ..config()
        };
        assert!(Redirect::new(&status).is_err());
        assert!(Redirect::new(&config()).is_err());
    }

    #[test]
    fn splits_hosts_and_ports() {
        assert_eq!(port_of("a.test:8080"), Some(8080));
        assert_eq!(port_of("a.test"), None);
        assert_eq!(port_of("[::1]:8443"), Some(8443));
        assert_eq!(port_of("[::1]"), None);
        assert_eq!(host_without_port("a.test:80"), "a.test");
        assert_eq!(host_without_port("a.test"), "a.test");
        assert_eq!(host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(host_without_port("[::1]"), "[::1]");
    }
}
