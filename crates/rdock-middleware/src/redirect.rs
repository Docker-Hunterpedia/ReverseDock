//! `redirect`: scheme redirects and regular-expression redirects, with Traefik's status codes
//! (301/308 permanent, 302/307 temporary; the second code for methods other than GET).

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Method};
use pingora::http::RequestHeader;
use rdock_model::middleware::{RedirectConfig, RedirectScheme};
use regex::Regex;

use crate::{BuildError, Context, Flow, Middleware, Reply};

#[derive(Debug)]
enum Target {
    Scheme {
        scheme: RedirectScheme,
        port: Option<u16>,
    },
    Regex {
        regex: Regex,
        replacement: String,
    },
}

/// The `redirect` middleware.
#[derive(Debug)]
pub(crate) struct Redirect {
    target: Target,
    permanent: bool,
}

impl Redirect {
    pub(crate) fn new(config: &RedirectConfig) -> Result<Self, BuildError> {
        let target = match (&config.scheme, &config.regex, &config.replacement) {
            (Some(scheme), None, None) => Target::Scheme {
                scheme: *scheme,
                port: config.port,
            },
            (None, Some(regex), Some(replacement)) => Target::Regex {
                regex: Regex::new(regex).map_err(|e| BuildError::Invalid(e.to_string()))?,
                replacement: replacement.clone(),
            },
            _ => {
                return Err(BuildError::Invalid(
                    "set `scheme`, or `regex` with `replacement`".to_owned(),
                ));
            }
        };
        Ok(Self {
            target,
            permanent: config.permanent,
        })
    }

    fn location(&self, req: &RequestHeader, cx: &Context) -> Option<String> {
        let path = req.uri.path_and_query().map_or("/", |p| p.as_str());
        match &self.target {
            Target::Scheme { scheme, port } => {
                let current = current_scheme(req, cx);
                let wanted = match scheme {
                    RedirectScheme::Http => "http",
                    RedirectScheme::Https => "https",
                };
                if current == wanted {
                    return None;
                }
                let default_port = if wanted == "https" { 443 } else { 80 };
                let host = host_without_port(&cx.authority);
                Some(match port {
                    Some(p) if *p != default_port => format!("{wanted}://{host}:{p}{path}"),
                    _ => format!("{wanted}://{host}{path}"),
                })
            }
            Target::Regex { regex, replacement } => {
                let scheme = if cx.tls { "https" } else { "http" };
                let url = format!("{scheme}://{}{path}", cx.authority);
                let captures = regex.captures(&url)?;
                let mut target = String::new();
                captures.expand(replacement, &mut target);
                (target != url).then_some(target)
            }
        }
    }
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
            status: status(self.permanent, &req.method),
            headers: vec![(http::header::LOCATION, value)],
            body: Some(Bytes::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, reply_header, request};

    fn scheme(scheme: RedirectScheme, port: Option<u16>, permanent: bool) -> Redirect {
        Redirect::new(&RedirectConfig {
            scheme: Some(scheme),
            regex: None,
            replacement: None,
            permanent,
            port,
        })
        .unwrap()
    }

    fn run(mw: &Redirect, method: &str, target: &str, tls: bool) -> Flow {
        let mut req = request(method, target, &[]);
        let mut c = cx();
        c.tls = tls;
        c.authority = "app.example.com:8080".to_owned();
        block_on(mw.request(&mut req, &mut c))
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
            scheme: None,
            regex: Some("^http://app\\.example\\.com:8080/(.*)$".into()),
            replacement: Some("https://www.example.com/${1}".into()),
            permanent: false,
            port: None,
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

    #[test]
    fn splits_hosts_and_ports() {
        assert_eq!(host_without_port("a.test:80"), "a.test");
        assert_eq!(host_without_port("a.test"), "a.test");
        assert_eq!(host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(host_without_port("[::1]"), "[::1]");
    }
}
