//! `cors`: cross-origin resource sharing. Preflight requests are answered here and never reach
//! the backend; other responses get the CORS headers when the origin is allowed.

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method};
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_model::middleware::CorsConfig;

use crate::{BuildError, Context, Flow, Middleware, Reply};

/// The `cors` middleware.
#[derive(Debug)]
pub(crate) struct Cors {
    any_origin: bool,
    origins: Vec<String>,
    methods: HeaderValue,
    headers: Option<HeaderValue>,
    expose: Option<HeaderValue>,
    credentials: bool,
    max_age: Option<HeaderValue>,
}

fn list(items: &[String]) -> Result<Option<HeaderValue>, BuildError> {
    if items.is_empty() {
        return Ok(None);
    }
    HeaderValue::from_str(&items.join(", "))
        .map(Some)
        .map_err(|_| BuildError::Invalid(format!("invalid CORS list `{}`", items.join(", "))))
}

impl Cors {
    pub(crate) fn new(config: &CorsConfig) -> Result<Self, BuildError> {
        Ok(Self {
            any_origin: config.allowed_origins.iter().any(|o| o == "*"),
            origins: config
                .allowed_origins
                .iter()
                .filter(|o| *o != "*")
                .map(|o| o.trim_end_matches('/').to_ascii_lowercase())
                .collect(),
            methods: list(&config.allowed_methods)?
                .unwrap_or(HeaderValue::from_static("GET, HEAD, POST")),
            headers: list(&config.allowed_headers)?,
            expose: list(&config.exposed_headers)?,
            credentials: config.allow_credentials,
            max_age: config
                .max_age
                .map(|d| HeaderValue::from(d.as_std().as_secs())),
        })
    }

    /// The `Access-Control-Allow-Origin` value for `origin`, if it is allowed.
    fn allow_origin(&self, origin: &HeaderValue) -> Option<HeaderValue> {
        let text = origin.to_str().ok()?.to_ascii_lowercase();
        if self.origins.contains(&text) {
            Some(origin.clone())
        } else if self.any_origin {
            Some(HeaderValue::from_static("*"))
        } else {
            None
        }
    }
}

fn is_preflight(req: &RequestHeader) -> bool {
    req.method == Method::OPTIONS
        && req.headers.contains_key(http::header::ORIGIN)
        && req
            .headers
            .contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD)
}

#[async_trait]
impl Middleware for Cors {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let origin = req.headers.get(http::header::ORIGIN).cloned();
        let allowed = origin.as_ref().and_then(|o| self.allow_origin(o));
        if !is_preflight(req) {
            cx.cors_origin = allowed;
            return Flow::Next;
        }
        let mut headers: Vec<(HeaderName, HeaderValue)> = vec![(
            http::header::VARY,
            HeaderValue::from_static(
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
            ),
        )];
        if let Some(allow) = allowed {
            headers.push((http::header::ACCESS_CONTROL_ALLOW_ORIGIN, allow));
            headers.push((
                http::header::ACCESS_CONTROL_ALLOW_METHODS,
                self.methods.clone(),
            ));
            if let Some(h) = &self.headers {
                headers.push((http::header::ACCESS_CONTROL_ALLOW_HEADERS, h.clone()));
            }
            if self.credentials {
                headers.push((
                    http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                ));
            }
            if let Some(age) = &self.max_age {
                headers.push((http::header::ACCESS_CONTROL_MAX_AGE, age.clone()));
            }
        }
        Flow::Reply(Reply {
            status: 204,
            headers,
            body: Some(Bytes::new()),
        })
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        let Some(origin) = cx.cors_origin.clone() else {
            return;
        };
        let wildcard = origin.as_bytes() == b"*";
        let _ = resp.insert_header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        if self.credentials {
            let _ = resp.insert_header(
                http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if let Some(expose) = &self.expose {
            let _ = resp.insert_header(http::header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        }
        if !wildcard {
            let _ = resp.append_header(http::header::VARY, HeaderValue::from_static("Origin"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, header, reply_header, request};

    fn cors(origins: &[&str], credentials: bool) -> Cors {
        Cors::new(&CorsConfig {
            allowed_origins: origins.iter().map(|s| (*s).to_owned()).collect(),
            allowed_methods: vec!["GET".into(), "PUT".into()],
            allowed_headers: vec!["X-Token".into()],
            exposed_headers: vec!["X-Total".into()],
            allow_credentials: credentials,
            max_age: Some(rdock_model::values::Duration::from_secs(600)),
        })
        .unwrap()
    }

    #[test]
    fn answers_preflights_for_allowed_origins() {
        let mw = cors(&["https://app.example.com"], true);
        let mut req = request(
            "OPTIONS",
            "/api",
            &[
                ("origin", "https://app.example.com"),
                ("access-control-request-method", "PUT"),
            ],
        );
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx())) else {
            panic!("preflight must be answered")
        };
        assert_eq!(reply.status, 204);
        assert_eq!(
            reply_header(&reply, "access-control-allow-origin"),
            Some("https://app.example.com")
        );
        assert_eq!(
            reply_header(&reply, "access-control-allow-methods"),
            Some("GET, PUT")
        );
        assert_eq!(
            reply_header(&reply, "access-control-allow-credentials"),
            Some("true")
        );
        assert_eq!(reply_header(&reply, "access-control-max-age"), Some("600"));

        let mut evil = request(
            "OPTIONS",
            "/api",
            &[
                ("origin", "https://evil.test"),
                ("access-control-request-method", "PUT"),
            ],
        );
        let Flow::Reply(reply) = block_on(mw.request(&mut evil, &mut cx())) else {
            panic!("preflight must be answered")
        };
        assert_eq!(reply_header(&reply, "access-control-allow-origin"), None);
    }

    #[test]
    fn decorates_normal_responses() {
        let mw = cors(&["*"], false);
        let mut req = request("GET", "/", &[("origin", "https://any.test")]);
        let mut c = cx();
        assert_eq!(block_on(mw.request(&mut req, &mut c)), Flow::Next);
        let mut resp = ResponseHeader::build(200, None).unwrap();
        block_on(mw.response(&mut resp, &mut c));
        assert_eq!(
            header(&resp.headers, "access-control-allow-origin"),
            Some("*")
        );
        assert_eq!(
            header(&resp.headers, "access-control-expose-headers"),
            Some("X-Total")
        );
        assert_eq!(header(&resp.headers, "vary"), None);

        let exact = cors(&["https://app.example.com"], false);
        let mut req = request("GET", "/", &[("origin", "https://app.example.com")]);
        let mut c = cx();
        block_on(exact.request(&mut req, &mut c));
        let mut resp = ResponseHeader::build(200, None).unwrap();
        block_on(exact.response(&mut resp, &mut c));
        assert_eq!(header(&resp.headers, "vary"), Some("Origin"));
    }
}
