//! `headers`: request and response header rules, and HSTS on HTTPS responses.

use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_model::middleware::{HeaderRules, HeadersConfig};

use crate::{BuildError, Context, Flow, Middleware};

/// Compiled header operations, applied in the order remove, set, add.
#[derive(Debug, Default)]
struct Rules {
    remove: Vec<HeaderName>,
    set: Vec<(HeaderName, HeaderValue)>,
    add: Vec<(HeaderName, HeaderValue)>,
}

impl Rules {
    fn new(rules: &HeaderRules) -> Result<Self, BuildError> {
        let pairs = |map: &std::collections::BTreeMap<String, String>| {
            map.iter()
                .map(|(k, v)| Ok((name(k)?, value(v)?)))
                .collect::<Result<Vec<_>, BuildError>>()
        };
        Ok(Self {
            remove: rules
                .remove
                .iter()
                .map(|n| name(n))
                .collect::<Result<_, _>>()?,
            set: pairs(&rules.set)?,
            add: pairs(&rules.add)?,
        })
    }
}

fn name(text: &str) -> Result<HeaderName, BuildError> {
    HeaderName::from_bytes(text.as_bytes())
        .map_err(|_| BuildError::Invalid(format!("`{text}` is not a valid header name")))
}

fn value(text: &str) -> Result<HeaderValue, BuildError> {
    HeaderValue::from_str(text)
        .map_err(|_| BuildError::Invalid(format!("`{text}` is not a valid header value")))
}

/// The `headers` middleware.
#[derive(Debug)]
pub(crate) struct Headers {
    request: Rules,
    response: Rules,
    hsts: Option<HeaderValue>,
}

impl Headers {
    pub(crate) fn new(config: &HeadersConfig) -> Result<Self, BuildError> {
        let hsts = config.hsts.map(|h| {
            let mut text = format!("max-age={}", h.max_age.as_std().as_secs());
            if h.include_subdomains {
                text.push_str("; includeSubDomains");
            }
            if h.preload {
                text.push_str("; preload");
            }
            text
        });
        Ok(Self {
            request: Rules::new(&config.request)?,
            response: Rules::new(&config.response)?,
            hsts: hsts.map(|t| value(&t)).transpose()?,
        })
    }
}

#[async_trait]
impl Middleware for Headers {
    async fn request(&self, req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        for name in &self.request.remove {
            req.remove_header(name);
        }
        for (name, value) in &self.request.set {
            // Valid names and values are always accepted.
            let _ = req.insert_header(name.clone(), value.clone());
        }
        for (name, value) in &self.request.add {
            let _ = req.append_header(name.clone(), value.clone());
        }
        Flow::Next
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        if cx.tls
            && let Some(hsts) = &self.hsts
        {
            let _ = resp.insert_header(http::header::STRICT_TRANSPORT_SECURITY, hsts.clone());
        }
        for name in &self.response.remove {
            resp.remove_header(name);
        }
        for (name, value) in &self.response.set {
            let _ = resp.insert_header(name.clone(), value.clone());
        }
        for (name, value) in &self.response.add {
            let _ = resp.append_header(name.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rdock_model::middleware::Hsts;
    use rdock_model::values::Duration;

    use super::*;
    use crate::test_support::{block_on, cx, header, request};

    fn rules(set: &[(&str, &str)], add: &[(&str, &str)], remove: &[&str]) -> HeaderRules {
        let map = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<BTreeMap<_, _>>()
        };
        HeaderRules {
            set: map(set),
            add: map(add),
            remove: remove.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn applies_remove_set_add_in_order() {
        let mw = Headers::new(&HeadersConfig {
            request: rules(&[("X-Env", "prod")], &[("X-Tag", "b")], &["X-Debug"]),
            response: rules(&[("Server", "rdock")], &[], &["X-Powered-By"]),
            hsts: None,
        })
        .unwrap();
        let mut req = request(
            "GET",
            "/",
            &[("x-debug", "1"), ("x-env", "dev"), ("x-tag", "a")],
        );
        let mut c = cx();
        assert_eq!(block_on(mw.request(&mut req, &mut c)), Flow::Next);
        assert_eq!(header(&req.headers, "x-debug"), None);
        assert_eq!(header(&req.headers, "x-env"), Some("prod"));
        assert_eq!(req.headers.get_all("x-tag").iter().count(), 2);

        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("x-powered-by", "php").unwrap();
        block_on(mw.response(&mut resp, &mut c));
        assert_eq!(header(&resp.headers, "x-powered-by"), None);
        assert_eq!(header(&resp.headers, "server"), Some("rdock"));
    }

    #[test]
    fn hsts_only_on_https() {
        let mw = Headers::new(&HeadersConfig {
            hsts: Some(Hsts {
                max_age: Duration::from_secs(31_536_000),
                include_subdomains: true,
                preload: false,
            }),
            ..HeadersConfig::default()
        })
        .unwrap();
        let mut resp = ResponseHeader::build(200, None).unwrap();
        let mut plain = cx();
        block_on(mw.response(&mut resp, &mut plain));
        assert_eq!(header(&resp.headers, "strict-transport-security"), None);
        let mut tls = cx();
        tls.tls = true;
        block_on(mw.response(&mut resp, &mut tls));
        assert_eq!(
            header(&resp.headers, "strict-transport-security"),
            Some("max-age=31536000; includeSubDomains")
        );
    }
}
