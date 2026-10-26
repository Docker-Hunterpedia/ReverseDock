//! `errors`: custom pages for selected status codes, from a file or from a service. The original
//! status is kept; the page replaces the body of backend responses and of the proxy's own errors.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Method};
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_model::middleware::ErrorsConfig;

use crate::{BuildEnv, BuildError, Context, Middleware, ServiceClient, read_file};

#[derive(Debug)]
enum Source {
    File {
        body: Bytes,
        content_type: HeaderValue,
    },
    Service {
        client: Arc<dyn ServiceClient>,
        path: String,
    },
}

/// The `errors` middleware.
#[derive(Debug)]
pub(crate) struct Errors {
    ranges: Vec<(u16, u16)>,
    source: Source,
}

fn parse_range(text: &str) -> Option<(u16, u16)> {
    let (from, to) = text.split_once('-').unwrap_or((text, text));
    Some((from.trim().parse().ok()?, to.trim().parse().ok()?))
}

fn content_type_for(path: &std::path::Path) -> HeaderValue {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => HeaderValue::from_static("application/json"),
        Some("txt") => HeaderValue::from_static("text/plain; charset=utf-8"),
        _ => HeaderValue::from_static("text/html; charset=utf-8"),
    }
}

impl Errors {
    pub(crate) fn new(config: &ErrorsConfig, env: &BuildEnv<'_>) -> Result<Self, BuildError> {
        let ranges = config
            .status
            .iter()
            .map(|s| {
                parse_range(s).ok_or_else(|| BuildError::Invalid(format!("invalid status `{s}`")))
            })
            .collect::<Result<_, _>>()?;
        let source = match (&config.file, &config.service) {
            (Some(file), None) => Source::File {
                body: Bytes::from(read_file(file)?),
                content_type: content_type_for(file),
            },
            (None, Some(service)) => Source::Service {
                client: (env.service)(service).ok_or_else(|| {
                    BuildError::Invalid(format!("service `{service}` does not exist"))
                })?,
                path: config.path.clone().unwrap_or_else(|| "/".to_owned()),
            },
            _ => return Err(BuildError::Invalid("set `file` or `service`".to_owned())),
        };
        Ok(Self { ranges, source })
    }

    fn covers(&self, status: u16) -> bool {
        self.ranges.iter().any(|(a, b)| (*a..=*b).contains(&status))
    }

    async fn page(&self, status: u16, cx: &Context) -> Option<(HeaderValue, Bytes)> {
        match &self.source {
            Source::File { body, content_type } => Some((content_type.clone(), body.clone())),
            Source::Service { client, path } => {
                let path = path.replace("{status}", &status.to_string());
                let mut req = RequestHeader::build(Method::GET, path.as_bytes(), None).ok()?;
                let _ = req.insert_header(http::header::HOST, cx.authority.as_str());
                match client.send(req).await {
                    Ok(page) => {
                        let content_type = page
                            .header
                            .headers
                            .get(http::header::CONTENT_TYPE)
                            .cloned()
                            .unwrap_or(HeaderValue::from_static("text/html; charset=utf-8"));
                        Some((content_type, page.body))
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "error page service failed");
                        None
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Middleware for Errors {
    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        let status = resp.status.as_u16();
        if cx.replace_body.is_some() || !self.covers(status) {
            return;
        }
        let Some((content_type, body)) = self.page(status, cx).await else {
            return;
        };
        for name in [
            http::header::CONTENT_ENCODING,
            http::header::ETAG,
            http::header::LAST_MODIFIED,
            http::header::CONTENT_RANGE,
            http::header::ACCEPT_RANGES,
            http::header::TRANSFER_ENCODING,
        ] {
            resp.remove_header(&name);
        }
        let _ = resp.insert_header(http::header::CONTENT_TYPE, content_type);
        let _ = resp.set_content_length(body.len());
        cx.compression = None;
        cx.replace_body = Some(body);
    }

    async fn error_page(&self, status: u16, cx: &Context) -> Option<(HeaderValue, Bytes)> {
        if self.covers(status) {
            self.page(status, cx).await
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpClient;
    use crate::client::{FetchError, Fetched};
    use crate::test_support::{block_on, cx, header};

    #[derive(Debug)]
    struct Pages;

    #[async_trait]
    impl ServiceClient for Pages {
        async fn send(&self, req: RequestHeader) -> Result<Fetched, FetchError> {
            let mut header = ResponseHeader::build(200, None).unwrap();
            header.insert_header("content-type", "text/plain").unwrap();
            Ok(Fetched {
                header,
                body: Bytes::from(format!("page for {}", req.uri.path())),
            })
        }
    }

    fn env_with_pages() -> (Arc<HttpClient>, Arc<dyn ServiceClient>) {
        (Arc::new(HttpClient::default()), Arc::new(Pages))
    }

    #[test]
    fn replaces_bodies_in_range_and_keeps_the_status() {
        let (client, pages) = env_with_pages();
        let lookup = move |_: &str| Some(pages.clone());
        let env = BuildEnv {
            service: &lookup,
            client,
        };
        let mw = Errors::new(
            &ErrorsConfig {
                status: vec!["500-599".into(), "404".into()],
                file: None,
                service: Some("pages".into()),
                path: Some("/{status}.html".into()),
            },
            &env,
        )
        .unwrap();
        let mut resp = ResponseHeader::build(503, None).unwrap();
        resp.insert_header("content-encoding", "gzip").unwrap();
        let mut c = cx();
        block_on(mw.response(&mut resp, &mut c));
        assert_eq!(resp.status.as_u16(), 503);
        assert_eq!(c.replace_body.as_deref(), Some(&b"page for /503.html"[..]));
        assert_eq!(header(&resp.headers, "content-encoding"), None);
        assert_eq!(header(&resp.headers, "content-length"), Some("18"));
        let mut ok = ResponseHeader::build(200, None).unwrap();
        let mut c = cx();
        block_on(mw.response(&mut ok, &mut c));
        assert!(c.replace_body.is_none());
        assert!(block_on(mw.error_page(502, &cx())).is_some());
        assert!(block_on(mw.error_page(401, &cx())).is_none());
    }

    #[test]
    fn serves_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("404.html");
        std::fs::write(&file, "<p>not here</p>").unwrap();
        let lookup = |_: &str| None;
        let env = BuildEnv {
            service: &lookup,
            client: Arc::new(HttpClient::default()),
        };
        let mw = Errors::new(
            &ErrorsConfig {
                status: vec!["404".into()],
                file: Some(file),
                service: None,
                path: None,
            },
            &env,
        )
        .unwrap();
        let (content_type, body) = block_on(mw.error_page(404, &cx())).unwrap();
        assert_eq!(content_type, "text/html; charset=utf-8");
        assert_eq!(&body[..], b"<p>not here</p>");
    }
}
