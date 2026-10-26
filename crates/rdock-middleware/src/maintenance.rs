//! `maintenance`: answers every request with a fixed status and page, except for allowed
//! client networks.

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use pingora::http::RequestHeader;
use rdock_model::middleware::MaintenanceConfig;
use rdock_model::values::IpNetwork;

use crate::{BuildError, Context, Flow, Middleware, Reply, read_file};

/// The `maintenance` middleware.
#[derive(Debug)]
pub(crate) struct Maintenance {
    enabled: bool,
    status: u16,
    page: Option<Bytes>,
    retry_after: Option<u64>,
    allow: Vec<IpNetwork>,
}

impl Maintenance {
    pub(crate) fn new(config: &MaintenanceConfig) -> Result<Self, BuildError> {
        Ok(Self {
            enabled: config.enabled,
            status: config.status,
            page: config
                .file
                .as_deref()
                .map(read_file)
                .transpose()?
                .map(Bytes::from),
            retry_after: config.retry_after.map(|d| d.as_std().as_secs()),
            allow: config.allow.clone(),
        })
    }
}

#[async_trait]
impl Middleware for Maintenance {
    async fn request(&self, _req: &mut RequestHeader, cx: &mut Context) -> Flow {
        if !self.enabled || self.allow.iter().any(|n| n.contains(&cx.client_ip)) {
            return Flow::Next;
        }
        let mut reply = Reply::status(self.status).header(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        if let Some(seconds) = self.retry_after {
            reply = reply.header(http::header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        if let Some(page) = &self.page {
            reply = reply.header(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            reply.body = Some(page.clone());
        }
        Flow::Reply(reply)
    }
}

#[cfg(test)]
mod tests {
    use rdock_model::values::Duration;

    use super::*;
    use crate::test_support::{block_on, cx, reply_header, request};

    #[test]
    fn answers_everyone_except_allowed_networks() {
        let dir = tempfile::tempdir().unwrap();
        let page = dir.path().join("down.html");
        std::fs::write(&page, "<h1>Back soon</h1>").unwrap();
        let mw = Maintenance::new(&MaintenanceConfig {
            file: Some(page),
            retry_after: Some(Duration::from_secs(120)),
            allow: vec!["10.0.0.0/8".parse().unwrap()],
            ..MaintenanceConfig::default()
        })
        .unwrap();
        let mut req = request("GET", "/", &[]);
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx())) else {
            panic!("maintenance must answer")
        };
        assert_eq!(reply.status, 503);
        assert_eq!(reply_header(&reply, "retry-after"), Some("120"));
        assert_eq!(reply_header(&reply, "cache-control"), Some("no-store"));
        assert_eq!(reply.body.as_deref(), Some(&b"<h1>Back soon</h1>"[..]));
        let mut office = cx();
        office.client_ip = "10.1.2.3".parse().unwrap();
        assert_eq!(block_on(mw.request(&mut req, &mut office)), Flow::Next);
    }
}
