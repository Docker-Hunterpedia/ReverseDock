#![doc = include_str!("../README.md")]

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_model::middleware::Middleware as Config;

mod auth;
pub mod client;
mod compress;
mod cors;
mod errors;
mod forward_auth;
mod hashes;
mod headers;
mod ip;
mod maintenance;
mod paths;
mod ratelimit;
mod redirect;

pub use client::{FetchError, Fetched, HttpClient};
pub use compress::Gzip;

/// What middlewares know about a request and share between its request and response phases.
#[derive(Debug)]
pub struct Context {
    /// Resolved client IP (after trusted-proxy handling).
    pub client_ip: IpAddr,
    /// The client connection uses TLS.
    pub tls: bool,
    /// Name of the matched route.
    pub route: Arc<str>,
    /// Request ID, also sent upstream as `X-Request-ID`.
    pub request_id: Arc<str>,
    /// `Host` (or `:authority`) as sent by the client, port included.
    pub authority: String,
    /// User authenticated by `basic_auth`, for the access log.
    pub user: Option<String>,
    /// Response compression chosen by `compress`; the proxy feeds the body through it.
    pub compression: Option<Gzip>,
    /// Body that replaces the upstream body (custom error pages).
    pub replace_body: Option<Bytes>,
    accepts_gzip: bool,
    head_request: bool,
    cors_origin: Option<HeaderValue>,
}

impl Context {
    /// A context for a new request.
    #[must_use]
    pub fn new(
        client_ip: IpAddr,
        tls: bool,
        route: Arc<str>,
        request_id: Arc<str>,
        authority: String,
    ) -> Self {
        Self {
            client_ip,
            tls,
            route,
            request_id,
            authority,
            user: None,
            compression: None,
            replace_body: None,
            accepts_gzip: false,
            head_request: false,
            cors_origin: None,
        }
    }
}

/// A response produced by a middleware instead of the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// Status code.
    pub status: u16,
    /// Headers to send.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Body; `None` means the proxy's standard error page for `status`.
    pub body: Option<Bytes>,
}

impl Reply {
    /// A reply with the standard page for `status`.
    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }
}

/// What happens after a middleware's request phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flow {
    /// Continue with the next middleware and then the backend.
    Next,
    /// Answer the client now.
    Reply(Reply),
}

/// A built-in middleware.
///
/// The request phase runs in chain order and may answer the request. The response phase runs in
/// reverse order, also for answers produced by later middlewares or by the proxy.
#[async_trait]
pub trait Middleware: Send + Sync + fmt::Debug {
    /// Inspects or changes the request before it is forwarded.
    async fn request(&self, _req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        Flow::Next
    }

    /// Changes the response before it is sent to the client.
    async fn response(&self, _resp: &mut ResponseHeader, _cx: &mut Context) {}

    /// A page for an error the proxy produced itself (502, 503, 504), if this middleware has
    /// one. Returns the content type and body.
    async fn error_page(&self, _status: u16, _cx: &Context) -> Option<(HeaderValue, Bytes)> {
        None
    }
}

/// A backend service a middleware can send requests to (error pages from a service).
#[async_trait]
pub trait ServiceClient: Send + Sync + fmt::Debug {
    /// Sends `req` to one of the service's backends.
    async fn send(&self, req: RequestHeader) -> Result<Fetched, FetchError>;
}

/// Inputs for building middlewares.
pub struct BuildEnv<'a> {
    /// Looks up a service by reference (`name` or `name@provider`).
    pub service: &'a dyn Fn(&str) -> Option<Arc<dyn ServiceClient>>,
    /// Shared HTTP client for `forward_auth`.
    pub client: Arc<HttpClient>,
}

/// Why a middleware could not be built.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// A referenced file could not be read.
    #[error("cannot read `{}`: {source}", path.display())]
    File {
        /// File that was read.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A setting is invalid (validation normally catches these first).
    #[error("{0}")]
    Invalid(String),
}

pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>, BuildError> {
    std::fs::read(path).map_err(|source| BuildError::File {
        path: path.to_owned(),
        source,
    })
}

/// Builds the middleware `name` from its configuration.
pub fn build(
    name: &str,
    config: &Config,
    env: &BuildEnv<'_>,
) -> Result<Arc<dyn Middleware>, BuildError> {
    Ok(match config {
        Config::Headers(c) => Arc::new(headers::Headers::new(c)?),
        Config::Redirect(c) => Arc::new(redirect::Redirect::new(c)?),
        Config::Rewrite(c) => Arc::new(paths::Rewrite::new(c)?),
        Config::StripPrefix(c) => Arc::new(paths::StripPrefix::new(c)),
        Config::AddPrefix(c) => Arc::new(paths::AddPrefix::new(c)),
        Config::ReplacePath(c) => Arc::new(paths::ReplacePath::new(c)),
        Config::BasicAuth(c) => Arc::new(auth::BasicAuth::new(c)?),
        Config::ForwardAuth(c) => Arc::new(forward_auth::ForwardAuth::new(c, env.client.clone())?),
        Config::IpAllow(c) => Arc::new(ip::IpFilter::allow(c)),
        Config::IpDeny(c) => Arc::new(ip::IpFilter::deny(c)),
        Config::RateLimit(c) => Arc::new(ratelimit::RateLimit::new(name, c)),
        Config::Cors(c) => Arc::new(cors::Cors::new(c)?),
        Config::Compress(c) => Arc::new(compress::Compress::new(c)),
        Config::Errors(c) => Arc::new(errors::Errors::new(c, env)?),
        Config::Maintenance(c) => Arc::new(maintenance::Maintenance::new(c)?),
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn cx() -> Context {
        Context::new(
            "192.0.2.10".parse().unwrap(),
            false,
            Arc::from("route"),
            Arc::from("req-1"),
            "app.example.com".to_owned(),
        )
    }

    pub(crate) fn request(
        method: &str,
        target: &str,
        headers: &[(&'static str, &str)],
    ) -> RequestHeader {
        let mut req = RequestHeader::build(method, target.as_bytes(), None).unwrap();
        for (name, value) in headers {
            req.append_header(*name, *value).unwrap();
        }
        req
    }

    pub(crate) fn header<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
        headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub(crate) fn reply_header<'a>(reply: &'a Reply, name: &str) -> Option<&'a str> {
        reply
            .headers
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .and_then(|(_, v)| v.to_str().ok())
    }

    pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }
}
