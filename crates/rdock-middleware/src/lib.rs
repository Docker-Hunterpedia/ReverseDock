#![doc = include_str!("../README.md")]

use std::any::Any;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_model::middleware::Middleware as Config;

mod agent;
mod api_key;
mod auth;
pub mod chain;
pub mod client;
mod client_cert;
mod compress;
pub mod consumers;
mod cors;
mod errors;
mod forward_auth;
mod hashes;
mod headers;
pub mod held;
mod hold_body;
mod ip;
mod jwt;
#[doc(hidden)]
pub use jwt::fuzz_verify as fuzz_jwt;
mod limits;
mod maintenance;
mod oidc;
#[doc(hidden)]
pub use oidc::cookie::fuzz_decode as fuzz_oidc_cookie;
mod paths;
pub mod phase;
mod plugin;
pub mod problem;
mod quota;
mod ratelimit;
mod redirect;
mod static_files;
mod transform;
mod validate;
pub mod wasm;

pub use api_key::IDENTITY_HEADERS as CONSUMER_HEADERS;
pub use chain::{Answered, Chain, Flags, Released};
pub use client::{ClientTls, FetchError, Fetched, HttpClient};
pub use client_cert::{ClientIdentity, IDENTITY_HEADERS};
pub use compress::Encoder;
pub use consumers::ConsumerIndex;
pub use held::{BodyHolder, HeldBody, HoldError, Spool};
pub use limits::Throttle;
pub use phase::{BodyHold, BodyVerdict, Capabilities, Consumer, LogSummary, Phases, Upstream};
pub use problem::ProblemKind;
pub use static_files::FileBody;

/// What middlewares know about a request and share between its phases.
///
/// Fields are set by the proxy (client, route, upstream) or by middlewares (user, consumer,
/// compression…). Per-middleware data that must survive from one phase to a later one goes in
/// the typed state slot ([`Self::state`], [`Self::set_state`]), which belongs to the middleware's
/// position in the chain.
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
    pub compression: Option<Encoder>,
    /// Body that replaces the upstream body (custom error pages).
    pub replace_body: Option<Bytes>,
    /// Claims of the token verified by `jwt`.
    pub claims: Option<Arc<serde_json::Map<String, serde_json::Value>>>,
    /// The verified client certificate of the connection, if any.
    pub client_cert: Option<Arc<ClientIdentity>>,
    /// Slots taken by `in_flight`, freed when the request ends.
    pub admitted: Vec<rdock_limits::Admitted>,
    /// Response byte limit set by `bandwidth`.
    pub throttle: Option<Throttle>,
    /// The consumer the request is attributed to, set by an authenticating middleware.
    pub consumer: Option<Consumer>,
    /// The public ID of the API key that authenticated the request (`api_key`).
    pub key_id: Option<Arc<str>>,
    /// The backend of the current attempt: set before `upstream_request`, kept for `log`.
    pub upstream: Option<Upstream>,
    /// Whether the request has a body: set by the proxy before the `request` phase (a declared
    /// length above zero, chunked framing, or an HTTP/2 stream that did not end with its
    /// headers; never for upgrades). A middleware that holds the body uses it to tell whether
    /// its `request_body` hook will run for this request.
    pub has_body: bool,
    /// Positions (below 64) whose middleware waived its body hold for this request.
    waived: u64,
    state: Vec<Option<Box<dyn Any + Send + Sync>>>,
    slot: usize,
    encoding: Option<rdock_model::middleware::CompressAlgorithm>,
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
            claims: None,
            client_cert: None,
            admitted: Vec::new(),
            throttle: None,
            consumer: None,
            key_id: None,
            upstream: None,
            has_body: false,
            waived: 0,
            state: Vec::new(),
            slot: 0,
            encoding: None,
            head_request: false,
            cors_origin: None,
        }
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("client_ip", &self.client_ip)
            .field("tls", &self.tls)
            .field("route", &self.route)
            .field("request_id", &self.request_id)
            .field("authority", &self.authority)
            .field("user", &self.user)
            .field("consumer", &self.consumer)
            .field("key_id", &self.key_id)
            .field("upstream", &self.upstream)
            .field("compression", &self.compression.is_some())
            .field("state_slots", &self.state.len())
            .finish_non_exhaustive()
    }
}

impl Context {
    /// This middleware's state of type `T`, if it set one in an earlier phase.
    #[must_use]
    pub fn state<T: Any>(&self) -> Option<&T> {
        self.state.get(self.slot)?.as_ref()?.downcast_ref()
    }

    /// This middleware's state of type `T`, mutably.
    pub fn state_mut<T: Any>(&mut self) -> Option<&mut T> {
        self.state.get_mut(self.slot)?.as_mut()?.downcast_mut()
    }

    /// Sets this middleware's state, replacing any earlier value.
    ///
    /// The slots are allocated when the request starts for chains in which a middleware
    /// declared [`Capabilities::with_state`]; a middleware that did not declare it still gets
    /// a slot here, at the cost of an allocation.
    pub fn set_state<T: Any + Send + Sync>(&mut self, value: T) {
        if self.state.len() <= self.slot {
            self.state.resize_with(self.slot + 1, || None);
        }
        self.state[self.slot] = Some(Box::new(value));
    }

    /// Takes this middleware's state of type `T` out of its slot.
    pub fn take_state<T: Any>(&mut self) -> Option<T> {
        let slot = self.state.get_mut(self.slot)?;
        if !slot.as_ref()?.is::<T>() {
            return None;
        }
        slot.take()?.downcast().ok().map(|b| *b)
    }

    /// Declares, in the `request` phase, that this middleware does not need the request body
    /// of this request after all (it decided from the head): its `request_body` hook is not
    /// called, and the proxy holds the body only if another middleware still needs it.
    /// Returns `false` when the chain is too long to waive (position 64 and later), in which
    /// case the hook runs as declared.
    pub fn waive_body_hold(&mut self) -> bool {
        if self.slot < 64 {
            self.waived |= 1 << self.slot;
            true
        } else {
            false
        }
    }

    /// Whether the middleware at `position` waived its body hold.
    pub(crate) fn waived(&self, position: usize) -> bool {
        position < 64 && self.waived & (1 << position) != 0
    }

    /// Whether any middleware waived its body hold.
    pub(crate) fn any_waived(&self) -> bool {
        self.waived != 0
    }

    /// Whether state slots were allocated for this request.
    #[must_use]
    pub fn has_state_slots(&self) -> bool {
        !self.state.is_empty()
    }

    /// Allocates one empty slot per middleware of the chain.
    pub(crate) fn prepare_state(&mut self, len: usize) {
        self.state.resize_with(len, || None);
    }

    /// Selects the slot of the middleware at `position` before one of its hooks runs.
    pub(crate) fn enter(&mut self, position: usize) {
        self.slot = position;
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
    pub body: Option<Body>,
    /// The kind of the standard page (its problem type), when `status` alone does not say it
    /// (`429` from a quota, `503` from maintenance). With a `body`, it marks that body as the
    /// middleware's plain stand-in for the standard page: routes whose `errors.format` is not
    /// `html` get the rendered page instead (`basic_auth`'s text).
    pub problem: Option<ProblemKind>,
    /// Extension members of the problem details (RFC 9457 §3.2), such as `validate`'s
    /// `errors`. Only rendered as problem details; never holds a value from the request.
    pub extensions: Option<Arc<serde_json::Map<String, serde_json::Value>>>,
}

/// The body of a [`Reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Bytes in memory, sent at once.
    Bytes(Bytes),
    /// Ranges of an open file (`static`), read and sent chunk by chunk.
    File(FileBody),
}

impl Body {
    /// Length in bytes: the `Content-Length` of the reply.
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::File(file) => file.remaining(),
        }
    }

    /// Whether the body has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes of an in-memory body.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::File(_) => None,
        }
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self::Bytes(bytes)
    }
}

impl Reply {
    /// A reply with the standard page for `status`.
    #[must_use]
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: None,
            problem: None,
            extensions: None,
        }
    }

    /// A reply with the standard page of `kind`.
    #[must_use]
    pub fn problem(kind: ProblemKind) -> Self {
        Self {
            problem: Some(kind),
            extensions: None,
            ..Self::status(kind.status())
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Adds an extension member to the problem details.
    #[must_use]
    pub fn extension(mut self, name: &str, value: serde_json::Value) -> Self {
        let mut map = self.extensions.as_deref().cloned().unwrap_or_default();
        map.insert(name.to_owned(), value);
        self.extensions = Some(Arc::new(map));
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

/// A middleware: hooks for the phases of a request (ADR-0030, "Pipeline and body phase").
///
/// On the way in the hooks run in the route's list order (`request`, `upstream_request`,
/// `request_body`); on the way out in reverse order (`response`, `response_body`, `log`).
/// `request` and `response` run for every middleware; the other hooks only for middlewares
/// whose [`Self::capabilities`] declare them, so a chain that uses none pays nothing. `response`
/// also runs for answers produced by later middlewares or by the proxy.
#[async_trait]
pub trait Middleware: Send + Sync + fmt::Debug {
    /// The phases this middleware uses, whether it wants a state slot, and whether the proxy
    /// should hold the request body for it. Read once, when the route's chain is built.
    fn capabilities(&self) -> Capabilities {
        Capabilities::DEFAULT
    }

    /// Inspects or changes the request before it is forwarded, or answers it.
    async fn request(&self, _req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        Flow::Next
    }

    /// Changes the request head about to be sent to the chosen backend
    /// ([`Context::upstream`]), or answers instead (the attempt is abandoned, no retry).
    /// Runs once per attempt, on a fresh copy of the request. Needs
    /// [`Phases::UPSTREAM_REQUEST`].
    async fn upstream_request(&self, _req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        Flow::Next
    }

    /// Inspects the complete request body before any of it is forwarded, and lets it pass,
    /// replaces it or answers instead. Needs [`Capabilities::with_body`].
    async fn request_body(&self, _body: &HeldBody, _cx: &mut Context) -> BodyVerdict {
        BodyVerdict::Continue
    }

    /// Changes the response before it is sent to the client.
    async fn response(&self, _resp: &mut ResponseHeader, _cx: &mut Context) {}

    /// Changes or counts one chunk of the response body before it is compressed and sent.
    /// Synchronous, as Pingora's body filter is: it cannot await. A middleware that changes
    /// the length removes `Content-Length` in [`Self::response`]. Needs
    /// [`Phases::RESPONSE_BODY`].
    fn response_body(&self, _body: &mut Option<Bytes>, _end_of_stream: bool, _cx: &mut Context) {}

    /// Observes the finished request. Cannot change anything. Needs [`Phases::LOG`].
    fn log(&self, _summary: &LogSummary, _cx: &Context) {}

    /// Whether the proxy translates gRPC-Web for routes using this middleware.
    fn translates_grpc_web(&self) -> bool {
        false
    }

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
    /// Shared HTTP client for `forward_auth` and agents.
    pub client: Arc<HttpClient>,
    /// The native plugins compiled into this binary (`type: plugin`).
    pub plugins: &'a rdock_plugin_api::Registry,
    /// Where plugins and agents count (panics, agent calls); `None` when validating.
    pub metrics: Option<&'a rdock_observability::Metrics>,
    /// The configuration's consumers and their keys, for `api_key`.
    pub consumers: Arc<ConsumerIndex>,
    /// Quota counters that outlive the configuration; `None` when validating (a throw-away
    /// registry is used then).
    pub quotas: Option<&'a rdock_limits::quota::QuotaRegistry>,
    /// The `Host` names of the routes using each middleware, by middleware name: the hosts
    /// `oidc` may build its redirect URI from.
    pub route_hosts: Arc<std::collections::HashMap<String, Vec<String>>>,
}

/// One problem found while building a middleware, at a path inside it (`name`,
/// `config.deny[1]`), for a diagnostic under `middlewares.<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Path relative to the middleware; empty for the middleware itself.
    pub path: String,
    /// What is wrong.
    pub message: String,
    /// How to fix it.
    pub hint: Option<String>,
}

impl Issue {
    /// An issue at `path`.
    #[must_use]
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
            hint: None,
        }
    }

    /// Adds a hint.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
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
    /// Problems at paths inside the middleware (a plugin's configuration, its name).
    #[error("{}", .0.iter().map(|i| i.message.as_str()).collect::<Vec<_>>().join("; "))]
    Issues(Vec<Issue>),
}

pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>, BuildError> {
    std::fs::read(path).map_err(|source| BuildError::File {
        path: path.to_owned(),
        source,
    })
}

/// Marks a route for gRPC-Web translation, which the proxy does.
#[derive(Debug)]
struct GrpcWeb;

#[async_trait]
impl Middleware for GrpcWeb {
    fn translates_grpc_web(&self) -> bool {
        true
    }
}

/// Marks a route as cached. The cache is not a middleware phase: the proxy looks responses up
/// after every `request` phase and stores them before every `response` phase (ADR-0030), so
/// this entry only carries the configuration the proxy compiles into the route's policy.
#[derive(Debug)]
struct CacheMarker;

#[async_trait]
impl Middleware for CacheMarker {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::NONE)
    }
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
        Config::InFlight(c) => Arc::new(limits::InFlight::new(c)),
        Config::ClientCert(c) => Arc::new(client_cert::ClientCert::new(c)),
        Config::Jwt(c) => Arc::new(jwt::Jwt::new(name, c, env.client.clone())?),
        Config::Bandwidth(c) => Arc::new(limits::Bandwidth::new(c)),
        Config::Cors(c) => Arc::new(cors::Cors::new(c)?),
        Config::Compress(c) => Arc::new(compress::Compress::new(c)),
        Config::Errors(c) => Arc::new(errors::Errors::new(c, env)?),
        Config::Maintenance(c) => Arc::new(maintenance::Maintenance::new(c)?),
        Config::Static(c) => Arc::new(static_files::Static::new(c)?),
        // The proxy converts the protocol itself (it needs the trailers); see `rdock-proxy`.
        Config::GrpcWeb(_) => Arc::new(GrpcWeb),
        Config::HoldBody(c) => Arc::new(hold_body::HoldBody::new(c)),
        Config::Cache(_) => Arc::new(CacheMarker),
        Config::Plugin(c) => Arc::new(plugin::PluginMiddleware::build(
            name,
            c,
            env.plugins,
            env.metrics,
        )?),
        Config::Wasm(c) => Arc::new(wasm::WasmMiddleware::build(name, c, env.metrics)?),
        Config::Agent(c) => Arc::new(agent::Agent::new(name, c, env)?),
        Config::CloudflareAccess(c) => {
            Arc::new(jwt::Jwt::cloudflare_access(name, c, env.client.clone())?)
        }
        Config::ApiKey(c) => Arc::new(api_key::ApiKey::new(name, c, env.consumers.clone())?),
        Config::Validate(c) => Arc::new(validate::Validate::new(name, c, env.metrics)?),
        Config::Transform(c) => Arc::new(transform::Transform::new(name, c, env.metrics)?),
        Config::Oidc(c) => Arc::new(oidc::Oidc::new(name, c, env)?),
        Config::Quota(c) => match env.quotas {
            Some(registry) => Arc::new(quota::Quota::new(name, c, registry)),
            None => Arc::new(quota::Quota::new(
                name,
                c,
                &rdock_limits::quota::QuotaRegistry::default(),
            )),
        },
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

    pub(crate) fn reply_bytes(reply: &Reply) -> Option<&[u8]> {
        reply.body.as_ref().and_then(Body::as_bytes).map(|b| &b[..])
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
