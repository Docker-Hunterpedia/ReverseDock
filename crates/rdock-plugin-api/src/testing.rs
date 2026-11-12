//! The SDK's test harness: run a plugin through its phases without a proxy and assert on what
//! it decided.
//!
//! The harness follows the proxy's rules: a hook runs only when the plugin declared its phase,
//! state survives between phases only when it declared [`Capabilities::with_state`], a body
//! longer than its [`crate::BodyLimit`] is refused with `413` before the plugin sees it, and
//! a body replacement needs [`crate::BodyLimit::replacing`]. It does not catch panics: in a
//! test a panic should fail the test (the proxy catches them and answers `500`).
//!
//! ```
//! use rdock_plugin_api::testing::{Harness, block_on, request};
//! use rdock_plugin_api::{Capabilities, Ctx, Decision, Phases, Plugin, RequestHead, Response, async_trait, http::StatusCode};
//!
//! /// Refuses requests without an `x-api-version` header.
//! struct RequireVersion;
//!
//! #[async_trait]
//! impl Plugin for RequireVersion {
//!     fn capabilities(&self) -> Capabilities { Capabilities::new(Phases::REQUEST) }
//!
//!     async fn request(&self, req: &mut RequestHead, _cx: &mut Ctx<'_>) -> Decision {
//!         if req.header("x-api-version").is_some() {
//!             Decision::Continue
//!         } else {
//!             Response::text(StatusCode::BAD_REQUEST, "x-api-version is required\n").into()
//!         }
//!     }
//! }
//!
//! let mut harness = Harness::new(RequireVersion);
//! let refused = block_on(harness.request(&mut request("GET", "/")));
//! assert_eq!(refused.response().map(|r| r.status()), Some(StatusCode::BAD_REQUEST));
//!
//! let mut ok = request("GET", "/").with_header("x-api-version", "2").unwrap();
//! assert!(block_on(harness.request(&mut ok)).is_continue());
//! ```

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};

use crate::{
    BodyDecision, Capabilities, ConfigError, Consumer, Ctx, Decision, Factory, Facts, LogSummary,
    Phases, Plugin, RequestBody, RequestHead, Response, ResponseHead, State, Upstream,
};

/// Runs a future to completion on the current thread, without an async runtime.
///
/// Enough for plugins that only compute; a plugin that uses Tokio (timers, files, sockets)
/// needs a Tokio test (`#[tokio::test]`) and the harness's async methods instead.
pub fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// A request head for tests: `method` and `target`, HTTP/1.1. An invalid method or target
/// gives a `GET /`, so a typo shows up as a failing assertion rather than a panic here.
#[must_use]
pub fn request(method: &str, target: &str) -> RequestHead {
    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    RequestHead::new(method.clone(), target)
        .or_else(|_| RequestHead::new(method, "/"))
        .unwrap_or_else(|_| {
            RequestHead::from_parts(
                Method::GET,
                http::Uri::from_static("/"),
                http::Version::HTTP_11,
                http::HeaderMap::new(),
            )
        })
}

/// A response head for tests, as a backend would send it.
#[must_use]
pub fn response(status: StatusCode) -> ResponseHead {
    ResponseHead::new(status)
}

/// What a whole exchange through [`Harness::run`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Outcome {
    /// The plugin's own answer, if it gave one (the backend was then not asked).
    pub answered: Option<Response>,
    /// The request head as the backend would have received it.
    pub upstream_request: RequestHead,
    /// The body as the backend would have received it (after a replacement).
    pub upstream_body: Option<Bytes>,
    /// The response head after the `response` phase (the plugin's answer's status when it
    /// answered).
    pub response: ResponseHead,
}

/// Runs one plugin through its phases, like one request through a route whose chain holds
/// only this plugin.
pub struct Harness {
    plugin: Arc<dyn Plugin>,
    caps: Capabilities,
    facts: Facts,
    state: State,
}

impl std::fmt::Debug for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Harness")
            .field("capabilities", &self.caps)
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl Harness {
    /// A harness for `plugin`, for a request from `192.0.2.10` on route `test`, without TLS.
    #[must_use]
    pub fn new(plugin: impl Plugin) -> Self {
        Self::from_arc(Arc::new(plugin))
    }

    /// A harness for a plugin already behind an `Arc`.
    #[must_use]
    pub fn from_arc(plugin: Arc<dyn Plugin>) -> Self {
        let caps = plugin.capabilities();
        Self {
            plugin,
            caps,
            facts: Facts::new(IpAddr::from([192, 0, 2, 10]), "test", "test-request"),
            state: State::default(),
        }
    }

    /// Builds the plugin with `factory` from `config`, as `rdock validate` and `rdock run` do.
    ///
    /// # Errors
    ///
    /// The factory refused the configuration.
    pub fn from_factory(
        factory: &dyn Factory,
        config: &serde_json::Value,
    ) -> Result<Self, ConfigError> {
        factory.build(config).map(Self::from_arc)
    }

    /// Sets the client address.
    #[must_use]
    pub fn client_ip(mut self, ip: IpAddr) -> Self {
        self.facts = self.facts.clone().with_client_ip(ip);
        self
    }

    /// Sets whether the client used TLS.
    #[must_use]
    pub fn tls(mut self, tls: bool) -> Self {
        self.facts = self.facts.clone().with_tls(tls);
        self
    }

    /// Sets the consumer an earlier middleware attributed the request to.
    #[must_use]
    pub fn consumer(mut self, consumer: Consumer) -> Self {
        self.facts = self.facts.clone().with_consumer(Some(consumer));
        self
    }

    /// Sets the backend chosen for the `upstream_request` and later phases.
    #[must_use]
    pub fn upstream(mut self, upstream: Upstream) -> Self {
        self.facts = self.facts.clone().with_upstream(Some(upstream));
        self
    }

    /// The plugin's declared capabilities.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        self.caps
    }

    /// The facts hooks see.
    #[must_use]
    pub fn facts(&self) -> &Facts {
        &self.facts
    }

    /// The plugin's state, as the last hook left it.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Starts a new request: forgets the state.
    pub fn reset(&mut self) {
        self.state = State::default();
    }

    fn declared(&self, phase: Phases) -> bool {
        self.caps.phases().contains(phase)
    }

    fn scratch(&mut self) -> &mut State {
        if !self.caps.state() {
            self.state = State::default();
        }
        &mut self.state
    }

    /// The `request` phase.
    pub async fn request(&mut self, req: &mut RequestHead) -> Decision {
        if !self.declared(Phases::REQUEST) {
            return Decision::Continue;
        }
        let facts = self.facts.clone();
        let plugin = self.plugin.clone();
        let mut cx = Ctx::new(&facts, self.scratch());
        plugin.request(req, &mut cx).await
    }

    /// The `upstream_request` phase.
    pub async fn upstream_request(&mut self, req: &mut RequestHead) -> Decision {
        if !self.declared(Phases::UPSTREAM_REQUEST) {
            return Decision::Continue;
        }
        let facts = self.facts.clone();
        let plugin = self.plugin.clone();
        let mut cx = Ctx::new(&facts, self.scratch());
        plugin.upstream_request(req, &mut cx).await
    }

    /// The `request_body` phase with `body`. A body over the declared limit is answered
    /// `413` without calling the plugin, as the proxy does; a replacement without
    /// [`crate::BodyLimit::replacing`] is answered `500`.
    pub async fn request_body(&mut self, body: impl Into<Bytes>) -> BodyDecision {
        let Some(limit) = self.caps.body() else {
            return BodyDecision::Continue;
        };
        let body = RequestBody::new(body);
        if body.len() as u64 > limit.max {
            return BodyDecision::Respond(Response::new(StatusCode::PAYLOAD_TOO_LARGE));
        }
        let facts = self.facts.clone();
        let plugin = self.plugin.clone();
        let mut cx = Ctx::new(&facts, self.scratch());
        match plugin.request_body(&body, &mut cx).await {
            BodyDecision::Replace(_) if !limit.replaces => {
                BodyDecision::Respond(Response::new(StatusCode::INTERNAL_SERVER_ERROR))
            }
            decision => decision,
        }
    }

    /// The `response` phase.
    pub async fn response(&mut self, resp: &mut ResponseHead) {
        if !self.declared(Phases::RESPONSE) {
            return;
        }
        let facts = self.facts.clone();
        let plugin = self.plugin.clone();
        let mut cx = Ctx::new(&facts, self.scratch());
        plugin.response(resp, &mut cx).await;
    }

    /// The `response_body` phase for one chunk.
    pub fn response_body(&mut self, chunk: &mut Option<Bytes>, end_of_stream: bool) {
        if !self.declared(Phases::RESPONSE_BODY) {
            return;
        }
        let facts = self.facts.clone();
        let plugin = self.plugin.clone();
        let mut cx = Ctx::new(&facts, self.scratch());
        plugin.response_body(chunk, end_of_stream, &mut cx);
    }

    /// The whole response body through `response_body`, as one chunk followed by the end of
    /// the stream.
    pub fn response_body_all(&mut self, body: impl Into<Bytes>) -> Bytes {
        let mut out = Vec::new();
        let mut chunk = Some(body.into());
        self.response_body(&mut chunk, false);
        out.extend_from_slice(chunk.as_deref().unwrap_or_default());
        let mut end = None;
        self.response_body(&mut end, true);
        out.extend_from_slice(end.as_deref().unwrap_or_default());
        Bytes::from(out)
    }

    /// The `log` phase.
    pub fn log(&self, summary: &LogSummary) {
        if !self.declared(Phases::LOG) {
            return;
        }
        let state = self.caps.state().then_some(&self.state);
        let cx = Ctx::read_only(&self.facts, state);
        self.plugin.log(summary, &cx);
    }

    /// A whole exchange: `request`, `upstream_request`, `request_body` (when `body` is
    /// given), then `response` on `backend` (or on the plugin's own answer's head), then
    /// `log`. State is reset first.
    pub async fn run(
        &mut self,
        mut req: RequestHead,
        body: Option<Bytes>,
        backend: ResponseHead,
    ) -> Outcome {
        self.reset();
        let mut answered = self.request(&mut req).await.response().cloned();
        if answered.is_none() {
            answered = self.upstream_request(&mut req).await.response().cloned();
        }
        let mut upstream_body = body.clone();
        if answered.is_none()
            && let Some(body) = body
        {
            match self.request_body(body).await {
                BodyDecision::Replace(bytes) => upstream_body = Some(bytes),
                BodyDecision::Respond(response) => answered = Some(response),
                _ => {}
            }
        }
        let mut response = match &answered {
            Some(answer) => ResponseHead::new(answer.status()),
            None => backend,
        };
        self.response(&mut response).await;
        self.log(&LogSummary::new(Some(response.status()), Duration::ZERO));
        Outcome {
            answered,
            upstream_request: req,
            upstream_body,
            response,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{BodyLimit, async_trait};

    /// Counts requests in its state and tags the response with the count.
    struct Counter;

    #[async_trait]
    impl Plugin for Counter {
        fn capabilities(&self) -> Capabilities {
            Capabilities::new(Phases::REQUEST | Phases::RESPONSE)
                .with_state()
                .with_body(BodyLimit::new(4))
        }

        async fn request(&self, _req: &mut RequestHead, cx: &mut Ctx<'_>) -> Decision {
            cx.set_state(1_u8);
            Decision::Continue
        }

        async fn request_body(&self, body: &RequestBody, _cx: &mut Ctx<'_>) -> BodyDecision {
            BodyDecision::Replace(body.bytes().clone())
        }

        async fn response(&self, resp: &mut ResponseHead, cx: &mut Ctx<'_>) {
            let seen = cx.state::<u8>().copied().unwrap_or(0);
            resp.set_header("x-seen", seen.to_string()).unwrap();
        }
    }

    #[test]
    fn the_harness_follows_the_proxy_rules() {
        let mut h = Harness::new(Counter);
        let outcome = block_on(h.run(
            request("POST", "/"),
            Some(Bytes::from_static(b"abc")),
            response(StatusCode::OK),
        ));
        assert_eq!(
            outcome.answered.map(|r| r.status()),
            Some(StatusCode::INTERNAL_SERVER_ERROR),
            "replacing without declaring it"
        );
        assert_eq!(outcome.response.header("x-seen"), Some("1"), "state kept");
        let outcome = block_on(h.run(
            request("POST", "/"),
            Some(Bytes::from_static(b"too long")),
            response(StatusCode::OK),
        ));
        assert_eq!(
            outcome.answered.map(|r| r.status()),
            Some(StatusCode::PAYLOAD_TOO_LARGE)
        );
        let h = Harness::new(Counter).client_ip("2001:db8::1".parse().unwrap());
        assert_eq!(h.facts().client_ip().to_string(), "2001:db8::1");
        assert_eq!(request("NOT A METHOD", "::").uri(), "/");
    }
}
