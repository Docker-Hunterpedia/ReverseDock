#![doc = include_str!("../README.md")]

mod caps;
mod context;
mod decision;
mod factory;
mod head;
pub mod testing;

use bytes::Bytes;

pub use async_trait::async_trait;
pub use bytes;
pub use http;
pub use serde_json;

pub use caps::{BodyLimit, Capabilities, Phases};
pub use context::{Consumer, Ctx, Facts, LogSummary, State, Upstream};
pub use decision::{BodyDecision, Decision, RequestBody, Response};
pub use factory::{ConfigError, ConfigIssue, Factory, Registry, RegistryError, typed};
pub use head::{
    HeadError, RequestHead, ResponseHead, is_protected_request_header, is_protected_response_header,
};

/// The version of this API (`0.x`: it may change in any release until 1.0). `rdock version`
/// prints the version a binary was built with.
pub const API_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A native plugin: hooks for the phases of a request.
///
/// The proxy calls only the hooks of the phases the plugin declares in
/// [`Self::capabilities`]. On the way in, plugins and built-in middlewares run in the route's
/// list order (`request`, `upstream_request`, `request_body`); on the way out in reverse
/// order (`response`, `response_body`, `log`). `response` also runs for answers given by later
/// middlewares or by the proxy.
///
/// A plugin runs inside the proxy with its privileges: it can read every header and body it
/// is given and everything the process can reach. A panic in a hook is caught: the proxy
/// counts it (`rdock_plugin_panics_total{plugin}`), logs it with the plugin's name and
/// answers that request with `500`; other requests are not affected.
///
/// Implement it with [`async_trait`](macro@async_trait) (re-exported here), because `async fn` in a trait object
/// needs it:
///
/// ```
/// use rdock_plugin_api::{
///     Capabilities, Ctx, Decision, Phases, Plugin, RequestHead, ResponseHead, async_trait,
/// };
///
/// /// Tags requests and responses with the route's name.
/// struct RouteTag;
///
/// #[async_trait]
/// impl Plugin for RouteTag {
///     fn capabilities(&self) -> Capabilities {
///         Capabilities::new(Phases::REQUEST | Phases::RESPONSE)
///     }
///
///     async fn request(&self, req: &mut RequestHead, cx: &mut Ctx<'_>) -> Decision {
///         let _ = req.set_header("x-route", cx.route());
///         Decision::Continue
///     }
///
///     async fn response(&self, resp: &mut ResponseHead, cx: &mut Ctx<'_>) {
///         let _ = resp.set_header("x-served-by-route", cx.route());
///     }
/// }
/// ```
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    /// The phases this plugin uses, whether it keeps per-request state, and whether the proxy
    /// should hold the request body for it. Read once, when the route's chain is built.
    fn capabilities(&self) -> Capabilities;

    /// Inspects or changes the request head before the backend is chosen, or answers.
    /// Needs [`Phases::REQUEST`].
    async fn request(&self, _req: &mut RequestHead, _cx: &mut Ctx<'_>) -> Decision {
        Decision::Continue
    }

    /// Changes the request head about to be sent to the chosen backend ([`Ctx::upstream`]),
    /// or answers instead (the attempt is abandoned and not retried). Runs once per attempt,
    /// on a fresh copy of the request. Needs [`Phases::UPSTREAM_REQUEST`].
    async fn upstream_request(&self, _req: &mut RequestHead, _cx: &mut Ctx<'_>) -> Decision {
        Decision::Continue
    }

    /// Inspects the complete request body before any of it is forwarded, and lets it pass,
    /// replaces it or answers instead. The backend already has the request head (the proxy
    /// sends it when it connects) but no byte of the body. Needs
    /// [`Capabilities::with_body`].
    async fn request_body(&self, _body: &RequestBody, _cx: &mut Ctx<'_>) -> BodyDecision {
        BodyDecision::Continue
    }

    /// Changes the response head before it is sent to the client. Needs
    /// [`Phases::RESPONSE`].
    async fn response(&self, _resp: &mut ResponseHead, _cx: &mut Ctx<'_>) {}

    /// Changes or counts one chunk of the response body before it is compressed and sent.
    /// Synchronous: it cannot await. A plugin that changes the length removes
    /// `Content-Length` in [`Self::response`]. The last call has `end_of_stream` set (its
    /// chunk may be `None`). Needs [`Phases::RESPONSE_BODY`].
    fn response_body(&self, _chunk: &mut Option<Bytes>, _end_of_stream: bool, _cx: &mut Ctx<'_>) {}

    /// Observes the finished request; cannot change anything. Needs [`Phases::LOG`].
    fn log(&self, _summary: &LogSummary, _cx: &Ctx<'_>) {}
}
