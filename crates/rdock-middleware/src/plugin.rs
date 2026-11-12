//! `plugin`: a native plugin (`rdock-plugin-api`) used as a middleware (F-EXT-02, ADR-0030).
//!
//! The adapter translates the proxy's Pingora heads into the plugin API's `http`-typed views and
//! back (changes are written back only when the plugin made some), maps decisions to replies,
//! declares the plugin's own capabilities, and isolates panics: a panic in any hook is caught,
//! counted in `rdock_plugin_panics_total{plugin}`, logged with the plugin's name and answered
//! with `500` for that request only. Without this, Tokio would catch the panic at the task
//! boundary and drop the client's whole connection (every HTTP/2 stream on it).

use std::any::Any;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::FutureExt;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_plugin_api as api;

use crate::held::HeldBody;
use crate::phase::{BodyHold, BodyVerdict, Capabilities, LogSummary, Phases};
use crate::{Body, BuildError, Context, Flow, Issue, Middleware, Reply};

/// The body of the `500` sent for a request whose plugin panicked.
const PANIC_BODY: &[u8] = b"Internal Server Error\n";

/// A plugin as a middleware.
pub(crate) struct PluginMiddleware {
    /// The registered plugin name (the metric label).
    plugin: Arc<str>,
    /// The middleware's name in the configuration.
    middleware: Arc<str>,
    inner: Arc<dyn api::Plugin>,
    caps: api::Capabilities,
    /// `rdock_plugin_panics_total{plugin}`, already labelled.
    panics: Option<rdock_observability::IntCounter>,
}

impl fmt::Debug for PluginMiddleware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginMiddleware")
            .field("plugin", &self.plugin)
            .field("middleware", &self.middleware)
            .field("capabilities", &self.caps)
            .finish_non_exhaustive()
    }
}

impl PluginMiddleware {
    /// Builds the plugin `config.name` with its factory from `plugins`.
    pub(crate) fn build(
        middleware: &str,
        config: &rdock_model::middleware::PluginConfig,
        plugins: &api::Registry,
        metrics: Option<&rdock_observability::Metrics>,
    ) -> Result<Self, BuildError> {
        let Some(factory) = plugins.get(&config.name) else {
            let message = if plugins.is_empty() {
                format!(
                    "no plugin `{}`: this build of rdock registers no plugins",
                    config.name
                )
            } else {
                format!(
                    "no plugin `{}` is registered in this build; registered: {}",
                    config.name,
                    plugins.names().collect::<Vec<_>>().join(", ")
                )
            };
            return Err(BuildError::Issues(vec![Issue::new("name", message).with_hint(
                "plugins are compiled into a custom binary that registers them (see the plugins guide)",
            )]));
        };
        let inner = factory
            .build(&serde_json::Value::Object(config.config.clone()))
            .map_err(|e| {
                BuildError::Issues(
                    e.issues()
                        .iter()
                        .map(|issue| {
                            let path = match issue.path.as_str() {
                                "" => "config".to_owned(),
                                p if p.starts_with('[') => format!("config{p}"),
                                p => format!("config.{p}"),
                            };
                            let mut out = Issue::new(path, issue.message.clone());
                            if let Some(hint) = &issue.hint {
                                out = out.with_hint(hint.clone());
                            }
                            out
                        })
                        .collect(),
                )
            })?;
        Ok(Self::new(middleware, &config.name, inner, metrics))
    }

    pub(crate) fn new(
        middleware: &str,
        plugin: &str,
        inner: Arc<dyn api::Plugin>,
        metrics: Option<&rdock_observability::Metrics>,
    ) -> Self {
        let caps = inner.capabilities();
        Self {
            plugin: Arc::from(plugin),
            middleware: Arc::from(middleware),
            inner,
            caps,
            panics: metrics.map(|m| m.plugin_panics.with_label_values(&[plugin])),
        }
    }

    fn declared(&self, phase: api::Phases) -> bool {
        self.caps.phases().contains(phase)
    }

    /// Counts and logs a caught panic.
    fn panicked(&self, phase: &str, payload: &(dyn Any + Send)) {
        if let Some(counter) = &self.panics {
            counter.inc();
        }
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "(no message)".to_owned());
        tracing::error!(
            plugin = %self.plugin,
            middleware = %self.middleware,
            phase,
            panic = %message,
            "a plugin panicked; this request is answered with 500"
        );
    }

    /// Runs an async hook, catching a panic.
    async fn guard<T>(&self, phase: &str, hook: impl Future<Output = T> + Send) -> Option<T> {
        match AssertUnwindSafe(hook).catch_unwind().await {
            Ok(value) => Some(value),
            Err(payload) => {
                self.panicked(phase, &*payload);
                None
            }
        }
    }
}

/// The plugin's facts from the proxy's context.
fn facts(cx: &Context) -> api::Facts {
    api::Facts::new(cx.client_ip, cx.route.clone(), cx.request_id.clone())
        .with_tls(cx.tls)
        .with_consumer(
            cx.consumer
                .as_ref()
                .map(|c| api::Consumer::new(c.name.clone(), c.groups.clone())),
        )
        .with_upstream(
            cx.upstream.as_ref().map(|u| {
                api::Upstream::new(u.service.clone(), u.backend.clone(), u.addr, u.attempt)
            }),
        )
}

/// The plugin's state slot in the proxy's context, when it declared one.
fn state(cx: &mut Context, wanted: bool) -> Option<&mut api::State> {
    if !wanted {
        return None;
    }
    if cx.state::<api::State>().is_none() {
        cx.set_state(api::State::default());
    }
    cx.state_mut::<api::State>()
}

pub(crate) fn request_view(req: &RequestHeader) -> api::RequestHead {
    api::RequestHead::from_parts(
        req.method.clone(),
        req.uri.clone(),
        req.version,
        req.headers.clone(),
    )
}

/// Writes a plugin's changes to the request head back.
pub(crate) fn apply_request(view: &api::RequestHead, req: &mut RequestHeader) {
    if !view.is_changed() {
        return;
    }
    if view.method() != req.method {
        req.set_method(view.method().clone());
    }
    if *view.uri() != req.uri {
        req.set_uri(view.uri().clone());
    }
    let (removed, appended) = header_changes(&req.headers, view.headers());
    for name in &removed {
        req.remove_header(name);
    }
    for (name, value) in appended {
        let _ = req.append_header(name, value);
    }
}

/// Writes a plugin's changes to the response head back.
pub(crate) fn apply_response(view: &api::ResponseHead, resp: &mut ResponseHeader) {
    if !view.is_changed() {
        return;
    }
    if view.status() != resp.status {
        let _ = resp.set_status(view.status());
    }
    let (removed, appended) = header_changes(&resp.headers, view.headers());
    for name in &removed {
        resp.remove_header(name);
    }
    for (name, value) in appended {
        let _ = resp.append_header(name, value);
    }
}

/// What turns the headers `old` into `new`: names to remove, then values to append. Pingora
/// keeps the case of header names in a side table, so its own methods must make the changes.
fn header_changes(
    old: &HeaderMap,
    new: &HeaderMap,
) -> (Vec<HeaderName>, Vec<(HeaderName, HeaderValue)>) {
    let mut removed: Vec<HeaderName> = old
        .keys()
        .filter(|name| !new.contains_key(*name))
        .cloned()
        .collect();
    let mut appended = Vec::new();
    for name in new.keys() {
        if !old.get_all(name).iter().eq(new.get_all(name).iter()) {
            removed.push(name.clone());
            appended.extend(new.get_all(name).iter().map(|v| (name.clone(), v.clone())));
        }
    }
    (removed, appended)
}

/// A plugin's answer as a reply; framing headers are the proxy's to compute.
pub(crate) fn reply(response: api::Response) -> Reply {
    let (status, headers, body) = response.into_parts();
    let mut out = Vec::with_capacity(headers.len());
    let mut last: Option<HeaderName> = None;
    for (name, value) in headers {
        // `HeaderMap::into_iter` gives the name only for the first of several values.
        let Some(name) = name.or_else(|| last.clone()) else {
            continue;
        };
        last = Some(name.clone());
        if !api::is_protected_response_header(&name) {
            out.push((name, value));
        }
    }
    Reply {
        status: status.as_u16(),
        headers: out,
        body: body.map(Body::Bytes),
        problem: None,
        extensions: None,
    }
}

fn internal_error() -> Reply {
    Reply {
        status: 500,
        headers: vec![(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        body: Some(Body::Bytes(Bytes::from_static(PANIC_BODY))),
        problem: None,
        extensions: None,
    }
}

#[async_trait]
impl Middleware for PluginMiddleware {
    fn capabilities(&self) -> Capabilities {
        let mut phases = Phases::NONE;
        for (theirs, ours) in [
            (api::Phases::REQUEST, Phases::REQUEST),
            (api::Phases::UPSTREAM_REQUEST, Phases::UPSTREAM_REQUEST),
            (api::Phases::RESPONSE, Phases::RESPONSE),
            (api::Phases::RESPONSE_BODY, Phases::RESPONSE_BODY),
            (api::Phases::LOG, Phases::LOG),
        ] {
            if self.declared(theirs) {
                phases = phases | ours;
            }
        }
        let mut caps = Capabilities::new(phases);
        if self.caps.state() {
            caps = caps.with_state();
        }
        if let Some(limit) = self.caps.body() {
            let mut hold = BodyHold::new(limit.max).timeout(limit.timeout);
            if limit.replaces {
                hold = hold.replacing();
            }
            caps = caps.with_body(hold);
        }
        caps
    }

    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        if !self.declared(api::Phases::REQUEST) {
            return Flow::Next;
        }
        let facts = facts(cx);
        let mut scratch = api::State::default();
        let state = state(cx, self.caps.state()).unwrap_or(&mut scratch);
        let mut view = request_view(req);
        let mut pcx = api::Ctx::new(&facts, state);
        let decision = self
            .guard("request", self.inner.request(&mut view, &mut pcx))
            .await;
        match decision {
            None => Flow::Reply(internal_error()),
            Some(api::Decision::Respond(response)) => Flow::Reply(reply(response)),
            Some(_) => {
                apply_request(&view, req);
                Flow::Next
            }
        }
    }

    async fn upstream_request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        if !self.declared(api::Phases::UPSTREAM_REQUEST) {
            return Flow::Next;
        }
        let facts = facts(cx);
        let mut scratch = api::State::default();
        let state = state(cx, self.caps.state()).unwrap_or(&mut scratch);
        let mut view = request_view(req);
        let mut pcx = api::Ctx::new(&facts, state);
        let decision = self
            .guard(
                "upstream_request",
                self.inner.upstream_request(&mut view, &mut pcx),
            )
            .await;
        match decision {
            None => Flow::Reply(internal_error()),
            Some(api::Decision::Respond(response)) => Flow::Reply(reply(response)),
            Some(_) => {
                apply_request(&view, req);
                Flow::Next
            }
        }
    }

    async fn request_body(&self, body: &HeldBody, cx: &mut Context) -> BodyVerdict {
        if self.caps.body().is_none() {
            return BodyVerdict::Continue;
        }
        let bytes = match body.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(plugin = %self.plugin, error = %e, "reading a held body failed");
                return BodyVerdict::Reply(Reply::status(500));
            }
        };
        let facts = facts(cx);
        let mut scratch = api::State::default();
        let state = state(cx, self.caps.state()).unwrap_or(&mut scratch);
        let view = api::RequestBody::new(bytes);
        let mut pcx = api::Ctx::new(&facts, state);
        let decision = self
            .guard("request_body", self.inner.request_body(&view, &mut pcx))
            .await;
        match decision {
            None => BodyVerdict::Reply(internal_error()),
            Some(api::BodyDecision::Replace(bytes)) => BodyVerdict::Replace(bytes),
            Some(api::BodyDecision::Respond(response)) => BodyVerdict::Reply(reply(response)),
            Some(_) => BodyVerdict::Continue,
        }
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        if !self.declared(api::Phases::RESPONSE) {
            return;
        }
        let facts = facts(cx);
        let mut scratch = api::State::default();
        let state = state(cx, self.caps.state()).unwrap_or(&mut scratch);
        let mut view =
            api::ResponseHead::from_parts(resp.status, resp.version, resp.headers.clone());
        let mut pcx = api::Ctx::new(&facts, state);
        let done = self
            .guard("response", self.inner.response(&mut view, &mut pcx))
            .await;
        if done.is_some() {
            apply_response(&view, resp);
            return;
        }
        // The head has not left yet: the client gets a 500 instead of the backend's answer.
        let names: Vec<HeaderName> = resp.headers.keys().cloned().collect();
        for name in names {
            resp.remove_header(&name);
        }
        let _ = resp.set_status(500);
        let _ = resp.insert_header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
        let _ = resp.set_content_length(PANIC_BODY.len());
        cx.compression = None;
        cx.replace_body = Some(Bytes::from_static(PANIC_BODY));
    }

    fn response_body(&self, body: &mut Option<Bytes>, end_of_stream: bool, cx: &mut Context) {
        if !self.declared(api::Phases::RESPONSE_BODY) {
            return;
        }
        let facts = facts(cx);
        let mut scratch = api::State::default();
        let state = state(cx, self.caps.state()).unwrap_or(&mut scratch);
        let original = body.clone();
        let mut pcx = api::Ctx::new(&facts, state);
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.inner.response_body(body, end_of_stream, &mut pcx);
        }));
        if let Err(payload) = result {
            // The head is gone: the chunk passes unchanged rather than half-transformed.
            self.panicked("response_body", &*payload);
            *body = original;
        }
    }

    fn log(&self, summary: &LogSummary, cx: &Context) {
        if !self.declared(api::Phases::LOG) {
            return;
        }
        let facts = facts(cx);
        let state = if self.caps.state() {
            cx.state::<api::State>()
        } else {
            None
        };
        let pcx = api::Ctx::read_only(&facts, state);
        let status = http::StatusCode::from_u16(summary.status).ok();
        let summary = api::LogSummary::new(status, summary.duration)
            .with_bytes(summary.bytes_in, summary.bytes_out)
            .with_upstream_duration(summary.upstream_duration)
            .with_error(summary.error.clone());
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.inner.log(&summary, &pcx);
        }));
        if let Err(payload) = result {
            self.panicked("log", &*payload);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use api::async_trait;

    use super::*;
    use crate::test_support::{block_on, cx, request};

    /// Sets a header, refuses `/deny`, panics on `/panic`, counts in its state.
    struct Probe {
        logged: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl api::Plugin for Probe {
        fn capabilities(&self) -> api::Capabilities {
            api::Capabilities::new(api::Phases::REQUEST | api::Phases::RESPONSE | api::Phases::LOG)
                .with_state()
        }

        async fn request(
            &self,
            req: &mut api::RequestHead,
            cx: &mut api::Ctx<'_>,
        ) -> api::Decision {
            match req.path() {
                "/deny" => api::Response::text(http::StatusCode::FORBIDDEN, "no\n")
                    .with_header(http::header::CONTENT_LENGTH, HeaderValue::from_static("99"))
                    .into(),
                "/panic" => panic!("boom"),
                _ => {
                    req.set_header("x-plugin", cx.route()).unwrap();
                    req.remove_header("x-drop").unwrap();
                    req.set_path("/rewritten").unwrap();
                    cx.set_state(7_u32);
                    api::Decision::Continue
                }
            }
        }

        async fn response(&self, resp: &mut api::ResponseHead, cx: &mut api::Ctx<'_>) {
            assert!(resp.status() != http::StatusCode::IM_A_TEAPOT, "teapot");
            let seen = cx.state::<u32>().copied().unwrap_or_default();
            resp.set_header("x-state", seen.to_string()).unwrap();
        }

        fn log(&self, _summary: &api::LogSummary, cx: &api::Ctx<'_>) {
            if cx.state::<u32>() == Some(&7) {
                self.logged.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn adapter(
        metrics: Option<&rdock_observability::Metrics>,
    ) -> (PluginMiddleware, Arc<AtomicUsize>) {
        let logged = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(Probe {
            logged: logged.clone(),
        });
        (
            PluginMiddleware::new("probe-mw", "probe", inner, metrics),
            logged,
        )
    }

    #[test]
    fn changes_are_written_back_and_state_spans_phases() {
        let (mw, logged) = adapter(None);
        let caps = mw.capabilities();
        assert!(caps.state());
        assert_eq!(
            caps.phases().names().collect::<Vec<_>>(),
            ["request", "response", "log"]
        );
        let mut cx = cx();
        cx.prepare_state(1);
        let mut req = request("GET", "/a?q=1", &[("x-drop", "1"), ("X-Keep", "k")]);
        assert_eq!(block_on(mw.request(&mut req, &mut cx)), Flow::Next);
        assert_eq!(req.uri, "/rewritten?q=1");
        assert_eq!(req.headers["x-plugin"], "route");
        assert!(!req.headers.contains_key("x-drop"));
        assert_eq!(req.headers["x-keep"], "k");
        let mut resp = ResponseHeader::build(200, None).unwrap();
        block_on(mw.response(&mut resp, &mut cx));
        assert_eq!(resp.headers["x-state"], "7");
        mw.log(
            &LogSummary {
                status: 200,
                bytes_in: 0,
                bytes_out: 0,
                duration: std::time::Duration::ZERO,
                upstream_duration: None,
                error: None,
            },
            &cx,
        );
        assert_eq!(logged.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn answers_drop_framing_headers() {
        let (mw, _) = adapter(None);
        let mut req = request("GET", "/deny", &[]);
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx())) else {
            panic!("an answer");
        };
        assert_eq!(reply.status, 403);
        assert!(
            reply
                .headers
                .iter()
                .all(|(n, _)| n != http::header::CONTENT_LENGTH)
        );
        assert_eq!(crate::test_support::reply_bytes(&reply), Some(&b"no\n"[..]));
    }

    #[test]
    fn a_panic_is_caught_counted_and_answered_with_500() {
        let metrics = rdock_observability::Metrics::new("test", "test").unwrap();
        let (mw, _) = adapter(Some(&metrics));
        let mut req = request("GET", "/panic", &[]);
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx())) else {
            panic!("an answer");
        };
        assert_eq!(reply.status, 500);
        assert_eq!(metrics.plugin_panics.with_label_values(&["probe"]).get(), 1);
        // The next request is served normally.
        let mut req = request("GET", "/ok", &[]);
        assert_eq!(block_on(mw.request(&mut req, &mut cx())), Flow::Next);
        // A panic in `response` turns the answer into a 500 before the head leaves.
        let mut cx = cx();
        let mut resp = ResponseHeader::build(418, None).unwrap();
        resp.insert_header("content-encoding", "gzip").unwrap();
        block_on(mw.response(&mut resp, &mut cx));
        assert_eq!(resp.status.as_u16(), 500);
        assert!(!resp.headers.contains_key("content-encoding"));
        assert_eq!(cx.replace_body.as_deref(), Some(PANIC_BODY));
        assert_eq!(metrics.plugin_panics.with_label_values(&["probe"]).get(), 2);
    }

    #[test]
    fn unknown_names_list_what_is_registered() {
        let config = rdock_model::middleware::PluginConfig {
            name: "geo".into(),
            config: serde_json::Map::new(),
        };
        let none = api::Registry::new();
        let Err(BuildError::Issues(issues)) = PluginMiddleware::build("m", &config, &none, None)
        else {
            panic!("an error");
        };
        assert_eq!(issues[0].path, "name");
        assert!(
            issues[0].message.contains("registers no plugins"),
            "{issues:?}"
        );
        let some = api::Registry::new()
            .plugin(
                "b",
                |_: &serde_json::Value| -> Result<Arc<dyn api::Plugin>, api::ConfigError> {
                    Err(api::ConfigError::at("list[1]", "bad").with_hint("fix it"))
                },
            )
            .plugin(
                "a",
                |_: &serde_json::Value| -> Result<Arc<dyn api::Plugin>, api::ConfigError> {
                    Err(api::ConfigError::new("empty"))
                },
            );
        let Err(BuildError::Issues(issues)) = PluginMiddleware::build("m", &config, &some, None)
        else {
            panic!("an error");
        };
        assert!(
            issues[0].message.ends_with("registered: a, b"),
            "{issues:?}"
        );
        let config = rdock_model::middleware::PluginConfig {
            name: "b".into(),
            config: serde_json::Map::new(),
        };
        let Err(BuildError::Issues(issues)) = PluginMiddleware::build("m", &config, &some, None)
        else {
            panic!("an error");
        };
        assert_eq!(issues[0].path, "config.list[1]");
        assert_eq!(issues[0].hint.as_deref(), Some("fix it"));
    }
}
