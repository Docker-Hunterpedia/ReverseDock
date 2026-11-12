//! `transform`: request and response header rules, and JSON Patch (RFC 6902) on JSON bodies
//! (F-GW-04, ADR-0030).
//!
//! Request bodies are held (up to `max_body`), patched and forwarded in place of the client's;
//! the proxy then drops the client's `Content-Length` (HTTP/1.1 chunked, HTTP/2 stream framing),
//! because the request head leaves before the body is known. Response bodies are patched in the
//! synchronous `response_body` phase: the chunks of an eligible response (2xx other than 204,
//! 205 and 206, JSON, not encoded by the backend, at most `max_body`) are collected and the
//! patched document is sent at the end. Anything else passes unchanged and is counted in
//! `rdock_transform_skipped_total{middleware, reason}`.
//!
//! The cache is not a phase (ADR-0030): it stores what the backend sent, before any `response`
//! hook runs, and a cached answer goes through this middleware again. Wherever `transform`
//! sits in the list, the store never holds a patched body and every hit is patched.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::Method;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_model::json_patch::{self, PatchError, PatchOp};
use rdock_model::transform::{OnNonJson, OnPatchError, TransformConfig, is_json_media_type};
use serde_json::{Value, json};

use crate::headers::Rules;
use crate::held::HeldBody;
use crate::phase::{BodyHold, BodyVerdict, Capabilities, Phases};
use crate::{BuildError, Context, Flow, Issue, Middleware, ProblemKind, Reply};

/// Response headers that describe the backend's bytes and are wrong for a patched body.
const STALE_RESPONSE_HEADERS: [&str; 6] = [
    "content-length",
    "etag",
    "accept-ranges",
    "content-md5",
    "content-digest",
    "repr-digest",
];

/// Where a response body stands.
#[derive(Debug)]
enum Collect {
    /// Collecting the chunks of an eligible response.
    Buffer(BytesMut),
    /// Passing chunks through (too large, or done).
    Pass,
}

/// Per-request state.
#[derive(Debug, Default)]
struct State {
    /// The request is a `HEAD`: its response has no body.
    head: bool,
    /// The request body is held and will be patched.
    patch_request: bool,
    /// The response body, once `response` found it eligible.
    response: Option<Collect>,
}

/// The `transform` middleware.
#[derive(Debug)]
pub(crate) struct Transform {
    name: Arc<str>,
    request_headers: Rules,
    response_headers: Rules,
    request_patch: Vec<PatchOp>,
    response_patch: Vec<PatchOp>,
    max_body: u64,
    on_error: OnPatchError,
    on_non_json: OnNonJson,
    metrics: Option<rdock_observability::Metrics>,
}

impl Transform {
    pub(crate) fn new(
        name: &str,
        config: &TransformConfig,
        metrics: Option<&rdock_observability::Metrics>,
    ) -> Result<Self, BuildError> {
        let mut issues = Vec::new();
        for (side, ops) in [
            ("request", &config.request.body.patch),
            ("response", &config.response.body.patch),
        ] {
            for (i, op) in ops.iter().enumerate() {
                if let Err(kind) = op.check() {
                    issues.push(Issue::new(
                        format!("{side}.body.patch[{i}]"),
                        format!("`{}`: {kind}", op.name()),
                    ));
                }
            }
        }
        if !issues.is_empty() {
            return Err(BuildError::Issues(issues));
        }
        Ok(Self {
            name: Arc::from(name),
            request_headers: Rules::new(&config.request.headers)?,
            response_headers: Rules::new(&config.response.headers)?,
            request_patch: config.request.body.patch.clone(),
            response_patch: config.response.body.patch.clone(),
            max_body: config.max_body.as_u64(),
            on_error: config.on_error,
            on_non_json: config.on_non_json,
            metrics: metrics.cloned(),
        })
    }

    fn skipped(&self, reason: &str) {
        if let Some(m) = &self.metrics {
            m.transform_skipped
                .with_label_values(&[&*self.name, reason])
                .inc();
        }
    }

    /// Whether a response with this head gets its body patched; the reason when not.
    fn eligible(
        &self,
        resp: &ResponseHeader,
        head: bool,
        compressing: bool,
    ) -> Result<(), &'static str> {
        let status = resp.status.as_u16();
        if head || !(200..300).contains(&status) || matches!(status, 204..=206) {
            return Err("status");
        }
        let header =
            |name: http::header::HeaderName| resp.headers.get(name).and_then(|v| v.to_str().ok());
        if !header(http::header::CONTENT_TYPE).is_some_and(is_json_media_type) {
            return Err("not_json");
        }
        // `compress` (when it chose to encode) marks the head; the body phase still sees
        // the backend's identity bytes.
        if !compressing
            && header(http::header::CONTENT_ENCODING)
                .is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity"))
        {
            return Err("encoded");
        }
        if let Some(length) = header(http::header::CONTENT_LENGTH) {
            match length.trim().parse::<u64>() {
                Ok(n) if n <= self.max_body => {}
                _ => return Err("too_large"),
            }
        }
        Ok(())
    }

    /// The patched document, or the error of the first failing operation. All or nothing.
    fn patch(doc: &Value, ops: &[PatchOp]) -> Result<Value, PatchError> {
        let mut copy = doc.clone();
        json_patch::apply(&mut copy, ops)?;
        Ok(copy)
    }

    /// The body to send at the end of an eligible response.
    fn finish_response(&self, collected: &[u8]) -> Bytes {
        let Ok(doc) = serde_json::from_slice::<Value>(collected) else {
            self.skipped("invalid_json");
            return Bytes::copy_from_slice(collected);
        };
        match Self::patch(&doc, &self.response_patch) {
            Ok(patched) => match serde_json::to_vec(&patched) {
                Ok(bytes) => Bytes::from(bytes),
                Err(_) => Bytes::copy_from_slice(collected),
            },
            Err(e) => {
                self.skipped("patch_failed");
                tracing::debug!(middleware = %self.name, error = %e, "response patch not applied; body sent unchanged");
                Bytes::copy_from_slice(collected)
            }
        }
    }
}

fn patch_failed(e: &PatchError) -> Reply {
    Reply::problem(ProblemKind::PatchFailed).extension(
        "errors",
        json!([{ "operation": e.index, "op": e.op, "message": e.kind.describe() }]),
    )
}

#[async_trait]
impl Middleware for Transform {
    fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::DEFAULT;
        if !self.request_patch.is_empty() || !self.response_patch.is_empty() {
            caps = caps.with_state();
        }
        if !self.request_patch.is_empty() {
            caps = caps.with_body(BodyHold::new(self.max_body).replacing());
        }
        if !self.response_patch.is_empty() {
            caps = caps.with(Phases::RESPONSE_BODY);
        }
        caps
    }

    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let mut state = State {
            head: req.method == Method::HEAD,
            ..State::default()
        };
        if !self.request_patch.is_empty() {
            let json = req
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(is_json_media_type);
            if !cx.has_body {
                cx.waive_body_hold();
            } else if json {
                state.patch_request = true;
            } else {
                cx.waive_body_hold();
                if self.on_non_json == OnNonJson::Reject {
                    return Flow::Reply(Reply::problem(ProblemKind::UnsupportedMediaType));
                }
            }
        }
        self.request_headers.apply_request(req);
        if !self.request_patch.is_empty() || !self.response_patch.is_empty() {
            cx.set_state(state);
        }
        Flow::Next
    }

    async fn request_body(&self, body: &HeldBody, cx: &mut Context) -> BodyVerdict {
        if !cx.state::<State>().is_some_and(|s| s.patch_request) {
            return BodyVerdict::Continue;
        }
        let bytes = match body.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(middleware = %self.name, error = %e, "reading the held request body failed");
                return BodyVerdict::Reply(Reply::problem(ProblemKind::InternalError));
            }
        };
        if bytes.is_empty() {
            return BodyVerdict::Continue;
        }
        let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
            return match self.on_non_json {
                OnNonJson::Reject => BodyVerdict::Reply(Reply::problem(ProblemKind::BadRequest)),
                OnNonJson::Pass => BodyVerdict::Continue,
            };
        };
        match Self::patch(&doc, &self.request_patch) {
            Ok(patched) => match serde_json::to_vec(&patched) {
                Ok(out) => BodyVerdict::Replace(Bytes::from(out)),
                Err(_) => BodyVerdict::Reply(Reply::problem(ProblemKind::InternalError)),
            },
            Err(e) => match self.on_error {
                OnPatchError::Reject => BodyVerdict::Reply(patch_failed(&e)),
                OnPatchError::Pass => {
                    tracing::debug!(middleware = %self.name, request_id = %cx.request_id, error = %e, "request patch not applied; body forwarded unchanged");
                    BodyVerdict::Continue
                }
            },
        }
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        self.response_headers.apply_response(resp);
        if self.response_patch.is_empty() {
            return;
        }
        let head = cx.state::<State>().is_some_and(|s| s.head);
        match self.eligible(resp, head, cx.compression.is_some()) {
            Ok(()) => {
                for name in STALE_RESPONSE_HEADERS {
                    resp.remove_header(name);
                }
                let collect = Collect::Buffer(BytesMut::new());
                match cx.state_mut::<State>() {
                    Some(state) => state.response = Some(collect),
                    None => cx.set_state(State {
                        response: Some(collect),
                        ..State::default()
                    }),
                }
            }
            Err(reason) => {
                self.skipped(reason);
                if let Some(state) = cx.state_mut::<State>() {
                    state.response = None;
                }
            }
        }
    }

    fn response_body(&self, body: &mut Option<Bytes>, end_of_stream: bool, cx: &mut Context) {
        let Some(state) = cx.state_mut::<State>() else {
            return;
        };
        let Some(Collect::Buffer(buffer)) = state.response.as_mut() else {
            return;
        };
        if let Some(chunk) = body.take() {
            buffer.extend_from_slice(&chunk);
        }
        if buffer.len() as u64 > self.max_body {
            // A body without a length that grew past the cap: send what was held, unchanged,
            // and pass the rest through.
            *body = Some(std::mem::take(buffer).freeze());
            state.response = Some(Collect::Pass);
            self.skipped("too_large");
            return;
        }
        if end_of_stream {
            let collected = std::mem::take(buffer);
            state.response = Some(Collect::Pass);
            *body = Some(self.finish_response(&collected));
        }
    }
}

#[cfg(test)]
mod tests;
