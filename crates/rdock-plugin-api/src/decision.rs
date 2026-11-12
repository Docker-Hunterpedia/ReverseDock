//! What a plugin answers: continue, or respond in place of the backend.

use bytes::Bytes;
use http::StatusCode;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};

/// A response produced by a plugin instead of the backend.
///
/// Without a body the proxy sends its standard page for the status (the route's `errors`
/// middleware may replace it). `Content-Length` and the other framing headers are computed by
/// the proxy; a plugin's values for them are dropped.
///
/// ```
/// use rdock_plugin_api::{Response, http::StatusCode};
///
/// let refusal = Response::text(StatusCode::FORBIDDEN, "blocked\n");
/// assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
/// assert_eq!(refusal.headers()["content-type"], "text/plain; charset=utf-8");
/// assert_eq!(refusal.body().map(|b| &b[..]), Some(&b"blocked\n"[..]));
///
/// let standard_page = Response::new(StatusCode::TOO_MANY_REQUESTS);
/// assert!(standard_page.body().is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Option<Bytes>,
}

impl Response {
    /// A response with the proxy's standard page for `status`.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    /// A `text/plain; charset=utf-8` response.
    #[must_use]
    pub fn text(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self::new(status)
            .with_header(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )
            .with_body(body)
    }

    /// Adds a header (appended to earlier values of the same name).
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// The status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The body; `None` means the standard page.
    #[must_use]
    pub fn body(&self) -> Option<&Bytes> {
        self.body.as_ref()
    }

    /// The parts, for the proxy.
    #[must_use]
    pub fn into_parts(self) -> (StatusCode, HeaderMap, Option<Bytes>) {
        (self.status, self.headers, self.body)
    }
}

/// The answer of the `request` and `upstream_request` phases.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// Go on: the next middleware, then the backend.
    Continue,
    /// Answer the client with this response; nothing goes to the backend.
    Respond(Response),
}

impl Decision {
    /// Whether this is [`Decision::Continue`].
    #[must_use]
    pub fn is_continue(&self) -> bool {
        matches!(self, Self::Continue)
    }

    /// The response, when this is [`Decision::Respond`].
    #[must_use]
    pub fn response(&self) -> Option<&Response> {
        match self {
            Self::Respond(response) => Some(response),
            Self::Continue => None,
        }
    }
}

impl From<Response> for Decision {
    fn from(response: Response) -> Self {
        Self::Respond(response)
    }
}

/// The answer of the `request_body` phase.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BodyDecision {
    /// Forward the body as it is (or as an earlier middleware replaced it).
    Continue,
    /// Forward these bytes instead. Needs [`crate::BodyLimit::replacing`]; a plugin that
    /// replaces without declaring it gets a `500` for that request.
    Replace(Bytes),
    /// Answer the client with this response; the upstream request is aborted and the backend
    /// sees no byte of the body.
    Respond(Response),
}

impl BodyDecision {
    /// The response, when this is [`BodyDecision::Respond`].
    #[must_use]
    pub fn response(&self) -> Option<&Response> {
        match self {
            Self::Respond(response) => Some(response),
            _ => None,
        }
    }
}

impl From<Response> for BodyDecision {
    fn from(response: Response) -> Self {
        Self::Respond(response)
    }
}

/// A complete request body held by the proxy, given to the `request_body` phase. It is never
/// longer than the plugin's [`crate::BodyLimit::max`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBody {
    bytes: Bytes,
}

impl RequestBody {
    /// A body (used by the proxy and by tests).
    #[must_use]
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// The bytes.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the body is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
