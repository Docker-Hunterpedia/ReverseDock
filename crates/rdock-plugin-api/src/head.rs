//! Typed views of the request and response heads, with bounded mutation: a plugin may change
//! headers, the method, the path and the query of a request, and the status and headers of a
//! response, but not the headers that frame the message on the wire, which belong to the proxy.

use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::uri::{PathAndQuery, Uri};
use http::{Method, StatusCode, Version};

/// Why a change to a head was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HeadError {
    /// The header name is not a valid HTTP field name.
    #[error("not a valid header name")]
    InvalidName,
    /// The header value contains bytes HTTP does not allow (control characters, line breaks).
    #[error("not a valid header value")]
    InvalidValue,
    /// The header frames the message (`Content-Length`, `Transfer-Encoding`, `Connection` and
    /// the other hop-by-hop headers); the proxy owns it.
    #[error("`{0}` is managed by the proxy and cannot be changed by a plugin")]
    Protected(HeaderName),
    /// The path does not start with `/` or contains characters a URI path cannot hold.
    #[error("not a valid path: {0}")]
    InvalidPath(String),
    /// The query contains characters a URI query cannot hold.
    #[error("not a valid query: {0}")]
    InvalidQuery(String),
    /// Informational statuses (1xx) cannot be set by a plugin.
    #[error("status {0} cannot be set by a plugin")]
    InvalidStatus(u16),
}

/// Headers that frame a message. Request heads protect all of them; response heads let a
/// plugin remove `Content-Length` (a body transformation that changes the length must).
const FRAMING: [&str; 8] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

fn is_framing(name: &HeaderName) -> bool {
    FRAMING.contains(&name.as_str())
}

/// Whether a plugin may not set or remove `name` on a request.
#[must_use]
pub fn is_protected_request_header(name: &HeaderName) -> bool {
    is_framing(name)
}

/// Whether a plugin may not set `name` on a response or in its own answer. `Content-Length`
/// may still be removed from a response.
#[must_use]
pub fn is_protected_response_header(name: &HeaderName) -> bool {
    is_framing(name)
}

fn name_of<N: TryInto<HeaderName>>(name: N) -> Result<HeaderName, HeadError> {
    name.try_into().map_err(|_| HeadError::InvalidName)
}

fn value_of<V: TryInto<HeaderValue>>(value: V) -> Result<HeaderValue, HeadError> {
    value.try_into().map_err(|_| HeadError::InvalidValue)
}

/// The request head as a plugin sees it.
///
/// ```
/// use rdock_plugin_api::RequestHead;
///
/// let mut req = RequestHead::get("/search?q=rust").unwrap();
/// req.set_header("x-team", "core").unwrap();
/// req.set_path("/v2/search").unwrap();
/// assert_eq!(req.uri().to_string(), "/v2/search?q=rust");
/// assert_eq!(req.header("x-team"), Some("core"));
/// assert!(req.set_header("content-length", "5").is_err(), "framing belongs to the proxy");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    changed: bool,
}

impl RequestHead {
    /// A request head from its parts (used by the proxy and by tests).
    #[must_use]
    pub fn from_parts(method: Method, uri: Uri, version: Version, headers: HeaderMap) -> Self {
        Self {
            method,
            uri,
            version,
            headers,
            changed: false,
        }
    }

    /// A `GET` for `target` (an origin-form target such as `/path?query`), HTTP/1.1, no
    /// headers.
    ///
    /// # Errors
    ///
    /// `target` is not a valid request target.
    pub fn get(target: &str) -> Result<Self, HeadError> {
        Self::new(Method::GET, target)
    }

    /// A request head for `method` and `target`, HTTP/1.1, no headers.
    ///
    /// # Errors
    ///
    /// `target` is not a valid request target.
    pub fn new(method: Method, target: &str) -> Result<Self, HeadError> {
        let uri = target
            .parse::<Uri>()
            .map_err(|_| HeadError::InvalidPath(target.to_owned()))?;
        Ok(Self::from_parts(
            method,
            uri,
            Version::HTTP_11,
            HeaderMap::new(),
        ))
    }

    /// Adds a header, for building requests in tests; framing headers are allowed here
    /// because a client sends them.
    ///
    /// # Errors
    ///
    /// The name or value is invalid.
    pub fn with_header<N, V>(mut self, name: N, value: V) -> Result<Self, HeadError>
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.append(name_of(name)?, value_of(value)?);
        Ok(self)
    }

    /// The method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Changes the method.
    pub fn set_method(&mut self, method: Method) {
        if method != self.method {
            self.method = method;
            self.changed = true;
        }
    }

    /// The request target.
    #[must_use]
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The path, `/` when the target has none.
    #[must_use]
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    /// The query string without `?`, if any.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    /// Replaces the path and keeps the query.
    ///
    /// # Errors
    ///
    /// The path does not start with `/` or contains `?`, `#` or characters a path cannot hold.
    pub fn set_path(&mut self, path: &str) -> Result<(), HeadError> {
        if !path.starts_with('/') || path.contains(['?', '#']) {
            return Err(HeadError::InvalidPath(path.to_owned()));
        }
        let target = match self.uri.query() {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        };
        self.set_target(&target)
            .map_err(|()| HeadError::InvalidPath(path.to_owned()))
    }

    /// Replaces the query (without `?`), or removes it with `None`.
    ///
    /// # Errors
    ///
    /// The query contains `#` or characters a query cannot hold.
    pub fn set_query(&mut self, query: Option<&str>) -> Result<(), HeadError> {
        let target = match query {
            Some(q) if q.contains('#') => return Err(HeadError::InvalidQuery(q.to_owned())),
            Some(q) => format!("{}?{q}", self.uri.path()),
            None => self.uri.path().to_owned(),
        };
        self.set_target(&target)
            .map_err(|()| HeadError::InvalidQuery(query.unwrap_or_default().to_owned()))
    }

    fn set_target(&mut self, target: &str) -> Result<(), ()> {
        let path_and_query = target.parse::<PathAndQuery>().map_err(|_| ())?;
        let mut parts = self.uri.clone().into_parts();
        parts.path_and_query = Some(path_and_query);
        let uri = Uri::from_parts(parts).map_err(|_| ())?;
        if uri != self.uri {
            self.uri = uri;
            self.changed = true;
        }
        Ok(())
    }

    /// The HTTP version the client used.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// All headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The first value of `name` as text, if present and visible ASCII.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Sets `name` to `value`, replacing every earlier value.
    ///
    /// # Errors
    ///
    /// The name or value is invalid, or the header frames the message
    /// ([`is_protected_request_header`]).
    pub fn set_header<N, V>(&mut self, name: N, value: V) -> Result<(), HeadError>
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        let name = Self::unprotected(name)?;
        self.headers.insert(name, value_of(value)?);
        self.changed = true;
        Ok(())
    }

    /// Adds a value to `name`, keeping earlier values.
    ///
    /// # Errors
    ///
    /// As [`Self::set_header`].
    pub fn append_header<N, V>(&mut self, name: N, value: V) -> Result<(), HeadError>
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        let name = Self::unprotected(name)?;
        self.headers.append(name, value_of(value)?);
        self.changed = true;
        Ok(())
    }

    /// Removes every value of `name`; returns whether there was one.
    ///
    /// # Errors
    ///
    /// The name is invalid or protected.
    pub fn remove_header<N: TryInto<HeaderName>>(&mut self, name: N) -> Result<bool, HeadError> {
        let name = Self::unprotected(name)?;
        let removed = self.headers.remove(name).is_some();
        self.changed |= removed;
        Ok(removed)
    }

    fn unprotected<N: TryInto<HeaderName>>(name: N) -> Result<HeaderName, HeadError> {
        let name = name_of(name)?;
        if is_protected_request_header(&name) {
            return Err(HeadError::Protected(name));
        }
        Ok(name)
    }

    /// Whether a plugin changed anything (the proxy writes changes back only then).
    #[must_use]
    pub fn is_changed(&self) -> bool {
        self.changed
    }
}

/// The response head as a plugin sees it.
///
/// ```
/// use rdock_plugin_api::{ResponseHead, http::StatusCode};
///
/// let mut resp = ResponseHead::new(StatusCode::OK);
/// resp.set_header("x-frame-options", "DENY").unwrap();
/// resp.set_status(StatusCode::NOT_FOUND).unwrap();
/// assert_eq!(resp.status(), StatusCode::NOT_FOUND);
/// assert!(resp.set_status(StatusCode::CONTINUE).is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    changed: bool,
}

impl ResponseHead {
    /// A response head with `status`, HTTP/1.1, no headers.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self::from_parts(status, Version::HTTP_11, HeaderMap::new())
    }

    /// A response head from its parts (used by the proxy and by tests).
    #[must_use]
    pub fn from_parts(status: StatusCode, version: Version, headers: HeaderMap) -> Self {
        Self {
            status,
            version,
            headers,
            changed: false,
        }
    }

    /// Adds a header, for building responses in tests; protected headers are allowed here
    /// because a backend sends them.
    ///
    /// # Errors
    ///
    /// The name or value is invalid.
    pub fn with_header<N, V>(mut self, name: N, value: V) -> Result<Self, HeadError>
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        self.headers.append(name_of(name)?, value_of(value)?);
        Ok(self)
    }

    /// The status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Changes the status.
    ///
    /// # Errors
    ///
    /// Informational statuses (1xx).
    pub fn set_status(&mut self, status: StatusCode) -> Result<(), HeadError> {
        if status.is_informational() {
            return Err(HeadError::InvalidStatus(status.as_u16()));
        }
        if status != self.status {
            self.status = status;
            self.changed = true;
        }
        Ok(())
    }

    /// The HTTP version of the response.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// All headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The first value of `name` as text, if present and visible ASCII.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Sets `name` to `value`, replacing every earlier value.
    ///
    /// # Errors
    ///
    /// The name or value is invalid, or the header frames the message.
    pub fn set_header<N, V>(&mut self, name: N, value: V) -> Result<(), HeadError>
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        let name = protected_response(name_of(name)?)?;
        self.headers.insert(name, value_of(value)?);
        self.changed = true;
        Ok(())
    }

    /// Adds a value to `name`, keeping earlier values.
    ///
    /// # Errors
    ///
    /// As [`Self::set_header`].
    pub fn append_header<N, V>(&mut self, name: N, value: V) -> Result<(), HeadError>
    where
        N: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        let name = protected_response(name_of(name)?)?;
        self.headers.append(name, value_of(value)?);
        self.changed = true;
        Ok(())
    }

    /// Removes every value of `name`; returns whether there was one. `Content-Length` may be
    /// removed (do so in `response` when `response_body` changes the length).
    ///
    /// # Errors
    ///
    /// The name is invalid or protected.
    pub fn remove_header<N: TryInto<HeaderName>>(&mut self, name: N) -> Result<bool, HeadError> {
        let name = name_of(name)?;
        if name != http::header::CONTENT_LENGTH {
            protected_response(name.clone())?;
        }
        let removed = self.headers.remove(name).is_some();
        self.changed |= removed;
        Ok(removed)
    }

    /// Whether a plugin changed anything.
    #[must_use]
    pub fn is_changed(&self) -> bool {
        self.changed
    }
}

fn protected_response(name: HeaderName) -> Result<HeaderName, HeadError> {
    if is_protected_response_header(&name) {
        Err(HeadError::Protected(name))
    } else {
        Ok(name)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn request_changes_are_tracked_and_bounded() {
        let mut req = RequestHead::new(Method::POST, "/a?x=1")
            .unwrap()
            .with_header("content-length", "3")
            .unwrap();
        assert!(!req.is_changed(), "building is not a change");
        assert_eq!(
            req.remove_header("Content-Length"),
            Err(HeadError::Protected(http::header::CONTENT_LENGTH))
        );
        assert_eq!(req.set_header("bad name", "x"), Err(HeadError::InvalidName));
        assert_eq!(
            req.set_header("x-a", "a\r\nb"),
            Err(HeadError::InvalidValue)
        );
        assert!(!req.is_changed(), "refused changes are not changes");
        assert!(matches!(
            req.set_path("relative"),
            Err(HeadError::InvalidPath(_))
        ));
        assert!(matches!(
            req.set_path("/a?b"),
            Err(HeadError::InvalidPath(_))
        ));
        req.set_query(None).unwrap();
        assert_eq!(req.uri(), "/a");
        req.set_query(Some("y=2&z")).unwrap();
        assert_eq!(req.query(), Some("y=2&z"));
        assert!(req.is_changed());
        assert!(!req.remove_header("x-missing").unwrap());
    }

    #[test]
    fn response_heads_may_drop_content_length_but_not_set_it() {
        let mut resp = ResponseHead::new(StatusCode::OK)
            .with_header("content-length", "10")
            .unwrap();
        assert!(resp.set_header("content-length", "5").is_err());
        assert!(resp.remove_header("content-length").unwrap());
        assert!(resp.is_changed());
        assert!(resp.remove_header("transfer-encoding").is_err());
    }
}
