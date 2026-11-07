//! A small client for DNS provider APIs: the hyper-rustls client the Cloudflare adapter uses
//! (platform verifier, no redirects followed), credentials applied afresh to every attempt,
//! 30 seconds per attempt, and retries with backoff that honour `Retry-After` and the
//! providers' `RateLimit-Reset` (ADR-0026).

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use percent_encoding::{AsciiSet, CONTROLS, NON_ALPHANUMERIC, utf8_percent_encode};
use rdock_acme::dns::DnsError;
use serde_json::Value;
use tracing::debug;

use crate::backoff::{ATTEMPTS, LONGEST_WAIT, jittered};
use crate::secret;

/// Time allowed for each attempt.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Characters escaped in a path segment.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Characters escaped in a query or form value: everything but RFC 3986's unreserved ones.
const VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// `text` as one path segment.
pub(crate) fn segment(text: &str) -> String {
    utf8_percent_encode(text, SEGMENT).to_string()
}

/// `pairs` as an `application/x-www-form-urlencoded` body or query string, with every byte but
/// the unreserved ones escaped (which is also what AWS signs, so the query needs no rewriting).
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                utf8_percent_encode(key, VALUE),
                utf8_percent_encode(value, VALUE)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Why a call failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RestError {
    /// The API answered with an error.
    #[error("{api} {request} answered {status}: {message}")]
    Status {
        api: &'static str,
        request: String,
        status: StatusCode,
        message: String,
    },
    /// The API could not be reached, or did not answer in time.
    #[error("{api} {request}: {message}")]
    Transport {
        api: &'static str,
        request: String,
        message: String,
    },
    /// The API asked to wait longer than a call may.
    #[error("{api} is rate limiting this credential; it allows the next request in {} s", wait.as_secs())]
    RateLimited { api: &'static str, wait: Duration },
    /// A successful answer was not JSON.
    #[error("{api} {request} answered without JSON")]
    NotJson { api: &'static str, request: String },
    /// The credentials could not be read or obtained.
    #[error(transparent)]
    Credentials(#[from] DnsError),
}

impl RestError {
    /// The status of an error answer.
    pub(crate) fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Whether the API answered `404 Not Found`.
    pub(crate) fn is_not_found(&self) -> bool {
        self.status() == Some(StatusCode::NOT_FOUND)
    }
}

impl From<RestError> for DnsError {
    fn from(error: RestError) -> Self {
        match error {
            RestError::Credentials(error) => error,
            other => DnsError(other.to_string()),
        }
    }
}

/// How every attempt proves who is calling.
#[async_trait]
pub(crate) trait Credentials: Send + Sync + fmt::Debug {
    /// Adds the credentials to `request` just before it is sent. Called for every attempt, so
    /// secrets are read and signatures made afresh each time.
    async fn apply(&self, request: &mut Request<Bytes>) -> Result<(), DnsError>;
}

/// A token from a `${file:…}`/`${env:…}` reference, sent as `Authorization: <scheme> <token>`.
#[derive(Debug)]
pub(crate) struct StaticToken {
    scheme: &'static str,
    reference: String,
    /// The setting holding the reference, named in errors.
    field: &'static str,
}

impl StaticToken {
    /// `Authorization: <scheme> <token>` with the token behind `reference`.
    pub(crate) fn new(scheme: &'static str, reference: &str, field: &'static str) -> Self {
        Self {
            scheme,
            reference: reference.to_owned(),
            field,
        }
    }
}

#[async_trait]
impl Credentials for StaticToken {
    async fn apply(&self, request: &mut Request<Bytes>) -> Result<(), DnsError> {
        let token = secret::resolve(&self.reference, self.field)?;
        let value = header_value(&format!("{} {token}", self.scheme), self.field)?;
        request.headers_mut().insert(header::AUTHORIZATION, value);
        Ok(())
    }
}

/// No credentials, for token endpoints that authenticate in the body.
#[derive(Debug)]
pub(crate) struct Anonymous;

#[async_trait]
impl Credentials for Anonymous {
    async fn apply(&self, _request: &mut Request<Bytes>) -> Result<(), DnsError> {
        Ok(())
    }
}

/// `text` as a header value; `field` names the setting it came from, never its content.
pub(crate) fn header_value(text: &str, field: &str) -> Result<HeaderValue, DnsError> {
    HeaderValue::from_str(text)
        .map_err(|_| DnsError(format!("{field} holds characters a header cannot carry")))
}

/// What a provider's error answer says.
#[derive(Debug, Default)]
pub(crate) struct ProviderError {
    /// The provider's message.
    pub(crate) message: Option<String>,
    /// Whether the provider marks the error as transient although its status is not (Route 53
    /// answers throttling with `400`).
    pub(crate) transient: bool,
}

/// How a provider's error answers are read.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ErrorFormat {
    /// JSON; the function finds the provider's message.
    Json(fn(&Value) -> Option<String>),
    /// Any other format.
    Raw(fn(&[u8]) -> ProviderError),
}

impl ErrorFormat {
    fn read(self, body: &[u8]) -> ProviderError {
        match self {
            Self::Json(message) => ProviderError {
                message: serde_json::from_slice::<Value>(body)
                    .ok()
                    .as_ref()
                    .and_then(message),
                transient: false,
            },
            Self::Raw(read) => read(body),
        }
    }
}

/// A request body and its media type.
pub(crate) struct Body {
    content_type: &'static str,
    bytes: Bytes,
}

impl Body {
    /// A body of type `content_type`.
    pub(crate) fn new(content_type: &'static str, bytes: impl Into<Bytes>) -> Self {
        Self {
            content_type,
            bytes: bytes.into(),
        }
    }

    fn json(value: &Value) -> Self {
        Self::new("application/json", value.to_string())
    }
}

/// One attempt's failure: final, or worth another attempt after the server's wait if it gave
/// one.
enum Failure {
    Final(RestError),
    Retry(RestError, Option<Duration>),
}

/// An API client for one provider and credential.
#[derive(Debug)]
pub(crate) struct RestClient {
    /// The provider's API name in messages, such as `DigitalOcean API`.
    api: &'static str,
    base: String,
    credentials: Arc<dyn Credentials>,
    errors: ErrorFormat,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl RestClient {
    /// A client calling `base` (no trailing slash needed) with the bearer token behind the
    /// reference `token`.
    pub(crate) fn new(
        api: &'static str,
        base: &str,
        token: &str,
        error_message: fn(&Value) -> Option<String>,
    ) -> Result<Self, DnsError> {
        Self::with(
            api,
            base,
            Arc::new(StaticToken::new("Bearer", token, "api_token")),
            ErrorFormat::Json(error_message),
        )
    }

    /// A client calling `base` with `credentials`, reading error answers as `errors`.
    pub(crate) fn with(
        api: &'static str,
        base: &str,
        credentials: Arc<dyn Credentials>,
        errors: ErrorFormat,
    ) -> Result<Self, DnsError> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|e| DnsError(format!("TLS setup: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            api,
            base: base.trim_end_matches('/').to_owned(),
            credentials,
            errors,
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    /// `GET path`.
    pub(crate) async fn get(&self, path: &str) -> Result<Value, RestError> {
        self.json(Method::GET, path, &[], None).await
    }

    /// `POST path` with a JSON body.
    pub(crate) async fn post(&self, path: &str, body: &Value) -> Result<Value, RestError> {
        self.json(Method::POST, path, &[], Some(body)).await
    }

    /// `PATCH path` with a JSON body.
    pub(crate) async fn patch(&self, path: &str, body: &Value) -> Result<Value, RestError> {
        self.json(Method::PATCH, path, &[], Some(body)).await
    }

    /// `DELETE path`.
    pub(crate) async fn delete(&self, path: &str) -> Result<Value, RestError> {
        self.json(Method::DELETE, path, &[], None).await
    }

    /// `POST path` with a form body, answered with JSON (OAuth token endpoints).
    pub(crate) async fn post_form(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
    ) -> Result<Value, RestError> {
        let body = Body::new("application/x-www-form-urlencoded", form(pairs));
        let bytes = self
            .send(
                Method::POST,
                path,
                &[("accept", "application/json")],
                Some(body),
            )
            .await?;
        self.parse(&Method::POST, path, &bytes)
    }

    /// Calls `method path` with extra `headers` and an optional JSON body. Returns the answer's
    /// JSON (`Null` for an empty body).
    pub(crate) async fn json(
        &self,
        method: Method,
        path: &str,
        headers: &[(&'static str, &str)],
        body: Option<&Value>,
    ) -> Result<Value, RestError> {
        let mut all = vec![("accept", "application/json")];
        all.extend_from_slice(headers);
        let bytes = self
            .send(method.clone(), path, &all, body.map(Body::json))
            .await?;
        self.parse(&method, path, &bytes)
    }

    fn parse(&self, method: &Method, path: &str, bytes: &[u8]) -> Result<Value, RestError> {
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(bytes).map_err(|_| RestError::NotJson {
            api: self.api,
            request: format!("{method} {path}"),
        })
    }

    /// Calls the API, retrying `429`, `409`, `423`, `5xx`, transport errors and errors the
    /// provider marks as transient up to [`ATTEMPTS`] times. Returns the answer's body.
    pub(crate) async fn send(
        &self,
        method: Method,
        path: &str,
        headers: &[(&'static str, &str)],
        body: Option<Body>,
    ) -> Result<Bytes, RestError> {
        let mut retry = 0;
        loop {
            let (error, asked) = match self.attempt(&method, path, headers, body.as_ref()).await {
                Ok(answer) => return Ok(answer),
                Err(Failure::Final(error)) => return Err(error),
                Err(Failure::Retry(error, asked)) => (error, asked),
            };
            retry += 1;
            if retry >= ATTEMPTS {
                return Err(error);
            }
            let wait = asked.unwrap_or_else(|| jittered(retry));
            if wait > LONGEST_WAIT {
                return Err(RestError::RateLimited {
                    api: self.api,
                    wait,
                });
            }
            debug!(api = self.api, %method, path, ?wait, %error, "retrying");
            tokio::time::sleep(wait).await;
        }
    }

    async fn attempt(
        &self,
        method: &Method,
        path: &str,
        headers: &[(&'static str, &str)],
        body: Option<&Body>,
    ) -> Result<Bytes, Failure> {
        let request_line = format!("{method} {path}");
        let transport = |message: String| RestError::Transport {
            api: self.api,
            request: request_line.clone(),
            message,
        };
        let mut builder = Request::builder()
            .method(method.clone())
            .uri(format!("{}{path}", self.base));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        if let Some(body) = body {
            builder = builder.header(header::CONTENT_TYPE, body.content_type);
        }
        let mut request = builder
            .body(body.map(|b| b.bytes.clone()).unwrap_or_default())
            .map_err(|e| Failure::Final(transport(e.to_string())))?;
        self.credentials
            .apply(&mut request)
            .await
            .map_err(|e| Failure::Final(RestError::Credentials(e)))?;
        let response = tokio::time::timeout(TIMEOUT, self.client.request(request.map(Full::new)))
            .await
            .map_err(|_| Failure::Retry(transport("no answer within 30 s".into()), None))?
            .map_err(|e| Failure::Retry(transport(e.to_string()), None))?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = tokio::time::timeout(TIMEOUT, response.into_body().collect())
            .await
            .map_err(|_| Failure::Retry(transport("no answer within 30 s".into()), None))?
            .map_err(|e| Failure::Retry(transport(e.to_string()), None))?
            .to_bytes();
        if status.is_success() {
            return Ok(bytes);
        }
        let said = self.errors.read(&bytes);
        let error = RestError::Status {
            api: self.api,
            request: request_line,
            status,
            message: said
                .message
                .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned()),
        };
        Err(if said.transient || is_transient(status) {
            Failure::Retry(error, server_wait(status, &headers, SystemTime::now()))
        } else {
            Failure::Final(error)
        })
    }
}

/// Statuses worth another attempt: rate limits, conflicts with a running change, server errors.
fn is_transient(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::CONFLICT | StatusCode::LOCKED
    ) || status.is_server_error()
}

/// How long the server asked to wait: `Retry-After` (seconds or a date), or on `429` the
/// `RateLimit-Reset` of DigitalOcean and Hetzner (a Unix time; a small number is read as
/// seconds from now).
fn server_wait(status: StatusCode, headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let text = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    };
    if let Some(value) = text("retry-after") {
        return value
            .parse::<u64>()
            .map(Duration::from_secs)
            .ok()
            .or_else(|| {
                httpdate::parse_http_date(value)
                    .ok()
                    .map(|at| at.duration_since(now).unwrap_or_default())
            });
    }
    if status != StatusCode::TOO_MANY_REQUESTS {
        return None;
    }
    let reset = text("ratelimit-reset")?.parse::<u64>().ok()?;
    let since_epoch = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(if reset > 1_000_000_000 {
        reset.saturating_sub(since_epoch)
    } else {
        reset
    }))
}

#[cfg(test)]
mod tests;
