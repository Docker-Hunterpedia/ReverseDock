//! A small JSON client for DNS provider APIs: the hyper-rustls client the Cloudflare adapter
//! uses (platform verifier, no redirects followed), a bearer token resolved for every call,
//! 30 seconds per attempt, and retries with backoff that honour `Retry-After` and the
//! providers' `RateLimit-Reset` (ADR-0026).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
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

/// `text` as one path segment.
pub(crate) fn segment(text: &str) -> String {
    utf8_percent_encode(text, SEGMENT).to_string()
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
    #[error("{api} is rate limiting this token; it allows the next request in {} s", wait.as_secs())]
    RateLimited { api: &'static str, wait: Duration },
    /// A successful answer was not JSON.
    #[error("{api} {request} answered {status} without JSON")]
    NotJson {
        api: &'static str,
        request: String,
        status: StatusCode,
    },
    /// The token reference could not be resolved.
    #[error(transparent)]
    Secret(#[from] DnsError),
}

impl RestError {
    /// Whether the API answered `404 Not Found`.
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::Status { status, .. } if *status == StatusCode::NOT_FOUND)
    }
}

impl From<RestError> for DnsError {
    fn from(error: RestError) -> Self {
        match error {
            RestError::Secret(error) => error,
            other => DnsError(other.to_string()),
        }
    }
}

/// One attempt's failure: final, or worth another attempt after the server's wait if it gave
/// one.
enum Failure {
    Final(RestError),
    Retry(RestError, Option<Duration>),
}

/// A JSON API client for one provider and token.
#[derive(Debug)]
pub(crate) struct RestClient {
    /// The provider's API name in messages, such as `DigitalOcean API`.
    api: &'static str,
    base: String,
    /// The token reference, resolved for each attempt.
    token: String,
    /// The provider's error text from an error answer's JSON.
    error_message: fn(&Value) -> Option<String>,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl RestClient {
    /// A client calling `base` (no trailing slash needed) with the bearer token `token`.
    pub(crate) fn new(
        api: &'static str,
        base: &str,
        token: &str,
        error_message: fn(&Value) -> Option<String>,
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
            token: token.to_owned(),
            error_message,
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    /// `GET path`.
    pub(crate) async fn get(&self, path: &str) -> Result<Value, RestError> {
        self.call(Method::GET, path, None).await
    }

    /// `POST path` with a JSON body.
    pub(crate) async fn post(&self, path: &str, body: &Value) -> Result<Value, RestError> {
        self.call(Method::POST, path, Some(body)).await
    }

    /// `DELETE path`.
    pub(crate) async fn delete(&self, path: &str) -> Result<Value, RestError> {
        self.call(Method::DELETE, path, None).await
    }

    /// Calls the API, retrying `429`, `409`, `423`, `5xx` and transport errors up to
    /// [`ATTEMPTS`] times. Returns the answer's JSON (`Null` for an empty body).
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, RestError> {
        let mut retry = 0;
        loop {
            let (error, asked) = match self.attempt(&method, path, body).await {
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
        body: Option<&Value>,
    ) -> Result<Value, Failure> {
        let token = secret::resolve(&self.token, "api_token")
            .map_err(|e| Failure::Final(RestError::Secret(e)))?;
        let request_line = format!("{method} {path}");
        let transport = |message: String| RestError::Transport {
            api: self.api,
            request: request_line.clone(),
            message,
        };
        let request = Request::builder()
            .method(method.clone())
            .uri(format!("{}{path}", self.base))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(
                body.map(Value::to_string).unwrap_or_default(),
            )))
            .map_err(|e| Failure::Final(transport(e.to_string())))?;
        let response = tokio::time::timeout(TIMEOUT, self.client.request(request))
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
        let json = if bytes.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice::<Value>(&bytes)
        };
        if status.is_success() {
            return json.map_err(|_| {
                Failure::Final(RestError::NotJson {
                    api: self.api,
                    request: request_line.clone(),
                    status,
                })
            });
        }
        let message = json
            .ok()
            .as_ref()
            .and_then(self.error_message)
            .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned());
        let error = RestError::Status {
            api: self.api,
            request: request_line,
            status,
            message,
        };
        Err(if is_transient(status) {
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
