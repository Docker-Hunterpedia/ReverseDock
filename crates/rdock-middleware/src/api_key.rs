//! `api_key`: authenticate requests with consumers' API keys (F-GW-01, ADR-0030).
//!
//! The key is read from the configured headers (`Authorization: Bearer` and `X-API-Key` by
//! default), then the query parameter if one is named; never from a cookie. A malformed key
//! (wrong prefix, length, alphabet or checksum) is refused without a lookup; a well-formed one
//! is found by its ID in the configuration's [`ConsumerIndex`] and the SHA-256 of its secret is
//! compared in constant time. The consumer is then set on the request and the key removed
//! before the request goes upstream.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use pingora::http::RequestHeader;
use rdock_model::gateway::{Anonymous, ApiKeyConfig};

use crate::consumers::ConsumerIndex;
use crate::{BuildError, Context, Flow, Middleware, ProblemKind, Reply};

/// Headers the backend gets about the consumer; copies sent by the client are removed.
pub const IDENTITY_HEADERS: [&str; 3] = ["x-consumer-name", "x-consumer-groups", "x-credential-id"];

/// The `api_key` middleware.
#[derive(Debug)]
pub(crate) struct ApiKey {
    name: String,
    headers: Vec<HeaderName>,
    query: Option<String>,
    forward: bool,
    anonymous: Anonymous,
    groups: Vec<String>,
    challenge: HeaderValue,
    invalid: HeaderValue,
    index: Arc<ConsumerIndex>,
}

/// Where a key was found.
enum Found<'a> {
    Header(&'a HeaderName, &'a str),
    Query(String),
    Missing,
    Repeated,
}

impl ApiKey {
    pub(crate) fn new(
        name: &str,
        config: &ApiKeyConfig,
        index: Arc<ConsumerIndex>,
    ) -> Result<Self, BuildError> {
        let invalid =
            |message: String| BuildError::Invalid(format!("middleware `{name}`: {message}"));
        let headers = config
            .headers
            .iter()
            .map(|h| {
                HeaderName::try_from(h.as_str())
                    .map_err(|_| invalid(format!("`{h}` is not a header name")))
            })
            .collect::<Result<_, _>>()?;
        let realm = config.realm.as_deref().unwrap_or("api");
        if realm.contains('"') || realm.contains('\\') {
            return Err(invalid("the realm cannot contain `\"` or `\\`".into()));
        }
        let challenge = HeaderValue::from_str(&format!("Bearer realm=\"{realm}\""))
            .map_err(|_| invalid("the realm is not a valid header value".into()))?;
        let invalid_challenge = HeaderValue::from_str(&format!(
            "Bearer realm=\"{realm}\", error=\"invalid_token\""
        ))
        .map_err(|_| invalid("the realm is not a valid header value".into()))?;
        Ok(Self {
            name: name.to_owned(),
            headers,
            query: config.query.clone(),
            forward: config.forward_credential,
            anonymous: config.anonymous,
            groups: config.groups.clone(),
            challenge,
            invalid: invalid_challenge,
            index,
        })
    }

    fn find<'a>(&'a self, req: &'a RequestHeader) -> Found<'a> {
        for header in &self.headers {
            let mut values = req.headers.get_all(header).iter();
            let Some(first) = values.next() else {
                continue;
            };
            if values.next().is_some() {
                return Found::Repeated;
            }
            let Ok(value) = first.to_str() else {
                return Found::Header(header, "");
            };
            if *header == http::header::AUTHORIZATION {
                // Other schemes (Basic for another middleware) are not ours.
                match value
                    .strip_prefix("Bearer ")
                    .or_else(|| value.strip_prefix("bearer "))
                {
                    Some(key) => return Found::Header(header, key.trim()),
                    None => continue,
                }
            }
            return Found::Header(header, value.trim());
        }
        let (Some(name), Some(query)) = (self.query.as_deref(), req.uri.query()) else {
            return Found::Missing;
        };
        let mut values = query.split('&').filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == name).then_some(v)
        });
        match (values.next(), values.next()) {
            (Some(value), None) => Found::Query(
                percent_encoding::percent_decode_str(value)
                    .decode_utf8_lossy()
                    .into_owned(),
            ),
            (Some(_), Some(_)) => Found::Repeated,
            (None, _) => Found::Missing,
        }
    }

    fn unauthorized(&self, invalid: bool) -> Flow {
        let challenge = if invalid {
            self.invalid.clone()
        } else {
            self.challenge.clone()
        };
        Flow::Reply(
            Reply::problem(ProblemKind::Unauthenticated)
                .header(http::header::WWW_AUTHENTICATE, challenge),
        )
    }

    /// Removes the query parameter that carried the key.
    fn strip_query(&self, req: &mut RequestHeader) {
        let (Some(name), Some(query)) = (self.query.as_deref(), req.uri.query()) else {
            return;
        };
        let kept: Vec<&str> = query
            .split('&')
            .filter(|pair| pair.split_once('=').map_or(*pair, |(k, _)| k) != name)
            .collect();
        let path = req.uri.path();
        let target = if kept.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{}", kept.join("&"))
        };
        if let Ok(uri) = target.parse() {
            req.set_uri(uri);
        }
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[async_trait]
impl Middleware for ApiKey {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        for header in IDENTITY_HEADERS {
            req.remove_header(header);
        }
        let (presented, header) = match self.find(req) {
            Found::Header(header, key) => (key.to_owned(), Some(header.clone())),
            Found::Query(key) => (key, None),
            Found::Missing => {
                return match self.anonymous {
                    Anonymous::Allow => Flow::Next,
                    Anonymous::Deny => self.unauthorized(false),
                };
            }
            Found::Repeated => {
                // The backend could read another copy than the one checked here.
                tracing::debug!(middleware = %self.name, "API key refused: more than one");
                return Flow::Reply(Reply::problem(ProblemKind::BadRequest).header(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_request\""),
                ));
            }
        };
        // Shape and checksum first: a typo or a made-up key costs no lookup.
        let Some((id, secret)) = rdock_credentials::API_KEY.parse(&presented) else {
            tracing::debug!(middleware = %self.name, "API key refused: malformed");
            return self.unauthorized(true);
        };
        let hash = rdock_credentials::hash_secret(secret);
        let Some(stored) = self.index.key(id) else {
            tracing::debug!(middleware = %self.name, key_id = %id, "API key refused: unknown");
            return self.unauthorized(true);
        };
        if !rdock_credentials::hashes_match(&hash, &stored.hash) {
            tracing::debug!(middleware = %self.name, key_id = %id, "API key refused: wrong secret");
            return self.unauthorized(true);
        }
        if stored.expires.is_some_and(|at| now() >= at) {
            tracing::debug!(middleware = %self.name, key_id = %id, "API key refused: expired");
            return self.unauthorized(true);
        }
        let consumer = stored.consumer.clone();
        if !self.groups.is_empty()
            && !consumer
                .groups
                .iter()
                .any(|g| self.groups.iter().any(|allowed| **g == **allowed))
        {
            tracing::debug!(middleware = %self.name, consumer = %consumer.name, "API key refused: group");
            return Flow::Reply(Reply::problem(ProblemKind::Forbidden));
        }
        if !self.forward {
            match &header {
                Some(header) => {
                    req.remove_header(header);
                }
                None => self.strip_query(req),
            }
        }
        if let Ok(value) = HeaderValue::from_str(&consumer.name) {
            let _ = req.insert_header("x-consumer-name", value);
        }
        if !consumer.groups.is_empty() {
            let groups: Vec<&str> = consumer.groups.iter().map(|g| &**g).collect();
            if let Ok(value) = HeaderValue::from_str(&groups.join(",")) {
                let _ = req.insert_header("x-consumer-groups", value);
            }
        }
        if let Ok(value) = HeaderValue::from_str(id) {
            let _ = req.insert_header("x-credential-id", value);
        }
        cx.key_id = Some(Arc::from(id));
        cx.consumer = Some(consumer);
        Flow::Next
    }
}

#[cfg(test)]
mod tests;
