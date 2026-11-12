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
enum Found {
    /// The key checked (from the first configured location that has one), and whether the
    /// query carried one too.
    Key {
        key: String,
        headers: Vec<HeaderName>,
        query: bool,
    },
    Missing,
    /// A location repeated, or two locations with different keys: the backend could read
    /// another key than the one checked here.
    Repeated,
}

/// Whether `value` has the shape of an API key (prefix, length, alphabet, checksum).
fn key_shaped(value: &str) -> bool {
    rdock_credentials::API_KEY.parse(value).is_some()
}

/// Whether the query pair `name=value` names `name` once its name is percent-decoded, so
/// `%61pi_key` is `api_key`.
fn query_name_is(pair: &str, name: &str) -> bool {
    let key = pair.split_once('=').map_or(pair, |(k, _)| k);
    percent_encoding::percent_decode_str(key).decode_utf8_lossy() == name
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

    /// The key in the configured locations: headers in their order, then the query
    /// parameter. The first location with a value gives the key; every other location is
    /// looked at too (L4 of the v0.8 review): one holding a different well-formed key is
    /// refused like a repeated header, and those holding a key are remembered so they can all
    /// be removed before the request goes upstream.
    fn find(&self, req: &RequestHeader) -> Found {
        let mut found: Vec<(Option<HeaderName>, String)> = Vec::new();
        for header in &self.headers {
            let mut values = req.headers.get_all(header).iter();
            let Some(first) = values.next() else {
                continue;
            };
            if values.next().is_some() {
                return Found::Repeated;
            }
            let Ok(value) = first.to_str() else {
                found.push((Some(header.clone()), String::new()));
                continue;
            };
            if *header == http::header::AUTHORIZATION {
                // Other schemes (Basic for another middleware) are not ours.
                if let Some(key) = value
                    .strip_prefix("Bearer ")
                    .or_else(|| value.strip_prefix("bearer "))
                {
                    found.push((Some(header.clone()), key.trim().to_owned()));
                }
                continue;
            }
            found.push((Some(header.clone()), value.trim().to_owned()));
        }
        if let (Some(name), Some(query)) = (self.query.as_deref(), req.uri.query()) {
            let mut values = query
                .split('&')
                .filter(|pair| query_name_is(pair, name))
                .map(|pair| pair.split_once('=').map_or("", |(_, v)| v));
            match (values.next(), values.next()) {
                (Some(value), None) => found.push((
                    None,
                    percent_encoding::percent_decode_str(value)
                        .decode_utf8_lossy()
                        .into_owned(),
                )),
                (Some(_), Some(_)) => return Found::Repeated,
                (None, _) => {}
            }
        }
        let Some((_, key)) = found.first().cloned() else {
            return Found::Missing;
        };
        let mut headers = Vec::new();
        let mut query = false;
        for (index, (location, value)) in found.into_iter().enumerate() {
            let same = value == key;
            if !same && key_shaped(&value) {
                return Found::Repeated;
            }
            if index == 0 || same || key_shaped(&value) {
                match location {
                    Some(header) => headers.push(header),
                    None => query = true,
                }
            }
        }
        Found::Key {
            key,
            headers,
            query,
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

    /// Removes the query parameter that carried the key, its name compared decoded.
    fn strip_query(&self, req: &mut RequestHeader) {
        let (Some(name), Some(query)) = (self.query.as_deref(), req.uri.query()) else {
            return;
        };
        let kept: Vec<&str> = query
            .split('&')
            .filter(|pair| !query_name_is(pair, name))
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
        let (presented, headers, in_query) = match self.find(req) {
            Found::Key {
                key,
                headers,
                query,
            } => (key, headers, query),
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
            for header in &headers {
                req.remove_header(header);
            }
            if in_query {
                self.strip_query(req);
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
