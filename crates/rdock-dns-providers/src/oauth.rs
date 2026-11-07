//! OAuth 2.0 access tokens for the cloud APIs (Google, Azure): obtained with a credential read
//! afresh for every call, cached until shortly before they expire, and obtained again as soon
//! as the credential changes, so a rotated key is used without a reload.

use std::fmt;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, header};
use rdock_acme::dns::DnsError;
use ring::digest::{SHA256, digest};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::rest::{Credentials, header_value};

/// A token is replaced this long before it expires.
const MARGIN: Duration = Duration::from_secs(300);

/// An access token and how long it is valid.
#[derive(Debug)]
pub(crate) struct AccessToken {
    pub(crate) token: String,
    pub(crate) lifetime: Duration,
}

impl AccessToken {
    /// `{"access_token": "…", "expires_in": 3599}` as token endpoints answer (RFC 6749 §5.1);
    /// the Azure instance metadata service writes `expires_in` as a string.
    pub(crate) fn from_answer(answer: &Value, api: &str) -> Result<Self, DnsError> {
        let token = answer["access_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| DnsError(format!("{api} answered without an access token")))?;
        let seconds = match &answer["expires_in"] {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse().ok(),
            _ => None,
        }
        .ok_or_else(|| DnsError(format!("{api} answered without `expires_in`")))?;
        Ok(Self {
            token: token.to_owned(),
            lifetime: Duration::from_secs(seconds),
        })
    }
}

/// The message of an OAuth error answer: `{"error": "invalid_client", "error_description": "…"}`
/// (RFC 6749 §5.2).
pub(crate) fn error_message(answer: &Value) -> Option<String> {
    let code = answer["error"].as_str()?;
    Some(match answer["error_description"].as_str() {
        Some(description) => format!("{description} ({code})"),
        None => code.to_owned(),
    })
}

/// Where access tokens come from.
#[async_trait]
pub(crate) trait TokenSource: Send + Sync + fmt::Debug {
    /// The credential as it is now, such as a key file or a client secret; a different value
    /// gets a new token. Empty when there is none to read (a managed identity).
    async fn credential(&self) -> Result<Vec<u8>, DnsError>;

    /// Exchanges `credential` for an access token.
    async fn exchange(&self, credential: &[u8]) -> Result<AccessToken, DnsError>;
}

/// The cached token, with the digest of the credential it was obtained with (never the
/// credential itself).
struct Cached {
    token: String,
    renew_at: Instant,
    credential: Vec<u8>,
}

/// `Authorization: Bearer <access token>` from a [`TokenSource`].
pub(crate) struct OAuthBearer<S> {
    source: S,
    cached: Mutex<Option<Cached>>,
}

impl<S: TokenSource> OAuthBearer<S> {
    pub(crate) fn new(source: S) -> Self {
        Self {
            source,
            cached: Mutex::new(None),
        }
    }

    /// A valid token: the cached one while the credential is unchanged and the token has more
    /// than [`MARGIN`] left, a new one otherwise. Callers wait for one exchange at a time.
    async fn token(&self) -> Result<String, DnsError> {
        let credential = self.source.credential().await?;
        let fingerprint = digest(&SHA256, &credential).as_ref().to_vec();
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached
            .as_ref()
            .filter(|c| c.credential == fingerprint && Instant::now() < c.renew_at)
        {
            return Ok(token.token.clone());
        }
        let fresh = self.source.exchange(&credential).await?;
        let token = fresh.token.clone();
        *cached = Some(Cached {
            token: fresh.token,
            renew_at: Instant::now() + fresh.lifetime.saturating_sub(MARGIN),
            credential: fingerprint,
        });
        Ok(token)
    }
}

impl<S: fmt::Debug> fmt::Debug for OAuthBearer<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthBearer")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<S: TokenSource> Credentials for OAuthBearer<S> {
    async fn apply(&self, request: &mut Request<Bytes>) -> Result<(), DnsError> {
        let token = self.token().await?;
        let value = header_value(&format!("Bearer {token}"), "the access token")?;
        request.headers_mut().insert(header::AUTHORIZATION, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use serde_json::json;

    use super::*;

    #[derive(Debug, Default)]
    struct Counting {
        credential: StdMutex<Vec<u8>>,
        lifetime: u64,
        exchanges: AtomicU32,
    }

    #[async_trait]
    impl TokenSource for Counting {
        async fn credential(&self) -> Result<Vec<u8>, DnsError> {
            Ok(self.credential.lock().unwrap().clone())
        }

        async fn exchange(&self, credential: &[u8]) -> Result<AccessToken, DnsError> {
            let n = self.exchanges.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(AccessToken {
                token: format!("{}-{n}", String::from_utf8_lossy(credential)),
                lifetime: Duration::from_secs(self.lifetime),
            })
        }
    }

    fn source(lifetime: u64) -> Counting {
        Counting {
            credential: StdMutex::new(b"key-a".to_vec()),
            lifetime,
            ..Counting::default()
        }
    }

    #[tokio::test]
    async fn tokens_are_reused_until_the_credential_changes() {
        let bearer = OAuthBearer::new(source(3600));
        assert_eq!(bearer.token().await.unwrap(), "key-a-1");
        assert_eq!(bearer.token().await.unwrap(), "key-a-1");
        *bearer.source.credential.lock().unwrap() = b"key-b".to_vec();
        assert_eq!(bearer.token().await.unwrap(), "key-b-2", "rotated");
    }

    #[tokio::test]
    async fn tokens_close_to_expiry_are_replaced() {
        let bearer = OAuthBearer::new(source(MARGIN.as_secs()));
        assert_eq!(bearer.token().await.unwrap(), "key-a-1");
        assert_eq!(bearer.token().await.unwrap(), "key-a-2");
    }

    #[test]
    fn token_answers_and_errors() {
        let token = AccessToken::from_answer(
            &json!({ "access_token": "t", "expires_in": "3599", "token_type": "Bearer" }),
            "IMDS",
        )
        .unwrap();
        assert_eq!(
            (token.token.as_str(), token.lifetime.as_secs()),
            ("t", 3599)
        );
        assert!(AccessToken::from_answer(&json!({ "expires_in": 1 }), "X").is_err());
        assert_eq!(
            error_message(
                &json!({ "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided." })
            ),
            Some("AADSTS7000215: Invalid client secret provided. (invalid_client)".to_owned())
        );
    }
}
