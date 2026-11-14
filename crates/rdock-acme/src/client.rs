//! The HTTPS client ACME requests go through: the same hyper and rustls build instant-acme's
//! default client uses (ring, the platform's roots or `acme.ca_root`), with two additions the
//! chaos suite asked for (ADR-0033):
//!
//! - **A deadline per request**, [`REQUEST_TIMEOUT`], for the answer and its whole body. A CA
//!   that accepts connections and never answers used to hold the order task, and with it every
//!   other certificate's renewal, forever.
//! - **`Retry-After`** on `429` and `503` answers is remembered ([`RetryHint`]), so the next
//!   attempt waits at least that long (RFC 8555 §6.6, RFC 9110 §10.2.3).

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

/// The longest one ACME request (connection, answer and body) may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// A `Retry-After` longer than this is capped (the CA's own backoff never exceeds a day).
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 3600);

/// The latest `Retry-After` a CA sent with a `429` or `503`, shared by the requests to it.
#[derive(Debug, Clone, Default)]
pub(crate) struct RetryHint(Arc<Mutex<Option<SystemTime>>>);

impl RetryHint {
    /// When the CA asked to be contacted again, if that is still ahead; clears the hint.
    pub fn take(&self) -> Option<SystemTime> {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let at = slot.take()?;
        (at > SystemTime::now()).then_some(at)
    }

    fn set(&self, at: SystemTime) {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none_or(|current| current < at) {
            *slot = Some(at);
        }
    }
}

/// An ACME HTTP client with a deadline per request.
pub(crate) struct TimedClient {
    client: Client<HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>,
    hint: RetryHint,
}

impl TimedClient {
    /// A client that trusts the platform's roots, or only `ca_root` when given.
    pub fn new(ca_root: Option<&Path>, hint: RetryHint) -> Result<Self, instant_acme::Error> {
        let builder = HttpsConnectorBuilder::new();
        let builder = match ca_root {
            Some(path) => {
                let mut roots = rustls::RootCertStore::empty();
                let certificates = CertificateDer::pem_file_iter(path)
                    .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
                for certificate in certificates {
                    let certificate =
                        certificate.map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
                    roots
                        .add(certificate)
                        .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
                }
                let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?
                .with_root_certificates(roots)
                .with_no_client_auth();
                builder.with_tls_config(config)
            }
            None => builder
                .try_with_platform_verifier()
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?,
        };
        let connector = builder.https_only().enable_http1().enable_http2().build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            hint,
        })
    }
}

/// When a `Retry-After` value (delay seconds or an HTTP date) asks to come back.
fn retry_after(value: &str) -> Option<SystemTime> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(SystemTime::now() + Duration::from_secs(seconds).min(MAX_RETRY_AFTER));
    }
    let at = http_date(value)?;
    Some(at.min(SystemTime::now() + MAX_RETRY_AFTER))
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// An IMF-fixdate (`Wed, 21 Oct 2015 07:28:00 GMT`, RFC 9110 §5.6.7), the form servers send.
fn http_date(value: &str) -> Option<SystemTime> {
    let fields: Vec<&str> = value.split_whitespace().collect();
    let [_, day, month, year, clock, "GMT"] = fields.as_slice() else {
        return None;
    };
    let month = i64::try_from(MONTHS.iter().position(|m| m == month)?).ok()? + 1;
    let (day, year): (i64, i64) = (day.parse().ok()?, year.parse().ok()?);
    let mut parts = clock.split(':').map(str::parse::<i64>);
    let (h, m, s) = (
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    );
    // Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = u64::try_from(days * 86_400 + h * 3600 + m * 60 + s).ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
}

impl HttpClient for TimedClient {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let sent = self.client.request(req);
        let hint = self.hint.clone();
        Box::pin(async move {
            let answered = async {
                let response = sent
                    .await
                    .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
                let (parts, body) = response.into_parts();
                let body = body
                    .collect()
                    .await
                    .map_err(instant_acme::Error::Hyper)?
                    .to_bytes();
                Ok::<_, instant_acme::Error>(Response::from_parts(parts, Full::new(body)))
            };
            let response = tokio::time::timeout(REQUEST_TIMEOUT, answered)
                .await
                .map_err(|_| {
                    instant_acme::Error::Other(
                        format!(
                            "the CA did not answer within {} seconds",
                            REQUEST_TIMEOUT.as_secs()
                        )
                        .into(),
                    )
                })??;
            if matches!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            ) && let Some(at) = response
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(retry_after)
            {
                hint.set(at);
            }
            Ok(BytesResponse::from(response))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_takes_seconds_and_dates() {
        let now = SystemTime::now();
        let at = retry_after("120").unwrap();
        assert!(at >= now + Duration::from_secs(119));
        let at = retry_after("Wed, 21 Oct 2099 07:28:00 GMT").unwrap();
        assert!(at <= SystemTime::now() + MAX_RETRY_AFTER + Duration::from_secs(1));
        assert_eq!(
            http_date("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_445_412_480))
        );
        assert!(retry_after("soon").is_none());
    }

    #[test]
    fn a_hint_is_taken_once_and_only_when_ahead() {
        let hint = RetryHint::default();
        hint.set(SystemTime::now() + Duration::from_secs(60));
        assert!(hint.take().is_some());
        assert!(hint.take().is_none());
        hint.set(SystemTime::now() - Duration::from_secs(1));
        assert!(hint.take().is_none());
    }
}
