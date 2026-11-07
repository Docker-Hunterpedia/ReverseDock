//! AWS Signature Version 4 with ring's HMAC-SHA256 and SHA-256, as described in
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html> (checked
//! 2026-11-07). Every header of the request but `authorization` is signed, `host` and
//! `x-amz-date` included.

use bytes::Bytes;
use http::{HeaderName, Request};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use rdock_acme::dns::DnsError;
use ring::digest::{SHA256, digest};
use ring::hmac;
use time::OffsetDateTime;

use crate::rest::header_value;

/// What `UriEncode()` leaves alone: the unreserved characters.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// An access key pair, with the session token of temporary credentials.
pub(crate) struct AwsKey {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    pub(crate) session_token: Option<String>,
}

/// Where a signature is valid: the date, the region and the service.
pub(crate) struct Scope<'a> {
    pub(crate) region: &'a str,
    pub(crate) service: &'a str,
}

/// Signs `request` at `now`: adds `host` (from the URI), `x-amz-date`, `x-amz-security-token`
/// when the key has a session token, and `authorization`.
pub(crate) fn sign(
    request: &mut Request<Bytes>,
    key: &AwsKey,
    scope: &Scope<'_>,
    now: OffsetDateTime,
) -> Result<(), DnsError> {
    let timestamp = timestamp(now);
    let authority = request
        .uri()
        .authority()
        .map(ToString::to_string)
        .ok_or_else(|| DnsError("the request has no host to sign".to_owned()))?;
    let headers = request.headers_mut();
    headers.insert(http::header::HOST, header_value(&authority, "host")?);
    headers.insert(
        HeaderName::from_static("x-amz-date"),
        header_value(&timestamp, "x-amz-date")?,
    );
    if let Some(token) = &key.session_token {
        headers.insert(
            HeaderName::from_static("x-amz-security-token"),
            header_value(token, "session_token")?,
        );
    }
    let (signed_headers, signature) = signature(request, &key.secret_access_key, scope, &timestamp);
    let credential_scope = credential_scope(&timestamp, scope);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        key.access_key_id
    );
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        header_value(&authorization, "access_key_id")?,
    );
    Ok(())
}

/// The signed header list and the signature of `request` as signed at `timestamp`
/// (`YYYYMMDD'T'HHMMSS'Z'`), which must match its `x-amz-date`.
pub(crate) fn signature(
    request: &Request<Bytes>,
    secret: &str,
    scope: &Scope<'_>,
    timestamp: &str,
) -> (String, String) {
    let (canonical, signed_headers) = canonical_request(request);
    let date = timestamp.get(..8).unwrap_or_default();
    let to_sign = string_to_sign(timestamp, &credential_scope(timestamp, scope), &canonical);
    let signature = hmac::sign(&signing_key(secret, date, scope), to_sign.as_bytes());
    (signed_headers, hex(signature.as_ref()))
}

/// `YYYYMMDD/region/service/aws4_request`.
fn credential_scope(timestamp: &str, scope: &Scope<'_>) -> String {
    format!(
        "{}/{}/{}/aws4_request",
        timestamp.get(..8).unwrap_or_default(),
        scope.region,
        scope.service
    )
}

/// `YYYYMMDD'T'HHMMSS'Z'` in UTC.
fn timestamp(now: OffsetDateTime) -> String {
    let utc = now.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// The canonical request and the signed header list; `authorization` is never signed.
fn canonical_request(request: &Request<Bytes>) -> (String, String) {
    let mut headers: Vec<(String, String)> = Vec::new();
    for name in request
        .headers()
        .keys()
        .filter(|name| *name != http::header::AUTHORIZATION)
    {
        let values: Vec<String> = request
            .headers()
            .get_all(name)
            .iter()
            .map(|value| {
                String::from_utf8_lossy(value.as_bytes())
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        headers.push((name.as_str().to_ascii_lowercase(), values.join(",")));
    }
    headers.sort();
    let signed_headers = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<Vec<_>>()
        .concat();
    let path = match request.uri().path() {
        "" => "/",
        path => path,
    };
    let canonical = format!(
        "{}\n{path}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        request.method(),
        canonical_query(request.uri().query().unwrap_or_default()),
        hex(digest(&SHA256, request.body()).as_ref())
    );
    (canonical, signed_headers)
}

/// Each name and value decoded, `UriEncode`d and sorted by name, then value.
fn canonical_query(query: &str) -> String {
    let encode = |text: &str| {
        let decoded = percent_decode_str(text).decode_utf8_lossy();
        utf8_percent_encode(&decoded, UNRESERVED).to_string()
    };
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (encode(name), encode(value))
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn string_to_sign(timestamp: &str, credential_scope: &str, canonical: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{}",
        hex(digest(&SHA256, canonical.as_bytes()).as_ref())
    )
}

/// `HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region), service), "aws4_request")`.
fn signing_key(secret: &str, date: &str, scope: &Scope<'_>) -> hmac::Key {
    let step = |key: &[u8], data: &str| {
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
    };
    let date_key = step(format!("AWS4{secret}").as_bytes(), date);
    let region_key = step(date_key.as_ref(), scope.region);
    let service_key = step(region_key.as_ref(), scope.service);
    hmac::Key::new(
        hmac::HMAC_SHA256,
        step(service_key.as_ref(), "aws4_request").as_ref(),
    )
}

/// Lowercase hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[cfg(test)]
mod tests;
