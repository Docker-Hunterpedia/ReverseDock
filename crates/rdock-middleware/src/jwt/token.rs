//! Compact JWS parsing, signature selection and claim checks (RFC 7515, RFC 7519, RFC 8725).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use super::keys::Key;

/// Largest token accepted.
pub(crate) const MAX_TOKEN: usize = 16 * 1024;

/// Why a token was refused. The text goes to the debug log, never to the client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Invalid {
    #[error("the token is malformed")]
    Malformed,
    #[error("algorithm `{0}` is not accepted")]
    Algorithm(String),
    #[error("the token needs an unsupported extension (`crit`)")]
    Critical,
    #[error("no key matches the token")]
    UnknownKey,
    #[error("the signature does not verify")]
    Signature,
    #[error("the token has expired")]
    Expired,
    #[error("the token has no expiry")]
    NoExpiry,
    #[error("the token is not valid yet")]
    NotYetValid,
    #[error("wrong issuer")]
    Issuer,
    #[error("wrong audience")]
    Audience,
}

/// What a valid token must satisfy.
pub(crate) struct Rules<'a> {
    pub(crate) issuer: Option<&'a str>,
    pub(crate) audiences: Option<&'a [String]>,
    pub(crate) leeway: Duration,
    pub(crate) now: SystemTime,
}

/// Verifies `token` with `keys` and returns its claims.
pub(crate) fn verify(
    token: &str,
    keys: &[&Key],
    rules: &Rules<'_>,
) -> Result<Map<String, Value>, Invalid> {
    if token.len() > MAX_TOKEN {
        return Err(Invalid::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Invalid::Malformed);
    };
    let header: Map<String, Value> = decode_json(header)?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(Invalid::Malformed)?;
    if header.contains_key("crit") {
        return Err(Invalid::Critical);
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let candidates: Vec<&Key> = keys
        .iter()
        .copied()
        .filter(|k| k.alg.name() == alg)
        .filter(|k| kid.is_none() || k.kid.is_none() || k.kid.as_deref() == kid)
        .collect();
    if candidates.is_empty() {
        return Err(if keys.iter().any(|k| k.alg.name() == alg) {
            Invalid::UnknownKey
        } else {
            Invalid::Algorithm(alg.chars().take(16).collect())
        });
    }
    let signature = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| Invalid::Malformed)?;
    let signed = &token.as_bytes()[..header_len(token)];
    if !candidates.iter().any(|k| k.verify(signed, &signature)) {
        return Err(Invalid::Signature);
    }
    let claims: Map<String, Value> = decode_json(payload)?;
    check_claims(&claims, rules)?;
    Ok(claims)
}

/// Length of `header.payload`, the signing input.
fn header_len(token: &str) -> usize {
    token.rfind('.').unwrap_or(token.len())
}

fn decode_json(part: &str) -> Result<Map<String, Value>, Invalid> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| Invalid::Malformed)?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(Invalid::Malformed),
    }
}

fn seconds(claims: &Map<String, Value>, name: &str) -> Result<Option<f64>, Invalid> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value.as_f64().map(Some).ok_or(Invalid::Malformed),
    }
}

fn check_claims(claims: &Map<String, Value>, rules: &Rules<'_>) -> Result<(), Invalid> {
    let now = rules
        .now
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    let leeway = rules.leeway.as_secs_f64();
    let exp = seconds(claims, "exp")?.ok_or(Invalid::NoExpiry)?;
    if now > exp + leeway {
        return Err(Invalid::Expired);
    }
    if seconds(claims, "nbf")?.is_some_and(|nbf| now + leeway < nbf) {
        return Err(Invalid::NotYetValid);
    }
    if let Some(issuer) = rules.issuer
        && claims.get("iss").and_then(Value::as_str) != Some(issuer)
    {
        return Err(Invalid::Issuer);
    }
    if let Some(audiences) = rules.audiences {
        let matches = |aud: &str| audiences.iter().any(|a| a == aud);
        let ok = match claims.get("aud") {
            Some(Value::String(aud)) => matches(aud),
            Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).any(matches),
            _ => false,
        };
        if !ok {
            return Err(Invalid::Audience);
        }
    }
    Ok(())
}
