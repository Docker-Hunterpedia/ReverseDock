//! Request path normalisation, following Traefik v3 (ADR-0014). The proxy routes and forwards
//! the normalised path; path middlewares re-check their results with it.
//!
//! 1. Percent-escapes of unreserved characters are decoded and all other escapes are upper-cased
//!    (`%7e` → `~`, `%2f` → `%2F`); a truncated escape is an error.
//! 2. Dot segments are removed and repeated slashes collapsed (`/./a/../b//` → `/b/`).
//!
//! The result is forwarded to the backend, so the backend sees the path that was routed. Routing
//! itself matches a decoded form in which only reserved characters and `%25` stay encoded, so
//! ``PathPrefix(`/foo bar`)`` matches `/foo%20bar` but ``PathPrefix(`/a/b`)`` does not match
//! `/a%2Fb`.

use std::borrow::Cow;

/// A normalised request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath {
    /// Percent-encoded path sent to the backend.
    pub forwarded: String,
    /// Decoded path used for `Path`, `PathPrefix` and `PathRegexp`.
    pub routing: String,
}

/// Why a path was rejected (answered with 400).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// A `%` not followed by two hex digits.
    #[error("invalid percent-encoding in the path")]
    BadEscape,
    /// A `#` fragment, which clients must not send.
    #[error("the request target contains a fragment")]
    Fragment,
}

/// Normalises a request path. `*` (the asterisk form of `OPTIONS *`) is kept as it is.
pub fn normalize(raw: &str) -> Result<NormalizedPath, PathError> {
    if raw.contains('#') {
        return Err(PathError::Fragment);
    }
    if raw == "*" {
        return Ok(NormalizedPath {
            forwarded: raw.to_owned(),
            routing: raw.to_owned(),
        });
    }
    let escaped = normalize_escapes(raw)?;
    let forwarded = remove_dot_segments(&escaped);
    let routing = decode_for_routing(&forwarded).into_owned();
    Ok(NormalizedPath { forwarded, routing })
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// RFC 3986 reserved characters, plus `%` itself, stay encoded for routing.
fn stays_encoded_for_routing(b: u8) -> bool {
    matches!(
        b,
        b':' | b'/'
            | b'?'
            | b'#'
            | b'['
            | b']'
            | b'@'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b'%'
    )
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes unreserved escapes and upper-cases the others.
fn normalize_escapes(raw: &str) -> Result<String, PathError> {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).and_then(|b| hex(*b)),
                bytes.get(i + 2).and_then(|b| hex(*b)),
            ) else {
                return Err(PathError::BadEscape);
            };
            let value = hi * 16 + lo;
            if is_unreserved(value) {
                out.push(char::from(value));
            } else {
                out.push('%');
                out.push(char::from(bytes[i + 1].to_ascii_uppercase()));
                out.push(char::from(bytes[i + 2].to_ascii_uppercase()));
            }
            i += 3;
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b'%' {
                i += 1;
            }
            out.push_str(&raw[start..i]);
        }
    }
    Ok(out)
}

/// RFC 3986 §5.2.4 dot-segment removal, with empty segments (`//`) dropped. A trailing slash is
/// kept, also when the last segment was `.` or `..`.
fn remove_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    let mut trailing_slash = false;
    for segment in path.split('/') {
        trailing_slash = false;
        match segment {
            "" | "." => trailing_slash = true,
            ".." => {
                segments.pop();
                trailing_slash = true;
            }
            other => segments.push(other),
        }
    }
    let mut out = String::with_capacity(path.len());
    for segment in &segments {
        out.push('/');
        out.push_str(segment);
    }
    if trailing_slash || out.is_empty() {
        out.push('/');
    }
    out
}

/// Decodes escapes other than reserved characters and `%25`. Falls back to the encoded form when
/// the decoded bytes are not UTF-8.
fn decode_for_routing(path: &str) -> Cow<'_, str> {
    if !path.contains('%') {
        return Cow::Borrowed(path);
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| Some(hex(*bytes.get(i + 1)?)? * 16 + hex(*bytes.get(i + 2)?)?))
            .flatten();
        match decoded {
            Some(value) if !stays_encoded_for_routing(value) => {
                out.push(value);
                i += 3;
            }
            _ => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    match String::from_utf8(out) {
        Ok(text) => Cow::Owned(text),
        Err(_) => Cow::Borrowed(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(raw: &str) -> (String, String) {
        let p = normalize(raw).unwrap();
        (p.forwarded, p.routing)
    }

    #[test]
    fn removes_dot_segments_and_double_slashes() {
        assert_eq!(n("/./foo/../bar//").0, "/bar/");
        assert_eq!(n("/a/b/../../..").0, "/");
        assert_eq!(n("/a//b").0, "/a/b");
        assert_eq!(n("/").0, "/");
        assert_eq!(n("").0, "/");
        assert_eq!(n("/a/.").0, "/a/");
        assert_eq!(n("/a/b/").0, "/a/b/");
    }

    #[test]
    fn decodes_unreserved_escapes_before_removing_dots() {
        assert_eq!(n("/%2e%2e/admin").0, "/admin");
        assert_eq!(n("/%7Euser/%41").0, "/~user/A");
        assert_eq!(n("/a%2fb").0, "/a%2Fb");
    }

    #[test]
    fn routing_keeps_reserved_escapes() {
        assert_eq!(n("/foo%20bar"), ("/foo%20bar".into(), "/foo bar".into()));
        assert_eq!(n("/a%2Fb"), ("/a%2Fb".into(), "/a%2Fb".into()));
        assert_eq!(n("/100%25"), ("/100%25".into(), "/100%25".into()));
        assert_eq!(n("/caf%C3%A9").1, "/café");
        assert_eq!(n("/bad%FF").1, "/bad%FF");
    }

    #[test]
    fn rejects_bad_escapes_and_fragments() {
        assert_eq!(normalize("/a%4"), Err(PathError::BadEscape));
        assert_eq!(normalize("/a%zz"), Err(PathError::BadEscape));
        assert_eq!(normalize("/a#b"), Err(PathError::Fragment));
        assert_eq!(n("*"), ("*".into(), "*".into()));
    }
}
