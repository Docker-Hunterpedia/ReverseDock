//! Updating a stored response with a `304 Not Modified` (RFC 9111 §3.2, §4.3.4).

use http::header::HeaderName;
use http::{HeaderMap, HeaderValue};

/// Fields a `304` never changes in the stored response: the framing and encoding of the
/// stored body (`Content-Length`, `Content-Encoding`, `Content-Range`, `Transfer-Encoding`),
/// connection-specific fields, fields the cache must not store (RFC 9111 §3.1), and
/// `Set-Cookie`, which would otherwise be handed to every later client.
const KEPT: [&str; 14] = [
    "content-length",
    "content-encoding",
    "content-range",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authentication-info",
    "set-cookie",
    "set-cookie2",
];

/// The fields a `304` replaces in the stored response, with their new values: every field
/// it carries (not only the validators) except the framing, connection and cookie fields listed in `KEPT` and those named by
/// `connection` in the `304`.
#[must_use]
pub fn updates(not_modified: &HeaderMap) -> Vec<(HeaderName, Vec<HeaderValue>)> {
    let nominated: Vec<String> = not_modified
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    not_modified
        .keys()
        .filter(|name| {
            let lower = name.as_str();
            !KEPT.contains(&lower) && !nominated.iter().any(|n| n == lower)
        })
        .map(|name| {
            (
                name.clone(),
                not_modified.get_all(name).iter().cloned().collect(),
            )
        })
        .collect()
}

/// Applies [`updates`] to `stored`.
pub fn merge_not_modified(stored: &mut HeaderMap, not_modified: &HeaderMap) {
    for (name, values) in updates(not_modified) {
        stored.remove(&name);
        for value in values {
            stored.append(name.clone(), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(*n, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn rfc9111_4_3_4_every_field_of_the_304_replaces_the_stored_one() {
        let mut stored = headers(&[
            ("cache-control", "max-age=1"),
            ("etag", "\"a\""),
            ("x-version", "1"),
            ("x-kept", "yes"),
            ("content-length", "10"),
            ("link", "</a>"),
            ("link", "</b>"),
        ]);
        let nm = headers(&[
            ("cache-control", "max-age=60"),
            ("x-version", "2"),
            ("link", "</c>"),
            ("content-length", "0"),
            ("set-cookie", "a=b"),
        ]);
        merge_not_modified(&mut stored, &nm);
        assert_eq!(stored["cache-control"], "max-age=60");
        assert_eq!(stored["x-version"], "2");
        assert_eq!(stored["x-kept"], "yes");
        assert_eq!(stored["etag"], "\"a\"");
        assert_eq!(stored["content-length"], "10");
        assert!(stored.get("set-cookie").is_none());
        let links: Vec<_> = stored.get_all("link").iter().collect();
        assert_eq!(links, ["</c>"]);
    }

    #[test]
    fn rfc9111_3_2_connection_nominated_fields_are_not_merged() {
        let mut stored = headers(&[("x-hop", "old")]);
        let nm = headers(&[("connection", "x-hop"), ("x-hop", "new")]);
        merge_not_modified(&mut stored, &nm);
        assert_eq!(stored["x-hop"], "old");
        assert!(stored.get("connection").is_none());
    }
}
