//! Invalidation after unsafe methods (RFC 9111 §4.4).

use http::header::{CONTENT_LOCATION, LOCATION};
use http::{HeaderMap, Method};

/// Whether `method` is unsafe (RFC 9110 §9.2.1): anything but `GET`, `HEAD`, `OPTIONS` and
/// `TRACE`.
#[must_use]
pub fn is_unsafe(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Whether a response status invalidates: a non-error status, 2xx or 3xx (RFC 9111 §4.4).
#[must_use]
pub fn invalidates(status: u16) -> bool {
    (200..400).contains(&status)
}

/// The URLs to invalidate after a successful unsafe request to `request_url` (as
/// [`public_url`] writes it): the request's own URL, and the `Location` and
/// `Content-Location` targets when they have the same scheme and host. Other hosts are never
/// touched (RFC 9111 §4.4: a cache MUST NOT invalidate them).
#[must_use]
pub fn targets(request_url: &str, response: &HeaderMap) -> Vec<String> {
    let mut out = vec![request_url.to_owned()];
    let Ok(base) = url::Url::parse(request_url) else {
        return out;
    };
    for name in [LOCATION, CONTENT_LOCATION] {
        let Some(value) = response.get(&name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        let Ok(target) = base.join(value.trim()) else {
            continue;
        };
        if target.scheme() != base.scheme() || target.host_str() != base.host_str() {
            continue;
        }
        let url = public_url(
            target.scheme(),
            target.host_str().unwrap_or_default(),
            target.path(),
            target.query(),
        );
        if !out.contains(&url) {
            out.push(url);
        }
    }
    out
}

/// The URL objects are recorded under and purged by: `scheme://host/path?query`, host in
/// lower case and without a port, the query as received (no `?` when empty).
#[must_use]
pub fn public_url(scheme: &str, host: &str, path: &str, query: Option<&str>) -> String {
    let mut url = format!(
        "{}://{}{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase(),
        if path.is_empty() { "/" } else { path }
    );
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(q);
    }
    url
}

/// Normalises a URL given to the purge API the way [`public_url`] records them: scheme and
/// host lower case, port and fragment removed. `None` when it is not an absolute `http` or
/// `https` URL.
#[must_use]
pub fn normalize_url(input: &str) -> Option<String> {
    let (scheme, rest) = input.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or_default();
    let (authority, path_query) = match rest.find(['/', '?']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = strip_port(authority);
    if host.is_empty() || host.contains('@') {
        return None;
    }
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_query, None),
    };
    Some(public_url(&scheme, host, path, query))
}

fn strip_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority
            .find(']')
            .map_or(authority, |end| &authority[..=end]);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
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
    fn rfc9110_9_2_1_unsafe_methods() {
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(is_unsafe(&m), "{m}");
        }
        for m in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert!(!is_unsafe(&m), "{m}");
        }
        assert!(invalidates(204) && invalidates(303) && !invalidates(404) && !invalidates(500));
    }

    #[test]
    fn rfc9111_4_4_location_and_content_location_on_the_same_host_only() {
        let resp = headers(&[
            ("location", "/items/7"),
            ("content-location", "https://other.test/x"),
        ]);
        assert_eq!(
            targets("https://app.test/items?x=1", &resp),
            ["https://app.test/items?x=1", "https://app.test/items/7"]
        );
        let resp = headers(&[("content-location", "HTTPS://APP.TEST:443/a")]);
        assert_eq!(
            targets("https://app.test/b", &resp),
            ["https://app.test/b", "https://app.test/a"]
        );
        let other_scheme = headers(&[("location", "http://app.test/a")]);
        assert_eq!(
            targets("https://app.test/b", &other_scheme),
            ["https://app.test/b"]
        );
    }

    #[test]
    fn purge_urls_are_normalised_like_recorded_ones() {
        assert_eq!(
            normalize_url("HTTPS://App.Test:8443/a/b?x=1#frag").as_deref(),
            Some("https://app.test/a/b?x=1")
        );
        assert_eq!(
            normalize_url("http://app.test").as_deref(),
            Some("http://app.test/")
        );
        assert_eq!(
            normalize_url("http://app.test?").as_deref(),
            Some("http://app.test/")
        );
        assert_eq!(normalize_url("ftp://app.test/").as_deref(), None);
        assert_eq!(normalize_url("/relative").as_deref(), None);
        assert_eq!(normalize_url("http://user@app.test/").as_deref(), None);
        assert_eq!(public_url("HTTP", "A.TEST", "", Some("")), "http://a.test/");
    }
}
