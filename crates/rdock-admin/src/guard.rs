//! Checks and headers every admin request goes through (ADR-0024): DNS-rebinding defence on
//! `Host`, cross-site checks on unsafe methods, and the security headers of every response.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Request, State as Extract};
use axum::middleware::Next;
use axum::response::Response;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use crate::routes::error;
use crate::{State, Transport};

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                   img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; \
                   frame-ancestors 'none'; form-action 'self'";

/// The host names a listener on `ip` answers to when none are configured.
pub(crate) fn default_hosts(ip: IpAddr) -> Vec<String> {
    if ip.is_loopback() {
        vec!["localhost".into(), "127.0.0.1".into(), "::1".into()]
    } else {
        vec![ip.to_string()]
    }
}

/// `host[:port]` or `[v6][:port]` without the port, lower-cased.
fn strip_port(authority: &str) -> String {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
    };
    host.to_ascii_lowercase()
}

fn allowed(state: &State, authority: &str) -> bool {
    let host = strip_port(authority);
    state
        .allowed_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&host))
}

fn request_host(request: &Request) -> Option<&str> {
    request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| request.uri().authority().map(http::uri::Authority::as_str))
}

/// A cross-site request for an unsafe method: `Sec-Fetch-Site` says so, or, when the browser
/// sent no Fetch Metadata, `Origin` names a host this listener does not answer to. Requests with
/// neither header come from programs, not browsers, and authenticate on their own.
fn cross_site(state: &State, headers: &HeaderMap) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return !matches!(site.as_bytes(), b"same-origin" | b"none");
    }
    headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|origin| {
            origin == "null"
                || !origin
                    .split_once("://")
                    .is_some_and(|(_, authority)| allowed(state, authority))
        })
}

pub(crate) async fn checks(
    Extract(state): Extract<Arc<State>>,
    request: Request,
    next: Next,
) -> Response {
    let transport = request
        .extensions()
        .get::<Transport>()
        .copied()
        .unwrap_or(Transport::Tcp { tls: false });
    if let Transport::Tcp { tls } = transport {
        if !request_host(&request).is_some_and(|host| allowed(&state, host)) {
            return error(
                StatusCode::MISDIRECTED_REQUEST,
                "this host name is not served by the admin API",
            );
        }
        let safe = matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        );
        if !safe && cross_site(&state, request.headers()) {
            return error(StatusCode::FORBIDDEN, "cross-site requests are refused");
        }
        let mut response = next.run(request).await;
        secure(response.headers_mut(), tls);
        return response;
    }
    let mut response = next.run(request).await;
    secure(response.headers_mut(), false);
    response
}

fn secure(headers: &mut HeaderMap, tls: bool) {
    let set = |headers: &mut HeaderMap, name: header::HeaderName, value: &'static str| {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    };
    set(headers, header::CACHE_CONTROL, "no-store");
    set(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(headers, header::REFERRER_POLICY, "no-referrer");
    set(headers, header::CONTENT_SECURITY_POLICY, CSP);
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    if tls {
        set(
            headers,
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::strip_port;

    #[test]
    fn ports_and_brackets_are_removed() {
        for (authority, host) in [
            ("localhost:2080", "localhost"),
            ("LOCALHOST", "localhost"),
            ("127.0.0.1:2080", "127.0.0.1"),
            ("[::1]:2080", "::1"),
            ("[::1]", "::1"),
            ("admin.example.com", "admin.example.com"),
        ] {
            assert_eq!(strip_port(authority), host, "{authority}");
        }
    }
}
