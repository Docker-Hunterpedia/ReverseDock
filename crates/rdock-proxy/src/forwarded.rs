//! Client IP resolution and forwarding headers (B-NET-08, architecture §6).
//!
//! Forwarding headers are believed only from trusted proxies. From anyone else they are removed
//! (including `_` spellings, which CGI-style backends treat like `-`) and rewritten; from a
//! trusted proxy they are kept and the proxy's address is appended to `X-Forwarded-For`.

use std::net::IpAddr;

use http::{HeaderMap, HeaderName, HeaderValue};
use ipnet::IpNet;
use pingora::http::RequestHeader;
use rdock_model::settings::ClientIpHeader;

/// At most this many `X-Forwarded-For` entries are examined, counted from the right.
const MAX_FORWARDED_HOPS: usize = 32;

/// Headers ReverseDock manages: removed when the peer is not trusted.
const MANAGED: [&str; 13] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-prefix",
    "x-forwarded-server",
    "x-forwarded-uri",
    "x-forwarded-method",
    "x-forwarded-tls-client-cert",
    "x-forwarded-tls-client-cert-info",
    "x-real-ip",
    "forwarded",
    "cf-connecting-ip",
];

/// How the client IP is derived.
#[derive(Debug, Clone, Default)]
pub struct ClientIpPolicy {
    trusted: Vec<IpNet>,
    header: ClientIpHeader,
}

impl ClientIpPolicy {
    /// A policy trusting `trusted` networks.
    #[must_use]
    pub fn new(trusted: Vec<IpNet>, header: ClientIpHeader) -> Self {
        Self { trusted, header }
    }

    /// Whether `ip` belongs to a trusted proxy.
    #[must_use]
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// The client IP of a request received from `peer`.
    #[must_use]
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = canonical(peer);
        if !self.is_trusted(peer) {
            return peer;
        }
        match self.header {
            ClientIpHeader::XRealIp => headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_ip)
                .unwrap_or(peer),
            // `CfConnectingIp` and the Cloudflare branch of `Auto` arrive with W-CF-02 (v0.3); the
            // capability check refuses `cf-connecting-ip` until then.
            ClientIpHeader::Auto
            | ClientIpHeader::XForwardedFor
            | ClientIpHeader::CfConnectingIp => self.walk_forwarded_for(peer, headers),
        }
    }

    /// Walks `X-Forwarded-For` from the right, skipping trusted hops; the first untrusted
    /// address is the client. If every hop is trusted, the left-most one is.
    fn walk_forwarded_for(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let mut entries: Vec<&str> = Vec::new();
        for value in headers.get_all("x-forwarded-for") {
            if let Ok(text) = value.to_str() {
                entries.extend(text.split(',').map(str::trim).filter(|s| !s.is_empty()));
            }
        }
        let mut client = peer;
        for entry in entries.iter().rev().take(MAX_FORWARDED_HOPS) {
            let Some(ip) = parse_ip(entry) else {
                // An unparsable hop cannot be trusted; stop at the last good one.
                break;
            };
            client = ip;
            if !self.is_trusted(ip) {
                break;
            }
        }
        client
    }
}

/// IPv4-mapped IPv6 addresses are treated as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Parses `1.2.3.4`, `1.2.3.4:80`, `2001:db8::1` or `[2001:db8::1]:443`.
fn parse_ip(text: &str) -> Option<IpAddr> {
    let text = text.trim().trim_matches('"');
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    if let Some(rest) = text.strip_prefix('[') {
        return rest.split_once(']')?.0.parse().ok().map(canonical);
    }
    let (host, _port) = text.rsplit_once(':')?;
    host.parse().ok().map(canonical)
}

/// What is known about the request when the forwarding headers are written.
#[derive(Debug, Clone, Copy)]
pub struct Forwarding<'a> {
    /// TCP peer.
    pub peer: IpAddr,
    /// Resolved client IP.
    pub client_ip: IpAddr,
    /// Whether the peer is a trusted proxy.
    pub trusted: bool,
    /// The connection uses TLS.
    pub tls: bool,
    /// `Host` (or `:authority`) as sent by the client, with port if any.
    pub host: Option<&'a str>,
}

/// Rewrites the forwarding headers of a request before it is sent upstream.
pub fn apply(req: &mut RequestHeader, info: &Forwarding<'_>) {
    if !info.trusted {
        remove_managed(req);
    }
    let websocket = req
        .headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let proto = match (info.tls, websocket) {
        (true, true) => "wss",
        (true, false) => "https",
        (false, true) => "ws",
        (false, false) => "http",
    };
    append_forwarded_for(req, canonical(info.peer));
    set(req, "x-real-ip", &canonical(info.client_ip).to_string());
    set_if_absent(req, "x-forwarded-proto", proto);
    if let Some(host) = info.host {
        set_if_absent(req, "x-forwarded-host", host);
    }
    let port = info
        .host
        .and_then(host_port)
        .unwrap_or(if info.tls { 443 } else { 80 });
    set_if_absent(req, "x-forwarded-port", &port.to_string());
}

/// The explicit port of a `Host` value.
fn host_port(host: &str) -> Option<u16> {
    let after = match host.rsplit_once(']') {
        Some((_, rest)) => rest,
        None if host.matches(':').count() == 1 => host.split_once(':').map_or("", |(_, p)| p),
        None => return None,
    };
    after.trim_start_matches(':').parse().ok()
}

fn remove_managed(req: &mut RequestHeader) {
    let doomed: Vec<HeaderName> = req
        .headers
        .keys()
        .filter(|name| {
            let dashed = name.as_str().replace('_', "-");
            MANAGED.contains(&dashed.as_str())
        })
        .cloned()
        .collect();
    for name in doomed {
        req.remove_header(&name);
    }
}

fn append_forwarded_for(req: &mut RequestHeader, peer: IpAddr) {
    let existing: Vec<String> = req
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let value = if existing.is_empty() {
        peer.to_string()
    } else {
        format!("{}, {peer}", existing.join(", "))
    };
    set(req, "x-forwarded-for", &value);
}

fn set(req: &mut RequestHeader, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        // Inserting a valid header value into the header map cannot fail.
        let _ = req.insert_header(name, value);
    }
}

fn set_if_absent(req: &mut RequestHeader, name: &'static str, value: &str) {
    if !req.headers.contains_key(name) {
        set(req, name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(*k, HeaderValue::from_str(v).unwrap());
        }
        map
    }

    #[test]
    fn untrusted_peers_are_the_client() {
        let policy = ClientIpPolicy::new(vec![net("10.0.0.0/8")], ClientIpHeader::Auto);
        let h = headers(&[("x-forwarded-for", "1.1.1.1")]);
        assert_eq!(policy.client_ip(ip("203.0.113.9"), &h), ip("203.0.113.9"));
    }

    #[test]
    fn walks_forwarded_for_from_the_right() {
        let policy = ClientIpPolicy::new(vec![net("10.0.0.0/8")], ClientIpHeader::XForwardedFor);
        let h = headers(&[
            ("x-forwarded-for", "6.6.6.6, 198.51.100.7"),
            ("x-forwarded-for", "10.0.0.2"),
        ]);
        assert_eq!(policy.client_ip(ip("10.0.0.1"), &h), ip("198.51.100.7"));
        let all_trusted = headers(&[("x-forwarded-for", "10.1.1.1, 10.2.2.2")]);
        assert_eq!(
            policy.client_ip(ip("10.0.0.1"), &all_trusted),
            ip("10.1.1.1")
        );
        let garbage = headers(&[("x-forwarded-for", "nonsense, 10.2.2.2")]);
        assert_eq!(policy.client_ip(ip("10.0.0.1"), &garbage), ip("10.2.2.2"));
        let mapped = headers(&[("x-forwarded-for", "[::ffff:198.51.100.7]:443")]);
        assert_eq!(
            policy.client_ip(ip("::ffff:10.0.0.1"), &mapped),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn x_real_ip_mode_reads_the_header_from_trusted_peers() {
        let policy = ClientIpPolicy::new(vec![net("10.0.0.0/8")], ClientIpHeader::XRealIp);
        let h = headers(&[("x-real-ip", "198.51.100.7")]);
        assert_eq!(policy.client_ip(ip("10.0.0.1"), &h), ip("198.51.100.7"));
        assert_eq!(policy.client_ip(ip("192.0.2.1"), &h), ip("192.0.2.1"));
    }

    fn request(pairs: &[(&'static str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        for (k, v) in pairs {
            req.append_header(*k, *v).unwrap();
        }
        req
    }

    fn header(req: &RequestHeader, name: &str) -> Option<String> {
        req.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    }

    #[test]
    fn untrusted_requests_are_rewritten() {
        let mut req = request(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("x_forwarded_for", "6.6.6.6"),
            ("x-forwarded-proto", "https"),
            ("x-real-ip", "6.6.6.6"),
            ("forwarded", "for=6.6.6.6"),
            ("cf-connecting-ip", "6.6.6.6"),
            ("upgrade", "websocket"),
        ]);
        apply(
            &mut req,
            &Forwarding {
                peer: ip("203.0.113.9"),
                client_ip: ip("203.0.113.9"),
                trusted: false,
                tls: false,
                host: Some("app.example.com:8080"),
            },
        );
        assert_eq!(
            header(&req, "x-forwarded-for").as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(header(&req, "x_forwarded_for"), None);
        assert_eq!(header(&req, "x-forwarded-proto").as_deref(), Some("ws"));
        assert_eq!(header(&req, "x-real-ip").as_deref(), Some("203.0.113.9"));
        assert_eq!(header(&req, "forwarded"), None);
        assert_eq!(header(&req, "cf-connecting-ip"), None);
        assert_eq!(
            header(&req, "x-forwarded-host").as_deref(),
            Some("app.example.com:8080")
        );
        assert_eq!(header(&req, "x-forwarded-port").as_deref(), Some("8080"));
    }

    #[test]
    fn trusted_requests_keep_the_chain() {
        let mut req = request(&[
            ("x-forwarded-for", "198.51.100.7"),
            ("x-forwarded-proto", "https"),
            ("forwarded", "for=198.51.100.7"),
        ]);
        apply(
            &mut req,
            &Forwarding {
                peer: ip("10.0.0.1"),
                client_ip: ip("198.51.100.7"),
                trusted: true,
                tls: false,
                host: Some("[2001:db8::1]"),
            },
        );
        assert_eq!(
            header(&req, "x-forwarded-for").as_deref(),
            Some("198.51.100.7, 10.0.0.1")
        );
        assert_eq!(header(&req, "x-forwarded-proto").as_deref(), Some("https"));
        assert_eq!(header(&req, "x-real-ip").as_deref(), Some("198.51.100.7"));
        assert_eq!(
            header(&req, "forwarded").as_deref(),
            Some("for=198.51.100.7")
        );
        assert_eq!(header(&req, "x-forwarded-port").as_deref(), Some("80"));
    }

    #[test]
    fn reads_ports_from_host_values() {
        assert_eq!(host_port("a.test:8443"), Some(8443));
        assert_eq!(host_port("a.test"), None);
        assert_eq!(host_port("[::1]:9000"), Some(9000));
        assert_eq!(host_port("[::1]"), None);
        assert_eq!(host_port("::1"), None);
    }
}
