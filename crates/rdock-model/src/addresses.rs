//! Which backend addresses a tenant's services may reach (H-SEC-07, ADR-0031 "As implemented
//! (review fixes, tenants and admission)").
//!
//! A tenant's objects are written by people who must not reach the proxy's own machine, its
//! network or the cloud's metadata service through it (server-side request forgery; OWASP's
//! SSRF Prevention Cheat Sheet,
//! <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>,
//! read 2026-11-13, recommends allow-lists of destinations and checking every resolved
//! address, since a DNS name can resolve anywhere). The rule is a [`BackendPolicy`]:
//!
//! - **unset `backend_networks`**: only globally routable unicast addresses;
//! - **set**: exactly the listed networks, nothing else; a cloud metadata address only when a
//!   network names that one address.
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are judged as the IPv4 address they carry,
//! and NAT64's well-known prefix (`64:ff9b::/96`, RFC 6052) as the IPv4 address embedded in
//! it. Validation applies the policy to IP literals; the data plane applies it to every
//! address a tenant backend resolves to, every time it resolves.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::values::IpNetwork;

/// Addresses of cloud instance metadata and credential services, refused even where their
/// range would otherwise be allowed: AWS, Google Cloud, Azure, Oracle Cloud and DigitalOcean
/// `169.254.169.254`; Amazon ECS task metadata `169.254.170.2`; EKS Pod Identity
/// `169.254.170.23`; AWS's IPv6 IMDS `fd00:ec2::254` and Pod Identity `fd00:ec2::23`; Alibaba
/// Cloud `100.100.100.200`; Azure's `WireServer` `168.63.129.16` (a public address).
pub const METADATA: [IpAddr; 7] = [
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2)),
    IpAddr::V4(Ipv4Addr::new(169, 254, 170, 23)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0023)),
    IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
    IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16)),
];

/// `ip` with an IPv4-mapped IPv6 address replaced by its IPv4 address.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// What kind of address `ip` is when it is not globally routable unicast, for diagnostics
/// and logs; `None` for a global unicast address that is not a metadata address.
#[must_use]
pub fn special(ip: IpAddr) -> Option<&'static str> {
    let ip = canonical(ip);
    if METADATA.contains(&ip) {
        return Some("a cloud metadata address");
    }
    match ip {
        IpAddr::V4(v4) => special_v4(v4),
        IpAddr::V6(v6) => special_v6(v6),
    }
}

/// Whether `ip` is a globally routable unicast address (and not a metadata address).
#[must_use]
pub fn is_global_unicast(ip: IpAddr) -> bool {
    special(ip).is_none()
}

fn special_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let [a, b, c, _] = ip.octets();
    let kind = if ip.is_unspecified() || a == 0 {
        "unspecified or \"this network\" (0.0.0.0/8)"
    } else if ip.is_loopback() {
        "loopback (127.0.0.0/8)"
    } else if ip.is_link_local() {
        "link-local (169.254.0.0/16)"
    } else if ip.is_private() {
        "private (RFC 1918)"
    } else if a == 100 && (64..128).contains(&b) {
        "shared address space (100.64.0.0/10, carrier-grade NAT)"
    } else if ip.is_multicast() {
        "multicast"
    } else if a >= 240 {
        "reserved or broadcast (240.0.0.0/4)"
    } else if ip.is_documentation() {
        "documentation"
    } else if a == 198 && (b == 18 || b == 19) {
        "benchmarking (198.18.0.0/15)"
    } else if a == 192 && b == 0 && c == 0 {
        "IETF protocol assignments (192.0.0.0/24)"
    } else if a == 192 && b == 88 && c == 99 {
        "6to4 relay anycast (192.88.99.0/24)"
    } else {
        return None;
    };
    Some(kind)
}

fn special_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let seg = ip.segments();
    // NAT64's well-known prefix carries an IPv4 address (RFC 6052): judge that one.
    if seg[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        let [hi1, hi2] = seg[6].to_be_bytes();
        let [lo1, lo2] = seg[7].to_be_bytes();
        return special_v4(Ipv4Addr::new(hi1, hi2, lo1, lo2))
            .map(|_| "NAT64 of a non-global address");
    }
    let kind = if ip.is_unspecified() {
        "unspecified (::)"
    } else if ip.is_loopback() {
        "loopback (::1)"
    } else if (seg[0] & 0xffc0) == 0xfe80 {
        "link-local (fe80::/10)"
    } else if (seg[0] & 0xfe00) == 0xfc00 {
        "unique local (fc00::/7)"
    } else if ip.is_multicast() {
        "multicast"
    } else if (seg[0] & 0xe000) != 0x2000 {
        // Outside 2000::/3, the only global unicast block assigned: IPv4-compatible and
        // other ::/8 forms, 100::/64 (discard) and the rest of the reserved space.
        "reserved (outside 2000::/3)"
    } else if seg[0] == 0x2001 && seg[1] == 0x0db8 || (seg[0] == 0x3fff && seg[1] < 0x1000) {
        "documentation (2001:db8::/32, 3fff::/20)"
    } else if seg[0] == 0x2001 && seg[1] < 0x0200 {
        "IETF protocol assignments (2001::/23, Teredo and benchmarking among them)"
    } else if seg[0] == 0x2002 {
        "6to4 (2002::/16), which carries an IPv4 address"
    } else {
        return None;
    };
    Some(kind)
}

/// The addresses a tenant's backends may connect to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BackendPolicy {
    /// Globally routable unicast addresses only (`backend_networks` unset).
    #[default]
    GlobalOnly,
    /// Exactly these networks.
    Networks(Vec<IpNetwork>),
}

impl BackendPolicy {
    /// The policy of `networks` (`tenants.<name>.backend_networks`).
    #[must_use]
    pub fn of(networks: &[IpNetwork]) -> Self {
        if networks.is_empty() {
            Self::GlobalOnly
        } else {
            Self::Networks(networks.to_vec())
        }
    }

    /// Why `ip` may not be reached, or `None` when it may.
    #[must_use]
    pub fn refusal(&self, ip: IpAddr) -> Option<String> {
        let ip = canonical(ip);
        match self {
            Self::GlobalOnly => {
                special(ip).map(|kind| format!("`{ip}` is {kind}, not a global unicast address"))
            }
            Self::Networks(networks) => {
                if !networks.iter().any(|n| n.contains(&ip)) {
                    return Some(format!("`{ip}` is outside `backend_networks`"));
                }
                if METADATA.contains(&ip) && !networks.iter().any(|n| n.is_single(ip)) {
                    return Some(format!(
                        "`{ip}` is a cloud metadata address; list it on its own (`{ip}/{}`) to allow it",
                        if ip.is_ipv4() { 32 } else { 128 }
                    ));
                }
                None
            }
        }
    }

    /// Whether `ip` may be reached.
    #[must_use]
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.refusal(ip).is_none()
    }
}

/// Whether `host` (a backend host as written, not a strict IP literal) would be read as an
/// IP address by the system resolver: the last label, after one trailing dot, is a number in
/// decimal, octal or `0x` hexadecimal (`127.1`, `2130706433`, `0x7f.0.0.1`, `0177.0.0.1`,
/// `0`). `inet_aton`, which glibc's and musl's `getaddrinfo` use for numeric hosts, accepts
/// these forms; no top-level domain is numeric (WHATWG URL Standard, "ends in a number",
/// <https://url.spec.whatwg.org/#ends-in-a-number-checker>, read 2026-11-13).
#[must_use]
pub fn looks_numeric(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let last = host.rsplit('.').next().unwrap_or(host);
    if last.is_empty() {
        return false;
    }
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    last.strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Host names that `/etc/hosts` files of common distributions map to the machine itself:
/// `localhost` and every name below it (RFC 6761 §6.3), `localhost.localdomain`,
/// `localhost6`, `localhost6.localdomain6`, and Debian's `ip6-localhost` and `ip6-loopback`.
#[must_use]
pub fn is_loopback_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || matches!(
            host.as_str(),
            "localhost.localdomain"
                | "localhost6"
                | "localhost6.localdomain6"
                | "ip6-localhost"
                | "ip6-loopback"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_classifier_refuses_every_special_range() {
        for (text, global) in [
            // IPv4
            ("0.0.0.0", false),
            ("0.1.2.3", false),
            ("127.0.0.1", false),
            ("127.255.255.254", false),
            ("10.0.0.1", false),
            ("172.16.0.1", false),
            ("172.31.255.255", false),
            ("192.168.1.1", false),
            ("100.64.0.1", false),
            ("100.127.255.255", false),
            ("169.254.0.1", false),
            ("169.254.169.254", false),
            ("192.0.0.8", false),
            ("192.0.2.1", false),
            ("198.18.0.1", false),
            ("198.51.100.1", false),
            ("203.0.113.1", false),
            ("192.88.99.1", false),
            ("224.0.0.1", false),
            ("239.255.255.250", false),
            ("240.0.0.1", false),
            ("255.255.255.255", false),
            ("168.63.129.16", false),
            ("8.8.8.8", true),
            ("1.1.1.1", true),
            ("100.63.255.255", true),
            ("100.128.0.1", true),
            ("172.32.0.1", true),
            ("81.2.69.142", true),
            // IPv6
            ("::", false),
            ("::1", false),
            ("::ffff:127.0.0.1", false),
            ("::ffff:169.254.169.254", false),
            ("::ffff:10.0.0.1", false),
            ("::127.0.0.1", false),
            ("fe80::1", false),
            ("febf::1", false),
            ("fc00::1", false),
            ("fd00:ec2::254", false),
            ("fd12:3456::1", false),
            ("ff02::1", false),
            ("100::1", false),
            ("2001:db8::1", false),
            ("3fff::1", false),
            ("2001::1", false),
            ("2001:2::1", false),
            ("2002:7f00:1::1", false),
            ("64:ff9b::7f00:1", false),
            ("64:ff9b::a9fe:a9fe", false),
            ("2001:4860:4860::8888", true),
            ("2606:4700::1111", true),
            ("::ffff:8.8.8.8", true),
            ("64:ff9b::808:808", true),
        ] {
            assert_eq!(is_global_unicast(ip(text)), global, "{text}");
        }
        assert_eq!(
            special(ip("::ffff:169.254.169.254")),
            Some("a cloud metadata address")
        );
    }

    #[test]
    fn listed_networks_allow_exactly_themselves() {
        let networks: Vec<IpNetwork> = ["10.0.0.0/8", "127.0.0.1", "0.0.0.0/0"]
            .iter()
            .map(|n| n.parse().unwrap())
            .collect();
        let policy = BackendPolicy::of(&networks[..2]);
        assert!(policy.allows(ip("10.1.2.3")));
        assert!(
            policy.allows(ip("::ffff:10.1.2.3")),
            "mapped forms are judged as IPv4"
        );
        assert!(policy.allows(ip("127.0.0.1")), "listed explicitly");
        assert!(!policy.allows(ip("127.0.0.2")));
        assert!(!policy.allows(ip("8.8.8.8")), "nothing else, global or not");
        let everything = BackendPolicy::of(&networks[2..]);
        assert!(everything.allows(ip("127.0.0.1")));
        assert!(
            !everything.allows(ip("169.254.169.254")),
            "metadata needs its own entry"
        );
        let metadata = BackendPolicy::of(&["169.254.169.254/32".parse().unwrap()]);
        assert!(metadata.allows(ip("169.254.169.254")));
        assert!(BackendPolicy::GlobalOnly.allows(ip("8.8.8.8")));
        assert!(!BackendPolicy::GlobalOnly.allows(ip("::ffff:127.0.0.1")));
    }

    #[test]
    fn numeric_hosts_and_loopback_names_are_recognised() {
        for host in [
            "127.1",
            "2130706433",
            "0",
            "0.0",
            "0x7f.0.0.1",
            "0x7f000001",
            "0177.0.0.1",
            "2852039166",
            "127.0.0.1.",
            "a.123",
            "a.0x1F",
        ] {
            assert!(looks_numeric(host), "{host}");
        }
        for host in [
            "example.com",
            "app",
            "a1",
            "0xzz",
            "web-1.internal",
            "123abc",
        ] {
            assert!(!looks_numeric(host), "{host}");
        }
        for host in [
            "localhost",
            "LOCALHOST.",
            "a.localhost",
            "localhost.localdomain",
            "ip6-localhost",
            "ip6-loopback",
            "localhost6",
        ] {
            assert!(is_loopback_name(host), "{host}");
        }
        assert!(!is_loopback_name("notlocalhost"));
    }
}
