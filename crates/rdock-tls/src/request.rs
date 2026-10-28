//! Certificates the configuration asks to be issued automatically.

use std::net::IpAddr;

/// One certificate to issue: its names, and the DNS provider when DNS-01 must be used.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertRequest {
    /// Names on the certificate, lower-case, in order; the first one names the certificate.
    pub names: Vec<String>,
    /// DNS provider (a key of `acme.dns_providers`) for DNS-01.
    pub dns_provider: Option<String>,
}

/// Suffixes no public certificate authority issues for (RFC 2606, RFC 6761, RFC 6762,
/// RFC 8375, and `.internal` from ICANN's 2024 reservation). The local CA's name constraints
/// permit exactly these names and their subdomains.
pub const PRIVATE_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "home.arpa",
    "test",
    "example",
    "invalid",
];

/// Whether `host` is a name or address that public certificate authorities do not certify:
/// a reserved suffix, a single-label name, or a loopback, private or link-local address.
#[must_use]
pub fn is_private_name(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        };
    }
    let name = host.strip_prefix("*.").unwrap_or(host).to_ascii_lowercase();
    !name.contains('.') || has_private_suffix(&name)
}

/// Whether `host`, a name for which [`is_private_name`] holds, is one the local CA can certify.
/// Single-label names such as `nas` are not: name constraints cannot express them, so a root
/// permitting them would permit every single-label name, including top-level domains.
#[must_use]
pub fn is_local_ca_name(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if literal.parse::<IpAddr>().is_ok() {
        return is_private_name(literal);
    }
    has_private_suffix(&host.strip_prefix("*.").unwrap_or(host).to_ascii_lowercase())
}

fn has_private_suffix(name: &str) -> bool {
    PRIVATE_SUFFIXES
        .iter()
        .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::{is_local_ca_name, is_private_name};

    #[test]
    fn recognises_names_public_cas_refuse() {
        for private in [
            "localhost",
            "app.localhost",
            "nas",
            "printer.local",
            "db.internal",
            "router.home.arpa",
            "site.test",
            "www.example",
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "[::1]",
            "fd00::1",
        ] {
            assert!(is_private_name(private), "{private}");
        }
        for public in [
            "app.example.com",
            "example.org",
            "203.0.113.7",
            "2001:db8::1",
            "localhost.dev",
        ] {
            assert!(!is_private_name(public), "{public}");
            assert!(!is_local_ca_name(public), "{public}");
        }
    }

    #[test]
    fn the_local_ca_takes_every_private_name_but_single_labels() {
        for name in [
            "localhost",
            "app.localhost",
            "db.internal",
            "127.0.0.1",
            "[::1]",
        ] {
            assert!(is_local_ca_name(name), "{name}");
        }
        for name in ["nas", "printer", "*.nas"] {
            assert!(!is_local_ca_name(name), "{name}");
        }
    }
}
