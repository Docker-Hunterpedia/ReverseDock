use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;
use regex::RegexBuilder;

use crate::ast::{Expr, Matcher};

/// Largest compiled size accepted for a regular expression in a rule.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Where a rule is used, which decides the matchers it may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// An HTTP route.
    Http,
    /// A TCP route.
    Tcp,
    /// A UDP route: a datagram shows only its source, so `ClientIP` is the only matcher.
    Udp,
}

/// A problem with one matcher of a parsed rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{matcher}: {message}")]
pub struct RuleError {
    /// The matcher, printed in canonical form.
    pub matcher: String,
    /// What is wrong with it.
    pub message: String,
}

impl Expr {
    /// Checks every matcher for use in `context`: the matcher fits the route type, regular
    /// expressions compile, paths start with `/`, hosts and IP ranges are well formed.
    #[must_use]
    pub fn validate(&self, context: Context) -> Vec<RuleError> {
        self.matchers()
            .into_iter()
            .filter_map(|m| {
                check(m, context).err().map(|message| RuleError {
                    matcher: m.to_string(),
                    message,
                })
            })
            .collect()
    }
}

fn check(matcher: &Matcher, context: Context) -> Result<(), String> {
    match context {
        Context::Http if !matcher.is_http() => {
            return Err(format!(
                "`{}` is a TCP matcher; HTTP routes use Host, Path, Header, Query, Method or ClientIP",
                matcher.name()
            ));
        }
        Context::Tcp if !matcher.is_tcp() => {
            return Err(format!(
                "`{}` is an HTTP matcher; TCP routes accept HostSNI, HostSNIRegexp, ClientIP, ALPN, ClientFingerprint, ClientCountry, ClientContinent and ClientASN",
                matcher.name()
            ));
        }
        Context::Udp if !matches!(matcher, Matcher::ClientIp(_)) && !matcher.needs_geoip() => {
            return Err(format!(
                "`{}` cannot match a datagram; UDP routes accept ClientIP, ClientCountry, ClientContinent and ClientASN only",
                matcher.name()
            ));
        }
        _ => {}
    }
    match matcher {
        Matcher::Host(host) | Matcher::HostSni(host) => check_host(host),
        Matcher::HostRegexp(re) | Matcher::PathRegexp(re) | Matcher::HostSniRegexp(re) => {
            check_regex(re)
        }
        Matcher::Path(path) | Matcher::PathPrefix(path) => check_path(path),
        Matcher::Method(method) => check_method(method),
        Matcher::Header { name, .. } => check_token(name, "header name"),
        Matcher::HeaderRegexp { name, regexp } => {
            check_token(name, "header name")?;
            check_regex(regexp)
        }
        Matcher::Query { key, .. } => check_not_empty(key, "query parameter name"),
        Matcher::QueryRegexp { key, regexp } => {
            check_not_empty(key, "query parameter name")?;
            check_regex(regexp)
        }
        Matcher::ClientIp(ip) => check_ip(ip),
        Matcher::Alpn(protocol) => check_alpn(protocol),
        Matcher::ClientFingerprint(values) => values.iter().try_for_each(|v| check_fingerprint(v)),
        Matcher::ClientCountry(codes) => codes.iter().try_for_each(|c| check_country(c)),
        Matcher::ClientContinent(codes) => codes.iter().try_for_each(|c| check_continent(c)),
        Matcher::ClientAsn(numbers) => numbers.iter().try_for_each(|n| check_asn(n)),
    }
}

/// A JA4 (`t13d1516h2_8daaf6152771_e5627efa2ab1`) or a JA3 (32 hex digits) value.
fn check_fingerprint(value: &str) -> Result<(), String> {
    if is_ja4(value) || (value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())) {
        Ok(())
    } else {
        Err(format!(
            "`{value}` is not a JA4 fingerprint (like `t13d1516h2_8daaf6152771_e5627efa2ab1`) or a JA3 hash (32 hex digits)"
        ))
    }
}

fn is_ja4(value: &str) -> bool {
    let mut parts = value.split('_');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let hex12 =
        |s: &str| s.len() == 12 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    a.len() == 10
        && a.is_ascii()
        && matches!(a.as_bytes().first(), Some(b't' | b'q' | b'd'))
        && matches!(a.as_bytes().get(3), Some(b'd' | b'i'))
        && a.get(4..8)
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        && a.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && hex12(b)
        && hex12(c)
}

fn check_country(code: &str) -> Result<(), String> {
    if code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(format!(
            "`{code}` is not an ISO 3166-1 alpha-2 country code in upper case (like `DE`)"
        ))
    }
}

/// The continent codes of GeoIP2 databases.
pub const CONTINENTS: [&str; 7] = ["AF", "AN", "AS", "EU", "NA", "OC", "SA"];

fn check_continent(code: &str) -> Result<(), String> {
    if CONTINENTS.contains(&code) {
        Ok(())
    } else {
        Err(format!(
            "`{code}` is not a continent code; use one of {}",
            CONTINENTS.join(", ")
        ))
    }
}

fn check_asn(number: &str) -> Result<(), String> {
    match number.parse::<u32>() {
        Ok(_) if !number.starts_with('+') => Ok(()),
        _ => Err(format!(
            "`{number}` is not an autonomous system number (digits only, like `64496`)"
        )),
    }
}

fn check_not_empty(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{what} must not be empty"))
    } else {
        Ok(())
    }
}

/// Checks a host as used by `Host` and `HostSNI`: `*`, `*.example.com` (one wildcard label),
/// DNS names (a trailing dot is allowed), IPv4 literals and IPv6 literals with or without
/// brackets. Underscores are allowed because container names use them. Returns a message
/// explaining the problem.
pub fn check_host(host: &str) -> Result<(), String> {
    if host == "*" {
        return Ok(());
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| format!("`{host}` is not a valid IPv6 literal"));
    }
    if host.parse::<Ipv6Addr>().is_ok() {
        return Ok(());
    }
    if !host.is_ascii() {
        return Err("non-ASCII hosts must be written in punycode (`xn--…`)".to_owned());
    }
    if host.contains(':') {
        return Err("a host must not include a port; routing ignores the port".to_owned());
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    let name = host.strip_prefix("*.").unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return Err(format!("`{host}` is not a valid host name"));
    }
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !valid {
            return Err(format!(
                "`{host}` is not a valid host name (label `{label}`)"
            ));
        }
    }
    Ok(())
}

fn check_regex(pattern: &str) -> Result<(), String> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map(|_| ())
        .map_err(|e| format!("invalid regular expression: {}", last_line(&e.to_string())))
}

/// The regex crate puts the actual error on the last non-empty line of its message.
fn last_line(text: &str) -> String {
    text.lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or(text)
        .trim()
        .to_owned()
}

fn check_path(path: &str) -> Result<(), String> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(format!("paths must start with `/` (write `/{path}`)"))
    }
}

/// RFC 9110 token characters.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

fn check_token(value: &str, what: &str) -> Result<(), String> {
    if !value.is_empty() && value.chars().all(is_tchar) {
        Ok(())
    } else {
        Err(format!("`{value}` is not a valid {what}"))
    }
}

/// Methods are compared in upper case, like Traefik, so `Method(`get`)` matches `GET`.
fn check_method(method: &str) -> Result<(), String> {
    check_token(method, "HTTP method")
}

fn check_ip(value: &str) -> Result<(), String> {
    if value.parse::<IpAddr>().is_ok() || value.parse::<IpNet>().is_ok() {
        Ok(())
    } else {
        Err(format!("`{value}` is not an IP address or CIDR range"))
    }
}

fn check_alpn(protocol: &str) -> Result<(), String> {
    check_not_empty(protocol, "ALPN protocol")?;
    if protocol.len() > 255 {
        return Err("ALPN protocol names are at most 255 bytes".to_owned());
    }
    if protocol.eq_ignore_ascii_case("acme-tls/1") {
        return Err("`acme-tls/1` is reserved for ACME TLS-ALPN-01 challenges".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Context::{Http, Tcp, Udp};
    use crate::parse;

    fn messages(rule: &str, context: super::Context) -> Vec<String> {
        parse(rule)
            .unwrap()
            .validate(context)
            .into_iter()
            .map(|e| e.message)
            .collect()
    }

    #[test]
    fn accepts_valid_rules() {
        for rule in [
            "Host(`example.com`) && PathPrefix(`/api`)",
            "Host(`*.example.com`) || Host(`*`) || Host(`10.0.0.1`) || Host(`[::1]`) || Host(`::1`)",
            "Host(`example.com.`) || Host(`my_app`) && Method(`PATCH`) && Header(`X-Api-Key`, `abc`)",
            "Method(`get`)",
            "HostRegexp(`^[a-z0-9-]+\\.tenants\\.example\\.com$`) && ClientIP(`2001:db8::/32`)",
            "Query(`debug`) && QueryRegexp(`id`, `^[0-9]+$`)",
        ] {
            assert_eq!(messages(rule, Http), Vec::<String>::new(), "{rule}");
        }
        assert_eq!(
            messages("HostSNI(`db.example.com`) && ALPN(`postgresql`)", Tcp),
            Vec::<String>::new()
        );
    }

    #[test]
    fn rejects_matchers_from_the_wrong_context() {
        assert!(messages("HostSNI(`a.com`)", Http)[0].contains("TCP matcher"));
        assert!(messages("Host(`a.com`)", Tcp)[0].contains("HTTP matcher"));
        assert_eq!(
            messages("ClientIP(`10.0.0.0/8`)", Tcp),
            Vec::<String>::new()
        );
    }

    #[test]
    fn udp_rules_accept_client_ip_only() {
        assert_eq!(
            messages("ClientIP(`10.0.0.0/8`) && !ClientIP(`10.1.0.0/16`)", Udp),
            Vec::<String>::new()
        );
        assert!(messages("HostSNI(`*`)", Udp)[0].contains("UDP routes accept ClientIP"));
        assert!(messages("Host(`a.com`)", Udp)[0].contains("UDP routes accept ClientIP"));
        assert!(messages("ClientIP(`10.0.0.0/33`)", Udp)[0].contains("CIDR"));
    }

    #[test]
    fn explains_bad_values() {
        assert!(messages("Path(`api`)", Http)[0].contains("start with `/`"));
        assert!(messages("Host(`a.com:443`)", Http)[0].contains("port"));
        assert!(messages("Host(`bücher.de`)", Http)[0].contains("punycode"));
        assert!(messages("Host(`-bad.com`)", Http)[0].contains("not a valid host"));
        assert!(messages("Method(`GET /`)", Http)[0].contains("not a valid HTTP method"));
        assert!(messages("ClientIP(`10.0.0.0/33`)", Http)[0].contains("CIDR"));
        assert!(
            messages("PathRegexp(`(unclosed`)", Http)[0].contains("invalid regular expression")
        );
        assert!(messages("HeaderRegexp(`bad header`, `x`)", Http)[0].contains("header name"));
        assert!(messages("ALPN(`acme-tls/1`)", Tcp)[0].contains("reserved"));
    }

    #[test]
    fn checks_fingerprint_and_geo_values() {
        for rule in [
            "ClientFingerprint(`t13d1516h2_8daaf6152771_e5627efa2ab1`, `ada70206e40642a3e4461f35503241d5`)",
            "ClientCountry(`DE`, `FR`) && ClientContinent(`EU`) || ClientASN(`64496`, `65551`)",
        ] {
            assert_eq!(messages(rule, Http), Vec::<String>::new(), "{rule}");
            assert_eq!(messages(rule, Tcp), Vec::<String>::new(), "{rule}");
        }
        assert_eq!(messages("ClientCountry(`DE`)", Udp), Vec::<String>::new());
        assert!(messages("ClientFingerprint(`x`)", Udp)[0].contains("datagram"));
        assert!(messages("ClientFingerprint(`t13d`)", Http)[0].contains("JA4"));
        assert!(messages("ClientCountry(`de`)", Http)[0].contains("upper case"));
        assert!(messages("ClientCountry(`DEU`)", Http)[0].contains("alpha-2"));
        assert!(messages("ClientContinent(`XX`)", Http)[0].contains("continent"));
        assert!(messages("ClientASN(`AS64496`)", Http)[0].contains("autonomous"));
        assert!(messages("ClientASN(`4294967296`)", Http)[0].contains("autonomous"));
    }

    #[test]
    fn reports_every_bad_matcher() {
        let errors = parse("Path(`a`) && Method(`G T`)").unwrap().validate(Http);
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].matcher, "Path(`a`)");
    }
}
