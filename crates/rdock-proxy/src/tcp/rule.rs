//! TCP route rules: `HostSNI`, `HostSNIRegexp`, `ALPN` and `ClientIP` from the shared rule
//! grammar, evaluated against what a connection shows before it is relayed.

use std::net::IpAddr;

use ipnet::IpNet;
use rdock_rules::{Expr, Matcher};
use rdock_tls::clienthello::ClientHello;
use regex::Regex;

use crate::router::{RuleCompileError, normalize_host, regex};

/// What a TCP rule looks at.
#[derive(Debug, Clone, Copy)]
pub struct TcpFacts<'a> {
    /// The ClientHello, `None` for a connection that does not start with TLS.
    pub hello: Option<&'a ClientHello>,
    /// The client (after the PROXY protocol step).
    pub client_ip: IpAddr,
    /// The JA4 of the ClientHello, computed only when a route uses `ClientFingerprint`.
    pub fingerprint: Option<&'a rdock_middleware::ClientFingerprint>,
}

impl<'a> TcpFacts<'a> {
    /// The server name, if the client sent one that is also a valid host for routing: the
    /// ClientHello parser already refuses IP literals and non-ASCII names; the router's host
    /// validation refuses the rest (wildcards, bad labels).
    fn sni(&self) -> Option<&'a str> {
        let sni = self.hello?.sni.as_deref()?;
        (!sni.contains('*') && rdock_rules::check_host(sni).is_ok()).then_some(sni)
    }
}

/// A compiled TCP rule.
#[derive(Debug, Clone)]
pub enum TcpRule {
    /// One matcher.
    Match(TcpMatcher),
    /// Negation.
    Not(Box<TcpRule>),
    /// All must match.
    All(Vec<TcpRule>),
    /// Any must match.
    Any(Vec<TcpRule>),
}

/// A compiled TCP matcher.
#[derive(Debug, Clone)]
pub enum TcpMatcher {
    /// ``HostSNI(`*`)``: any connection, with or without TLS and SNI.
    AnySni,
    /// ``HostSNI(`db.example.com`)``.
    Sni(String),
    /// ``HostSNI(`*.example.com`)``, stored as `.example.com`.
    SniWildcard(String),
    /// `HostSNIRegexp(..)`.
    SniRegexp(Regex),
    /// `ALPN(..)`: one of the protocols the client offers.
    Alpn(Vec<u8>),
    /// `ClientIP(..)`.
    ClientIp(IpNet),
    /// `ClientFingerprint(..)`.
    Fingerprint(Vec<String>),
    /// `ClientCountry`, `ClientContinent`, `ClientASN`.
    Geo(crate::router::GeoMatcher),
}

impl TcpRule {
    /// Compiles a parsed TCP rule.
    ///
    /// # Errors
    ///
    /// An HTTP matcher or a regular expression that does not compile; validation reports both
    /// first.
    pub fn compile(expr: &Expr) -> Result<Self, RuleCompileError> {
        Self::compile_with(expr, None)
    }

    /// Compiles a parsed TCP (or UDP) rule; GeoIP matchers look up in `geo`.
    ///
    /// # Errors
    ///
    /// As [`Self::compile`], and a GeoIP matcher without a database.
    pub fn compile_with(
        expr: &Expr,
        geo: Option<&std::sync::Arc<crate::geoip::GeoIp>>,
    ) -> Result<Self, RuleCompileError> {
        let each = |items: &[Expr]| {
            items
                .iter()
                .map(|e| Self::compile_with(e, geo))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(match expr {
            Expr::Matcher(m) => Self::Match(compile_matcher(m, geo)?),
            Expr::Not(inner) => Self::Not(Box::new(Self::compile_with(inner, geo)?)),
            Expr::And(items) => Self::All(each(items)?),
            Expr::Or(items) => Self::Any(each(items)?),
        })
    }

    /// Whether the connection matches.
    #[must_use]
    pub fn matches(&self, facts: &TcpFacts<'_>) -> bool {
        match self {
            Self::Match(m) => m.matches(facts),
            Self::Not(inner) => !inner.matches(facts),
            Self::All(items) => items.iter().all(|r| r.matches(facts)),
            Self::Any(items) => items.iter().any(|r| r.matches(facts)),
        }
    }
}

fn compile_matcher(
    m: &Matcher,
    geo: Option<&std::sync::Arc<crate::geoip::GeoIp>>,
) -> Result<TcpMatcher, RuleCompileError> {
    if let Some(geo) = crate::router::GeoMatcher::compile(m, geo)? {
        return Ok(TcpMatcher::Geo(geo));
    }
    Ok(match m {
        Matcher::ClientFingerprint(values) => TcpMatcher::Fingerprint(values.clone()),
        Matcher::HostSni(host) if host == "*" => TcpMatcher::AnySni,
        Matcher::HostSni(host) => match host.strip_prefix("*.") {
            Some(parent) => TcpMatcher::SniWildcard(format!(".{}", normalize_host(parent))),
            None => TcpMatcher::Sni(normalize_host(host)),
        },
        Matcher::HostSniRegexp(re) => TcpMatcher::SniRegexp(regex(re)?),
        Matcher::Alpn(protocol) => TcpMatcher::Alpn(protocol.as_bytes().to_vec()),
        Matcher::ClientIp(ip) => TcpMatcher::ClientIp(
            ip.parse::<IpNet>()
                .or_else(|_| ip.parse::<IpAddr>().map(IpNet::from))
                .map_err(|e| RuleCompileError(e.to_string()))?,
        ),
        other => {
            return Err(RuleCompileError(format!(
                "`{}` is an HTTP matcher",
                other.name()
            )));
        }
    })
}

impl TcpMatcher {
    fn matches(&self, facts: &TcpFacts<'_>) -> bool {
        match self {
            Self::AnySni => true,
            Self::Sni(name) => facts.sni() == Some(name.as_str()),
            Self::SniWildcard(suffix) => facts.sni().is_some_and(|sni| {
                sni.strip_suffix(suffix.as_str())
                    .is_some_and(|label| !label.is_empty() && !label.contains('.'))
            }),
            Self::SniRegexp(re) => facts.sni().is_some_and(|sni| re.is_match(sni)),
            Self::Alpn(protocol) => facts
                .hello
                .is_some_and(|hello| hello.alpn.iter().any(|offered| offered == protocol)),
            Self::ClientIp(net) => net.contains(&facts.client_ip),
            Self::Fingerprint(values) => facts
                .fingerprint
                .is_some_and(|fp| crate::router::fingerprint_in(fp, values)),
            Self::Geo(geo) => geo.matches(facts.client_ip),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn rule(text: &str) -> TcpRule {
        TcpRule::compile(&rdock_rules::parse(text).unwrap()).unwrap()
    }

    fn hello(sni: Option<&str>, alpn: &[&str]) -> ClientHello {
        ClientHello {
            sni: sni.map(str::to_owned),
            alpn: alpn.iter().map(|p| p.as_bytes().to_vec()).collect(),
        }
    }

    fn matches(text: &str, hello: Option<&ClientHello>, ip: &str) -> bool {
        rule(text).matches(&TcpFacts {
            hello,
            client_ip: ip.parse().unwrap(),
            fingerprint: None,
        })
    }

    #[test]
    fn host_sni_matches_exact_wildcard_and_any_names() {
        let db = hello(Some("db.example.com"), &[]);
        let deep = hello(Some("a.db.example.com"), &[]);
        let none = hello(None, &[]);
        assert!(matches("HostSNI(`db.example.com`)", Some(&db), "10.0.0.1"));
        assert!(matches("HostSNI(`DB.Example.com.`)", Some(&db), "10.0.0.1"));
        assert!(!matches(
            "HostSNI(`db.example.com`)",
            Some(&deep),
            "10.0.0.1"
        ));
        assert!(matches("HostSNI(`*.example.com`)", Some(&db), "10.0.0.1"));
        assert!(!matches(
            "HostSNI(`*.example.com`)",
            Some(&deep),
            "10.0.0.1"
        ));
        assert!(!matches(
            "HostSNI(`*.example.com`)",
            Some(&none),
            "10.0.0.1"
        ));
        // `*` matches every connection: TLS with or without SNI, and plain bytes.
        assert!(matches("HostSNI(`*`)", Some(&none), "10.0.0.1"));
        assert!(matches("HostSNI(`*`)", None, "10.0.0.1"));
        assert!(!matches("HostSNI(`db.example.com`)", None, "10.0.0.1"));
        assert!(matches("HostSNIRegexp(`^db\\.`)", Some(&db), "10.0.0.1"));
        assert!(!matches("HostSNIRegexp(`.*`)", Some(&none), "10.0.0.1"));
    }

    #[test]
    fn names_that_fail_host_validation_never_match() {
        for bad in [
            "*.example.com",
            "-db.example.com",
            "db..example.com",
            "db_.example.com:5432",
        ] {
            let h = hello(Some(bad), &[]);
            assert!(
                !matches("HostSNIRegexp(`.*`)", Some(&h), "10.0.0.1"),
                "{bad}"
            );
            assert!(matches("HostSNI(`*`)", Some(&h), "10.0.0.1"), "{bad}");
        }
    }

    #[test]
    fn client_fingerprint_matches_only_a_computed_value() {
        const JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
        let fp = rdock_middleware::ClientFingerprint {
            ja4: Some(std::sync::Arc::from(JA4)),
            ja3: None,
        };
        let r = rule(&format!(
            "ClientFingerprint(`{JA4}`, `ada70206e40642a3e4461f35503241d5`)"
        ));
        let facts = |fingerprint| TcpFacts {
            hello: None,
            client_ip: "10.0.0.1".parse().unwrap(),
            fingerprint,
        };
        assert!(r.matches(&facts(Some(&fp))));
        assert!(!r.matches(&facts(None)), "absent never matches");
        // Negation is plain boolean logic: a connection without a fingerprint is not in the list.
        let not = rule(&format!("!ClientFingerprint(`{JA4}`)"));
        assert!(not.matches(&facts(None)));
        assert!(!not.matches(&facts(Some(&fp))));
    }

    #[test]
    fn geo_matchers_need_a_database() {
        let expr = rdock_rules::parse("ClientCountry(`DE`)").unwrap();
        let err = TcpRule::compile(&expr).unwrap_err();
        assert!(err.to_string().contains("geoip.database"), "{err}");
    }

    #[test]
    fn alpn_and_client_ip_combine() {
        let pg = hello(Some("db.example.com"), &["postgresql"]);
        let rule_text = "HostSNI(`db.example.com`) && ALPN(`postgresql`) && ClientIP(`10.0.0.0/8`)";
        assert!(matches(rule_text, Some(&pg), "10.1.2.3"));
        assert!(!matches(rule_text, Some(&pg), "192.0.2.1"));
        let h2 = hello(Some("db.example.com"), &["h2"]);
        assert!(!matches(rule_text, Some(&h2), "10.1.2.3"));
        assert!(matches("!ALPN(`h2`)", Some(&pg), "10.1.2.3"));
        assert!(matches(
            "ClientIP(`2001:db8::/32`) || ALPN(`h2`)",
            None,
            "2001:db8::1"
        ));
    }

    #[test]
    fn http_matchers_do_not_compile() {
        let expr = rdock_rules::parse("Host(`a.com`)").unwrap();
        assert!(TcpRule::compile(&expr).is_err());
    }
}
