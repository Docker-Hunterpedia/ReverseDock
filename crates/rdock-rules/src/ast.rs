use std::fmt;

/// A parsed routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A single matcher, such as ``Host(`example.com`)``.
    Matcher(Matcher),
    /// Negation: `!expr`.
    Not(Box<Expr>),
    /// Two or more expressions that must all match: `a && b`.
    And(Vec<Expr>),
    /// Two or more expressions of which at least one must match: `a || b`.
    Or(Vec<Expr>),
}

/// A matcher and its arguments. Names and arity follow Traefik v3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    /// `Host(domain)`: exact host, `*.example.com` (one label) or `*`.
    Host(String),
    /// `HostRegexp(regexp)`.
    HostRegexp(String),
    /// `Path(path)`: exact path.
    Path(String),
    /// `PathPrefix(prefix)`.
    PathPrefix(String),
    /// `PathRegexp(regexp)`.
    PathRegexp(String),
    /// `Method(method)`.
    Method(String),
    /// `Header(name, value)`.
    Header {
        /// Header name.
        name: String,
        /// Exact header value.
        value: String,
    },
    /// `HeaderRegexp(name, regexp)`.
    HeaderRegexp {
        /// Header name.
        name: String,
        /// Regular expression for the header value.
        regexp: String,
    },
    /// `Query(key, value)`, or `Query(key)`, which matches the parameter with an empty value
    /// (`?key` or `?key=`) like Traefik.
    Query {
        /// Query parameter name.
        key: String,
        /// Exact value; `None` means the empty value.
        value: Option<String>,
    },
    /// `QueryRegexp(key, regexp)`.
    QueryRegexp {
        /// Query parameter name.
        key: String,
        /// Regular expression for the value.
        regexp: String,
    },
    /// `ClientIP(ip or CIDR)`.
    ClientIp(String),
    /// `HostSNI(domain)` (TCP): exact SNI, `*.example.com` or `*`.
    HostSni(String),
    /// `HostSNIRegexp(regexp)` (TCP).
    HostSniRegexp(String),
    /// `ALPN(protocol)` (TCP).
    Alpn(String),
    /// `ClientFingerprint(value, ...)`: the connection's JA4 (or JA3) equals one of the values.
    /// Never matches a connection without a fingerprint (H-SEC-03).
    ClientFingerprint(Vec<String>),
    /// `ClientCountry(code, ...)`: ISO 3166-1 alpha-2 codes. An address the GeoIP database
    /// does not know never matches (H-SEC-04).
    ClientCountry(Vec<String>),
    /// `ClientContinent(code, ...)`: `AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`.
    ClientContinent(Vec<String>),
    /// `ClientASN(number, ...)`: autonomous system numbers.
    ClientAsn(Vec<String>),
}

/// Most values a list matcher (`ClientCountry`, …) takes.
pub(crate) const MAX_LIST_ARGS: usize = 64;

/// Name, arity and constructor of a matcher; the parser's single source of truth.
pub(crate) struct Spec {
    pub(crate) name: &'static str,
    pub(crate) min_args: usize,
    pub(crate) max_args: usize,
    /// Builds the matcher from arguments whose count is within `min_args..=max_args`.
    pub(crate) build: fn(Args) -> Matcher,
}

/// Arguments of a matcher call, consumed in order.
pub(crate) struct Args(std::vec::IntoIter<String>);

impl Args {
    pub(crate) fn new(args: Vec<String>) -> Self {
        Self(args.into_iter())
    }

    /// The next argument; the arity check guarantees required ones exist.
    fn take(&mut self) -> String {
        self.0.next().unwrap_or_default()
    }

    fn take_optional(&mut self) -> Option<String> {
        self.0.next()
    }

    fn rest(self) -> Vec<String> {
        self.0.collect()
    }
}

pub(crate) const SPECS: &[Spec] = &[
    Spec {
        name: "Host",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::Host(a.take()),
    },
    Spec {
        name: "HostRegexp",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::HostRegexp(a.take()),
    },
    Spec {
        name: "Path",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::Path(a.take()),
    },
    Spec {
        name: "PathPrefix",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::PathPrefix(a.take()),
    },
    Spec {
        name: "PathRegexp",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::PathRegexp(a.take()),
    },
    Spec {
        name: "Method",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::Method(a.take()),
    },
    Spec {
        name: "Header",
        min_args: 2,
        max_args: 2,
        build: |mut a| Matcher::Header {
            name: a.take(),
            value: a.take(),
        },
    },
    Spec {
        name: "HeaderRegexp",
        min_args: 2,
        max_args: 2,
        build: |mut a| Matcher::HeaderRegexp {
            name: a.take(),
            regexp: a.take(),
        },
    },
    Spec {
        name: "Query",
        min_args: 1,
        max_args: 2,
        build: |mut a| Matcher::Query {
            key: a.take(),
            value: a.take_optional(),
        },
    },
    Spec {
        name: "QueryRegexp",
        min_args: 2,
        max_args: 2,
        build: |mut a| Matcher::QueryRegexp {
            key: a.take(),
            regexp: a.take(),
        },
    },
    Spec {
        name: "ClientIP",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::ClientIp(a.take()),
    },
    Spec {
        name: "HostSNI",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::HostSni(a.take()),
    },
    Spec {
        name: "HostSNIRegexp",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::HostSniRegexp(a.take()),
    },
    Spec {
        name: "ALPN",
        min_args: 1,
        max_args: 1,
        build: |mut a| Matcher::Alpn(a.take()),
    },
    Spec {
        name: "ClientFingerprint",
        min_args: 1,
        max_args: MAX_LIST_ARGS,
        build: |a| Matcher::ClientFingerprint(a.rest()),
    },
    Spec {
        name: "ClientCountry",
        min_args: 1,
        max_args: MAX_LIST_ARGS,
        build: |a| Matcher::ClientCountry(a.rest()),
    },
    Spec {
        name: "ClientContinent",
        min_args: 1,
        max_args: MAX_LIST_ARGS,
        build: |a| Matcher::ClientContinent(a.rest()),
    },
    Spec {
        name: "ClientASN",
        min_args: 1,
        max_args: MAX_LIST_ARGS,
        build: |a| Matcher::ClientAsn(a.rest()),
    },
];

impl Matcher {
    /// The matcher's name as written in a rule, e.g. `"PathPrefix"`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Host(_) => "Host",
            Self::HostRegexp(_) => "HostRegexp",
            Self::Path(_) => "Path",
            Self::PathPrefix(_) => "PathPrefix",
            Self::PathRegexp(_) => "PathRegexp",
            Self::Method(_) => "Method",
            Self::Header { .. } => "Header",
            Self::HeaderRegexp { .. } => "HeaderRegexp",
            Self::Query { .. } => "Query",
            Self::QueryRegexp { .. } => "QueryRegexp",
            Self::ClientIp(_) => "ClientIP",
            Self::HostSni(_) => "HostSNI",
            Self::HostSniRegexp(_) => "HostSNIRegexp",
            Self::Alpn(_) => "ALPN",
            Self::ClientFingerprint(_) => "ClientFingerprint",
            Self::ClientCountry(_) => "ClientCountry",
            Self::ClientContinent(_) => "ClientContinent",
            Self::ClientAsn(_) => "ClientASN",
        }
    }

    /// The matcher's arguments in source order.
    #[must_use]
    pub fn args(&self) -> Vec<&str> {
        match self {
            Self::Host(a)
            | Self::HostRegexp(a)
            | Self::Path(a)
            | Self::PathPrefix(a)
            | Self::PathRegexp(a)
            | Self::Method(a)
            | Self::ClientIp(a)
            | Self::HostSni(a)
            | Self::HostSniRegexp(a)
            | Self::Alpn(a) => vec![a],
            Self::Header { name, value } => vec![name, value],
            Self::HeaderRegexp { name, regexp } => vec![name, regexp],
            Self::Query { key, value } => {
                let mut args = vec![key.as_str()];
                args.extend(value.as_deref());
                args
            }
            Self::QueryRegexp { key, regexp } => vec![key, regexp],
            Self::ClientFingerprint(list)
            | Self::ClientCountry(list)
            | Self::ClientContinent(list)
            | Self::ClientAsn(list) => list.iter().map(String::as_str).collect(),
        }
    }

    /// Whether the matcher needs the GeoIP database (`geoip`).
    #[must_use]
    pub fn needs_geoip(&self) -> bool {
        matches!(
            self,
            Self::ClientCountry(_) | Self::ClientContinent(_) | Self::ClientAsn(_)
        )
    }

    /// Whether the matcher can be used in an HTTP route.
    #[must_use]
    pub fn is_http(&self) -> bool {
        !matches!(
            self,
            Self::HostSni(_) | Self::HostSniRegexp(_) | Self::Alpn(_)
        )
    }

    /// Whether the matcher can be used in a TCP route.
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        matches!(
            self,
            Self::HostSni(_)
                | Self::HostSniRegexp(_)
                | Self::Alpn(_)
                | Self::ClientIp(_)
                | Self::ClientFingerprint(_)
                | Self::ClientCountry(_)
                | Self::ClientContinent(_)
                | Self::ClientAsn(_)
        )
    }
}

impl Expr {
    /// All matchers in the expression, depth first.
    #[must_use]
    pub fn matchers(&self) -> Vec<&Matcher> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect<'a>(&'a self, out: &mut Vec<&'a Matcher>) {
        match self {
            Self::Matcher(m) => out.push(m),
            Self::Not(inner) => inner.collect(out),
            Self::And(items) | Self::Or(items) => items.iter().for_each(|e| e.collect(out)),
        }
    }

    /// Whether a ``HostSNI(`*`)`` matcher appears without negation: the only way a TCP rule
    /// can match a connection that does not start with TLS.
    #[must_use]
    pub fn has_any_sni(&self) -> bool {
        self.any_positive(
            &|m| matches!(m, Matcher::HostSni(host) if host == "*"),
            false,
        )
    }

    /// Whether the rule looks at the TLS ClientHello: `HostSNI` with a name, `HostSNIRegexp`
    /// or `ALPN`.
    #[must_use]
    pub fn reads_client_hello(&self) -> bool {
        self.matchers().into_iter().any(|m| match m {
            Matcher::HostSni(host) => host != "*",
            Matcher::HostSniRegexp(_) | Matcher::Alpn(_) => true,
            _ => false,
        })
    }

    /// Whether a `ClientFingerprint` matcher appears anywhere in the rule.
    #[must_use]
    pub fn uses_fingerprint(&self) -> bool {
        self.matchers()
            .into_iter()
            .any(|m| matches!(m, Matcher::ClientFingerprint(_)))
    }

    /// Whether the rule needs the GeoIP database.
    #[must_use]
    pub fn uses_geoip(&self) -> bool {
        self.matchers().into_iter().any(Matcher::needs_geoip)
    }

    fn any_positive(&self, test: &dyn Fn(&Matcher) -> bool, negated: bool) -> bool {
        match self {
            Self::Matcher(m) => !negated && test(m),
            Self::Not(inner) => inner.any_positive(test, !negated),
            Self::And(items) | Self::Or(items) => {
                items.iter().any(|item| item.any_positive(test, negated))
            }
        }
    }

    /// Host values of `Host` matchers that are not negated. These are the names eligible for
    /// automatic certificates.
    #[must_use]
    pub fn positive_hosts(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.collect_hosts(&|m| matches!(m, Matcher::Host(_)), false, &mut out);
        out
    }

    /// Host values of `HostSNI` matchers that are not negated: the names a TCP route that
    /// terminates TLS needs certificates for.
    #[must_use]
    pub fn positive_sni_hosts(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.collect_hosts(&|m| matches!(m, Matcher::HostSni(_)), false, &mut out);
        out
    }

    fn collect_hosts<'a>(
        &'a self,
        wanted: &dyn Fn(&Matcher) -> bool,
        negated: bool,
        out: &mut Vec<&'a str>,
    ) {
        match self {
            Self::Matcher(m @ (Matcher::Host(host) | Matcher::HostSni(host)))
                if !negated && wanted(m) =>
            {
                out.push(host);
            }
            Self::Matcher(_) => {}
            Self::Not(inner) => inner.collect_hosts(wanted, !negated, out),
            Self::And(items) | Self::Or(items) => {
                for item in items {
                    item.collect_hosts(wanted, negated, out);
                }
            }
        }
    }

    fn is_composite(&self) -> bool {
        matches!(self, Self::And(_) | Self::Or(_))
    }
}

impl fmt::Display for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.name())?;
        for (i, arg) in self.args().into_iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write_quoted(f, arg)?;
        }
        f.write_str(")")
    }
}

/// Writes a string as a backtick literal, or as an escaped double-quoted literal when it
/// contains a backtick.
fn write_quoted(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    if !value.contains('`') {
        return write!(f, "`{value}`");
    }
    f.write_str("\"")?;
    for c in value.chars() {
        match c {
            '\\' => f.write_str("\\\\")?,
            '"' => f.write_str("\\\"")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c => write!(f, "{c}")?,
        }
    }
    f.write_str("\"")
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Matcher(m) => m.fmt(f),
            Self::Not(inner) if inner.is_composite() => write!(f, "!({inner})"),
            Self::Not(inner) => write!(f, "!{inner}"),
            Self::And(items) => write_joined(f, items, " && "),
            Self::Or(items) => write_joined(f, items, " || "),
        }
    }
}

/// Joins operands, wrapping composite operands in parentheses so the output parses back to
/// the same tree.
fn write_joined(f: &mut fmt::Formatter<'_>, items: &[Expr], separator: &str) -> fmt::Result {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            f.write_str(separator)?;
        }
        if item.is_composite() {
            write!(f, "({item})")?;
        } else {
            write!(f, "{item}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::parse;

    #[test]
    fn finds_positive_sni_matchers() {
        let expr =
            parse("HostSNI(`db.example.com`) || (HostSNI(`*`) && !HostSNI(`x.example.com`))")
                .unwrap();
        assert_eq!(expr.positive_sni_hosts(), ["db.example.com", "*"]);
        assert!(expr.has_any_sni());
        assert!(expr.reads_client_hello());
        assert!(!parse("!HostSNI(`*`)").unwrap().has_any_sni());
        let plain = parse("HostSNI(`*`) && ClientIP(`10.0.0.0/8`)").unwrap();
        assert!(plain.has_any_sni());
        assert!(!plain.reads_client_hello());
        assert!(parse("ALPN(`postgresql`)").unwrap().reads_client_hello());
        assert_eq!(
            parse("Host(`a.com`)").unwrap().positive_sni_hosts(),
            Vec::<&str>::new()
        );
    }
}
