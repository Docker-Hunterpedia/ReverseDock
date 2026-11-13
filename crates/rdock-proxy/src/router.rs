//! Route matching: rules compiled from the Traefik v3 grammar, evaluated in priority order.

use std::collections::BTreeSet;
use std::net::IpAddr;

use http::{HeaderMap, HeaderName};
use ipnet::IpNet;
use rdock_rules::{Expr, Matcher};
use regex::{Regex, RegexBuilder};

/// Largest compiled size of a rule regular expression (the validator uses the same limit).
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// The parts of a request that rules look at.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// Host without port or trailing dot, lower case, IPv6 without brackets.
    pub host: &'a str,
    /// Decoded routing path (see [`rdock_rules::path`]).
    pub path: &'a str,
    /// Request method.
    pub method: &'a str,
    /// Request headers.
    pub headers: &'a HeaderMap,
    /// Decoded query parameters, in order.
    pub query: &'a [(String, String)],
    /// Resolved client IP.
    pub client_ip: IpAddr,
}

/// A compiled rule.
#[derive(Debug, Clone)]
pub enum Rule {
    /// One matcher.
    Match(Box<Compiled>),
    /// Negation.
    Not(Box<Rule>),
    /// All must match.
    All(Vec<Rule>),
    /// Any must match.
    Any(Vec<Rule>),
}

/// A compiled matcher.
#[derive(Debug, Clone)]
pub enum Compiled {
    /// `Host(*)`.
    AnyHost,
    /// `Host(example.com)`.
    Host(String),
    /// `Host(*.example.com)`, stored as `.example.com`.
    HostWildcard(String),
    /// `HostRegexp(..)`.
    HostRegexp(Regex),
    /// `Path(..)`.
    Path(String),
    /// `PathPrefix(..)`: a plain string prefix, like Traefik.
    PathPrefix(String),
    /// `PathRegexp(..)`.
    PathRegexp(Regex),
    /// `Method(..)`, upper case.
    Method(String),
    /// `Header(name, value)`: any value of the header equals `value`.
    Header(HeaderName, String),
    /// `HeaderRegexp(name, re)`: any value matches.
    HeaderRegexp(HeaderName, Regex),
    /// `Query(key, value)`; one argument means the empty value.
    Query(String, String),
    /// `QueryRegexp(key, re)`.
    QueryRegexp(String, Regex),
    /// `ClientIP(..)`.
    ClientIp(IpNet),
}

/// A matcher that cannot be compiled; validation reports these before compilation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RuleCompileError(pub String);

impl Rule {
    /// Compiles a parsed HTTP rule.
    pub fn compile(expr: &Expr) -> Result<Self, RuleCompileError> {
        Ok(match expr {
            Expr::Matcher(m) => Self::Match(Box::new(compile_matcher(m)?)),
            Expr::Not(inner) => Self::Not(Box::new(Self::compile(inner)?)),
            Expr::And(items) => {
                Self::All(items.iter().map(Self::compile).collect::<Result<_, _>>()?)
            }
            Expr::Or(items) => {
                Self::Any(items.iter().map(Self::compile).collect::<Result<_, _>>()?)
            }
        })
    }

    /// `None` when the request matches, else the first term that does not, in words.
    #[must_use]
    pub fn explain(&self, facts: &Facts<'_>) -> Option<String> {
        match self {
            Self::Match(m) => (!m.matches(facts)).then(|| m.mismatch(facts)),
            Self::Not(inner) => inner
                .matches(facts)
                .then(|| "a negated condition (`!`) matches this request".to_owned()),
            Self::All(items) => items.iter().find_map(|r| r.explain(facts)),
            Self::Any(items) => {
                let reasons: Vec<String> = items.iter().map_while(|r| r.explain(facts)).collect();
                (reasons.len() == items.len())
                    .then(|| format!("none of the alternatives match: {}", reasons.join("; ")))
            }
        }
    }

    /// Whether the request matches.
    #[must_use]
    pub fn matches(&self, facts: &Facts<'_>) -> bool {
        match self {
            Self::Match(m) => m.matches(facts),
            Self::Not(inner) => !inner.matches(facts),
            Self::All(items) => items.iter().all(|r| r.matches(facts)),
            Self::Any(items) => items.iter().any(|r| r.matches(facts)),
        }
    }
}

pub(crate) fn regex(pattern: &str) -> Result<Regex, RuleCompileError> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| RuleCompileError(e.to_string()))
}

fn header_name(name: &str) -> Result<HeaderName, RuleCompileError> {
    HeaderName::from_bytes(name.as_bytes()).map_err(|e| RuleCompileError(e.to_string()))
}

/// Lower-cases a host pattern and removes a trailing dot and IPv6 brackets.
#[must_use]
pub fn normalize_host(host: &str) -> String {
    let host = host.trim_end_matches('.');
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

fn compile_matcher(m: &Matcher) -> Result<Compiled, RuleCompileError> {
    Ok(match m {
        Matcher::Host(host) if host == "*" => Compiled::AnyHost,
        Matcher::Host(host) => match host.strip_prefix("*.") {
            Some(parent) => Compiled::HostWildcard(format!(".{}", normalize_host(parent))),
            None => Compiled::Host(normalize_host(host)),
        },
        Matcher::HostRegexp(re) => Compiled::HostRegexp(regex(re)?),
        Matcher::Path(p) => Compiled::Path(p.clone()),
        Matcher::PathPrefix(p) => Compiled::PathPrefix(p.clone()),
        Matcher::PathRegexp(re) => Compiled::PathRegexp(regex(re)?),
        Matcher::Method(method) => Compiled::Method(method.to_ascii_uppercase()),
        Matcher::Header { name, value } => Compiled::Header(header_name(name)?, value.clone()),
        Matcher::HeaderRegexp { name, regexp } => {
            Compiled::HeaderRegexp(header_name(name)?, regex(regexp)?)
        }
        Matcher::Query { key, value } => {
            Compiled::Query(key.clone(), value.clone().unwrap_or_default())
        }
        Matcher::QueryRegexp { key, regexp } => Compiled::QueryRegexp(key.clone(), regex(regexp)?),
        Matcher::ClientIp(ip) => Compiled::ClientIp(
            ip.parse::<IpNet>()
                .or_else(|_| ip.parse::<IpAddr>().map(IpNet::from))
                .map_err(|e| RuleCompileError(e.to_string()))?,
        ),
        Matcher::HostSni(_) | Matcher::HostSniRegexp(_) | Matcher::Alpn(_) => {
            return Err(RuleCompileError(format!("`{}` is a TCP matcher", m.name())));
        }
    })
}

impl Compiled {
    /// Why this matcher does not match `f`.
    fn mismatch(&self, f: &Facts<'_>) -> String {
        let header = |name: &HeaderName| {
            let values: Vec<&str> = f
                .headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            if values.is_empty() {
                "missing".to_owned()
            } else {
                format!("`{}`", values.join(", "))
            }
        };
        match self {
            Self::AnyHost => "never".to_owned(),
            Self::Host(host) => format!("Host(`{host}`): the host is `{}`", f.host),
            Self::HostWildcard(suffix) => format!("Host(`*{suffix}`): the host is `{}`", f.host),
            Self::HostRegexp(re) => format!("HostRegexp(`{re}`): the host is `{}`", f.host),
            Self::Path(p) => format!("Path(`{p}`): the path is `{}`", f.path),
            Self::PathPrefix(p) => format!("PathPrefix(`{p}`): the path is `{}`", f.path),
            Self::PathRegexp(re) => format!("PathRegexp(`{re}`): the path is `{}`", f.path),
            Self::Method(m) => format!("Method(`{m}`): the method is `{}`", f.method),
            Self::Header(name, value) => {
                format!("Header(`{name}`, `{value}`): it is {}", header(name))
            }
            Self::HeaderRegexp(name, re) => {
                format!("HeaderRegexp(`{name}`, `{re}`): it is {}", header(name))
            }
            Self::Query(key, value) => format!("Query(`{key}`, `{value}`): not in the query"),
            Self::QueryRegexp(key, re) => {
                format!("QueryRegexp(`{key}`, `{re}`): no matching value")
            }
            Self::ClientIp(net) => format!("ClientIP(`{net}`): the client is `{}`", f.client_ip),
        }
    }

    fn matches(&self, f: &Facts<'_>) -> bool {
        match self {
            Self::AnyHost => true,
            Self::Host(host) => f.host == host,
            Self::HostWildcard(suffix) => f
                .host
                .strip_suffix(suffix.as_str())
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            Self::HostRegexp(re) => re.is_match(f.host),
            Self::Path(p) => f.path == p,
            Self::PathPrefix(p) => f.path.starts_with(p.as_str()),
            Self::PathRegexp(re) => re.is_match(f.path),
            Self::Method(m) => f.method == m,
            Self::Header(name, value) => f
                .headers
                .get_all(name)
                .iter()
                .any(|v| v.as_bytes() == value.as_bytes()),
            Self::HeaderRegexp(name, re) => f
                .headers
                .get_all(name)
                .iter()
                .any(|v| v.to_str().is_ok_and(|v| re.is_match(v))),
            Self::Query(key, value) => f.query.iter().any(|(k, v)| k == key && v == value),
            Self::QueryRegexp(key, re) => f.query.iter().any(|(k, v)| k == key && re.is_match(v)),
            Self::ClientIp(net) => net.contains(&f.client_ip),
        }
    }
}

/// The hosts a compiled rule can match, as the route index sees them: a sound
/// over-approximation, so a rule outside a request's candidates can never match it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostKeys {
    /// The index cannot tell: no host condition, `HostRegexp`, a negation, `Host(*)`…
    Any,
    /// Only these exact hosts and one-label wildcards (suffixes such as `.example.com`).
    Some {
        exact: Vec<String>,
        wildcards: Vec<String>,
    },
}

impl HostKeys {
    fn of(rule: &Rule) -> Self {
        match rule {
            Rule::Match(m) => match m.as_ref() {
                Compiled::Host(host) => Self::Some {
                    exact: vec![host.clone()],
                    wildcards: Vec::new(),
                },
                Compiled::HostWildcard(suffix) => Self::Some {
                    exact: Vec::new(),
                    wildcards: vec![suffix.clone()],
                },
                _ => Self::Any,
            },
            Rule::Not(_) => Self::Any,
            // Every item must match, so any constrained item bounds the whole; keep the
            // smallest.
            Rule::All(items) => {
                items
                    .iter()
                    .map(Self::of)
                    .fold(Self::Any, |acc, next| match (acc, next) {
                        (Self::Any, other) | (other, Self::Any) => other,
                        (a, b) => {
                            if a.len() <= b.len() {
                                a
                            } else {
                                b
                            }
                        }
                    })
            }
            // One item must match: the union, unless an item is unconstrained.
            Rule::Any(items) => {
                let mut exact = Vec::new();
                let mut wildcards = Vec::new();
                for item in items {
                    match Self::of(item) {
                        Self::Any => return Self::Any,
                        Self::Some {
                            exact: e,
                            wildcards: w,
                        } => {
                            exact.extend(e);
                            wildcards.extend(w);
                        }
                    }
                }
                Self::Some { exact, wildcards }
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Any => usize::MAX,
            Self::Some { exact, wildcards } => exact.len() + wildcards.len(),
        }
    }
}

/// The routes of a listener by host, so a request is checked only against the routes that can
/// match its host (exact `Host` names, one-label `Host(*.…)` wildcards) and the routes the
/// index cannot decide (no host condition, `HostRegexp`, negations, `Host(*)`, an `||` with an
/// unconstrained side). Candidates come out in the listener's evaluation order, so the first
/// candidate that matches is the route a scan of every route would find.
#[derive(Debug, Default, Clone)]
pub struct RouteIndex {
    exact: std::collections::HashMap<Box<str>, Vec<usize>>,
    wildcards: std::collections::HashMap<Box<str>, Vec<usize>>,
    rest: Vec<usize>,
}

impl RouteIndex {
    /// Indexes rules given in evaluation order.
    #[must_use]
    pub fn build<'a>(rules: impl IntoIterator<Item = &'a Rule>) -> Self {
        let mut index = Self::default();
        for (position, rule) in rules.into_iter().enumerate() {
            match HostKeys::of(rule) {
                HostKeys::Any => index.rest.push(position),
                HostKeys::Some { exact, wildcards } => {
                    for host in exact {
                        push_unique(index.exact.entry(host.into()).or_default(), position);
                    }
                    for suffix in wildcards {
                        push_unique(index.wildcards.entry(suffix.into()).or_default(), position);
                    }
                }
            }
        }
        index
    }

    /// Positions of the rules that can match `host`, ascending. `host` is compared as the
    /// rules compare it (the normalised request host).
    pub fn candidates<'a>(&'a self, host: &str) -> impl Iterator<Item = usize> + 'a {
        let exact = self.exact.get(host).map_or(&[][..], Vec::as_slice);
        // `Host(*.example.com)` matches `<label>.example.com` with a non-empty label without
        // dots, so its suffix starts at the host's first dot.
        let wildcard = host
            .find('.')
            .filter(|&dot| dot > 0)
            .and_then(|dot| self.wildcards.get(&host[dot..]))
            .map_or(&[][..], Vec::as_slice);
        Merge {
            lists: [exact, wildcard, &self.rest],
        }
    }
}

/// Adds `position` unless it is already the last entry (a rule naming one host twice).
fn push_unique(list: &mut Vec<usize>, position: usize) {
    if list.last() != Some(&position) {
        list.push(position);
    }
}

/// Merges three ascending lists into one ascending sequence without allocating.
struct Merge<'a> {
    lists: [&'a [usize]; 3],
}

impl Iterator for Merge<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let value = self.lists.iter().filter_map(|l| l.first().copied()).min()?;
        // A position in two lists (an exact host and a wildcard of the same rule) comes out
        // once.
        for list in &mut self.lists {
            if let Some(rest) = list.strip_prefix(&[value]) {
                *list = rest;
            }
        }
        Some(value)
    }
}

/// The hosts a rule can match: a finite set, or any host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSet {
    /// Any host.
    Any,
    /// Only these hosts (normalised; wildcards as `*.example.com`).
    Some(BTreeSet<String>),
}

impl HostSet {
    /// A safe over-approximation of the hosts `expr` matches.
    #[must_use]
    pub fn of(expr: &Expr) -> Self {
        match expr {
            Expr::Matcher(Matcher::Host(h)) if h != "*" => {
                Self::Some(BTreeSet::from([normalize_host(h)]))
            }
            Expr::Matcher(_) | Expr::Not(_) => Self::Any,
            Expr::And(items) => items.iter().map(Self::of).fold(Self::Any, Self::intersect),
            Expr::Or(items) => items
                .iter()
                .map(Self::of)
                .fold(Self::Some(BTreeSet::new()), Self::union),
        }
    }

    fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::Any, s) | (s, Self::Any) => s,
            // Both finite: keep the smaller set; exact intersection would need wildcard logic and
            // an over-approximation is all callers need.
            (Self::Some(a), Self::Some(b)) => Self::Some(if a.len() <= b.len() { a } else { b }),
        }
    }

    fn union(self, other: Self) -> Self {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => Self::Any,
            (Self::Some(mut a), Self::Some(b)) => {
                a.extend(b);
                Self::Some(a)
            }
        }
    }

    /// Adds every host of `other`.
    pub fn extend(&mut self, other: Self) {
        let current = std::mem::replace(self, Self::Some(BTreeSet::new()));
        *self = current.union(other);
    }

    /// Whether `host` (normalised) is in the set.
    #[must_use]
    pub fn contains(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Some(hosts) => hosts.iter().any(|h| match h.strip_prefix("*.") {
                Some(parent) => host
                    .strip_suffix(parent)
                    .and_then(|label| label.strip_suffix('.'))
                    .is_some_and(|label| !label.is_empty() && !label.contains('.')),
                None => h == host,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(text: &str) -> Rule {
        Rule::compile(&rdock_rules::parse(text).unwrap()).unwrap()
    }

    struct Req {
        host: &'static str,
        path: &'static str,
        method: &'static str,
        headers: HeaderMap,
        query: Vec<(String, String)>,
        ip: IpAddr,
    }

    impl Req {
        fn new(host: &'static str, path: &'static str) -> Self {
            Self {
                host,
                path,
                method: "GET",
                headers: HeaderMap::new(),
                query: Vec::new(),
                ip: "192.0.2.1".parse().unwrap(),
            }
        }

        fn facts(&self) -> Facts<'_> {
            Facts {
                host: self.host,
                path: self.path,
                method: self.method,
                headers: &self.headers,
                query: &self.query,
                client_ip: self.ip,
            }
        }
    }

    #[test]
    fn hosts_are_case_insensitive_and_wildcards_cover_one_label() {
        assert!(
            rule("Host(`APP.example.com.`)").matches(&Req::new("app.example.com", "/").facts())
        );
        let wild = rule("Host(`*.example.com`)");
        assert!(wild.matches(&Req::new("a.example.com", "/").facts()));
        assert!(!wild.matches(&Req::new("a.b.example.com", "/").facts()));
        assert!(!wild.matches(&Req::new("example.com", "/").facts()));
        assert!(rule("Host(`*`)").matches(&Req::new("anything", "/").facts()));
        assert!(rule("Host(`[::1]`)").matches(&Req::new("::1", "/").facts()));
    }

    #[test]
    fn paths_follow_traefik() {
        let prefix = rule("PathPrefix(`/api`)");
        assert!(prefix.matches(&Req::new("h", "/api/v1").facts()));
        assert!(
            prefix.matches(&Req::new("h", "/apiv2").facts()),
            "plain string prefix"
        );
        assert!(!rule("Path(`/products`)").matches(&Req::new("h", "/products/").facts()));
        assert!(
            rule("PathRegexp(`v[0-9]+`)").matches(&Req::new("h", "/api/v2/x").facts()),
            "unanchored"
        );
    }

    #[test]
    fn methods_headers_queries_and_ips() {
        let mut req = Req::new("h", "/");
        req.method = "POST";
        req.headers.append("x-env", "test".parse().unwrap());
        req.headers.append("x-env", "prod".parse().unwrap());
        req.query = vec![("mobile".into(), String::new()), ("q".into(), "a".into())];
        let f = req.facts();
        assert!(rule("Method(`post`)").matches(&f));
        assert!(rule("Header(`X-Env`, `prod`)").matches(&f), "any value");
        assert!(rule("HeaderRegexp(`x-env`, `^pr`)").matches(&f));
        assert!(
            rule("Query(`mobile`)").matches(&f),
            "one argument = empty value"
        );
        assert!(!rule("Query(`q`)").matches(&f));
        assert!(rule("Query(`q`, `a`)").matches(&f));
        assert!(rule("QueryRegexp(`q`, `^a$`)").matches(&f));
        assert!(rule("ClientIP(`192.0.2.0/24`)").matches(&f));
        assert!(rule("ClientIP(`192.0.2.1`)").matches(&f));
        assert!(rule("!ClientIP(`10.0.0.0/8`) && (Method(`GET`) || Method(`POST`))").matches(&f));
    }

    /// A small deterministic generator (xorshift64*), so the differential test needs no
    /// extra dependency and every failure is reproducible from its seed.
    struct Gen(u64);

    impl Gen {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            items[usize::try_from(self.next() % items.len() as u64).unwrap()]
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    const HOSTS: [&str; 12] = [
        "a.test",
        "b.test",
        "A.Test",
        "x.a.test",
        "y.a.test",
        "a.b.a.test",
        "test",
        "b.test.",
        "[::1]",
        "127.0.0.1",
        "c.example.com",
        "",
    ];

    fn matcher(g: &mut Gen) -> String {
        match g.below(12) {
            0..=3 => format!("Host(`{}`)", g.pick(&HOSTS[..10])),
            4 | 5 => format!(
                "Host(`*.{}`)",
                g.pick(&["a.test", "test", "example.com", "b.a.test", "A.TEST"])
            ),
            6 => "Host(`*`)".to_owned(),
            7 => format!("HostRegexp(`{}`)", g.pick(&["^a", "test$", "^x\\.", "."])),
            8 => format!("PathPrefix(`{}`)", g.pick(&["/", "/api", "/a"])),
            9 => format!("Path(`{}`)", g.pick(&["/", "/api/v1"])),
            10 => format!("Method(`{}`)", g.pick(&["GET", "POST"])),
            _ => format!("Header(`x-env`, `{}`)", g.pick(&["prod", "test"])),
        }
    }

    fn expression(g: &mut Gen, depth: u32) -> String {
        if depth == 0 {
            return matcher(g);
        }
        match g.below(6) {
            0 | 1 => matcher(g),
            2 => format!("!({})", expression(g, depth - 1)),
            3 | 4 => format!(
                "({} && {})",
                expression(g, depth - 1),
                expression(g, depth - 1)
            ),
            _ => format!(
                "({} || {})",
                expression(g, depth - 1),
                expression(g, depth - 1)
            ),
        }
    }

    /// The index finds exactly the route a scan of every route finds, for random rule sets and
    /// requests, including hosts the proxy would have normalised first.
    #[test]
    fn route_index_matches_the_linear_scan() {
        let request_hosts = [
            "a.test",
            "b.test",
            "x.a.test",
            "y.a.test",
            "a.b.a.test",
            "q.b.a.test",
            "test",
            "z.test",
            "::1",
            "127.0.0.1",
            "c.example.com",
            "example.com",
            ".a.test",
            "A.TEST",
            "",
            "b.test.",
        ];
        let mut g = Gen(0x9E37_79B9_7F4A_7C15);
        let (mut checked, mut matched) = (0, 0);
        for _ in 0..400 {
            let count = 1 + g.below(40);
            let rules: Vec<Rule> = (0..count)
                .map(|_| {
                    let depth = u32::try_from(g.below(4)).unwrap();
                    rule(&expression(&mut g, depth))
                })
                .collect();
            let index = RouteIndex::build(&rules);
            for host in request_hosts {
                for path in ["/", "/api/v1", "/a/b"] {
                    for method in ["GET", "POST"] {
                        let mut req = Req::new(host, path);
                        req.method = method;
                        if g.below(2) == 0 {
                            req.headers.append("x-env", "prod".parse().unwrap());
                        }
                        let facts = req.facts();
                        let scanned = rules.iter().position(|r| r.matches(&facts));
                        let indexed = index.candidates(host).find(|&i| rules[i].matches(&facts));
                        assert_eq!(
                            indexed, scanned,
                            "host {host:?} path {path} rules {rules:?}"
                        );
                        checked += 1;
                        matched += usize::from(scanned.is_some_and(|i| i > 0));
                    }
                }
            }
        }
        assert!(checked > 10_000);
        assert!(
            matched > checked / 10,
            "{matched} of {checked} matched past the first rule"
        );
    }

    #[test]
    fn route_index_skips_routes_of_other_hosts() {
        let rules: Vec<Rule> = [
            "Host(`a.test`)",
            "Host(`*.a.test`) && PathPrefix(`/x`)",
            "PathPrefix(`/`)",
            "Host(`b.test`) || Host(`*.b.test`)",
            "Host(`a.test`) && Method(`POST`)",
            "!Host(`c.test`)",
        ]
        .iter()
        .map(|r| rule(r))
        .collect();
        let index = RouteIndex::build(&rules);
        assert_eq!(index.candidates("a.test").collect::<Vec<_>>(), [0, 2, 4, 5]);
        assert_eq!(index.candidates("q.a.test").collect::<Vec<_>>(), [1, 2, 5]);
        assert_eq!(index.candidates("x.b.test").collect::<Vec<_>>(), [2, 3, 5]);
        assert_eq!(index.candidates("b.test").collect::<Vec<_>>(), [2, 3, 5]);
        assert_eq!(index.candidates("other").collect::<Vec<_>>(), [2, 5]);
    }

    #[test]
    fn host_sets_over_approximate() {
        let set = |rule: &str| HostSet::of(&rdock_rules::parse(rule).unwrap());
        assert_eq!(
            set("Host(`a.test`) && PathPrefix(`/x`)"),
            HostSet::Some(BTreeSet::from(["a.test".to_owned()]))
        );
        assert_eq!(set("Host(`a.test`) || PathPrefix(`/x`)"), HostSet::Any);
        assert_eq!(set("!Host(`a.test`)"), HostSet::Any);
        let wild = set("Host(`*.example.com`) || Host(`b.test`)");
        assert!(wild.contains("x.example.com"));
        assert!(!wild.contains("x.y.example.com"));
        assert!(wild.contains("b.test"));
        assert!(!wild.contains("c.test"));
    }
}
