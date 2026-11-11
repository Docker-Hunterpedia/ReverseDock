//! Host names: listener/route intersection, matching and the rule matchers that express them.
//!
//! Semantics (Gateway API v1.7.0, `HTTPRouteSpec.Hostnames`, `Listener.Hostname`): a host name
//! is exact (`foo.example.com`) or has one leading wildcard label (`*.example.com`), which is a
//! **suffix match over any number of labels**: `*.example.com` matches `foo.example.com` and
//! `foo.bar.example.com`, never `example.com`. A route without host names takes the
//! listener's; a listener without a host name takes the route's; when both have some, only
//! the route host names that intersect the listener's are served, and a route with none
//! left is not accepted on that listener (`NoMatchingListenerHostname`).
//!
//! The router's ``Host(`*.example.com`)`` covers one label only, so wildcards are written as
//! ``HostRegexp(`^.+\.example\.com$`)`` (and `HostSNIRegexp` for SNI).

use rdock_rules::Matcher;

/// The host names a route serves on one listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intersection {
    /// Every host (neither the listener nor the route names one).
    Any,
    /// Only these (lower case, sorted, unique).
    Hosts(Vec<String>),
    /// None: the route does not attach to the listener.
    Empty,
}

/// The intersection of a listener's host name with a route's host names.
#[must_use]
pub fn intersect(listener: Option<&str>, route: &[String]) -> Intersection {
    let listener = listener
        .filter(|l| !l.is_empty())
        .map(str::to_ascii_lowercase);
    let route: Vec<String> = route.iter().map(|h| h.to_ascii_lowercase()).collect();
    let mut hosts: Vec<String> = match (&listener, route.is_empty()) {
        (None, true) => return Intersection::Any,
        (None, false) => route,
        (Some(l), true) => vec![l.clone()],
        (Some(l), false) => route.iter().filter_map(|h| intersect_one(l, h)).collect(),
    };
    hosts.sort();
    hosts.dedup();
    if hosts.is_empty() {
        Intersection::Empty
    } else {
        Intersection::Hosts(hosts)
    }
}

/// The intersection of two host names (both lower case): the more specific one when one
/// covers the other, else `None`.
#[must_use]
pub fn intersect_one(listener: &str, route: &str) -> Option<String> {
    match (wildcard_base(listener), wildcard_base(route)) {
        (None, None) => (listener == route).then(|| listener.to_owned()),
        (None, Some(_)) => covers(route, listener).then(|| listener.to_owned()),
        (Some(_), None) => covers(listener, route).then(|| route.to_owned()),
        (Some(l), Some(r)) => {
            if r == l || r.ends_with(&format!(".{l}")) {
                Some(route.to_owned())
            } else if l.ends_with(&format!(".{r}")) {
                Some(listener.to_owned())
            } else {
                None
            }
        }
    }
}

/// `example.com` for `*.example.com`; `None` for an exact host name.
#[must_use]
pub fn wildcard_base(host: &str) -> Option<&str> {
    host.strip_prefix("*.")
}

/// Whether the host name pattern `pattern` (exact or wildcard) matches the concrete host
/// `host` (both lower case).
#[must_use]
pub fn covers(pattern: &str, host: &str) -> bool {
    match wildcard_base(pattern) {
        None => pattern == host,
        Some(base) => host
            .strip_suffix(base)
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty()),
    }
}

/// Precedence of a host name (`HTTPRouteSpec.Hostnames`): first the number of characters of
/// a matching non-wildcard host name, then the number of characters of the host name. Every
/// host (no host name) is `(0, 0)`.
#[must_use]
pub fn specificity(host: Option<&str>) -> (usize, usize) {
    match host {
        None => (0, 0),
        Some(h) if wildcard_base(h).is_some() => (0, h.len()),
        Some(h) => (h.len(), h.len()),
    }
}

/// The HTTP matcher for one host name.
#[must_use]
pub fn http_matcher(host: &str) -> Matcher {
    match wildcard_base(host) {
        None => Matcher::Host(host.to_owned()),
        Some(base) => Matcher::HostRegexp(format!("^.+\\.{}$", escape_regex(base))),
    }
}

/// The TCP (SNI) matcher for one host name.
#[must_use]
pub fn sni_matcher(host: &str) -> Matcher {
    match wildcard_base(host) {
        None => Matcher::HostSni(host.to_owned()),
        Some(base) => Matcher::HostSniRegexp(format!("^.+\\.{}$", escape_regex(base))),
    }
}

/// Escapes every regular-expression metacharacter of `value`.
#[must_use]
pub fn escape_regex(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 2);
    for c in value.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) || c.is_whitespace() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(list: &[&str]) -> Vec<String> {
        list.iter().map(|h| (*h).to_owned()).collect()
    }

    #[test]
    fn intersection_follows_the_specification_table() {
        // `HTTPRouteSpec.Hostnames`: a listener with `test.example.com` matches routes with
        // no host names, `test.example.com` or `*.example.com`.
        assert_eq!(
            intersect(Some("test.example.com"), &[]),
            Intersection::Hosts(hosts(&["test.example.com"]))
        );
        assert_eq!(
            intersect(Some("test.example.com"), &hosts(&["*.example.com"])),
            Intersection::Hosts(hosts(&["test.example.com"]))
        );
        assert_eq!(
            intersect(Some("test.example.com"), &hosts(&["other.example.com"])),
            Intersection::Empty
        );
        // A listener with `*.example.com` matches `*.example.com`, `test.example.com` and
        // `foo.test.example.com`, not `example.com` or `test.example.net`.
        assert_eq!(
            intersect(
                Some("*.example.com"),
                &hosts(&[
                    "*.example.com",
                    "test.example.com",
                    "foo.test.example.com",
                    "example.com",
                    "test.example.net"
                ])
            ),
            Intersection::Hosts(hosts(&[
                "*.example.com",
                "foo.test.example.com",
                "test.example.com"
            ]))
        );
        // Wildcard against wildcard: the more specific one.
        assert_eq!(
            intersect(Some("*.com"), &hosts(&["*.example.com"])),
            Intersection::Hosts(hosts(&["*.example.com"]))
        );
        assert_eq!(
            intersect(Some("*.example.com"), &hosts(&["*.com"])),
            Intersection::Hosts(hosts(&["*.example.com"]))
        );
        assert_eq!(
            intersect(Some("*.example.com"), &hosts(&["*.example.net"])),
            Intersection::Empty
        );
        // No listener host name.
        assert_eq!(intersect(None, &[]), Intersection::Any);
        assert_eq!(
            intersect(None, &hosts(&["B.example.com", "a.example.com"])),
            Intersection::Hosts(hosts(&["a.example.com", "b.example.com"]))
        );
        // `httproute-hostname-intersection`: `*.specific.com` on `very.specific.com`.
        assert_eq!(
            intersect(
                Some("very.specific.com"),
                &hosts(&["non.matching.com", "*.specific.com"])
            ),
            Intersection::Hosts(hosts(&["very.specific.com"]))
        );
        assert_eq!(
            intersect(Some("*.wildcard.io"), &hosts(&["wildcard.io"])),
            Intersection::Empty
        );
    }

    #[test]
    fn wildcards_cover_any_number_of_labels() {
        assert!(covers("*.example.com", "foo.example.com"));
        assert!(covers("*.example.com", "foo.bar.example.com"));
        assert!(!covers("*.example.com", "example.com"));
        assert!(!covers("*.example.com", "fooexample.com"));
        assert!(covers("a.example.com", "a.example.com"));
        assert!(!covers("a.example.com", "b.example.com"));
    }

    #[test]
    fn matchers_and_specificity() {
        assert_eq!(
            http_matcher("*.example.com").to_string(),
            r"HostRegexp(`^.+\.example\.com$`)"
        );
        assert_eq!(http_matcher("a.b").to_string(), "Host(`a.b`)");
        assert_eq!(
            sni_matcher("*.a-b.io").to_string(),
            r"HostSNIRegexp(`^.+\.a\-b\.io$`)"
        );
        assert!(specificity(Some("foo.bar.com")) > specificity(Some("*.bar.com")));
        assert!(specificity(Some("*.foo.bar.com")) > specificity(Some("*.bar.com")));
        assert!(specificity(Some("a.io")) > specificity(Some("*.very-long-name.io")));
        assert!(specificity(Some("*.io")) > specificity(None));
    }
}
