//! Route priorities that encode the Gateway API's precedence.
//!
//! The router evaluates routes by `priority` (highest first), then by name, and uses the rule
//! length only when the priority is 0, so every generated route carries an explicit, non-zero
//! priority built from these fields, most significant first (Gateway API v1.7.0,
//! `HTTPRouteSpec.Hostnames` and `HTTPRouteRule.Matches`):
//!
//! | bits   | field | order |
//! |--------|-------|-------|
//! | 53–60  | characters of a matching non-wildcard host name (0 for a wildcard or none) | more first |
//! | 45–52  | characters of the matching host name | more first |
//! | 43–44  | path match kind: `Exact` 3, `RegularExpression` 2, `PathPrefix` 1 | higher first |
//! | 32–42  | characters of the path value | more first |
//! | 31     | a method match | with first |
//! | 26–30  | number of header matches | more first |
//! | 21–25  | number of query parameter matches | more first |
//! | 5–20   | the route's rank: older `creationTimestamp` first, then `{namespace}/{name}` | older first |
//! | 0–4    | rule index within the route | earlier first |
//!
//! Each field is clamped to its width (host names up to 255 characters, paths up to 2047,
//! 31 headers or query parameters, 65 535 routes, 31 rules); the specification limits paths
//! to 1024 characters, headers and query parameters to 16 per match and rules to 16 per
//! route, so only the route rank can saturate, after which routes tie and fall back to their
//! names. The precedence of `RegularExpression` paths is implementation-specific: they rank
//! after `Exact` and before every `PathPrefix`. The total stays below 2⁶¹, so priorities are
//! positive. GRPCRoute uses the same layout: an exact service and method counts as an exact
//! path of `service` + `method` characters, a service alone as a prefix, a method alone or a
//! regular expression as a regular expression.

/// The kind of path match, in precedence order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathKind {
    /// `PathPrefix`.
    Prefix = 1,
    /// `RegularExpression`.
    Regex = 2,
    /// `Exact`.
    Exact = 3,
}

/// The fields of a priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Precedence {
    /// [`super::hostnames::specificity`] of the route's host name.
    pub host: (usize, usize),
    /// Path match kind.
    pub path_kind: PathKind,
    /// Characters of the path value.
    pub path_len: usize,
    /// Whether the match has a method.
    pub method: bool,
    /// Number of header matches.
    pub headers: usize,
    /// Number of query parameter matches.
    pub query: usize,
    /// The route's rank among all routes (0 = oldest).
    pub route_rank: usize,
    /// The rule's index in the route.
    pub rule: usize,
}

fn clamp(value: usize, bits: u32) -> i64 {
    let max = (1_i64 << bits) - 1;
    i64::try_from(value).map_or(max, |v| v.min(max))
}

impl Precedence {
    /// The priority.
    #[must_use]
    pub fn priority(&self) -> i64 {
        let rank = (1_i64 << 16) - 1 - clamp(self.route_rank, 16);
        let rule = 31 - clamp(self.rule, 5);
        (clamp(self.host.0, 8) << 53)
            | (clamp(self.host.1, 8) << 45)
            | ((self.path_kind as i64) << 43)
            | (clamp(self.path_len, 11) << 32)
            | (i64::from(self.method) << 31)
            | (clamp(self.headers, 5) << 26)
            | (clamp(self.query, 5) << 21)
            | (rank << 5)
            | rule
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Precedence {
        Precedence {
            host: (0, 0),
            path_kind: PathKind::Prefix,
            path_len: 1,
            method: false,
            headers: 0,
            query: 0,
            route_rank: 0,
            rule: 0,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_order_of_the_specification() {
        // From most to least preferred; each differs from the next only in the field that
        // decides, and the less preferred one wins every later field.
        let chain = [
            Precedence {
                host: (11, 11),
                ..base()
            },
            Precedence {
                host: (9, 9),
                path_kind: PathKind::Exact,
                path_len: 100,
                method: true,
                headers: 16,
                query: 16,
                route_rank: 0,
                rule: 0,
            },
            Precedence {
                host: (0, 13),
                ..base()
            },
            Precedence {
                host: (0, 9),
                path_kind: PathKind::Exact,
                path_len: 100,
                method: true,
                headers: 16,
                query: 16,
                ..base()
            },
            Precedence {
                path_kind: PathKind::Exact,
                path_len: 2,
                route_rank: 9,
                rule: 9,
                ..base()
            },
            Precedence {
                path_kind: PathKind::Regex,
                path_len: 50,
                ..base()
            },
            Precedence {
                path_len: 10,
                route_rank: 9,
                rule: 9,
                ..base()
            },
            Precedence {
                path_len: 9,
                method: true,
                route_rank: 9,
                rule: 9,
                ..base()
            },
            Precedence {
                path_len: 9,
                headers: 16,
                query: 16,
                route_rank: 9,
                rule: 9,
                ..base()
            },
            Precedence {
                path_len: 9,
                headers: 15,
                query: 16,
                ..base()
            },
            Precedence {
                path_len: 9,
                headers: 15,
                query: 15,
                route_rank: 9,
                rule: 9,
                ..base()
            },
            Precedence {
                path_len: 9,
                headers: 15,
                query: 14,
                route_rank: 8,
                rule: 9,
                ..base()
            },
            Precedence {
                path_len: 9,
                headers: 15,
                query: 14,
                route_rank: 9,
                rule: 0,
                ..base()
            },
            Precedence {
                path_len: 9,
                headers: 15,
                query: 14,
                route_rank: 9,
                rule: 1,
                ..base()
            },
        ];
        for pair in chain.windows(2) {
            assert!(
                pair[0].priority() > pair[1].priority(),
                "{:?} should beat {:?}",
                pair[0],
                pair[1]
            );
        }
        for p in &chain {
            assert!(p.priority() > 0);
        }
    }

    #[test]
    fn extremes_stay_positive_and_saturate() {
        let max = Precedence {
            host: (10_000, 10_000),
            path_kind: PathKind::Exact,
            path_len: 1 << 20,
            method: true,
            headers: 1000,
            query: 1000,
            route_rank: 0,
            rule: 0,
        };
        assert!(max.priority() > 0);
        assert!(max.priority() < 1 << 61);
        let last = Precedence {
            route_rank: usize::MAX,
            rule: usize::MAX,
            ..base()
        };
        assert!(last.priority() > 0);
    }
}
