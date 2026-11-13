//! How the query string enters the key (`key.query`).
//!
//! A parameter left out of the key is also removed from the request sent to the origin, so
//! the origin can never answer differently for something the key does not see (web cache
//! "entanglement": an unkeyed parameter reflected in a stored page).

use percent_encoding::percent_decode_str;

/// A parameter name pattern: exact, or a prefix when it ends with `*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern(String);

impl Pattern {
    /// A pattern from configuration (`utm_*`, `page`).
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        Self(pattern.to_owned())
    }

    fn matches(&self, name: &str) -> bool {
        match self.0.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => name == self.0,
        }
    }
}

/// The route's rule for the query string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum QueryRule {
    /// The query exactly as forwarded (the default).
    #[default]
    AsSent,
    /// Parameters sorted by name; repeated names keep their order.
    Sorted,
    /// Only these parameters are kept, in their order.
    Only(Vec<Pattern>),
    /// These parameters are removed.
    Ignore(Vec<Pattern>),
}

/// The query for the key and, when the rule removed parameters, the query to forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filtered {
    /// The query as it enters the key.
    pub key: String,
    /// The new query for the origin; `None` when the forwarded query stays as it is.
    pub forward: Option<String>,
}

fn decoded_name(pair: &str) -> String {
    let name = pair.split_once('=').map_or(pair, |(n, _)| n);
    let spaced = name.replace('+', " ");
    percent_decode_str(&spaced).decode_utf8_lossy().into_owned()
}

/// Applies `rule` to the raw query (without `?`).
#[must_use]
pub fn apply(rule: &QueryRule, raw: Option<&str>) -> Filtered {
    let raw = raw.unwrap_or_default();
    let pairs = || raw.split('&').filter(|p| !p.is_empty());
    match rule {
        QueryRule::AsSent => Filtered {
            key: raw.to_owned(),
            forward: None,
        },
        QueryRule::Sorted => {
            let mut items: Vec<(String, &str)> = pairs().map(|p| (decoded_name(p), p)).collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            Filtered {
                key: items.iter().map(|(_, p)| *p).collect::<Vec<_>>().join("&"),
                forward: None,
            }
        }
        QueryRule::Only(patterns) | QueryRule::Ignore(patterns) => {
            let keep_matching = matches!(rule, QueryRule::Only(_));
            let kept: Vec<&str> = pairs()
                .filter(|p| {
                    let name = decoded_name(p);
                    patterns.iter().any(|pat| pat.matches(&name)) == keep_matching
                })
                .collect();
            let key = kept.join("&");
            let changed = key != raw;
            Filtered {
                forward: changed.then(|| key.clone()),
                key,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(p: &[&str]) -> Vec<Pattern> {
        p.iter().map(|s| Pattern::new(s)).collect()
    }

    #[test]
    fn as_sent_keeps_the_query_untouched() {
        let f = apply(&QueryRule::AsSent, Some("b=2&a=1"));
        assert_eq!(f.key, "b=2&a=1");
        assert_eq!(f.forward, None);
        assert_eq!(apply(&QueryRule::AsSent, None).key, "");
    }

    #[test]
    fn sorted_orders_by_name_and_keeps_repeated_names_in_order() {
        let f = apply(&QueryRule::Sorted, Some("b=2&a=2&a=1&%61b=3"));
        assert_eq!(f.key, "a=2&a=1&%61b=3&b=2", "`%61b` is `ab`");
        assert_eq!(f.forward, None);
        assert_eq!(
            apply(&QueryRule::Sorted, Some("x=1&y=2")).key,
            apply(&QueryRule::Sorted, Some("y=2&x=1")).key
        );
    }

    #[test]
    fn allow_and_deny_lists_rewrite_the_forwarded_query_too() {
        let f = apply(
            &QueryRule::Ignore(pats(&["utm_*", "fbclid"])),
            Some("utm_source=a&page=2&fbclid=x"),
        );
        assert_eq!(f.key, "page=2");
        assert_eq!(f.forward.as_deref(), Some("page=2"));
        let f = apply(
            &QueryRule::Only(pats(&["page"])),
            Some("page=2&utm_source=a"),
        );
        assert_eq!(f.key, "page=2");
        assert_eq!(f.forward.as_deref(), Some("page=2"));
        // Nothing removed: nothing to forward differently.
        let f = apply(&QueryRule::Only(pats(&["page"])), Some("page=2"));
        assert_eq!(f.forward, None);
        // Encoded names are matched decoded.
        let f = apply(
            &QueryRule::Ignore(pats(&["utm_*"])),
            Some("utm%5Fsource=a&b=1"),
        );
        assert_eq!(f.key, "b=1");
    }
}
