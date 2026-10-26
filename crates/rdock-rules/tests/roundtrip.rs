//! Property tests: canonical printing round-trips, and the parser never panics.

// Strategy helpers build constant regexes, which cannot fail.
#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use rdock_rules::{Expr, Matcher, default_priority, parse};

/// Arbitrary short strings, including backticks, quotes, backslashes and line breaks.
fn text() -> impl Strategy<Value = String> {
    proptest::string::string_regex("(?s).{0,12}").unwrap()
}

fn matcher() -> impl Strategy<Value = Matcher> {
    prop_oneof![
        text().prop_map(Matcher::Host),
        text().prop_map(Matcher::HostRegexp),
        text().prop_map(Matcher::Path),
        text().prop_map(Matcher::PathPrefix),
        text().prop_map(Matcher::PathRegexp),
        text().prop_map(Matcher::Method),
        (text(), text()).prop_map(|(name, value)| Matcher::Header { name, value }),
        (text(), text()).prop_map(|(name, regexp)| Matcher::HeaderRegexp { name, regexp }),
        (text(), proptest::option::of(text()))
            .prop_map(|(key, value)| Matcher::Query { key, value }),
        (text(), text()).prop_map(|(key, regexp)| Matcher::QueryRegexp { key, regexp }),
        text().prop_map(Matcher::ClientIp),
        text().prop_map(Matcher::HostSni),
        text().prop_map(Matcher::HostSniRegexp),
        text().prop_map(Matcher::Alpn),
    ]
}

fn expr() -> impl Strategy<Value = Expr> {
    matcher()
        .prop_map(Expr::Matcher)
        .prop_recursive(4, 40, 4, |inner| {
            prop_oneof![
                inner.clone().prop_map(|e| Expr::Not(Box::new(e))),
                proptest::collection::vec(inner.clone(), 2..4).prop_map(Expr::And),
                proptest::collection::vec(inner, 2..4).prop_map(Expr::Or),
            ]
        })
}

/// Token soup that looks like rules, to reach deep parser paths.
fn rule_like() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[A-Za-z()`\"!&|, \\\\\n]{0,80}").unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn printing_then_parsing_returns_the_same_expression(e in expr()) {
        let printed = e.to_string();
        prop_assert_eq!(parse(&printed), Ok(e));
    }

    #[test]
    fn canonical_form_is_a_fixed_point(input in rule_like()) {
        if let Ok(e) = parse(&input) {
            let printed = e.to_string();
            prop_assert_eq!(parse(&printed).map(|e| e.to_string()), Ok(printed));
        }
    }

    #[test]
    fn parser_never_panics_on_arbitrary_text(input in "(?s).{0,200}") {
        let _ = parse(&input);
    }

    #[test]
    fn parser_never_panics_on_rule_like_text(input in rule_like()) {
        if let Err(err) = parse(&input) {
            let _ = err.render(&input);
        }
    }

    #[test]
    fn default_priority_is_the_rule_length(input in "(?s).{0,64}") {
        prop_assert_eq!(default_priority(&input), input.len());
    }
}
