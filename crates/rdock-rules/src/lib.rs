#![doc = include_str!("../README.md")]

mod ast;
mod lexer;
mod parser;
mod suggest;
mod validate;

pub use ast::{Expr, Matcher};
pub use parser::{MAX_DEPTH, MAX_RULE_BYTES, ParseError, ParseErrorKind, parse};
pub use suggest::closest_match;
pub use validate::{Context, RuleError, check_host};

/// Default priority of a rule: its length in bytes, as in Traefik. Longer rules win.
#[must_use]
pub fn default_priority(rule: &str) -> usize {
    rule.len()
}
