use std::fmt;

use crate::ast::{Args, Expr, SPECS, Spec};
use crate::lexer::{Tok, Token, tokenize};
use crate::suggest::closest_match;

/// Longest rule accepted, in bytes.
pub const MAX_RULE_BYTES: usize = 16 * 1024;

/// Deepest nesting of parentheses and `!` accepted. Keeps parsing iterative-safe for hostile
/// input.
pub const MAX_DEPTH: usize = 32;

/// Why a rule could not be parsed, and where.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind} (at byte {offset})")]
pub struct ParseError {
    /// Byte offset in the rule where the problem was found.
    pub offset: usize,
    /// What went wrong.
    pub kind: ParseErrorKind,
}

/// The kinds of parse errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// The rule is empty or only whitespace.
    Empty,
    /// The rule exceeds [`MAX_RULE_BYTES`].
    TooLong,
    /// Parentheses or `!` nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A character that cannot start a token.
    UnexpectedChar(char),
    /// `&` or `|` written once instead of twice.
    SingleOperator(char),
    /// A string literal without its closing quote.
    UnterminatedString,
    /// An unknown escape sequence in a double-quoted string.
    InvalidEscape(char),
    /// A raw newline in a double-quoted string.
    NewlineInString,
    /// The parser expected something else.
    Expected {
        /// What was expected.
        expected: &'static str,
        /// What was found instead.
        found: String,
    },
    /// A matcher name that does not exist.
    UnknownMatcher {
        /// The name as written.
        name: String,
        /// The closest known matcher, if any.
        suggestion: Option<&'static str>,
    },
    /// A matcher called with the wrong number of arguments.
    WrongArity {
        /// The matcher.
        matcher: &'static str,
        /// Accepted argument counts, e.g. `"1"` or `"1 or 2"`.
        expected: &'static str,
        /// Arguments given.
        found: usize,
    },
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("rule is empty"),
            Self::TooLong => write!(f, "rule is longer than {MAX_RULE_BYTES} bytes"),
            Self::TooDeep => write!(f, "rule nests deeper than {MAX_DEPTH} levels"),
            Self::UnexpectedChar(c) => write!(f, "unexpected character `{}`", c.escape_debug()),
            Self::SingleOperator(c) => write!(f, "`{c}` must be doubled: write `{c}{c}`"),
            Self::UnterminatedString => f.write_str("string is not closed"),
            Self::InvalidEscape(c) => {
                write!(
                    f,
                    "unknown escape `\\{}` (allowed: \\\\ \\\" \\n \\r \\t)",
                    c.escape_debug()
                )
            }
            Self::NewlineInString => {
                f.write_str("double-quoted strings cannot contain a line break; write `\\n`")
            }
            Self::Expected { expected, found } => write!(f, "expected {expected}, found {found}"),
            Self::UnknownMatcher { name, suggestion } => {
                write!(f, "unknown matcher `{name}`")?;
                if let Some(s) = suggestion {
                    write!(f, "; did you mean `{s}`?")?;
                }
                Ok(())
            }
            Self::WrongArity {
                matcher,
                expected,
                found,
            } => {
                write!(f, "`{matcher}` takes {expected} argument(s), found {found}")?;
                if *found > 1 && *expected == "1" {
                    write!(
                        f,
                        "; Traefik v3 takes one value per matcher, combine them with `||`"
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl ParseError {
    pub(crate) fn new(offset: usize, kind: ParseErrorKind) -> Self {
        Self { offset, kind }
    }

    /// Renders the offending line of `rule` with a caret under the error position.
    #[must_use]
    pub fn render(&self, rule: &str) -> String {
        let offset = floor_char_boundary(rule, self.offset.min(rule.len()));
        let line_start = rule[..offset].rfind('\n').map_or(0, |i| i + 1);
        let line_end = rule[offset..].find('\n').map_or(rule.len(), |i| offset + i);
        let column = rule[line_start..offset].chars().count();
        format!(
            "{}\n{}^ {}",
            &rule[line_start..line_end],
            " ".repeat(column),
            self.kind
        )
    }
}

fn floor_char_boundary(s: &str, mut index: usize) -> usize {
    while !s.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Parses a Traefik v3 compatible rule.
///
/// ```
/// use rdock_rules::{parse, Expr, Matcher};
///
/// let rule = parse("Host(`example.com`) && PathPrefix(`/api`)").unwrap();
/// assert_eq!(
///     rule,
///     Expr::And(vec![
///         Expr::Matcher(Matcher::Host("example.com".into())),
///         Expr::Matcher(Matcher::PathPrefix("/api".into())),
///     ])
/// );
/// ```
pub fn parse(rule: &str) -> Result<Expr, ParseError> {
    if rule.len() > MAX_RULE_BYTES {
        return Err(ParseError::new(MAX_RULE_BYTES, ParseErrorKind::TooLong));
    }
    let tokens = tokenize(rule)?;
    if tokens.is_empty() {
        return Err(ParseError::new(0, ParseErrorKind::Empty));
    }
    let mut parser = Parser {
        tokens,
        pos: 0,
        end: rule.len(),
    };
    let expr = parser.or(0)?;
    if let Some(token) = parser.peek() {
        return Err(ParseError::new(
            token.start,
            ParseErrorKind::Expected {
                expected: "`&&`, `||` or the end of the rule",
                found: token.tok.describe(),
            },
        ));
    }
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    end: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn eat(&mut self, tok: &Tok) -> bool {
        if self.peek().is_some_and(|t| &t.tok == tok) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn here(&self) -> usize {
        self.peek().map_or(self.end, |t| t.start)
    }

    fn found(&self) -> String {
        self.peek()
            .map_or_else(|| "the end of the rule".to_owned(), |t| t.tok.describe())
    }

    fn expected(&self, expected: &'static str) -> ParseError {
        ParseError::new(
            self.here(),
            ParseErrorKind::Expected {
                expected,
                found: self.found(),
            },
        )
    }

    fn or(&mut self, depth: usize) -> Result<Expr, ParseError> {
        let mut items = vec![self.and(depth)?];
        while self.eat(&Tok::Or) {
            items.push(self.and(depth)?);
        }
        Ok(collapse(items, Expr::Or))
    }

    fn and(&mut self, depth: usize) -> Result<Expr, ParseError> {
        let mut items = vec![self.unary(depth)?];
        while self.eat(&Tok::And) {
            items.push(self.unary(depth)?);
        }
        Ok(collapse(items, Expr::And))
    }

    fn unary(&mut self, depth: usize) -> Result<Expr, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::new(self.here(), ParseErrorKind::TooDeep));
        }
        if self.eat(&Tok::Not) {
            return Ok(Expr::Not(Box::new(self.unary(depth + 1)?)));
        }
        self.primary(depth)
    }

    fn primary(&mut self, depth: usize) -> Result<Expr, ParseError> {
        match self.peek().map(|t| t.tok.clone()) {
            Some(Tok::LParen) => {
                self.pos += 1;
                let expr = self.or(depth + 1)?;
                if !self.eat(&Tok::RParen) {
                    return Err(self.expected("`)`"));
                }
                Ok(expr)
            }
            Some(Tok::Ident(name)) => {
                let start = self.here();
                self.pos += 1;
                self.matcher(&name, start)
            }
            _ => Err(self.expected("a matcher such as Host(`example.com`), `!` or `(`")),
        }
    }

    fn matcher(&mut self, name: &str, start: usize) -> Result<Expr, ParseError> {
        // Traefik matches matcher names case-insensitively (`host`, `HOST`, `PathPrefix`).
        let Some(spec) = SPECS.iter().find(|s| s.name.eq_ignore_ascii_case(name)) else {
            let suggestion = closest_match(name, SPECS.iter().map(|s| s.name));
            return Err(ParseError::new(
                start,
                ParseErrorKind::UnknownMatcher {
                    name: name.to_owned(),
                    suggestion,
                },
            ));
        };
        if !self.eat(&Tok::LParen) {
            return Err(self.expected("`(` after the matcher name"));
        }
        let mut args = Vec::new();
        if !self.eat(&Tok::RParen) {
            loop {
                match self.peek().map(|t| t.tok.clone()) {
                    Some(Tok::Str(value)) => {
                        self.pos += 1;
                        args.push(value);
                    }
                    _ => return Err(self.expected("a string in backticks or double quotes")),
                }
                if self.eat(&Tok::Comma) {
                    continue;
                }
                if self.eat(&Tok::RParen) {
                    break;
                }
                return Err(self.expected("`,` or `)`"));
            }
        }
        check_arity(spec, args.len(), start)?;
        Ok(Expr::Matcher((spec.build)(Args::new(args))))
    }
}

fn check_arity(spec: &Spec, found: usize, start: usize) -> Result<(), ParseError> {
    if (spec.min_args..=spec.max_args).contains(&found) {
        return Ok(());
    }
    let expected = match (spec.min_args, spec.max_args) {
        (1, 1) => "1",
        (2, 2) => "2",
        _ => "1 or 2",
    };
    Err(ParseError::new(
        start,
        ParseErrorKind::WrongArity {
            matcher: spec.name,
            expected,
            found,
        },
    ))
}

/// One operand stays itself; several become an `And`/`Or` node.
fn collapse(mut items: Vec<Expr>, node: fn(Vec<Expr>) -> Expr) -> Expr {
    if items.len() == 1
        && let Some(only) = items.pop()
    {
        return only;
    }
    node(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Matcher;

    fn host(h: &str) -> Expr {
        Expr::Matcher(Matcher::Host(h.into()))
    }
    fn path(p: &str) -> Expr {
        Expr::Matcher(Matcher::Path(p.into()))
    }
    fn method(m: &str) -> Expr {
        Expr::Matcher(Matcher::Method(m.into()))
    }
    fn kind(rule: &str) -> ParseErrorKind {
        parse(rule).unwrap_err().kind
    }

    #[test]
    fn parses_every_traefik_matcher() {
        let rule = "Host(`a.example.com`) && HostRegexp(`^.+\\.example\\.com$`) && Path(`/p`) \
            && PathPrefix(`/api`) && PathRegexp(`^/v[0-9]+`) && Method(`GET`) \
            && Header(`X-A`, `1`) && HeaderRegexp(`X-B`, `^b`) && Query(`mobile`) \
            && Query(`lang`, `en`) && QueryRegexp(`id`, `^[0-9]+$`) && ClientIP(`10.0.0.0/8`)";
        let Expr::And(items) = parse(rule).unwrap() else {
            panic!("expected And")
        };
        assert_eq!(items.len(), 12);
        assert_eq!(
            items[8],
            Expr::Matcher(Matcher::Query {
                key: "mobile".into(),
                value: None
            })
        );
        let tcp = parse("HostSNI(`*`) || HostSNIRegexp(`^db`) || ALPN(`h2`)").unwrap();
        assert!(tcp.matchers().iter().all(|m| m.is_tcp()));
    }

    #[test]
    fn not_binds_tighter_than_and_which_binds_tighter_than_or() {
        assert_eq!(
            parse("Host(`a`) && Path(`/x`) || Method(`GET`)").unwrap(),
            Expr::Or(vec![Expr::And(vec![host("a"), path("/x")]), method("GET")])
        );
        assert_eq!(
            parse("Host(`a`) || Path(`/x`) && Method(`GET`)").unwrap(),
            Expr::Or(vec![host("a"), Expr::And(vec![path("/x"), method("GET")])])
        );
        assert_eq!(
            parse("!Host(`a`) && Path(`/x`)").unwrap(),
            Expr::And(vec![Expr::Not(Box::new(host("a"))), path("/x")])
        );
        assert_eq!(
            parse("!(Host(`a`) || Path(`/x`))").unwrap(),
            Expr::Not(Box::new(Expr::Or(vec![host("a"), path("/x")])))
        );
    }

    #[test]
    fn parenthesised_groups_are_kept() {
        assert_eq!(
            parse("(Host(`a`) && Path(`/x`)) && Method(`GET`)").unwrap(),
            Expr::And(vec![Expr::And(vec![host("a"), path("/x")]), method("GET")])
        );
    }

    #[test]
    fn double_quoted_strings_support_escapes() {
        assert_eq!(parse(r#"Host("a\"b\\c")"#).unwrap(), host("a\"b\\c"));
        assert_eq!(parse("Path(\"/a\\tb\")").unwrap(), path("/a\tb"));
    }

    #[test]
    fn reports_errors_with_offsets() {
        assert_eq!(parse("").unwrap_err().kind, ParseErrorKind::Empty);
        assert_eq!(parse("   ").unwrap_err().kind, ParseErrorKind::Empty);
        assert_eq!(
            parse("Host(`a`) & Path(`/`)").unwrap_err(),
            ParseError::new(10, ParseErrorKind::SingleOperator('&'))
        );
        assert_eq!(kind("Host(`a"), ParseErrorKind::UnterminatedString);
        assert_eq!(kind("Host(\"a\\qb\")"), ParseErrorKind::InvalidEscape('q'));
        assert_eq!(kind("Host(\"a\nb\")"), ParseErrorKind::NewlineInString);
        assert_eq!(
            kind("Host(`a`) Path(`/`)"),
            ParseErrorKind::Expected {
                expected: "`&&`, `||` or the end of the rule",
                found: "`Path`".into()
            }
        );
        assert_eq!(
            kind("Host(`a`"),
            ParseErrorKind::Expected {
                expected: "`,` or `)`",
                found: "the end of the rule".into()
            }
        );
        assert_eq!(
            kind("Host(a)"),
            ParseErrorKind::Expected {
                expected: "a string in backticks or double quotes",
                found: "`a`".into()
            }
        );
        assert_eq!(kind("Host(`a`) && #"), ParseErrorKind::UnexpectedChar('#'));
    }

    #[test]
    fn matcher_names_ignore_case_like_traefik() {
        assert_eq!(parse("host(`a`)").unwrap(), host("a"));
        assert_eq!(
            parse("PATHPREFIX(`/a`)").unwrap().to_string(),
            "PathPrefix(`/a`)"
        );
    }

    #[test]
    fn suggests_known_matchers() {
        assert_eq!(
            kind("PathPrefx(`/a`)"),
            ParseErrorKind::UnknownMatcher {
                name: "PathPrefx".into(),
                suggestion: Some("PathPrefix")
            }
        );
    }

    #[test]
    fn checks_arity_and_explains_traefik_v2_lists() {
        let err = parse("Host(`a.com`, `b.com`)").unwrap_err();
        assert_eq!(
            err.kind,
            ParseErrorKind::WrongArity {
                matcher: "Host",
                expected: "1",
                found: 2
            }
        );
        assert!(err.kind.to_string().contains("combine them with `||`"));
        assert_eq!(
            kind("Header(`X-A`)"),
            ParseErrorKind::WrongArity {
                matcher: "Header",
                expected: "2",
                found: 1
            }
        );
        assert_eq!(
            kind("Query()"),
            ParseErrorKind::WrongArity {
                matcher: "Query",
                expected: "1 or 2",
                found: 0
            }
        );
    }

    #[test]
    fn limits_length_and_depth() {
        assert_eq!(
            kind(&"x".repeat(MAX_RULE_BYTES + 1)),
            ParseErrorKind::TooLong
        );
        let deep = format!(
            "{}Host(`a`){}",
            "(".repeat(MAX_DEPTH + 2),
            ")".repeat(MAX_DEPTH + 2)
        );
        assert_eq!(kind(&deep), ParseErrorKind::TooDeep);
        assert_eq!(
            kind(&format!("{}Host(`a`)", "!".repeat(10_000))),
            ParseErrorKind::TooDeep
        );
    }

    #[test]
    fn renders_a_caret_under_the_error() {
        let rule = "Host(`a`) & Path(`/`)";
        let rendered = parse(rule).unwrap_err().render(rule);
        assert_eq!(
            rendered,
            "Host(`a`) & Path(`/`)\n          ^ `&` must be doubled: write `&&`"
        );
    }
}
