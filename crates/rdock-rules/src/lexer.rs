use crate::parser::{ParseError, ParseErrorKind};

/// A lexical token of the rule grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tok {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    Comma,
    And,
    Or,
    Not,
}

/// A token and the byte offset where it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) tok: Tok,
    pub(crate) start: usize,
}

impl Tok {
    /// Human-readable description used in error messages.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Ident(name) => format!("`{name}`"),
            Self::Str(_) => "a string".to_owned(),
            Self::LParen => "`(`".to_owned(),
            Self::RParen => "`)`".to_owned(),
            Self::Comma => "`,`".to_owned(),
            Self::And => "`&&`".to_owned(),
            Self::Or => "`||`".to_owned(),
            Self::Not => "`!`".to_owned(),
        }
    }
}

/// Splits a rule into tokens.
pub(crate) fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some(&(start, c)) = chars.peek() {
        let tok = match c {
            c if c.is_whitespace() => {
                chars.next();
                continue;
            }
            '(' | ')' | ',' | '!' => {
                chars.next();
                match c {
                    '(' => Tok::LParen,
                    ')' => Tok::RParen,
                    ',' => Tok::Comma,
                    _ => Tok::Not,
                }
            }
            '&' | '|' => {
                chars.next();
                if chars.next_if(|&(_, next)| next == c).is_none() {
                    return Err(ParseError::new(start, ParseErrorKind::SingleOperator(c)));
                }
                if c == '&' { Tok::And } else { Tok::Or }
            }
            '`' => {
                chars.next();
                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some((_, '`')) => break,
                        Some((_, ch)) => value.push(ch),
                        None => {
                            return Err(ParseError::new(start, ParseErrorKind::UnterminatedString));
                        }
                    }
                }
                Tok::Str(value)
            }
            '"' => {
                chars.next();
                Tok::Str(double_quoted(&mut chars, start)?)
            }
            c if c.is_ascii_alphabetic() => {
                let mut name = String::new();
                while let Some((_, ch)) = chars.next_if(|&(_, ch)| ch.is_ascii_alphanumeric()) {
                    name.push(ch);
                }
                Tok::Ident(name)
            }
            other => {
                return Err(ParseError::new(
                    start,
                    ParseErrorKind::UnexpectedChar(other),
                ));
            }
        };
        tokens.push(Token { tok, start });
    }
    Ok(tokens)
}

/// Reads the rest of a double-quoted string after its opening quote.
fn double_quoted(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    start: usize,
) -> Result<String, ParseError> {
    let mut value = String::new();
    loop {
        match chars.next() {
            Some((_, '"')) => return Ok(value),
            Some((pos, '\\')) => match chars.next() {
                Some((_, 'n')) => value.push('\n'),
                Some((_, 'r')) => value.push('\r'),
                Some((_, 't')) => value.push('\t'),
                Some((_, '\\')) => value.push('\\'),
                Some((_, '"')) => value.push('"'),
                Some((_, other)) => {
                    return Err(ParseError::new(pos, ParseErrorKind::InvalidEscape(other)));
                }
                None => return Err(ParseError::new(start, ParseErrorKind::UnterminatedString)),
            },
            Some((pos, '\n')) => return Err(ParseError::new(pos, ParseErrorKind::NewlineInString)),
            Some((_, ch)) => value.push(ch),
            None => return Err(ParseError::new(start, ParseErrorKind::UnterminatedString)),
        }
    }
}
