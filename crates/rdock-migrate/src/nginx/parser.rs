//! A small parser for NGINX configuration syntax (ADR-0033: our own, no dependency).
//!
//! The syntax, as `ngx_conf_read_token` in NGINX reads it (nginx.org, "Beginner's Guide":
//! "simple directives" end with `;`, "block directives" with `{ … }`, `#` starts a comment;
//! <https://nginx.org/en/docs/beginners_guide.html>, read 2026-11-14): a directive is a name and
//! arguments, then `;` or a block; arguments are bare words or single- or double-quoted strings;
//! a backslash escapes the next character (`\"`, `\'`, `\\`, `\t`, `\r`, `\n` as in
//! `ngx_conf_read_token`); `${name}` keeps its braces inside a bare word; the body of a
//! `*_by_lua_block` is raw text with balanced braces. Variables (`$host`) stay as text.
//!
//! Limits: blocks nest at most [`MAX_DEPTH`] deep (no recursion: an explicit stack), a file has at
//! most [`MAX_BYTES`] bytes, and every token and directive keeps its line and column.

/// Deepest block nesting accepted.
pub const MAX_DEPTH: usize = 64;
/// Largest file read.
pub const MAX_BYTES: usize = 4 * 1024 * 1024;

/// One argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg {
    /// The text, with quotes removed and escapes applied.
    pub text: String,
    /// It was quoted.
    pub quoted: bool,
}

/// One directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// Its name.
    pub name: String,
    /// Its arguments.
    pub args: Vec<Arg>,
    /// Its block, for a block directive (`http`, `server`, `location`, …).
    pub block: Option<Vec<Directive>>,
    /// The raw body of a `*_by_lua_block`.
    pub raw: Option<String>,
    /// Index of the file it was read from.
    pub file: usize,
    /// Line (1-based).
    pub line: u32,
    /// Column (1-based).
    pub column: u32,
}

impl Directive {
    /// The argument texts.
    pub fn values(&self) -> Vec<&str> {
        self.args.iter().map(|a| a.text.as_str()).collect()
    }

    /// The first argument, or `""`.
    pub fn arg(&self, i: usize) -> &str {
        self.args.get(i).map_or("", |a| a.text.as_str())
    }

    /// `name arg1 arg2`, shortened, as reports name it.
    pub fn label(&self) -> String {
        let mut text = self.name.clone();
        for arg in &self.args {
            text.push(' ');
            if arg.quoted || arg.text.contains(char::is_whitespace) || arg.text.is_empty() {
                text.push('"');
                text.push_str(&arg.text.replace('"', "\\\""));
                text.push('"');
            } else {
                text.push_str(&arg.text);
            }
            if text.len() > 120 {
                text.truncate(117);
                text.push_str("...");
                break;
            }
        }
        text
    }
}

/// Why a file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}, column {column}: {message}")]
pub struct ParseError {
    /// Line (1-based).
    pub line: u32,
    /// Column (1-based).
    pub column: u32,
    /// What is wrong.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(Arg),
    Semicolon,
    Open,
    Close,
}

struct Lexer<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
    line: u32,
    column: u32,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            text,
            pos: 0,
            line: 1,
            column: 1,
        }
    }

    fn error(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            line: self.line,
            column: self.column,
            message: message.into(),
        }
    }

    fn bump(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.column = 1;
        } else if b & 0xC0 != 0x80 {
            self.column += 1;
        }
        Some(b)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// The next token with its position, or `None` at the end.
    #[allow(clippy::match_same_arms)] // a brace ends a word unless it belongs to `${…}`
    fn next(&mut self) -> Result<Option<(Token, u32, u32)>, ParseError> {
        loop {
            match self.peek() {
                None => return Ok(None),
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.bump();
                }
                Some(b'#') => {
                    while let Some(b) = self.peek() {
                        if b == b'\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some(_) => break,
            }
        }
        let (line, column) = (self.line, self.column);
        let token = match self.peek() {
            Some(b';') => {
                self.bump();
                Token::Semicolon
            }
            Some(b'{') => {
                self.bump();
                Token::Open
            }
            Some(b'}') => {
                self.bump();
                Token::Close
            }
            Some(q @ (b'"' | b'\'')) => {
                self.bump();
                let mut out: Vec<u8> = Vec::new();
                loop {
                    match self.bump() {
                        None => return Err(self.error("unterminated quoted string")),
                        Some(b'\\') => match self.bump() {
                            None => return Err(self.error("unterminated quoted string")),
                            Some(c) => push_escape(&mut out, c),
                        },
                        Some(c) if c == q => break,
                        Some(c) => out.push(c),
                    }
                }
                // A quoted string must be followed by a separator.
                if let Some(next) = self.peek()
                    && !matches!(next, b' ' | b'\t' | b'\r' | b'\n' | b';' | b'{' | b'}')
                {
                    return Err(self.error("unexpected character after a quoted string"));
                }
                Token::Word(Arg {
                    text: String::from_utf8_lossy(&out).into_owned(),
                    quoted: true,
                })
            }
            Some(_) => {
                let mut out: Vec<u8> = Vec::new();
                let mut variable_brace = false;
                while let Some(b) = self.peek() {
                    match b {
                        b' ' | b'\t' | b'\r' | b'\n' | b';' => break,
                        b'{' if out.last() == Some(&b'$') => {
                            variable_brace = true;
                            out.push(b);
                            self.bump();
                        }
                        b'}' if variable_brace => {
                            variable_brace = false;
                            out.push(b);
                            self.bump();
                        }
                        b'{' | b'}' => break,
                        b'\\' => {
                            self.bump();
                            match self.bump() {
                                None => {
                                    return Err(self.error("a backslash at the end of the file"));
                                }
                                Some(c) => push_escape(&mut out, c),
                            }
                        }
                        _ => {
                            out.push(b);
                            self.bump();
                        }
                    }
                }
                if variable_brace {
                    return Err(self.error("unclosed `${`"));
                }
                Token::Word(Arg {
                    text: String::from_utf8_lossy(&out).into_owned(),
                    quoted: false,
                })
            }
            None => return Ok(None),
        };
        Ok(Some((token, line, column)))
    }

    /// The raw text of a block after its `{`, up to the matching `}` (for `*_by_lua_block`).
    fn raw_block(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        let mut depth = 1usize;
        let mut quote: Option<u8> = None;
        while let Some(b) = self.bump() {
            match (quote, b) {
                (Some(_), b'\\') => {
                    self.bump();
                }
                (Some(q), c) if c == q => quote = None,
                (None, b'"' | b'\'') => quote = Some(b),
                (None, b'{') => depth += 1,
                (None, b'}') => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(self.text.get(start..self.pos - 1).unwrap_or("").to_owned());
                    }
                }
                _ => {}
            }
        }
        Err(self.error("unterminated block"))
    }
}

fn push_escape(out: &mut Vec<u8>, c: u8) {
    match c {
        b't' => out.push(b'\t'),
        b'r' => out.push(b'\r'),
        b'n' => out.push(b'\n'),
        b'"' | b'\'' | b'\\' => out.push(c),
        other => {
            // NGINX keeps an unknown escape as written.
            out.push(b'\\');
            out.push(other);
        }
    }
}

/// Parses one file's text.
#[allow(clippy::too_many_lines)] // one pass, in reading order
pub fn parse(text: &str, file: usize) -> Result<Vec<Directive>, ParseError> {
    if text.len() > MAX_BYTES {
        return Err(ParseError {
            line: 1,
            column: 1,
            message: format!("the file is larger than {MAX_BYTES} bytes"),
        });
    }
    let mut lexer = Lexer::new(text);
    // The open blocks: (directives so far, the directive that opened the block).
    let mut stack: Vec<(Vec<Directive>, Option<Directive>)> = vec![(Vec::new(), None)];
    let mut pending: Option<Directive> = None;
    while let Some((token, line, column)) = lexer.next()? {
        match token {
            Token::Word(arg) => match &mut pending {
                Some(d) => d.args.push(arg),
                None => {
                    pending = Some(Directive {
                        name: arg.text,
                        args: Vec::new(),
                        block: None,
                        raw: None,
                        file,
                        line,
                        column,
                    });
                }
            },
            Token::Semicolon => {
                let Some(d) = pending.take() else {
                    return Err(ParseError {
                        line,
                        column,
                        message: "unexpected `;`".to_owned(),
                    });
                };
                if let Some((list, _)) = stack.last_mut() {
                    list.push(d);
                }
            }
            Token::Open => {
                let Some(mut d) = pending.take() else {
                    return Err(ParseError {
                        line,
                        column,
                        message: "unexpected `{`".to_owned(),
                    });
                };
                if d.name.ends_with("_by_lua_block") {
                    d.raw = Some(lexer.raw_block()?);
                    if let Some((list, _)) = stack.last_mut() {
                        list.push(d);
                    }
                    continue;
                }
                if stack.len() > MAX_DEPTH {
                    return Err(ParseError {
                        line,
                        column,
                        message: format!("blocks nest deeper than {MAX_DEPTH}"),
                    });
                }
                stack.push((Vec::new(), Some(d)));
            }
            Token::Close => {
                if pending.is_some() {
                    return Err(ParseError {
                        line,
                        column,
                        message: "a directive without `;` before `}`".to_owned(),
                    });
                }
                if stack.len() < 2 {
                    return Err(ParseError {
                        line,
                        column,
                        message: "unexpected `}`".to_owned(),
                    });
                }
                let Some((list, Some(mut opener))) = stack.pop() else {
                    return Err(ParseError {
                        line,
                        column,
                        message: "unexpected `}`".to_owned(),
                    });
                };
                opener.block = Some(list);
                if let Some((parent, _)) = stack.last_mut() {
                    parent.push(opener);
                }
            }
        }
    }
    if let Some(d) = pending {
        return Err(ParseError {
            line: d.line,
            column: d.column,
            message: format!("`{}` has no `;` or block", d.name),
        });
    }
    if stack.len() > 1 {
        return Err(lexer.error("unexpected end of file: a block is not closed"));
    }
    Ok(stack.pop().map(|(list, _)| list).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directives_blocks_quotes_and_comments() {
        let text = "http { # comment\n  server {\n    listen 80 default_server;\n    add_header X-A \"a b\\\"c\";\n    set $x '${y}z';\n    rewrite ^/(.*)$ /x/$1 break;\n  }\n}\n";
        let tree = parse(text, 0).unwrap();
        let http = &tree[0];
        assert_eq!(http.name, "http");
        let server = &http.block.as_ref().unwrap()[0];
        let directives = server.block.as_ref().unwrap();
        assert_eq!(directives[0].values(), ["80", "default_server"]);
        assert_eq!(directives[0].line, 3);
        assert_eq!(directives[1].arg(1), "a b\"c");
        assert!(directives[1].args[1].quoted);
        assert_eq!(directives[2].arg(1), "${y}z");
        assert_eq!(directives[3].arg(0), "^/(.*)$");
    }

    #[test]
    fn variables_in_braces_stay_words() {
        let tree = parse("return 301 https://${host}$request_uri;", 0).unwrap();
        assert_eq!(tree[0].arg(1), "https://${host}$request_uri");
    }

    #[test]
    fn lua_blocks_are_raw() {
        let tree = parse(
            "content_by_lua_block { ngx.say(\"}\") if a then b() end }\nlisten 80;",
            0,
        )
        .unwrap();
        assert_eq!(tree.len(), 2);
        assert!(tree[0].raw.as_deref().unwrap().contains("ngx.say"));
    }

    #[test]
    fn errors_have_positions() {
        assert_eq!(
            parse("server {\n listen 80;\n", 0).unwrap_err().message,
            "unexpected end of file: a block is not closed"
        );
        let err = parse("listen 80\n}", 0).unwrap_err();
        assert_eq!((err.line, err.column), (2, 1));
        assert!(parse("a \"b", 0).is_err());
        assert!(parse(";", 0).is_err());
        let deep = "a {".repeat(MAX_DEPTH + 2) + &"}".repeat(MAX_DEPTH + 2);
        assert!(parse(&deep, 0).unwrap_err().message.contains("deeper"));
    }
}
