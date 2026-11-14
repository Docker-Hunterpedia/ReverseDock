//! Compose variable interpolation and `.env` files, for `rdock migrate traefik` on a raw Compose
//! file (ADR-0033).
//!
//! The rules follow the Compose Specification's interpolation chapter
//! (<https://github.com/compose-spec/compose-spec/blob/main/12-interpolation.md>, the same text
//! as <https://docs.docker.com/reference/compose-file/interpolation/>, read 2026-11-14) and
//! Docker's page on environment files
//! (<https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/#env-file-syntax>,
//! read 2026-11-14):
//!
//! - `$VAR` and `${VAR}`; `${VAR:-default}` (unset or empty) and `${VAR-default}` (unset);
//!   `${VAR:?err}` and `${VAR?err}` (Compose stops with `err`); `${VAR:+alt}` and `${VAR+alt}`.
//!   Defaults and messages may hold further references (`${A:-${B}}`).
//! - `$$` is a literal `$`. A `$` that starts no valid reference is kept as it is.
//! - A variable that is unset and has no default becomes the empty string (Compose warns).
//! - Only values are interpolated, not mapping keys; a `KEY=VALUE` list item is a value.
//!
//! Nothing here reads the process environment: the caller passes the variables.

use std::collections::BTreeMap;

/// Variables available to `${…}` references.
pub type Vars = BTreeMap<String, String>;

/// Something about a reference that the user has to look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// `${NAME}` without a default, and `NAME` is not set: Compose uses the empty string.
    Unset(String),
    /// `${NAME?message}` or `${NAME:?message}` with `NAME` unset (or empty): Compose refuses
    /// the file with `message`.
    Required {
        /// The variable.
        name: String,
        /// Compose's error message.
        message: String,
    },
    /// `${` without its closing `}`, or a braced reference that is not `NAME[op word]`.
    Invalid(String),
}

impl Problem {
    /// One line for the report.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Unset(name) => {
                format!("`${{{name}}}` is not set and has no default; Compose uses an empty string")
            }
            Self::Required { name, message } => {
                format!("`${{{name}}}` is required and not set (Compose stops: {message})")
            }
            Self::Invalid(text) => format!("`{text}` is not a valid Compose reference"),
        }
    }

    /// The variable concerned, if any.
    #[must_use]
    pub fn variable(&self) -> Option<&str> {
        match self {
            Self::Unset(name) | Self::Required { name, .. } => Some(name),
            Self::Invalid(_) => None,
        }
    }
}

/// `text` with every reference replaced, and what needs a look.
#[must_use]
pub fn interpolate(text: &str, vars: &Vars) -> (String, Vec<Problem>) {
    let mut problems = Vec::new();
    let out = expand(text, vars, &mut problems, 0);
    (out, problems)
}

/// Deepest nesting of `${…}` followed; deeper text is kept as it is.
const MAX_DEPTH: u8 = 16;

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_name(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn expand(text: &str, vars: &Vars, problems: &mut Vec<Problem>, depth: u8) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '$' {
            out.push(c);
            i += 1;
            continue;
        }
        match chars.get(i + 1) {
            Some('$') => {
                out.push('$');
                i += 2;
            }
            Some('{') if depth < MAX_DEPTH => {
                let Some(end) = closing(&chars, i + 2) else {
                    problems.push(Problem::Invalid(chars[i..].iter().collect()));
                    out.extend(&chars[i..]);
                    return out;
                };
                let inner: String = chars[i + 2..end].iter().collect();
                out.push_str(&braced(&inner, vars, problems, depth));
                i = end + 1;
            }
            Some(&n) if is_name_start(n) => {
                let start = i + 1;
                let mut end = start;
                while end < chars.len() && is_name(chars[end]) {
                    end += 1;
                }
                let name: String = chars[start..end].iter().collect();
                match vars.get(&name) {
                    Some(value) => out.push_str(value),
                    None => problems.push(Problem::Unset(name)),
                }
                i = end;
            }
            _ => {
                out.push('$');
                i += 1;
            }
        }
    }
    out
}

/// The index of the `}` that closes a `${` whose content starts at `start`.
fn closing(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    while i < chars.len() {
        match chars[i] {
            '$' if chars.get(i + 1) == Some(&'$') => i += 1,
            '$' if chars.get(i + 1) == Some(&'{') => {
                depth += 1;
                i += 1;
            }
            '}' if depth == 0 => return Some(i),
            '}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    None
}

/// The content of `${…}`: `NAME`, or `NAME` followed by an operator and a word.
fn braced(inner: &str, vars: &Vars, problems: &mut Vec<Problem>, depth: u8) -> String {
    let name_len = inner
        .char_indices()
        .take_while(|(i, c)| {
            if *i == 0 {
                is_name_start(*c)
            } else {
                is_name(*c)
            }
        })
        .count();
    if name_len == 0 {
        problems.push(Problem::Invalid(format!("${{{inner}}}")));
        return String::new();
    }
    let (name, rest) = inner.split_at(name_len);
    let value = vars.get(name);
    let empty = value.is_none_or(String::is_empty);
    let word = |text: &str, problems: &mut Vec<Problem>| expand(text, vars, problems, depth + 1);
    let (op, text) = ["?", ":?", ":-", "-", ":+", "+"]
        .iter()
        .filter_map(|op| rest.strip_prefix(op).map(|text| (*op, text)))
        // `:-` before `-`: the longest operator that matches.
        .max_by_key(|(op, _)| op.len())
        .unwrap_or(("", rest));
    match op {
        "" if text.is_empty() => {
            if value.is_none() {
                problems.push(Problem::Unset(name.to_owned()));
            }
            value.cloned().unwrap_or_default()
        }
        ":-" if empty => word(text, problems),
        "-" if value.is_none() => word(text, problems),
        ":?" | "?" if (op == ":?" && empty) || (op == "?" && value.is_none()) => {
            let message = word(text, problems);
            problems.push(Problem::Required {
                name: name.to_owned(),
                message,
            });
            String::new()
        }
        ":-" | "-" | ":?" | "?" => value.cloned().unwrap_or_default(),
        ":+" if !empty => word(text, problems),
        "+" if value.is_some() => word(text, problems),
        ":+" | "+" => String::new(),
        _ => {
            problems.push(Problem::Invalid(format!("${{{inner}}}")));
            String::new()
        }
    }
}

/// Reads an environment file: `KEY=VALUE` or `KEY: VALUE` lines, `#` comments, quoted values
/// (single quotes literal and possibly over several lines, double quotes with `\n`, `\t`,
/// `\r`, `\\` and escaped quotes), inline comments after a space (unquoted) or after the
/// closing quote, an optional `export ` prefix. Unquoted and double-quoted values are
/// interpolated with the variables already defined (earlier lines and `known`). Returns the
/// variables, or the first line that cannot be read.
pub fn env_file(text: &str, known: &Vars) -> Result<Vars, String> {
    let mut vars = Vars::new();
    let mut lines = text.lines().enumerate().peekable();
    while let Some((number, line)) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let split = trimmed
            .find(['=', ':'])
            .ok_or_else(|| format!("line {}: expected KEY=VALUE", number + 1))?;
        let key = trimmed[..split].trim();
        if key.is_empty() || !key.chars().all(is_name) {
            return Err(format!(
                "line {}: `{key}` is not a variable name",
                number + 1
            ));
        }
        let raw = trimmed[split + 1..].trim();
        let value = if let Some(rest) = raw.strip_prefix('\'') {
            let mut body = rest.to_owned();
            while !closes(&body, '\'') {
                let Some((_, next)) = lines.next() else {
                    return Err(format!("line {}: unterminated single quote", number + 1));
                };
                body.push('\n');
                body.push_str(next);
            }
            unquote(&body, '\'', false)
        } else if let Some(rest) = raw.strip_prefix('"') {
            if !closes(rest, '"') {
                return Err(format!("line {}: unterminated double quote", number + 1));
            }
            let mut scope = known.clone();
            scope.extend(vars.clone());
            interpolate(&unquote(rest, '"', true), &scope).0
        } else {
            let value = raw.find(" #").map_or(raw, |at| &raw[..at]).trim_end();
            let mut scope = known.clone();
            scope.extend(vars.clone());
            interpolate(value, &scope).0
        };
        vars.insert(key.to_owned(), value);
    }
    Ok(vars)
}

/// Whether `body` (after the opening quote) contains an unescaped closing `quote`.
fn closes(body: &str, quote: char) -> bool {
    let mut escaped = false;
    for c in body.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            c if c == quote && !escaped => return true,
            _ => escaped = false,
        }
    }
    false
}

/// The text up to the closing `quote`, with escaped quotes (and, in double quotes, `\n`, `\t`,
/// `\r` and `\\`) resolved.
fn unquote(body: &str, quote: char, escapes: bool) -> String {
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(q) if q == quote => out.push(q),
                Some('n') if escapes => out.push('\n'),
                Some('t') if escapes => out.push('\t'),
                Some('r') if escapes => out.push('\r'),
                Some('\\') if escapes => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            c if c == quote => break,
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vars {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn references_follow_the_compose_specification() {
        let v = vars(&[("DOMAIN", "example.com"), ("EMPTY", "")]);
        let cases = [
            ("Host(`${DOMAIN}`)", "Host(`example.com`)"),
            ("Host(`$DOMAIN`)", "Host(`example.com`)"),
            ("${MISSING:-fallback}", "fallback"),
            ("${EMPTY:-fallback}", "fallback"),
            ("${EMPTY-fallback}", ""),
            ("${MISSING-fallback}", "fallback"),
            ("${DOMAIN:+on}", "on"),
            ("${EMPTY:+on}", ""),
            ("${EMPTY+on}", "on"),
            ("${MISSING+on}", ""),
            ("${MISSING:-${DOMAIN}}", "example.com"),
            ("${MISSING:-${ALSO:-deep}}", "deep"),
            ("$$apr1$$x$$y", "$apr1$x$y"),
            ("https://$${1}", "https://${1}"),
            ("cost: $5", "cost: $5"),
            ("$2y$05$/abc", "$2y$05$/abc"),
        ];
        for (input, want) in cases {
            let (got, problems) = interpolate(input, &v);
            assert_eq!(got, want, "{input}");
            assert!(problems.is_empty(), "{input}: {problems:?}");
        }
    }

    #[test]
    fn unset_required_and_invalid_references_are_problems() {
        let v = Vars::new();
        assert_eq!(
            interpolate("a${NOPE}b", &v),
            ("ab".to_owned(), vec![Problem::Unset("NOPE".into())])
        );
        let (_, problems) = interpolate("${NOPE:?set NOPE first}", &v);
        assert_eq!(
            problems,
            vec![Problem::Required {
                name: "NOPE".into(),
                message: "set NOPE first".into()
            }]
        );
        let (_, problems) = interpolate("${EMPTY?x}", &vars(&[("EMPTY", "")]));
        assert_eq!(problems, Vec::new());
        assert!(matches!(
            interpolate("${1}", &v).1[..],
            [Problem::Invalid(_)]
        ));
        // An unescaped bcrypt hash: `$abc` is a reference, as Compose reads it.
        assert_eq!(
            interpolate("$2y$05$abc", &v),
            ("$2y$05".to_owned(), vec![Problem::Unset("abc".into())])
        );
        assert!(matches!(
            interpolate("${OPEN", &v).1[..],
            [Problem::Invalid(_)]
        ));
    }

    #[test]
    fn env_files_follow_the_documented_syntax() {
        let text = "# comment\n\nDOMAIN=example.com\nexport A = spaced  \nB: colon\nC=\"x # kept\" # dropped\nD='literal $DOMAIN'\nE=\"$DOMAIN\\tz\"\nF=val# kept\nG=val # dropped\nH='two\nlines'\nI=${DOMAIN:-no}\n";
        let v = env_file(text, &Vars::new()).unwrap();
        assert_eq!(v["DOMAIN"], "example.com");
        assert_eq!(v["A"], "spaced");
        assert_eq!(v["B"], "colon");
        assert_eq!(v["C"], "x # kept");
        assert_eq!(v["D"], "literal $DOMAIN");
        assert_eq!(v["E"], "example.com\tz");
        assert_eq!(v["F"], "val# kept");
        assert_eq!(v["G"], "val");
        assert_eq!(v["H"], "two\nlines");
        assert_eq!(v["I"], "example.com");
        assert!(env_file("not a pair\n", &Vars::new()).is_err());
        assert!(env_file("A=\"open\n", &Vars::new()).is_err());
    }
}
