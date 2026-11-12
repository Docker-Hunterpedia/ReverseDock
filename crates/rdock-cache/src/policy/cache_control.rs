//! `Cache-Control` and `Pragma` parsing (RFC 9111 §5.2, §5.4).
//!
//! Directives are read from every field line of the header, split on commas outside quoted
//! strings, with case-insensitive names. The first occurrence of a directive wins. Unknown
//! directives are kept and ignored by the callers (§5.2.3).

use http::HeaderMap;
use http::header::{CACHE_CONTROL, HeaderName, PRAGMA};

/// The largest delta-seconds value a cache must represent (RFC 9111 §1.2.2): larger values
/// are treated as this one.
pub const DELTA_SECONDS_MAX: u32 = 2_147_483_648;

/// A numeric directive's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seconds {
    /// A valid delta-seconds value (capped at [`DELTA_SECONDS_MAX`]).
    Valid(u32),
    /// Present but not a delta-seconds value (`max-age=abc`, `max-age`, `max-age=-1`).
    Invalid,
}

/// The directives of one `Cache-Control` header (all its field lines).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directives {
    entries: Vec<(String, Option<String>)>,
}

impl Directives {
    /// Parses the field lines `values` of a `Cache-Control`-like header.
    pub fn parse<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut entries = Vec::new();
        for value in values {
            let Ok(text) = std::str::from_utf8(value) else {
                continue;
            };
            for item in split_outside_quotes(text) {
                let item = item.trim_matches([' ', '\t']);
                if item.is_empty() {
                    continue;
                }
                let (name, value) = match item.split_once('=') {
                    Some((name, value)) => (name, Some(unquote(value.trim_matches([' ', '\t'])))),
                    None => (item, None),
                };
                let name = name.trim_matches([' ', '\t']).to_ascii_lowercase();
                if name.is_empty() || !name.bytes().all(is_token_byte) {
                    continue;
                }
                entries.push((name, value));
            }
        }
        Self { entries }
    }

    /// The `Cache-Control` directives of `headers`.
    #[must_use]
    pub fn of(headers: &HeaderMap) -> Self {
        Self::named(headers, &CACHE_CONTROL)
    }

    /// The directives of the header `name` of `headers`.
    #[must_use]
    pub fn named(headers: &HeaderMap, name: &HeaderName) -> Self {
        Self::parse(
            headers
                .get_all(name)
                .iter()
                .map(http::HeaderValue::as_bytes),
        )
    }

    /// Whether no directive is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the directive `name` (lower case) is present.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| n == name)
    }

    /// The value of the first `name` directive: `None` when absent, `Some(None)` without a
    /// value.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<Option<&str>> {
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_deref())
    }

    /// The delta-seconds value of the first `name` directive.
    #[must_use]
    pub fn seconds(&self, name: &str) -> Option<Seconds> {
        self.value(name).map(|value| match value {
            Some(v) => parse_delta_seconds(v),
            None => Seconds::Invalid,
        })
    }

    /// The field names listed by a qualified directive (`private="set-cookie, x-a"`), lower
    /// case; empty when the directive is absent or unqualified.
    #[must_use]
    pub fn field_names(&self, name: &str) -> Vec<String> {
        match self.value(name) {
            Some(Some(list)) => list
                .split(',')
                .map(|f| f.trim_matches([' ', '\t']).to_ascii_lowercase())
                .filter(|f| !f.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// `delta-seconds = 1*DIGIT` (RFC 9111 §1.2.2); overflow saturates at [`DELTA_SECONDS_MAX`].
#[must_use]
pub fn parse_delta_seconds(value: &str) -> Seconds {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Seconds::Invalid;
    }
    let mut n: u64 = 0;
    for b in value.bytes() {
        n = n.saturating_mul(10).saturating_add(u64::from(b - b'0'));
        if n >= u64::from(DELTA_SECONDS_MAX) {
            return Seconds::Valid(DELTA_SECONDS_MAX);
        }
    }
    Seconds::Valid(u32::try_from(n).unwrap_or(DELTA_SECONDS_MAX))
}

/// Whether the request asks for revalidation with the deprecated `Pragma: no-cache`, which
/// counts only when the request has no `Cache-Control` (RFC 9111 §5.4).
#[must_use]
pub fn pragma_no_cache(headers: &HeaderMap) -> bool {
    !headers.contains_key(CACHE_CONTROL) && Directives::named(headers, &PRAGMA).has("no-cache")
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Splits on commas that are not inside a quoted string.
fn split_outside_quotes(text: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                items.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    items.push(&text[start..]);
    items
}

/// Removes the quotes and escapes of a quoted string; tokens pass unchanged.
fn unquote(value: &str) -> String {
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return value.to_owned();
    };
    let mut out = String::with_capacity(inner.len());
    let mut escaped = false;
    for c in inner.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cc(lines: &[&str]) -> Directives {
        Directives::parse(lines.iter().map(|l| l.as_bytes()))
    }

    #[test]
    fn rfc9111_5_2_directives_are_case_insensitive_and_span_field_lines() {
        let d = cc(&["Public, MAX-AGE=60", "s-maxage=\"30\""]);
        assert!(d.has("public"));
        assert_eq!(d.seconds("max-age"), Some(Seconds::Valid(60)));
        assert_eq!(d.seconds("s-maxage"), Some(Seconds::Valid(30)));
        assert_eq!(d.seconds("min-fresh"), None);
    }

    #[test]
    fn rfc9111_5_2_first_occurrence_wins_and_unknown_directives_are_kept() {
        let d = cc(&["max-age=10, max-age=20, x-ext=\"a,b\", foo"]);
        assert_eq!(d.seconds("max-age"), Some(Seconds::Valid(10)));
        assert_eq!(d.value("x-ext"), Some(Some("a,b")));
        assert!(d.has("foo"));
    }

    #[test]
    fn rfc9111_1_2_2_delta_seconds_saturate_and_reject_garbage() {
        assert_eq!(parse_delta_seconds("0"), Seconds::Valid(0));
        assert_eq!(
            parse_delta_seconds("99999999999999999999"),
            Seconds::Valid(DELTA_SECONDS_MAX)
        );
        for bad in ["", "-1", "1.5", " 3", "abc", "1e3"] {
            assert_eq!(parse_delta_seconds(bad), Seconds::Invalid, "{bad:?}");
        }
        assert_eq!(cc(&["max-age"]).seconds("max-age"), Some(Seconds::Invalid));
    }

    #[test]
    fn rfc9111_5_2_2_7_qualified_private_lists_field_names() {
        let d = cc(&["private=\"Set-Cookie, X-Secret\", no-cache=\"x-a\""]);
        assert_eq!(d.field_names("private"), ["set-cookie", "x-secret"]);
        assert_eq!(d.field_names("no-cache"), ["x-a"]);
        assert_eq!(
            cc(&["private"]).field_names("private"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn rfc9111_5_4_pragma_counts_only_without_cache_control() {
        let mut h = HeaderMap::new();
        h.insert(PRAGMA, "no-cache".parse().unwrap());
        assert!(pragma_no_cache(&h));
        h.insert(CACHE_CONTROL, "max-age=5".parse().unwrap());
        assert!(!pragma_no_cache(&h));
    }

    #[test]
    fn empty_items_and_invalid_names_are_skipped() {
        let d = cc(&[" , ,max-age=1,,  bad name=2, =3"]);
        assert_eq!(d.seconds("max-age"), Some(Seconds::Valid(1)));
        assert!(!d.has("bad name"));
        assert_eq!(d.entries.len(), 1);
    }
}
