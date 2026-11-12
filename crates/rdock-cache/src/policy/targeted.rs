//! Targeted cache control (RFC 9213): a field such as `CDN-Cache-Control` that carries
//! `Cache-Control` directives for one class of caches only.
//!
//! A targeted field is a Structured Field Dictionary (RFC 9213 §2.1, RFC 9651 §3.2). The
//! first field of the route's list with a valid, non-empty value replaces `Cache-Control`
//! and `Expires` for this cache; an empty or invalid one is ignored, as if absent. A known
//! directive with a value of the wrong type (`max-age="60"`, `no-store=1`) makes the field
//! invalid: guessing what the origin meant could store what it wanted kept out.

use http::HeaderMap;
use http::header::HeaderName;

use super::cache_control::{DELTA_SECONDS_MAX, Directives};

/// The targeted field of the RFC that applies to every CDN (RFC 9213 §3).
pub const CDN_CACHE_CONTROL: &str = "cdn-cache-control";

/// Directives whose value is a non-negative Integer.
const INTEGER_DIRECTIVES: [&str; 4] = [
    "max-age",
    "s-maxage",
    "stale-if-error",
    "stale-while-revalidate",
];

/// Directives that are a Boolean, or a String of field names (RFC 9213 §2.1).
const LIST_DIRECTIVES: [&str; 2] = ["no-cache", "private"];

/// Directives that are a Boolean only.
const FLAG_DIRECTIVES: [&str; 7] = [
    "no-store",
    "public",
    "must-revalidate",
    "proxy-revalidate",
    "no-transform",
    "immutable",
    "must-understand",
];

/// The directives a response's caching is decided by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// The directives in effect.
    pub cc: Directives,
    /// The lower-case name of the targeted field they came from; `None` for `Cache-Control`.
    pub targeted: Option<String>,
}

impl Effective {
    /// Whether `Expires` counts (it does not when a targeted field is in effect).
    #[must_use]
    pub fn expires(&self) -> bool {
        self.targeted.is_none()
    }
}

/// The directives of the first field of `targeted` with a valid, non-empty value, else those
/// of `Cache-Control` (RFC 9213 §2.1).
#[must_use]
pub fn effective(headers: &HeaderMap, targeted: &[HeaderName]) -> Effective {
    for name in targeted {
        if let Some(cc) = targeted_directives(headers, name) {
            return Effective {
                cc,
                targeted: Some(name.as_str().to_owned()),
            };
        }
    }
    Effective {
        cc: Directives::of(headers),
        targeted: None,
    }
}

/// The directives of the targeted field `name`, when it is present, valid and not empty.
#[must_use]
pub fn targeted_directives(headers: &HeaderMap, name: &HeaderName) -> Option<Directives> {
    let mut lines = Vec::new();
    for value in headers.get_all(name) {
        lines.push(value.to_str().ok()?);
    }
    // Field lines combine with commas (RFC 9651 §4.2); an empty line adds nothing.
    let combined = lines
        .iter()
        .map(|l| l.trim_matches([' ', '\t']))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    let members = parse_dictionary(&combined)?;
    if members.is_empty() {
        return None;
    }
    let mut entries = Vec::with_capacity(members.len());
    for (key, item) in members {
        let value = match (key.as_str(), item) {
            (_, Item::Boolean(false)) => continue,
            (k, Item::Integer(n)) if INTEGER_DIRECTIVES.contains(&k) => {
                if n < 0 {
                    return None;
                }
                Some(n.min(i64::from(DELTA_SECONDS_MAX)).to_string())
            }
            (k, _) if INTEGER_DIRECTIVES.contains(&k) => return None,
            (k, Item::Boolean(true)) if LIST_DIRECTIVES.contains(&k) => None,
            (k, Item::String(list)) if LIST_DIRECTIVES.contains(&k) => Some(list),
            (k, _) if LIST_DIRECTIVES.contains(&k) => return None,
            (k, Item::Boolean(true)) if FLAG_DIRECTIVES.contains(&k) => None,
            (k, _) if FLAG_DIRECTIVES.contains(&k) => return None,
            // Unknown directives are kept and ignored (RFC 9111 §5.2.3).
            (_, Item::Boolean(true)) => None,
            (_, Item::Integer(n)) => Some(n.to_string()),
            (_, Item::String(s) | Item::Token(s)) => Some(s),
            (_, Item::Other) => Some(String::new()),
        };
        entries.push((key, value));
    }
    Some(Directives::from_entries(entries))
}

/// A dictionary member's value, as far as cache directives need it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Boolean(bool),
    Integer(i64),
    String(String),
    Token(String),
    /// A Decimal, Byte Sequence, Date, Display String or Inner List.
    Other,
}

/// Parses a Structured Field Dictionary (RFC 9651 §4.2.2); `None` on any parse error.
/// Parameters are validated and dropped. A repeated key keeps its last value, in the
/// position of its first occurrence.
fn parse_dictionary(input: &str) -> Option<Vec<(String, Item)>> {
    let mut p = Parser {
        bytes: input.trim_matches(' ').as_bytes(),
        pos: 0,
    };
    let mut members: Vec<(String, Item)> = Vec::new();
    while !p.done() {
        let key = p.key()?;
        let item = if p.eat(b'=') {
            p.item_or_inner_list()?
        } else {
            p.parameters()?;
            Item::Boolean(true)
        };
        match members.iter_mut().find(|(k, _)| *k == key) {
            Some(member) => member.1 = item,
            None => members.push((key, item)),
        }
        p.ows();
        if p.done() {
            break;
        }
        if !p.eat(b',') {
            return None;
        }
        p.ows();
        if p.done() {
            return None;
        }
    }
    Some(members)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn done(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }

    fn key(&mut self) -> Option<String> {
        let start = self.pos;
        match self.peek()? {
            b'a'..=b'z' | b'*' => self.pos += 1,
            _ => return None,
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.*".contains(&b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        Some(String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned())
    }

    fn item_or_inner_list(&mut self) -> Option<Item> {
        if self.eat(b'(') {
            loop {
                self.sp();
                if self.eat(b')') {
                    break;
                }
                self.bare_item()?;
                self.parameters()?;
                if !matches!(self.peek(), Some(b' ' | b')')) {
                    return None;
                }
            }
            self.parameters()?;
            return Some(Item::Other);
        }
        let item = self.bare_item()?;
        self.parameters()?;
        Some(item)
    }

    fn parameters(&mut self) -> Option<()> {
        while self.eat(b';') {
            self.sp();
            self.key()?;
            if self.eat(b'=') {
                self.bare_item()?;
            }
        }
        Some(())
    }

    fn bare_item(&mut self) -> Option<Item> {
        match self.peek()? {
            b'-' | b'0'..=b'9' => self.number(),
            b'"' => self.string().map(Item::String),
            b'*' | b'A'..=b'Z' | b'a'..=b'z' => Some(Item::Token(self.token())),
            b':' => self.byte_sequence(),
            b'?' => self.boolean(),
            b'@' => {
                self.pos += 1;
                match self.number()? {
                    Item::Integer(_) => Some(Item::Other),
                    _ => None,
                }
            }
            b'%' => self.display_string(),
            _ => None,
        }
    }

    fn number(&mut self) -> Option<Item> {
        let negative = self.eat(b'-');
        let start = self.pos;
        let mut dot = None;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else if b == b'.' && dot.is_none() {
                dot = Some(self.pos);
                self.pos += 1;
            } else {
                break;
            }
            let len = self.pos - start;
            if (dot.is_none() && len > 15) || (dot.is_some() && len > 16) {
                return None;
            }
        }
        let digits = &self.bytes[start..self.pos];
        if digits.first().is_none_or(|b| !b.is_ascii_digit()) {
            return None;
        }
        match dot {
            None => {
                let mut n: i64 = 0;
                for b in digits {
                    n = n * 10 + i64::from(b - b'0');
                }
                Some(Item::Integer(if negative { -n } else { n }))
            }
            Some(at) => {
                let whole = at - start;
                let fraction = self.pos - at - 1;
                if whole > 12 || fraction == 0 || fraction > 3 {
                    return None;
                }
                Some(Item::Other)
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let b = self.peek()?;
            self.pos += 1;
            match b {
                b'\\' => {
                    let next = self.peek()?;
                    if next != b'"' && next != b'\\' {
                        return None;
                    }
                    self.pos += 1;
                    out.push(char::from(next));
                }
                b'"' => return Some(out),
                0x20..=0x7e => out.push(char::from(b)),
                _ => return None,
            }
        }
    }

    fn token(&mut self) -> String {
        let start = self.pos;
        self.pos += 1;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned()
    }

    fn byte_sequence(&mut self) -> Option<Item> {
        self.pos += 1;
        while let Some(b) = self.peek() {
            self.pos += 1;
            if b == b':' {
                return Some(Item::Other);
            }
            if !(b.is_ascii_alphanumeric() || b"+/=".contains(&b)) {
                return None;
            }
        }
        None
    }

    fn boolean(&mut self) -> Option<Item> {
        self.pos += 1;
        let value = match self.peek()? {
            b'0' => false,
            b'1' => true,
            _ => return None,
        };
        self.pos += 1;
        Some(Item::Boolean(value))
    }

    fn display_string(&mut self) -> Option<Item> {
        self.pos += 1;
        if !self.eat(b'"') {
            return None;
        }
        loop {
            let b = self.peek()?;
            self.pos += 1;
            match b {
                b'"' => return Some(Item::Other),
                b'%' => {
                    for _ in 0..2 {
                        let h = self.peek()?;
                        if !(h.is_ascii_digit() || (b'a'..=b'f').contains(&h)) {
                            return None;
                        }
                        self.pos += 1;
                    }
                }
                0x20..=0x7e => {}
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::cache_control::Seconds;

    fn cdn(lines: &[&str]) -> Option<Directives> {
        let mut h = HeaderMap::new();
        for l in lines {
            h.append(CDN_CACHE_CONTROL, l.parse().unwrap());
        }
        targeted_directives(&h, &HeaderName::from_static(CDN_CACHE_CONTROL))
    }

    #[test]
    fn rfc9213_2_1_directives_map_onto_cache_control_ones() {
        let d = cdn(&["max-age=3600, no-cache, private=\"x-a, x-b\"", "foobar"]).unwrap();
        assert_eq!(d.seconds("max-age"), Some(Seconds::Valid(3600)));
        assert!(d.unqualified_no_cache());
        assert_eq!(d.field_names("private"), ["x-a", "x-b"]);
        assert!(d.has("foobar"));
        let big = cdn(&["max-age=99999999999"]).unwrap();
        assert_eq!(
            big.seconds("max-age"),
            Some(Seconds::Valid(DELTA_SECONDS_MAX))
        );
        // `?0` is a false boolean: the directive is absent.
        assert!(!cdn(&["no-store=?0, max-age=5"]).unwrap().has("no-store"));
        // Parameters are dropped; an unknown directive may hold any type.
        let d = cdn(&["max-age=5;x=1, ext=(a b);y, other=1.5, bytes=:aGk=:"]).unwrap();
        assert_eq!(d.seconds("max-age"), Some(Seconds::Valid(5)));
        assert!(d.has("ext") && d.has("other") && d.has("bytes"));
    }

    #[test]
    fn rfc9213_2_1_invalid_or_empty_fields_are_ignored() {
        for bad in [
            "max-age=10000, &&&&&",
            "max-age=\"10000\"",
            "max-age =100",
            "max-age= 100",
            "MaX-aGe=3600",
            "max-age=-1",
            "max-age=1.5",
            "no-store=1",
            "private=x-a",
            "max-age=5,",
            "max-age=1234567890123456",
            "a=\"unterminated",
        ] {
            assert_eq!(cdn(&[bad]), None, "{bad:?}");
        }
        assert_eq!(cdn(&[""]), None);
        assert_eq!(cdn(&[]), None);
    }

    #[test]
    fn rfc9213_2_1_the_first_valid_targeted_field_replaces_cache_control() {
        let mut h = HeaderMap::new();
        h.insert("cache-control", "no-store".parse().unwrap());
        h.insert("cdn-cache-control", "max-age=10000".parse().unwrap());
        h.insert("rdock-cache-control", "max-age=\"x\"".parse().unwrap());
        let own = HeaderName::from_static("rdock-cache-control");
        let cdn = HeaderName::from_static(CDN_CACHE_CONTROL);
        let e = effective(&h, &[own.clone(), cdn.clone()]);
        assert_eq!(e.targeted.as_deref(), Some(CDN_CACHE_CONTROL));
        assert!(!e.expires());
        assert!(!e.cc.has("no-store"));
        let e = effective(&h, &[]);
        assert!(e.targeted.is_none() && e.expires() && e.cc.has("no-store"));
        h.insert("cdn-cache-control", "&&".parse().unwrap());
        assert!(effective(&h, &[own, cdn]).cc.has("no-store"));
    }

    #[test]
    fn rfc9651_dictionary_keys_repeat_last_value_wins() {
        let d = cdn(&["max-age=1, max-age=2"]).unwrap();
        assert_eq!(d.seconds("max-age"), Some(Seconds::Valid(2)));
    }
}
