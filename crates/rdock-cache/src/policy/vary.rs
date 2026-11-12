//! `Vary` (RFC 9110 §12.5.5, RFC 9111 §4.1): which request fields select a stored variant.

use http::HeaderMap;
use http::header::VARY;
use pingora::cache::VarianceBuilder;

/// A response's `Vary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vary {
    /// No `Vary`: one variant.
    None,
    /// `Vary: *` (anywhere in the list): never matches, never stored.
    Star,
    /// The nominated request fields: lower case, sorted, without duplicates.
    Fields(Vec<String>),
}

/// Parses every `Vary` field line of `headers`.
#[must_use]
pub fn parse_vary(headers: &HeaderMap) -> Vary {
    let mut fields = Vec::new();
    for value in headers.get_all(VARY) {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for name in text.split(',') {
            let name = name.trim_matches([' ', '\t']);
            if name == "*" {
                return Vary::Star;
            }
            if !name.is_empty() {
                fields.push(name.to_ascii_lowercase());
            }
        }
    }
    if fields.is_empty() {
        return Vary::None;
    }
    fields.sort();
    fields.dedup();
    Vary::Fields(fields)
}

/// Fields whose values compare without regard to case (lists of tokens).
const CASELESS: [&str; 4] = [
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
];

/// The normalised value of request field `name`: field lines joined, list items trimmed and
/// joined with `,`, lower case for the content-negotiation fields; `None` when absent.
#[must_use]
pub fn normalized_value(request: &HeaderMap, name: &str) -> Option<Vec<u8>> {
    let mut lines = request.get_all(name).iter().peekable();
    lines.peek()?;
    let mut items: Vec<String> = Vec::new();
    for line in lines {
        let text = String::from_utf8_lossy(line.as_bytes());
        for item in text.split(',') {
            let item = item.trim_matches([' ', '\t']);
            if !item.is_empty() {
                items.push(item.split_whitespace().collect::<Vec<_>>().join(" "));
            }
        }
    }
    let mut joined = items.join(",");
    if CASELESS.contains(&name) {
        joined.make_ascii_lowercase();
    }
    Some(joined.into_bytes())
}

/// The variance of a request for a response that varies on `fields`; `None` when there are
/// none. An absent field and an empty one are different variants.
#[must_use]
pub fn variance(fields: &[String], request: &HeaderMap) -> Option<[u8; 16]> {
    if fields.is_empty() {
        return None;
    }
    let mut builder = VarianceBuilder::new();
    for name in fields {
        let value = match normalized_value(request, name) {
            Some(mut v) => {
                v.insert(0, b'=');
                v
            }
            None => b"\0absent".to_vec(),
        };
        builder.add_owned_name_value(name.clone(), value);
    }
    builder.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(*n, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn rfc9111_4_1_vary_lists_are_merged_lowercased_and_star_wins() {
        assert_eq!(parse_vary(&HeaderMap::new()), Vary::None);
        assert_eq!(
            parse_vary(&headers(&[
                ("vary", "Accept-Encoding, accept"),
                ("vary", "X-A,accept")
            ])),
            Vary::Fields(vec![
                "accept".into(),
                "accept-encoding".into(),
                "x-a".into()
            ])
        );
        assert_eq!(
            parse_vary(&headers(&[("vary", "accept"), ("vary", "*")])),
            Vary::Star
        );
        assert_eq!(parse_vary(&headers(&[("vary", " , ")])), Vary::None);
    }

    #[test]
    fn rfc9111_4_1_variance_normalises_whitespace_lines_and_case() {
        let fields = vec!["accept-encoding".to_owned(), "x-a".to_owned()];
        let a = headers(&[("accept-encoding", "GZIP,  br"), ("x-a", "v")]);
        let b = headers(&[
            ("accept-encoding", "gzip"),
            ("accept-encoding", "br"),
            ("x-a", "v"),
        ]);
        assert_eq!(variance(&fields, &a), variance(&fields, &b));
        let c = headers(&[("accept-encoding", "gzip, br"), ("x-a", "V")]);
        assert_ne!(
            variance(&fields, &a),
            variance(&fields, &c),
            "x-a keeps its case"
        );
        assert_eq!(variance(&[], &a), None);
    }

    #[test]
    fn rfc9111_4_1_absent_and_empty_fields_are_different_variants() {
        let fields = vec!["x-a".to_owned()];
        let absent = variance(&fields, &HeaderMap::new());
        let empty = variance(&fields, &headers(&[("x-a", "")]));
        assert!(absent.is_some());
        assert_ne!(absent, empty);
    }
}
