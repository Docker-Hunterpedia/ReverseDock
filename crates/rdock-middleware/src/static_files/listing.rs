//! Directory listings (F-WEB-02, ADR-0030): the entries of one directory, negotiated by
//! `Accept` and rendered as a built-in HTML page or as JSON.
//!
//! Nothing here touches the file system; `root.rs` reads the entries (applying the `hidden` and
//! `symlinks` policies) and this module only turns them into bytes. No templates: the page is
//! built here from escaped names, so a file name is never interpreted as markup or as a URL.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use pingora::http::RequestHeader;
use serde::Serialize;

/// Most entries one listing holds. More are cut off and the answer says so (`truncated`).
pub(crate) const MAX_ENTRIES: usize = 10_000;

/// Most directory entries read for one listing, hidden and refused ones included, so a
/// directory of millions of names costs bounded work. Reaching it also marks the listing as
/// cut off.
pub(crate) const MAX_SCANNED: usize = 10 * MAX_ENTRIES;

/// The strictest policy that still renders the page: nothing may be loaded and nothing is
/// styled, so a name that slipped through escaping still could not run or fetch anything. The
/// page relies on the browser's default styles (and `color-scheme`) instead of inline CSS.
pub(crate) const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// What a name is, after the `symlinks` policy has been applied: a followed link is what it
/// leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EntryKind {
    File,
    Dir,
}

/// One listed name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Entry {
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) kind: EntryKind,
    /// Bytes, for files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) size: Option<u64>,
    /// RFC 3339, UTC, to the second; absent when the file system gives none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) modified: Option<String>,
    /// The name is a symbolic link that the `symlinks` policy follows (`kind` is its target's).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) symlink: bool,
}

/// The entries of a directory as read, in file system order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Listing {
    /// The directory relative to the root, without slashes at either end; empty for the root.
    pub(crate) relative: String,
    /// The request path ended with `/`; otherwise links name the directory first.
    pub(crate) trailing_slash: bool,
    pub(crate) entries: Vec<Entry>,
    /// More entries exist than are shown.
    pub(crate) truncated: bool,
}

/// The two representations of a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Html,
    Json,
}

/// A rendered listing.
pub(crate) struct Rendered {
    pub(crate) content_type: &'static str,
    pub(crate) body: Bytes,
}

#[derive(Serialize)]
struct JsonListing<'a> {
    path: &'a str,
    entries: &'a [Entry],
    truncated: bool,
}

impl Listing {
    /// Sorts by name, bytewise on the UTF-8 name, directories and files mixed. The order does
    /// not depend on the locale or the file system, so listings are stable and testable.
    pub(crate) fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.name.cmp(&b.name));
    }

    /// The directory as the client addresses it: `/`, `/docs/`, `/docs/api/`.
    pub(crate) fn url_path(&self) -> String {
        if self.relative.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}/", self.relative)
        }
    }

    pub(crate) fn render(&self, format: Format) -> Option<Rendered> {
        match format {
            Format::Html => Some(Rendered {
                content_type: "text/html; charset=utf-8",
                body: Bytes::from(self.html()),
            }),
            Format::Json => {
                let json = JsonListing {
                    path: &self.url_path(),
                    entries: &self.entries,
                    truncated: self.truncated,
                };
                serde_json::to_vec(&json).ok().map(|body| Rendered {
                    // RFC 8259 §11: JSON has no `charset` parameter; it is always UTF-8.
                    content_type: "application/json",
                    body: Bytes::from(body),
                })
            }
        }
    }

    fn html(&self) -> String {
        let shown = display(&self.url_path());
        let mut page = String::with_capacity(512 + self.entries.len() * 160);
        page.push_str(
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <meta name=\"color-scheme\" content=\"light dark\">\n\
             <meta name=\"robots\" content=\"noindex\">\n",
        );
        let _ = write!(
            page,
            "<title>Index of {shown}</title>\n</head>\n<body>\n<h1>Index of {shown}</h1>\n"
        );
        page.push_str(
            "<table>\n<thead><tr><th scope=\"col\" align=\"left\">Name</th>\
             <th scope=\"col\" align=\"right\">Size</th>\
             <th scope=\"col\" align=\"left\">Last modified (UTC)</th></tr></thead>\n<tbody>\n",
        );
        // Links are relative to the directory, so a `strip_prefix` before `static` cannot break
        // them. Without a trailing slash (`directory_redirect: false`) they name the directory
        // first.
        let base = if self.trailing_slash {
            "./".to_owned()
        } else {
            let last = self.relative.rsplit('/').next().unwrap_or_default();
            format!("{}/", encode(last))
        };
        if !self.relative.is_empty() {
            let parent = if self.trailing_slash { "../" } else { "./" };
            let _ = writeln!(
                page,
                "<tr><td><a href=\"{parent}\">../</a></td><td></td><td></td></tr>"
            );
        }
        for entry in &self.entries {
            let (slash, size) = match entry.kind {
                EntryKind::Dir => ("/", String::new()),
                EntryKind::File => ("", entry.size.map(human_size).unwrap_or_default()),
            };
            let _ = writeln!(
                page,
                "<tr><td><a href=\"{base}{}{slash}\">{}{slash}</a></td>\
                 <td align=\"right\">{size}</td><td>{}</td></tr>",
                encode(&entry.name),
                display(&entry.name),
                entry.modified.as_deref().unwrap_or_default(),
            );
        }
        page.push_str("</tbody>\n</table>\n");
        if self.entries.is_empty() {
            page.push_str("<p>This directory is empty.</p>\n");
        }
        if self.truncated {
            let _ = writeln!(
                page,
                "<p>Only some of the entries are shown: a listing holds at most {MAX_ENTRIES}.</p>"
            );
        }
        page.push_str("</body>\n</html>\n");
        page
    }
}

/// Everything but the unreserved characters of RFC 3986 §2.3 is escaped, so `:` cannot make a
/// name look like a URL scheme and `?`, `#`, `%` and `/` stay part of the name.
const ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// A name as one URL path segment.
fn encode(name: &str) -> String {
    utf8_percent_encode(name, ENCODE).to_string()
}

/// A name as HTML text. `&`, `<`, `>`, `"` and `'` are escaped; control characters and the
/// Unicode bidirectional controls (which can reorder what the reader sees, as in
/// `evil\u{202e}gpj.exe`) are shown as U+FFFD. The JSON listing keeps names exactly.
fn display(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control()
                || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
            {
                out.push('\u{fffd}');
            }
            c => out.push(c),
        }
    }
    out
}

/// `1023 B`, `1.5 KiB`, `12.0 MiB`.
#[allow(clippy::cast_precision_loss)]
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// `2026-11-11T10:20:30Z`; `None` outside the years 0000 to 9999.
pub(crate) fn rfc3339(time: SystemTime) -> Option<String> {
    let seconds: i64 = match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).ok()?,
        Err(before) => {
            // Round toward the earlier second: the time is before the epoch.
            let d = before.duration();
            -i64::try_from(d.as_secs()).ok()? - i64::from(d.subsec_nanos() > 0)
        }
    };
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Howard Hinnant's `civil_from_days`, valid for the whole proleptic Gregorian calendar.
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

/// HTML unless the client prefers JSON: `Accept` ranges are weighed by their `q` and the most
/// specific range that matches a type decides its weight (RFC 9110 §12.5.1). A tie, a missing
/// header and an `Accept` that accepts neither all give HTML. Parameters other than `q` are
/// ignored.
pub(crate) fn negotiate(req: &RequestHeader) -> Format {
    let mut ranges: Vec<(String, String, f32)> = Vec::new();
    for value in req.headers.get_all(http::header::ACCEPT) {
        let Ok(text) = value.to_str() else { continue };
        ranges.extend(text.split(',').filter_map(parse_range));
    }
    let weight = |kind: &str, subtype: &str| {
        ranges
            .iter()
            .filter_map(|(k, s, q)| {
                let specificity = match (k.as_str(), s.as_str()) {
                    ("*", "*") => 0,
                    (k2, "*") if k2 == kind => 1,
                    (k2, s2) if k2 == kind && s2 == subtype => 2,
                    _ => return None,
                };
                Some((specificity, *q))
            })
            .max_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)))
            .map_or(0.0, |(_, q)| q)
    };
    if weight("application", "json") > weight("text", "html") {
        Format::Json
    } else {
        Format::Html
    }
}

/// One `Accept` item: lower-case type, subtype and weight. Items that are not a media range or
/// carry a `q` outside 0 to 1 are ignored.
fn parse_range(item: &str) -> Option<(String, String, f32)> {
    let mut parts = item.split(';');
    let (kind, subtype) = parts.next()?.trim().split_once('/')?;
    let (kind, subtype) = (
        kind.trim().to_ascii_lowercase(),
        subtype.trim().to_ascii_lowercase(),
    );
    if kind.is_empty() || subtype.is_empty() || (kind == "*" && subtype != "*") {
        return None;
    }
    let mut q = 1.0;
    for param in parts {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            q = value.trim().parse::<f32>().ok()?;
            if !(0.0..=1.0).contains(&q) {
                return None;
            }
        }
    }
    Some((kind, subtype, q))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::request;

    fn file(name: &str) -> Entry {
        Entry {
            name: name.to_owned(),
            kind: EntryKind::File,
            size: Some(12),
            modified: Some("2026-11-11T10:20:30Z".to_owned()),
            symlink: false,
        }
    }

    fn dir(name: &str) -> Entry {
        Entry {
            kind: EntryKind::Dir,
            size: None,
            ..file(name)
        }
    }

    fn listing(relative: &str, entries: Vec<Entry>) -> Listing {
        Listing {
            relative: relative.to_owned(),
            trailing_slash: true,
            entries,
            truncated: false,
        }
    }

    fn html(listing: &Listing) -> String {
        let rendered = listing.render(Format::Html).unwrap();
        assert_eq!(rendered.content_type, "text/html; charset=utf-8");
        String::from_utf8(rendered.body.to_vec()).unwrap()
    }

    /// Every `href` of the page, in order.
    fn hrefs(page: &str) -> Vec<&str> {
        page.split("href=\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .collect()
    }

    #[test]
    fn nasty_names_are_escaped_in_text_and_encoded_in_links() {
        let names = [
            "<script>alert(1)</script>",
            "a\"b'c",
            "a&b&amp;c",
            "hash#tag",
            "what?x=1",
            "100%",
            "%2e%2e",
            "with space.txt",
            "caf\u{e9}.txt",
            "\u{65e5}\u{672c}.txt",
            "-rf",
            "--help",
            "javascript:alert(1)",
            "data:text/html,<b>x",
            "//evil.example/x",
            "a;b",
            "semi:colon",
            "tab\there",
            "new\nline",
            "evil\u{202e}gpj.exe",
            "\"><img src=x onerror=alert(1)>",
        ];
        let page = html(&listing("dir", names.iter().map(|n| file(n)).collect()));
        // The only markup in the page is ours: no name turned into a tag or an attribute.
        assert!(!page.contains("<script"), "{page}");
        assert!(!page.contains("<img"), "{page}");
        assert!(!page.contains("onerror=alert(1)>"), "{page}");
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(page.contains("a&quot;b&#39;c"));
        assert!(page.contains("a&amp;b&amp;amp;c"));
        assert!(
            page.contains("evil\u{fffd}gpj.exe"),
            "bidi control replaced"
        );
        assert!(!page.contains('\u{202e}'));
        assert!(!page.contains("new\nline"));
        let links = hrefs(&page);
        // The parent link first, then one link per name, in order.
        assert_eq!(links[0], "../");
        let expected = [
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "a%22b%27c",
            "a%26b%26amp%3Bc",
            "hash%23tag",
            "what%3Fx%3D1",
            "100%25",
            "%252e%252e",
            "with%20space.txt",
            "caf%C3%A9.txt",
            "%E6%97%A5%E6%9C%AC.txt",
            "-rf",
            "--help",
            "javascript%3Aalert%281%29",
            "data%3Atext%2Fhtml%2C%3Cb%3Ex",
            "%2F%2Fevil.example%2Fx",
            "a%3Bb",
            "semi%3Acolon",
            "tab%09here",
            "new%0Aline",
            "evil%E2%80%AEgpj.exe",
            "%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
        ];
        assert_eq!(links.len(), expected.len() + 1);
        for (link, name) in links[1..].iter().zip(expected) {
            // Always relative to the directory, never a scheme or an authority.
            assert_eq!(*link, format!("./{name}"));
            assert!(link.starts_with("./"));
            assert!(
                link[2..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%')),
                "{link}"
            );
        }
    }

    #[test]
    fn every_link_decodes_back_to_its_name() {
        for name in [
            "a b",
            "caf\u{e9}",
            "100%",
            "x#y?z",
            "-rf",
            "javascript:1",
            "%41",
        ] {
            let encoded = encode(name);
            let decoded = percent_encoding::percent_decode_str(&encoded)
                .decode_utf8()
                .unwrap();
            assert_eq!(decoded, name);
        }
    }

    #[test]
    fn directories_have_a_trailing_slash_and_the_root_has_no_parent() {
        let page = html(&listing("", vec![dir("sub"), file("a.txt")]));
        assert_eq!(hrefs(&page), ["./sub/", "./a.txt"]);
        assert!(page.contains(">sub/</a>"));
        assert!(page.contains("<title>Index of /</title>"));
        let nested = html(&listing("a/b", vec![]));
        assert_eq!(hrefs(&nested), ["../"]);
        assert!(nested.contains("<h1>Index of /a/b/</h1>"));
        assert!(nested.contains("This directory is empty."));
    }

    #[test]
    fn without_a_trailing_slash_links_name_the_directory_first() {
        let mut l = listing("a/my dir", vec![file("x y"), dir("sub")]);
        l.trailing_slash = false;
        assert_eq!(
            hrefs(&html(&l)),
            ["./", "my%20dir/x%20y", "my%20dir/sub/"],
            "parent, file, directory"
        );
    }

    #[test]
    fn the_page_shows_sizes_times_and_the_cut_off() {
        let mut l = listing("", vec![file("a")]);
        l.entries[0].size = Some(1536);
        l.truncated = true;
        let page = html(&l);
        assert!(page.contains("1.5 KiB"));
        assert!(page.contains("2026-11-11T10:20:30Z"));
        assert!(page.contains("at most 10000"));
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(human_size(u64::MAX), "16384.0 PiB");
    }

    #[test]
    fn json_has_the_documented_shape() {
        let mut link = file("link");
        link.symlink = true;
        let mut l = listing("docs", vec![file("a.txt"), dir("sub"), link]);
        l.truncated = true;
        let rendered = l.render(Format::Json).unwrap();
        assert_eq!(rendered.content_type, "application/json");
        let json: serde_json::Value = serde_json::from_slice(&rendered.body).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "path": "/docs/",
                "truncated": true,
                "entries": [
                    { "name": "a.txt", "type": "file", "size": 12, "modified": "2026-11-11T10:20:30Z" },
                    { "name": "sub", "type": "dir", "modified": "2026-11-11T10:20:30Z" },
                    { "name": "link", "type": "file", "size": 12, "modified": "2026-11-11T10:20:30Z", "symlink": true },
                ],
            })
        );
        let root = listing("", vec![]).render(Format::Json).unwrap();
        assert_eq!(
            &root.body[..],
            br#"{"path":"/","entries":[],"truncated":false}"#
        );
        // Names are kept exactly, JSON-escaped.
        let odd = listing("", vec![file("<b>\"\u{202e}\n")])
            .render(Format::Json)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&odd.body).unwrap();
        assert_eq!(json["entries"][0]["name"], "<b>\"\u{202e}\n");
    }

    #[test]
    fn sorting_is_bytewise_with_directories_and_files_mixed() {
        let mut l = listing(
            "",
            vec![
                file("b"),
                dir("a"),
                file("B"),
                file("_x"),
                file("\u{e9}"),
                dir("a-b"),
                file("10"),
                file("9"),
            ],
        );
        l.sort();
        let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["10", "9", "B", "_x", "a", "a-b", "b", "\u{e9}"]);
    }

    #[test]
    fn rfc3339_formats_utc() {
        let at = |secs: i64| {
            let time = if secs >= 0 {
                UNIX_EPOCH + std::time::Duration::from_secs(secs.unsigned_abs())
            } else {
                UNIX_EPOCH - std::time::Duration::from_secs(secs.unsigned_abs())
            };
            rfc3339(time).unwrap()
        };
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(-1), "1969-12-31T23:59:59Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z", "leap day");
        assert_eq!(at(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(at(4_102_444_799), "2099-12-31T23:59:59Z");
        assert_eq!(at(253_402_300_799), "9999-12-31T23:59:59Z");
        assert_eq!(at(-62_135_596_800), "0001-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH + std::time::Duration::from_secs(253_402_300_800)),
            None
        );
        let half = UNIX_EPOCH - std::time::Duration::from_millis(500);
        assert_eq!(rfc3339(half).unwrap(), "1969-12-31T23:59:59Z");
    }

    fn pick(accept: &[&str]) -> Format {
        let headers: Vec<(&'static str, &str)> = accept.iter().map(|v| ("accept", *v)).collect();
        negotiate(&request("GET", "/", &headers))
    }

    #[test]
    fn accept_chooses_json_only_when_it_is_preferred() {
        assert_eq!(pick(&[]), Format::Html, "no header");
        assert_eq!(pick(&["*/*"]), Format::Html, "tie goes to HTML");
        assert_eq!(pick(&[""]), Format::Html);
        assert_eq!(pick(&["text/html"]), Format::Html);
        assert_eq!(pick(&["application/json"]), Format::Json);
        assert_eq!(
            pick(&["Application/JSON"]),
            Format::Json,
            "case-insensitive"
        );
        assert_eq!(pick(&["application/json, text/plain"]), Format::Json);
        assert_eq!(
            pick(&["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"]),
            Format::Html,
            "a browser"
        );
        assert_eq!(pick(&["application/json, text/html;q=0.5"]), Format::Json);
        assert_eq!(pick(&["application/json;q=0.5, text/html"]), Format::Html);
        assert_eq!(
            pick(&["application/json;q=0.9, text/html;q=0.8"]),
            Format::Json
        );
        assert_eq!(
            pick(&["text/html;q=0.1, application/json;q=0.1"]),
            Format::Html
        );
        assert_eq!(
            pick(&["application/json;q=0, */*"]),
            Format::Html,
            "q=0 refuses it"
        );
        assert_eq!(
            pick(&["text/html;q=0, */*"]),
            Format::Json,
            "HTML refused by name"
        );
        assert_eq!(pick(&["application/*"]), Format::Json);
        assert_eq!(pick(&["text/*;q=0.2, application/json"]), Format::Json);
        assert_eq!(
            pick(&["text/html;q=0.1, */*;q=0.9"]),
            Format::Json,
            "the more specific range decides its own weight"
        );
        assert_eq!(pick(&["*/*;q=0.5, application/json;q=0.4"]), Format::Html);
        assert_eq!(
            pick(&["text/html", "application/json;q=0.2"]),
            Format::Html,
            "two lines"
        );
        assert_eq!(
            pick(&["application/json;Q=1, text/html;q=0.5"]),
            Format::Json
        );
        assert_eq!(
            pick(&["application/json;charset=utf-8;q=0.9, text/html;q=0.1"]),
            Format::Json
        );
        assert_eq!(pick(&["image/png"]), Format::Html, "neither accepted: HTML");
    }

    #[test]
    fn malformed_accept_is_ignored() {
        for accept in [
            "application/json;q=abc, text/html;q=0.5",
            "application/json;q=2, text/html;q=0.5",
            "application/json;q=-1, text/html;q=0.5",
            "json, html",
            "*/json",
            "/",
            ";;;",
            ",,,",
        ] {
            assert_eq!(pick(&[accept]), Format::Html, "{accept}");
        }
    }
}
