//! The HTTP answer for a found file: validators, the RFC 9110 §13.2.2 precondition order,
//! byte ranges (§14) and the representation headers.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderName,
    IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE, LAST_MODIFIED,
    RANGE, VARY,
};
use http::{HeaderValue, Method};
use http_range_header::{EndPosition, StartPosition};
use pingora::http::RequestHeader;
use rdock_model::middleware::{CompressAlgorithm, StaticConfig};
use ring::rand::{SecureRandom, SystemRandom};

use super::body::{FileBody, Segment};
use super::listing::{self, Listing};
use super::root::Found;
use crate::{Body, BuildError, Reply};

const OCTET_STREAM: &str = "application/octet-stream";
const NOSNIFF: HeaderName = HeaderName::from_static("x-content-type-options");
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");

/// Media types that differ from `mime_guess`: RFC 9239 makes `text/javascript` the only
/// JavaScript type, also for modules.
const TYPE_OVERRIDES: [(&str, &str); 1] = [("mjs", "text/javascript")];

/// How the representation headers of answers are built.
#[derive(Debug)]
pub(crate) struct Answers {
    max_ranges: usize,
    nosniff: bool,
    /// `Vary: Accept-Encoding` on every answer: the representation depends on it.
    vary: bool,
    cache_default: HeaderValue,
    /// Path prefix → value, longest prefix first.
    cache_paths: Vec<(String, HeaderValue)>,
    /// Lowercase extension → media type.
    types: BTreeMap<String, HeaderValue>,
}

/// The selected representation: a file or one of its sidecars.
struct Representation {
    file: Arc<std::fs::File>,
    len: u64,
    modified: SystemTime,
    etag: String,
    coding: Option<CompressAlgorithm>,
    /// URL path of the file as built, for its media type and `Cache-Control`.
    served: String,
}

/// What the preconditions decide.
#[derive(Debug, PartialEq, Eq)]
enum Precondition {
    Proceed,
    Failed,
    NotModified,
}

/// How much of the representation to send.
#[derive(Debug, PartialEq, Eq)]
enum Ranges {
    Whole,
    /// Inclusive `(first, last)` byte positions, sorted, not overlapping.
    Parts(Vec<(u64, u64)>),
    Unsatisfiable,
}

fn header_value(value: &str, what: &str) -> Result<HeaderValue, BuildError> {
    HeaderValue::from_str(value)
        .map_err(|_| BuildError::Invalid(format!("`{value}` is not a valid {what}")))
}

/// Seconds since the epoch: HTTP dates have no finer resolution.
fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A strong validator from the modification time (ns) and size, like NGINX's, with the
/// sidecar's coding so the variants of a file never share a tag.
fn entity_tag(modified: SystemTime, len: u64, coding: Option<CompressAlgorithm>) -> String {
    let nanos = modified
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut tag = format!("\"{nanos:x}-{len:x}");
    if let Some(coding) = coding {
        let _ = write!(tag, "-{}", coding_name(coding));
    }
    tag.push('"');
    tag
}

fn coding_name(coding: CompressAlgorithm) -> &'static str {
    match coding {
        CompressAlgorithm::Zstd => "zstd",
        CompressAlgorithm::Br => "br",
        CompressAlgorithm::Gzip => "gzip",
    }
}

/// `text/*`, JavaScript, JSON and XML (SVG included) are sent with `charset=utf-8`.
fn with_charset(media: &str) -> String {
    let textual = media.starts_with("text/")
        || matches!(
            media,
            "application/javascript" | "application/json" | "application/xml"
        )
        || media.ends_with("+json")
        || media.ends_with("+xml");
    if textual {
        format!("{media}; charset=utf-8")
    } else {
        media.to_owned()
    }
}

/// All values of a header, joined as one list.
fn list(req: &RequestHeader, name: &HeaderName) -> Option<String> {
    let values: Vec<&str> = req
        .headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(","))
}

fn date(req: &RequestHeader, name: &HeaderName) -> Option<SystemTime> {
    let value = req.headers.get(name)?.to_str().ok()?;
    httpdate::parse_http_date(value.trim()).ok()
}

/// Whether an `If-Match`/`If-None-Match` list holds `*` or a tag `matches` accepts.
fn any_tag(list: &str, matches: impl Fn(&str) -> bool) -> bool {
    list.trim() == "*" || list.split(',').map(str::trim).any(matches)
}

impl Representation {
    fn new(found: Found) -> Self {
        let modified = found.metadata.modified().unwrap_or(UNIX_EPOCH);
        let len = found.metadata.len();
        Self {
            etag: entity_tag(modified, len, found.coding),
            file: Arc::new(found.file),
            len,
            modified,
            coding: found.coding,
            served: format!("/{}", found.served),
        }
    }

    /// RFC 9110 §8.8.3.2: strong comparison needs two strong, equal tags.
    fn strong_match(&self, tag: &str) -> bool {
        tag == self.etag
    }

    /// Weak comparison ignores `W/`.
    fn weak_match(&self, tag: &str) -> bool {
        tag.strip_prefix("W/").unwrap_or(tag) == self.etag
    }

    /// RFC 9110 §13.2.2, steps 1 to 4 (the methods here are GET and HEAD).
    fn preconditions(&self, req: &RequestHeader) -> Precondition {
        let modified = seconds(self.modified);
        if let Some(tags) = list(req, &IF_MATCH) {
            if !any_tag(&tags, |t| self.strong_match(t)) {
                return Precondition::Failed;
            }
        } else if let Some(since) = date(req, &IF_UNMODIFIED_SINCE)
            && modified > seconds(since)
        {
            return Precondition::Failed;
        }
        if let Some(tags) = list(req, &IF_NONE_MATCH) {
            if any_tag(&tags, |t| self.weak_match(t)) {
                return Precondition::NotModified;
            }
        } else if let Some(since) = date(req, &IF_MODIFIED_SINCE)
            && modified <= seconds(since)
        {
            return Precondition::NotModified;
        }
        Precondition::Proceed
    }

    /// RFC 9110 §13.1.5: `If-Range` holds for the current strong tag or the exact
    /// modification date; a weak tag never matches.
    fn if_range_holds(&self, req: &RequestHeader) -> bool {
        let Some(value) = req.headers.get(IF_RANGE).and_then(|v| v.to_str().ok()) else {
            return true;
        };
        let value = value.trim();
        if value.starts_with('"') || value.starts_with("W/") {
            return self.strong_match(value);
        }
        httpdate::parse_http_date(value).is_ok_and(|d| seconds(d) == seconds(self.modified))
    }
}

/// The ranges to send for a `Range` header on a representation of `len` bytes (RFC 9110
/// §14.1.1, §14.2). A malformed header, an invalid range (last before first) or more ranges
/// than allowed means the whole representation; ranges that start past the end are dropped,
/// and none left means unsatisfiable. Overlapping and adjacent ranges are merged.
fn select_ranges(header: &str, len: u64, max: usize) -> Ranges {
    let Ok(parsed) = http_range_header::parse_range_header(header) else {
        return Ranges::Whole;
    };
    if parsed.ranges.len() > max {
        return Ranges::Whole;
    }
    let mut parts = Vec::new();
    for range in &parsed.ranges {
        let (first, last) = match (range.start, range.end) {
            (StartPosition::Index(first), EndPosition::Index(last)) if last < first => {
                return Ranges::Whole;
            }
            (StartPosition::Index(first), EndPosition::Index(last)) => (first, last),
            (StartPosition::Index(first), EndPosition::LastByte) => (first, u64::MAX),
            (StartPosition::FromLast(suffix), _) => (len.saturating_sub(suffix), u64::MAX),
        };
        if first < len {
            parts.push((first, last.min(len - 1)));
        }
    }
    if parts.is_empty() {
        return Ranges::Unsatisfiable;
    }
    parts.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(parts.len());
    for (first, last) in parts {
        match merged.last_mut() {
            Some(previous) if first <= previous.1.saturating_add(1) => {
                previous.1 = previous.1.max(last);
            }
            _ => merged.push((first, last)),
        }
    }
    Ranges::Parts(merged)
}

/// A `multipart/byteranges` boundary that cannot be predicted from outside.
fn boundary() -> Option<String> {
    let mut random = [0u8; 12];
    SystemRandom::new().fill(&mut random).ok()?;
    Some(random.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    }))
}

impl Answers {
    pub(crate) fn new(config: &StaticConfig) -> Result<Self, BuildError> {
        let mut cache_paths = config
            .cache_control
            .paths
            .iter()
            .map(|(prefix, value)| Ok((prefix.clone(), header_value(value, "Cache-Control")?)))
            .collect::<Result<Vec<_>, BuildError>>()?;
        cache_paths.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.len()));
        let types = config
            .types
            .iter()
            .map(|(ext, media)| Ok((ext.to_ascii_lowercase(), header_value(media, "media type")?)))
            .collect::<Result<_, BuildError>>()?;
        Ok(Self {
            max_ranges: usize::try_from(config.max_ranges).unwrap_or(1),
            nosniff: config.nosniff,
            vary: !config.precompressed.is_empty(),
            cache_default: header_value(&config.cache_control.default, "Cache-Control")?,
            cache_paths,
            types,
        })
    }

    /// The answer for `found`: 200, 206, 304, 412 or 416.
    pub(crate) fn reply(&self, req: &RequestHeader, found: Found) -> Reply {
        let rep = Representation::new(found);
        match rep.preconditions(req) {
            Precondition::Failed => return self.vary(Reply::status(412)),
            Precondition::NotModified => {
                let mut reply = self.validators(Reply::status(304), &rep);
                reply.body = Some(Body::Bytes(Bytes::new()));
                return reply;
            }
            Precondition::Proceed => {}
        }
        // Range is defined for GET only (RFC 9110 §14.2).
        let ranges = match req.headers.get(RANGE).and_then(|v| v.to_str().ok()) {
            Some(header) if req.method == Method::GET && rep.if_range_holds(req) => {
                select_ranges(header, rep.len, self.max_ranges)
            }
            _ => Ranges::Whole,
        };
        match ranges {
            Ranges::Unsatisfiable => {
                let range = format!("bytes */{}", rep.len);
                self.vary(Reply::status(416))
                    .header(CONTENT_RANGE, value_of(&range))
            }
            Ranges::Parts(parts) if parts.len() == 1 => {
                let (first, last) = parts[0];
                let range = format!("bytes {first}-{last}/{}", rep.len);
                let segment = Segment::File {
                    offset: first,
                    len: last - first + 1,
                };
                self.entity(206, &rep, vec![segment])
                    .header(CONTENT_RANGE, value_of(&range))
            }
            // A multipart body has no single coding to declare, so a sidecar is sent whole.
            Ranges::Parts(parts) if rep.coding.is_none() => self.multipart(&rep, &parts),
            Ranges::Parts(_) | Ranges::Whole => {
                let whole = Segment::File {
                    offset: 0,
                    len: rep.len,
                };
                self.entity(200, &rep, vec![whole])
            }
        }
    }

    /// The answer for a directory listing: always `200`, whatever the conditional and range
    /// headers say. A listing has no validator, because nothing cheap and correct can make one
    /// (the directory's modification time does not change when a file inside it does, and a
    /// hash of the page would cost the whole read anyway), so there is nothing a precondition
    /// could be compared with; and ranges of a generated page are of no use.
    pub(crate) fn listing(&self, req: &RequestHeader, found: &Listing) -> Reply {
        let rendered = listing::negotiate(req);
        let Some(rendered) = found.render(rendered) else {
            return Reply::status(500);
        };
        let mut reply = Reply::status(200)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static(rendered.content_type),
            )
            .header(VARY, HeaderValue::from_static("Accept"))
            .header(CACHE_CONTROL, self.cache_control(&found.url_path()).clone())
            .header(
                CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(listing::CONTENT_SECURITY_POLICY),
            )
            .header(REFERRER_POLICY, HeaderValue::from_static("no-referrer"))
            .header(NOSNIFF, HeaderValue::from_static("nosniff"));
        reply.body = Some(Body::Bytes(rendered.body));
        reply
    }

    fn vary(&self, reply: Reply) -> Reply {
        if self.vary {
            reply.header(VARY, HeaderValue::from_static("Accept-Encoding"))
        } else {
            reply
        }
    }

    /// The headers a 304 carries too (RFC 9110 §15.4.5).
    fn validators(&self, reply: Reply, rep: &Representation) -> Reply {
        let reply = reply
            .header(ETAG, value_of(&rep.etag))
            .header(
                LAST_MODIFIED,
                value_of(&httpdate::fmt_http_date(rep.modified)),
            )
            .header(CACHE_CONTROL, self.cache_control(&rep.served).clone());
        self.vary(reply)
    }

    /// A 200 or single-range 206 with the representation headers.
    fn entity(&self, status: u16, rep: &Representation, segments: Vec<Segment>) -> Reply {
        let mut reply = self
            .validators(Reply::status(status), rep)
            .header(CONTENT_TYPE, self.content_type(&rep.served))
            .header(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        if let Some(coding) = rep.coding {
            reply = reply.header(
                CONTENT_ENCODING,
                HeaderValue::from_static(coding_name(coding)),
            );
        }
        if self.nosniff {
            reply = reply.header(NOSNIFF, HeaderValue::from_static("nosniff"));
        }
        reply.body = Some(Body::File(FileBody::new(rep.file.clone(), segments)));
        reply
    }

    /// A 206 with `multipart/byteranges` (RFC 9110 §14.6), or the whole file when no boundary
    /// can be made.
    fn multipart(&self, rep: &Representation, parts: &[(u64, u64)]) -> Reply {
        let Some(boundary) = boundary() else {
            let whole = Segment::File {
                offset: 0,
                len: rep.len,
            };
            return self.entity(200, rep, vec![whole]);
        };
        let content_type = self.content_type(&rep.served);
        let part_type = content_type.to_str().unwrap_or(OCTET_STREAM);
        let mut segments = Vec::with_capacity(parts.len() * 2 + 1);
        for (i, (first, last)) in parts.iter().enumerate() {
            let separator = if i == 0 { "" } else { "\r\n" };
            segments.push(Segment::Bytes(Bytes::from(format!(
                "{separator}--{boundary}\r\nContent-Type: {part_type}\r\nContent-Range: bytes {first}-{last}/{}\r\n\r\n",
                rep.len
            ))));
            segments.push(Segment::File {
                offset: *first,
                len: last - first + 1,
            });
        }
        segments.push(Segment::Bytes(Bytes::from(format!(
            "\r\n--{boundary}--\r\n"
        ))));
        let mut reply = self.entity(206, rep, segments);
        let multipart = format!("multipart/byteranges; boundary={boundary}");
        reply.headers.retain(|(name, _)| name != CONTENT_TYPE);
        reply.header(CONTENT_TYPE, value_of(&multipart))
    }

    fn cache_control(&self, served: &str) -> &HeaderValue {
        self.cache_paths
            .iter()
            .find(|(prefix, _)| served.starts_with(prefix.as_str()))
            .map_or(&self.cache_default, |(_, value)| value)
    }

    /// The media type of the file as built (a sidecar has its base name's type).
    fn content_type(&self, served: &str) -> HeaderValue {
        let extension = served
            .rsplit('/')
            .next()
            .and_then(|name| name.rsplit_once('.'))
            .map(|(_, ext)| ext.to_ascii_lowercase());
        let Some(extension) = extension else {
            return HeaderValue::from_static(OCTET_STREAM);
        };
        if let Some(value) = self.types.get(&extension) {
            return value.clone();
        }
        let media = TYPE_OVERRIDES
            .iter()
            .find(|(ext, _)| *ext == extension)
            .map(|(_, media)| *media)
            .or_else(|| mime_guess::from_ext(&extension).first_raw())
            .unwrap_or(OCTET_STREAM);
        value_of(&with_charset(media))
    }
}

/// A header value from text built here (ASCII only).
fn value_of(text: &str) -> HeaderValue {
    HeaderValue::from_str(text).unwrap_or_else(|_| HeaderValue::from_static(""))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rdock_model::middleware::StaticCacheControl;

    use super::*;
    use crate::test_support::{reply_header, request};

    #[test]
    fn ranges_follow_rfc_9110() {
        let pick = |header: &str| select_ranges(header, 1000, 2);
        assert_eq!(pick("bytes=0-99"), Ranges::Parts(vec![(0, 99)]));
        assert_eq!(pick("bytes=100-"), Ranges::Parts(vec![(100, 999)]));
        assert_eq!(pick("bytes=-100"), Ranges::Parts(vec![(900, 999)]));
        assert_eq!(
            pick("bytes=-5000"),
            Ranges::Parts(vec![(0, 999)]),
            "suffix longer than the file"
        );
        assert_eq!(pick("bytes=990-5000"), Ranges::Parts(vec![(990, 999)]));
        assert_eq!(
            pick("bytes=0-0,-1"),
            Ranges::Parts(vec![(0, 0), (999, 999)])
        );
        assert_eq!(
            pick("bytes=0-10,5-20"),
            Ranges::Parts(vec![(0, 20)]),
            "overlap merged"
        );
        assert_eq!(
            pick("bytes=11-20,0-10"),
            Ranges::Parts(vec![(0, 20)]),
            "adjacent merged"
        );
        assert_eq!(pick("bytes=1000-"), Ranges::Unsatisfiable);
        assert_eq!(pick("bytes=9999999-"), Ranges::Unsatisfiable);
        assert_eq!(pick("bytes=5000-6000,0-1"), Ranges::Parts(vec![(0, 1)]));
        assert_eq!(pick("bytes=20-10"), Ranges::Whole, "last before first");
        assert_eq!(
            pick("bytes=0-1,3-4,6-7"),
            Ranges::Whole,
            "more than max_ranges"
        );
        for malformed in [
            "",
            "bytes=",
            "bytes=a-b",
            "items=0-1",
            "bytes=--1",
            "bytes= 0-1",
        ] {
            assert_eq!(pick(malformed), Ranges::Whole, "{malformed:?}");
        }
        assert_eq!(
            select_ranges("bytes=-1", 0, 1),
            Ranges::Unsatisfiable,
            "empty file"
        );
    }

    #[test]
    fn media_types_and_charsets() {
        let mut config = config();
        config.types.insert("TS".into(), "text/typescript".into());
        let answers = Answers::new(&config).unwrap();
        let ct = |path: &str| answers.content_type(path).to_str().unwrap().to_owned();
        assert_eq!(ct("/index.html"), "text/html; charset=utf-8");
        assert_eq!(ct("/app.js"), "text/javascript; charset=utf-8");
        assert_eq!(ct("/app.mjs"), "text/javascript; charset=utf-8");
        assert_eq!(ct("/data.json"), "application/json; charset=utf-8");
        assert_eq!(ct("/logo.svg"), "image/svg+xml; charset=utf-8");
        assert_eq!(ct("/feed.xml"), "text/xml; charset=utf-8");
        assert_eq!(ct("/logo.png"), "image/png");
        assert_eq!(
            ct("/main.ts"),
            "text/typescript",
            "the types map wins, case-insensitive"
        );
        assert_eq!(ct("/blob.unknownext"), "application/octet-stream");
        assert_eq!(ct("/LICENSE"), "application/octet-stream");
    }

    #[test]
    fn longest_cache_prefix_wins() {
        let mut config = config();
        config.cache_control = StaticCacheControl {
            default: "no-cache".into(),
            paths: [
                (
                    "/assets/".to_owned(),
                    "public, max-age=31536000, immutable".to_owned(),
                ),
                ("/assets/live/".to_owned(), "no-store".to_owned()),
            ]
            .into(),
        };
        let answers = Answers::new(&config).unwrap();
        let cc = |path: &str| answers.cache_control(path).to_str().unwrap().to_owned();
        assert_eq!(cc("/index.html"), "no-cache");
        assert_eq!(
            cc("/assets/app.1f3.js"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(cc("/assets/live/feed.json"), "no-store");
    }

    fn config() -> StaticConfig {
        serde_json::from_value(serde_json::json!({ "root": "/srv" })).unwrap()
    }

    /// A representation of a 1000-byte file modified at a fixed time.
    fn answer(headers: &[(&'static str, &str)]) -> Reply {
        answer_with(&config(), "GET", headers)
    }

    fn answer_with(config: &StaticConfig, method: &str, headers: &[(&'static str, &str)]) -> Reply {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![b'x'; 1000]).unwrap();
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        file.as_file().set_modified(modified).unwrap();
        let found = Found {
            metadata: file.as_file().metadata().unwrap(),
            file: file.reopen().unwrap(),
            served: "page.html".to_owned(),
            coding: None,
        };
        Answers::new(config)
            .unwrap()
            .reply(&request(method, "/page.html", headers), found)
    }

    const ETAG_NOW: &str = "\"17979cfe362a0000-3e8\"";
    const MODIFIED: &str = "Tue, 14 Nov 2023 22:13:20 GMT";

    #[test]
    fn validators_are_strong_and_dated() {
        let reply = answer(&[]);
        assert_eq!(reply.status, 200);
        assert_eq!(reply_header(&reply, "etag"), Some(ETAG_NOW));
        assert_eq!(reply_header(&reply, "last-modified"), Some(MODIFIED));
        assert_eq!(reply_header(&reply, "accept-ranges"), Some("bytes"));
        assert_eq!(reply_header(&reply, "vary"), Some("Accept-Encoding"));
        assert_eq!(reply_header(&reply, "cache-control"), Some("no-cache"));
        assert_eq!(
            reply_header(&reply, "x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(reply.body.as_ref().map(Body::len), Some(1000));
    }

    #[test]
    fn preconditions_in_rfc_9110_order() {
        let status = |headers: &[(&'static str, &str)]| answer(headers).status;
        let stale = "\"0-1\"";
        let weak_now = format!("W/{ETAG_NOW}");
        let later = "Wed, 15 Nov 2023 00:00:00 GMT";
        let earlier = "Mon, 13 Nov 2023 00:00:00 GMT";
        // If-None-Match: weak comparison, lists, `*`.
        assert_eq!(status(&[("if-none-match", ETAG_NOW)]), 304);
        assert_eq!(
            status(&[("if-none-match", &format!("{stale}, {ETAG_NOW}"))]),
            304
        );
        assert_eq!(status(&[("if-none-match", &weak_now)]), 304);
        assert_eq!(status(&[("if-none-match", "*")]), 304);
        assert_eq!(status(&[("if-none-match", stale)]), 200);
        // If-Modified-Since, ignored next to If-None-Match and when invalid.
        assert_eq!(status(&[("if-modified-since", MODIFIED)]), 304);
        assert_eq!(status(&[("if-modified-since", later)]), 304);
        assert_eq!(status(&[("if-modified-since", earlier)]), 200);
        assert_eq!(status(&[("if-modified-since", "yesterday")]), 200);
        assert_eq!(
            status(&[("if-none-match", stale), ("if-modified-since", later)]),
            200
        );
        // If-Match: strong comparison; If-Unmodified-Since ignored next to it.
        assert_eq!(status(&[("if-match", ETAG_NOW)]), 200);
        assert_eq!(status(&[("if-match", "*")]), 200);
        assert_eq!(status(&[("if-match", &weak_now)]), 412);
        assert_eq!(status(&[("if-match", stale)]), 412);
        assert_eq!(status(&[("if-unmodified-since", earlier)]), 412);
        assert_eq!(status(&[("if-unmodified-since", later)]), 200);
        assert_eq!(
            status(&[("if-match", ETAG_NOW), ("if-unmodified-since", earlier)]),
            200
        );
        // A failed If-Match comes before a matching If-None-Match.
        assert_eq!(
            status(&[("if-match", stale), ("if-none-match", ETAG_NOW)]),
            412
        );
    }

    #[test]
    fn not_modified_keeps_the_validators_and_has_no_body() {
        let reply = answer(&[("if-none-match", ETAG_NOW)]);
        for name in ["etag", "last-modified", "cache-control", "vary"] {
            assert!(reply_header(&reply, name).is_some(), "{name}");
        }
        assert_eq!(reply_header(&reply, "content-type"), None);
        assert_eq!(reply.body.as_ref().map(Body::len), Some(0));
    }

    #[test]
    fn ranges_and_if_range() {
        let reply = answer(&[("range", "bytes=0-99")]);
        assert_eq!(reply.status, 206);
        assert_eq!(
            reply_header(&reply, "content-range"),
            Some("bytes 0-99/1000")
        );
        assert_eq!(reply.body.as_ref().map(Body::len), Some(100));
        let unsatisfiable = answer(&[("range", "bytes=5000-")]);
        assert_eq!(unsatisfiable.status, 416);
        assert_eq!(
            reply_header(&unsatisfiable, "content-range"),
            Some("bytes */1000")
        );
        assert_eq!(
            reply_header(&unsatisfiable, "vary"),
            Some("Accept-Encoding")
        );
        assert_eq!(
            answer(&[("range", "bytes=0-0,-1")]).status,
            200,
            "max_ranges 1"
        );
        for (if_range, status) in [
            (ETAG_NOW, 206),
            ("\"0-1\"", 200),
            (&*format!("W/{ETAG_NOW}"), 200),
            (MODIFIED, 206),
            ("Mon, 13 Nov 2023 00:00:00 GMT", 200),
        ] {
            let reply = answer(&[("range", "bytes=0-9"), ("if-range", if_range)]);
            assert_eq!(reply.status, status, "If-Range {if_range}");
        }
        let head = answer_with(&config(), "HEAD", &[("range", "bytes=0-9")]);
        assert_eq!(
            (head.status, head.body.as_ref().map(Body::len)),
            (200, Some(1000))
        );
    }

    #[test]
    fn several_ranges_become_multipart_when_allowed() {
        let mut config = config();
        config.max_ranges = 2;
        let reply = answer_with(&config, "GET", &[("range", "bytes=0-0,-1")]);
        assert_eq!(reply.status, 206);
        let content_type = reply_header(&reply, "content-type").unwrap().to_owned();
        let boundary = content_type
            .strip_prefix("multipart/byteranges; boundary=")
            .unwrap();
        assert_eq!(boundary.len(), 24);
        assert_eq!(reply_header(&reply, "content-range"), None);
        let Some(Body::File(mut body)) = reply.body else {
            panic!("a file body")
        };
        let text = crate::test_support::block_on(async {
            let mut out = Vec::new();
            while !body.is_finished() {
                out.extend_from_slice(&body.next_chunk().await.unwrap());
            }
            String::from_utf8(out).unwrap()
        });
        let expected = format!(
            "--{boundary}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Range: bytes 0-0/1000\r\n\r\nx\r\n--{boundary}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Range: bytes 999-999/1000\r\n\r\nx\r\n--{boundary}--\r\n"
        );
        assert_eq!(text, expected);
    }
}
