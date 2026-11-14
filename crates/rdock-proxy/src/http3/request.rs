//! HTTP/3 request headers: our own QPACK decoding and validation, and the mapping onto Pingora's
//! [`RequestHeader`] (ADR-0032).
//!
//! h3 0.0.8 leaves the intermediary rules of RFC 9114 §4.1–4.3 to its user and gives no access to
//! the field list as sent (its QPACK decoder is private and folds pseudo-header fields into an
//! `http::Request`, the last duplicate winning). So the HEADERS frame is decoded here, from the
//! bytes, and checked before anything reaches the pipeline:
//!
//! - **QPACK** (RFC 9204): static table only (rdock announces a dynamic table of capacity 0, so a
//!   dynamic reference is a decoding error, §2.2.3), Huffman strings checked for padding and EOS
//!   (RFC 7541 §5.2), integers bounded. The decoded section is counted as RFC 9114 §4.2.2 does
//!   (name + value + 32 bytes per field) and decoding stops as soon as it passes the limit.
//! - **Pseudo-header fields** (RFC 9114 §4.3): only `:method`, `:scheme`, `:authority` and
//!   `:path`; each at most once; all before the first regular field; `:method`, `:scheme` and
//!   `:path` present; `:status` (a response field), `:protocol` (extended CONNECT, planned) and
//!   unknown ones refused; `CONNECT` refused (rdock does not tunnel over HTTP/3).
//! - **Field names and values** (RFC 9114 §4.2, §10.3; RFC 9110 §5.5, §5.6.2): names lowercase
//!   `token` characters; values without NUL, CR, LF or other controls except HTAB, and without
//!   leading or trailing whitespace.
//! - **Connection-specific fields** (RFC 9114 §4.2): `connection`, `keep-alive`,
//!   `proxy-connection`, `transfer-encoding` and `upgrade` refused; `te` only as `trailers`.
//! - **Authority** (RFC 9114 §4.3.1): `:authority` or `host` present, equal when both are, at
//!   most one `host`, no userinfo, a `host[:port]` form.
//! - **Path**: origin form (`/…`), or `*` for `OPTIONS` only; visible ASCII, no fragment.
//! - **`content-length`**: at most one, digits only; the session then checks it against the
//!   DATA actually received (RFC 9114 §4.1.2).
//!
//! `cookie` fields, which HTTP/3 may split, are joined with `"; "` (RFC 9114 §4.2.1) so an
//! HTTP/1.1 backend sees one.
//!
//! Nothing here depends on quinn or h3: it is built without the `http3` feature too, so its
//! unit tests and the fuzz target (`tests/fuzz`, `http3_request`) run everywhere.

use bytes::Bytes;
use pingora::http::RequestHeader;

/// Bytes a field counts on top of its name and value (RFC 9114 §4.2.2, RFC 9204 §3.2.1).
pub const FIELD_OVERHEAD: u64 = 32;

/// Why a request's header section was refused. Every case resets the request stream with
/// `H3_MESSAGE_ERROR` (RFC 9114 §4.1.2), except [`Malformed::TooLarge`], which is answered with
/// 431 (§4.2.2), and QPACK errors, which close the connection with
/// `QPACK_DECOMPRESSION_FAILED` (RFC 9204 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    /// The field section cannot be decoded.
    #[error("QPACK: {0}")]
    Qpack(&'static str),
    /// The decoded field section is larger than `max_header_size`.
    #[error("the header section is larger than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: u64,
    },
    /// A pseudo-header field is missing, repeated, unknown, misplaced or invalid.
    #[error("pseudo-header field: {0}")]
    Pseudo(&'static str),
    /// A field name is not a lowercase token.
    #[error("invalid field name")]
    FieldName,
    /// A field value has a forbidden character or surrounding whitespace.
    #[error("invalid value of field `{0}`")]
    FieldValue(String),
    /// A connection-specific field (RFC 9114 §4.2).
    #[error("connection-specific field `{0}`")]
    ConnectionSpecific(String),
    /// `:authority` and `host` are missing, differ, repeat or have an invalid form.
    #[error("authority: {0}")]
    Authority(&'static str),
    /// `content-length` is repeated or not a number.
    #[error("invalid content-length")]
    ContentLength,
    /// `CONNECT` (tunnels are not offered over HTTP/3).
    #[error("CONNECT is not supported over HTTP/3")]
    Connect,
}

impl Malformed {
    /// A short label for `rdock_http3_malformed_requests_total{reason}`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Qpack(_) => "qpack",
            Self::TooLarge { .. } => "too_large",
            Self::Pseudo(_) => "pseudo_header",
            Self::FieldName => "field_name",
            Self::FieldValue(_) => "field_value",
            Self::ConnectionSpecific(_) => "connection_specific",
            Self::Authority(_) => "authority",
            Self::ContentLength => "content_length",
            Self::Connect => "connect",
        }
    }

    /// A QPACK error, which is a connection error (RFC 9204 §2.2).
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Self::Qpack(_))
    }
}

/// A request header section that passed every check.
#[derive(Debug)]
pub struct Mapped {
    /// The request for the pipeline: origin-form path, `Host` set from the authority, version
    /// HTTP/3.
    pub header: RequestHeader,
    /// The declared body length, which the session holds the DATA frames to.
    pub content_length: Option<u64>,
}

/// Decodes, validates and maps a HEADERS frame payload. `max_header_size` bounds the decoded
/// section as RFC 9114 §4.2.2 counts it.
///
/// # Errors
///
/// The section is malformed; see [`Malformed`].
pub fn map(block: &[u8], max_header_size: u64) -> Result<Mapped, Malformed> {
    let fields = decode(block, max_header_size)?;
    build(&fields)
}

/// One decoded field line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Name as sent.
    pub name: Bytes,
    /// Value as sent.
    pub value: Bytes,
}

/// Decodes a QPACK field section that uses the static table only.
///
/// # Errors
///
/// [`Malformed::Qpack`] for an encoding error or a dynamic-table reference;
/// [`Malformed::TooLarge`] once the decoded fields pass `max_header_size`.
pub fn decode(block: &[u8], max_header_size: u64) -> Result<Vec<Field>, Malformed> {
    let mut input = Input { bytes: block };
    // Required Insert Count (8-bit prefix) and Base (sign bit, 7-bit prefix), RFC 9204 §4.5.1.
    let (required_insert_count, _) = input.integer(8)?;
    if required_insert_count != 0 {
        return Err(Malformed::Qpack("dynamic table reference"));
    }
    let _base = input.integer(7)?;
    let mut fields = Vec::new();
    let mut size = 0u64;
    while let Some(&first) = input.bytes.first() {
        let field = if first & 0x80 != 0 {
            // Indexed field line: 1 T index(6).
            let (index, flags) = input.integer(6)?;
            if flags & 0x40 == 0 {
                return Err(Malformed::Qpack("dynamic table reference"));
            }
            let (name, value) = static_entry(index)?;
            Field {
                name: Bytes::from_static(name.as_bytes()),
                value: Bytes::from_static(value.as_bytes()),
            }
        } else if first & 0x40 != 0 {
            // Literal with name reference: 0 1 N T index(4).
            let (index, flags) = input.integer(4)?;
            if flags & 0x10 == 0 {
                return Err(Malformed::Qpack("dynamic table reference"));
            }
            let (name, _) = static_entry(index)?;
            let value = input.string(7, budget(max_header_size, size))?;
            Field {
                name: Bytes::from_static(name.as_bytes()),
                value,
            }
        } else if first & 0x20 != 0 {
            // Literal with literal name: 0 0 1 N H length(3).
            let name = input.string(3, budget(max_header_size, size))?;
            let value = input.string(7, budget(max_header_size, size))?;
            Field { name, value }
        } else {
            // 0001 (indexed, post-base) and 0000 (literal, post-base name): both dynamic.
            return Err(Malformed::Qpack("dynamic table reference"));
        };
        size = size
            .saturating_add(field.name.len() as u64)
            .saturating_add(field.value.len() as u64)
            .saturating_add(FIELD_OVERHEAD);
        if size > max_header_size {
            return Err(Malformed::TooLarge {
                limit: max_header_size,
            });
        }
        fields.push(field);
    }
    Ok(fields)
}

/// How many decoded bytes a string may still have before the section is too large, and the
/// limit.
fn budget(max: u64, used: u64) -> (u64, u64) {
    (max.saturating_sub(used), max)
}

struct Input<'a> {
    bytes: &'a [u8],
}

impl Input<'_> {
    /// A prefix integer (RFC 7541 §5.1) with an `n`-bit prefix; returns it and the first byte
    /// (its flag bits). Values above 2^32 are refused: nothing in a field section needs them.
    fn integer(&mut self, n: u32) -> Result<(u64, u8), Malformed> {
        let (&first, rest) = self
            .bytes
            .split_first()
            .ok_or(Malformed::Qpack("truncated integer"))?;
        self.bytes = rest;
        let mask = u8::try_from((1u16 << n) - 1).unwrap_or(u8::MAX);
        let mut value = u64::from(first & mask);
        if value < u64::from(mask) {
            return Ok((value, first));
        }
        let mut shift = 0u32;
        loop {
            let (&byte, rest) = self
                .bytes
                .split_first()
                .ok_or(Malformed::Qpack("truncated integer"))?;
            self.bytes = rest;
            value += u64::from(byte & 0x7f) << shift;
            if value > u64::from(u32::MAX) {
                return Err(Malformed::Qpack("integer too large"));
            }
            if byte & 0x80 == 0 {
                return Ok((value, first));
            }
            shift += 7;
            // Five continuation bytes hold any value up to 2^32; more is an over-long
            // encoding, and a shift past 63 would overflow.
            if shift > 28 {
                return Err(Malformed::Qpack("integer too large"));
            }
        }
    }

    /// A string literal with an `n`-bit length prefix whose Huffman flag is the bit above it.
    /// `budget` is (bytes the section may still decode to, the section's limit).
    fn string(&mut self, n: u32, budget: (u64, u64)) -> Result<Bytes, Malformed> {
        let huffman_flag = 1u8 << n;
        let (length, first) = self.integer(n)?;
        let huffman = first & huffman_flag != 0;
        let length = usize::try_from(length).map_err(|_| Malformed::Qpack("string too long"))?;
        if length > self.bytes.len() {
            return Err(Malformed::Qpack("truncated string"));
        }
        let (raw, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        // The longest Huffman code is 30 bits: a string decodes to at least 8/30 of its
        // length. One that must pass the budget is refused before decoding; the caller counts
        // what the others decode to.
        let least = if huffman {
            (length as u64).saturating_mul(8) / 30
        } else {
            length as u64
        };
        if least > budget.0 {
            return Err(Malformed::TooLarge { limit: budget.1 });
        }
        if huffman {
            huffman_decode(raw).map(Bytes::from)
        } else {
            Ok(Bytes::copy_from_slice(raw))
        }
    }
}

/// Code lengths of the HPACK/QPACK Huffman code for the 256 octets (RFC 7541 Appendix B; the
/// code is canonical, so the lengths define it). EOS (symbol 256) is 30 bits of ones.
const HUFFMAN_LENGTHS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

/// Longest code (EOS).
const MAX_CODE: usize = 30;
/// The EOS symbol.
const EOS: u16 = 256;

/// The canonical code, ready for decoding: for each length, the first code and the index of its
/// first symbol in `symbols`, and the symbols in code order.
struct Canonical {
    first_code: [u32; MAX_CODE + 1],
    first_index: [u16; MAX_CODE + 1],
    count: [u16; MAX_CODE + 1],
    symbols: [u16; 257],
}

const fn length_of(symbol: usize) -> usize {
    if symbol == 256 {
        MAX_CODE
    } else {
        HUFFMAN_LENGTHS[symbol] as usize
    }
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "symbols are below 257 and counts below 2^16; `try_from` is not const"
)]
const fn canonical() -> Canonical {
    let mut count = [0u16; MAX_CODE + 1];
    let mut s = 0;
    while s < 257 {
        count[length_of(s)] += 1;
        s += 1;
    }
    let mut first_code = [0u32; MAX_CODE + 1];
    let mut first_index = [0u16; MAX_CODE + 1];
    let mut code = 0u32;
    let mut index = 0u16;
    let mut len = 1;
    while len <= MAX_CODE {
        first_code[len] = code;
        first_index[len] = index;
        code = (code + count[len] as u32) << 1;
        index += count[len];
        len += 1;
    }
    // Symbols in code order: by length, then by symbol value.
    let mut symbols = [0u16; 257];
    let mut next = first_index;
    let mut s = 0;
    while s < 257 {
        let l = length_of(s);
        symbols[next[l] as usize] = s as u16;
        next[l] += 1;
        s += 1;
    }
    Canonical {
        first_code,
        first_index,
        count,
        symbols,
    }
}

static CANONICAL: Canonical = canonical();

/// Decodes a Huffman-coded string (RFC 7541 §5.2): EOS inside the string, padding longer than
/// seven bits and padding that is not the most significant bits of EOS are errors.
fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, Malformed> {
    let table = &CANONICAL;
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut code = 0u32;
    let mut len = 0usize;
    // Whether every bit of the current partial code is a one (candidate padding).
    let mut all_ones = true;
    for &byte in input {
        for bit in (0..8).rev() {
            let b = u32::from((byte >> bit) & 1);
            code = (code << 1) | b;
            all_ones &= b == 1;
            len += 1;
            if len > MAX_CODE {
                return Err(Malformed::Qpack("invalid Huffman code"));
            }
            let offset = code.wrapping_sub(table.first_code[len]);
            if code >= table.first_code[len] && offset < u32::from(table.count[len]) {
                let symbol = table.symbols[usize::from(table.first_index[len]) + offset as usize];
                if symbol == EOS {
                    return Err(Malformed::Qpack("EOS in a Huffman string"));
                }
                out.push(u8::try_from(symbol).unwrap_or(0));
                code = 0;
                len = 0;
                all_ones = true;
            }
        }
    }
    if len > 7 || !all_ones {
        return Err(Malformed::Qpack("invalid Huffman padding"));
    }
    Ok(out)
}

/// The QPACK static table (RFC 9204 Appendix A).
const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

fn static_entry(index: u64) -> Result<(&'static str, &'static str), Malformed> {
    usize::try_from(index)
        .ok()
        .and_then(|i| STATIC_TABLE.get(i))
        .copied()
        .ok_or(Malformed::Qpack("static table index out of range"))
}

/// Whether `byte` is a `tchar` (RFC 9110 §5.6.2).
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// A field value of RFC 9110 §5.5 without surrounding whitespace: visible characters, SP,
/// HTAB and obs-text; never NUL, CR, LF or another control.
fn valid_value(value: &[u8]) -> bool {
    let surrounding = |b: Option<&u8>| matches!(b, Some(b' ' | b'\t'));
    if surrounding(value.first()) || surrounding(value.last()) {
        return false;
    }
    value
        .iter()
        .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// Fields that only mean something on one HTTP/1.1 connection (RFC 9114 §4.2).
const CONNECTION_SPECIFIC: [&str; 5] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

#[derive(Default)]
struct Pseudo<'a> {
    method: Option<&'a [u8]>,
    scheme: Option<&'a [u8]>,
    authority: Option<&'a [u8]>,
    path: Option<&'a [u8]>,
}

/// Checks the decoded fields and builds the request.
#[allow(
    clippy::too_many_lines,
    reason = "the checks of RFC 9114 §4.1-4.3, in order"
)]
fn build(fields: &[Field]) -> Result<Mapped, Malformed> {
    let mut pseudo = Pseudo::default();
    let mut regular = false;
    for field in fields {
        let name = field.name.as_ref();
        if let Some(rest) = name.strip_prefix(b":") {
            if regular {
                return Err(Malformed::Pseudo("after a regular field"));
            }
            let slot = match rest {
                b"method" => &mut pseudo.method,
                b"scheme" => &mut pseudo.scheme,
                b"authority" => &mut pseudo.authority,
                b"path" => &mut pseudo.path,
                b"status" => return Err(Malformed::Pseudo("`:status` in a request")),
                b"protocol" => {
                    return Err(Malformed::Pseudo(
                        "`:protocol` (extended CONNECT is not supported)",
                    ));
                }
                _ => return Err(Malformed::Pseudo("unknown")),
            };
            if slot.replace(field.value.as_ref()).is_some() {
                return Err(Malformed::Pseudo("repeated"));
            }
            continue;
        }
        regular = true;
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b) && !b.is_ascii_uppercase()) {
            return Err(Malformed::FieldName);
        }
    }
    let method = pseudo
        .method
        .ok_or(Malformed::Pseudo("`:method` missing"))?;
    if method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
        return Err(Malformed::Pseudo("invalid `:method`"));
    }
    if method == b"CONNECT" {
        return Err(Malformed::Connect);
    }
    match pseudo.scheme {
        Some(b"https") => {}
        Some(_) => return Err(Malformed::Pseudo("`:scheme` must be `https`")),
        None => return Err(Malformed::Pseudo("`:scheme` missing")),
    }
    let path = pseudo.path.ok_or(Malformed::Pseudo("`:path` missing"))?;
    check_path(method, path)?;

    let mut host: Option<&[u8]> = None;
    let mut content_length: Option<u64> = None;
    let mut cookies: Vec<&[u8]> = Vec::new();
    let mut header = RequestHeader::build(method, path, Some(fields.len() + 1))
        .map_err(|_| Malformed::Pseudo("invalid `:method` or `:path`"))?;
    header.set_version(http::Version::HTTP_3);
    for field in fields.iter().filter(|f| !f.name.starts_with(b":")) {
        let name = field.name.as_ref();
        let value = field.value.as_ref();
        let text = std::str::from_utf8(name).map_err(|_| Malformed::FieldName)?;
        if !valid_value(value) {
            return Err(Malformed::FieldValue(text.to_owned()));
        }
        if CONNECTION_SPECIFIC.contains(&text) {
            return Err(Malformed::ConnectionSpecific(text.to_owned()));
        }
        match text {
            "te" if value != b"trailers" => {
                return Err(Malformed::ConnectionSpecific("te".into()));
            }
            "host" => {
                if host.replace(value).is_some() {
                    return Err(Malformed::Authority("`host` repeated"));
                }
                continue;
            }
            "content-length" => {
                if content_length.is_some() {
                    return Err(Malformed::ContentLength);
                }
                if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                    return Err(Malformed::ContentLength);
                }
                let n = std::str::from_utf8(value)
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or(Malformed::ContentLength)?;
                content_length = Some(n);
            }
            "cookie" => {
                cookies.push(value);
                continue;
            }
            _ => {}
        }
        let value = http::HeaderValue::from_bytes(value)
            .map_err(|_| Malformed::FieldValue(text.to_owned()))?;
        header
            .append_header(text.to_owned(), value)
            .map_err(|_| Malformed::FieldName)?;
    }
    let authority = match (pseudo.authority, host) {
        (Some(a), Some(h)) if a != h => {
            return Err(Malformed::Authority("`:authority` and `host` differ"));
        }
        (Some(a), _) => a,
        (None, Some(h)) => h,
        (None, None) => return Err(Malformed::Authority("`:authority` missing")),
    };
    check_authority(authority)?;
    let host = http::HeaderValue::from_bytes(authority)
        .map_err(|_| Malformed::Authority("invalid characters"))?;
    header
        .insert_header(http::header::HOST, host)
        .map_err(|_| Malformed::Authority("invalid characters"))?;
    if !cookies.is_empty() {
        let joined = cookies.join(&b"; "[..]);
        let value = http::HeaderValue::from_bytes(&joined)
            .map_err(|_| Malformed::FieldValue("cookie".into()))?;
        header
            .insert_header(http::header::COOKIE, value)
            .map_err(|_| Malformed::FieldValue("cookie".into()))?;
    }
    Ok(Mapped {
        header,
        content_length,
    })
}

/// `:path`: origin form or `*` (OPTIONS only); visible ASCII without a fragment.
fn check_path(method: &[u8], path: &[u8]) -> Result<(), Malformed> {
    if path == b"*" {
        return if method == b"OPTIONS" {
            Ok(())
        } else {
            Err(Malformed::Pseudo("`:path` `*` is for OPTIONS only"))
        };
    }
    if path.first() != Some(&b'/') {
        return Err(Malformed::Pseudo("`:path` is not in origin form"));
    }
    if !path.iter().all(|&b| (0x21..0x7f).contains(&b) && b != b'#') {
        return Err(Malformed::Pseudo("invalid character in `:path`"));
    }
    Ok(())
}

/// `host[:port]`: a registered name or IPv4 address, or an IPv6 literal in brackets; no
/// userinfo; a port of digits only.
fn check_authority(authority: &[u8]) -> Result<(), Malformed> {
    if authority.is_empty() {
        return Err(Malformed::Authority("empty"));
    }
    if authority.contains(&b'@') {
        return Err(Malformed::Authority("userinfo"));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix(b"[") {
        let close = rest
            .iter()
            .position(|&b| b == b']')
            .ok_or(Malformed::Authority("unclosed IPv6 literal"))?;
        let (literal, after) = rest.split_at(close);
        let literal =
            std::str::from_utf8(literal).map_err(|_| Malformed::Authority("invalid IPv6"))?;
        if literal.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(Malformed::Authority("invalid IPv6 literal"));
        }
        let after = &after[1..];
        match after.split_first() {
            None => (&b""[..], None),
            Some((b':', port)) => (&b""[..], Some(port)),
            Some(_) => return Err(Malformed::Authority("text after the IPv6 literal")),
        }
    } else {
        match authority.iter().rposition(|&b| b == b':') {
            Some(i) => (&authority[..i], Some(&authority[i + 1..])),
            None => (authority, None),
        }
    };
    let reg_name = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
            )
    };
    if !authority.starts_with(b"[") && (host.is_empty() || !host.iter().all(|&b| reg_name(b))) {
        return Err(Malformed::Authority("invalid host"));
    }
    if let Some(port) = port
        && (port.is_empty()
            || port.len() > 5
            || !port.iter().all(u8::is_ascii_digit)
            || std::str::from_utf8(port)
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
                .is_none())
    {
        return Err(Malformed::Authority("invalid port"));
    }
    Ok(())
}

/// Test helpers: an encoder for field sections (literal names and values, no Huffman unless
/// asked), shared with the end-to-end tests' raw client.
pub mod encode {
    /// A prefix integer with an `n`-bit prefix and the flag bits `flags` in the first byte.
    pub fn integer(out: &mut Vec<u8>, n: u32, flags: u8, value: u64) {
        let max = (1u64 << n) - 1;
        if value < max {
            out.push(flags | u8::try_from(value).unwrap_or(0));
            return;
        }
        out.push(flags | u8::try_from(max).unwrap_or(0));
        let mut rest = value - max;
        while rest >= 128 {
            out.push(u8::try_from(rest % 128).unwrap_or(0) | 0x80);
            rest /= 128;
        }
        out.push(u8::try_from(rest).unwrap_or(0));
    }

    /// A field section of literal fields, in the order given, without Huffman coding.
    #[must_use]
    pub fn section(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = vec![0, 0];
        for (name, value) in fields {
            integer(&mut out, 3, 0x20, name.len() as u64);
            out.extend_from_slice(name);
            integer(&mut out, 7, 0, value.len() as u64);
            out.extend_from_slice(value);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: u64 = 64 * 1024;

    fn get(extra: &[(&[u8], &[u8])]) -> Vec<(&'static [u8], &'static [u8])> {
        let mut fields: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"app.example.com"),
            (b":path", b"/a?b=c"),
        ];
        fields.extend_from_slice(extra);
        // The tests only pass static byte strings.
        fields
            .into_iter()
            .map(|(n, v)| -> (&'static [u8], &'static [u8]) {
                (Box::leak(n.into()), Box::leak(v.into()))
            })
            .collect()
    }

    fn mapped(fields: &[(&[u8], &[u8])]) -> Result<Mapped, Malformed> {
        map(&encode::section(fields), LIMIT)
    }

    #[test]
    fn a_plain_request_maps_with_host_and_version() {
        let m = mapped(&get(&[(b"user-agent", b"t"), (b"content-length", b"5")])).unwrap();
        assert_eq!(m.header.method, http::Method::GET);
        assert_eq!(m.header.uri.path(), "/a");
        assert_eq!(m.header.uri.query(), Some("b=c"));
        assert_eq!(m.header.version, http::Version::HTTP_3);
        assert_eq!(m.header.headers["host"], "app.example.com");
        assert_eq!(m.header.headers["user-agent"], "t");
        assert_eq!(m.content_length, Some(5));
    }

    #[test]
    fn huffman_and_the_static_table_decode() {
        // RFC 7541 C.4.1: "www.example.com" Huffman-coded.
        let www = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huffman_decode(&www).unwrap(), b"www.example.com");
        // RFC 7541 C.4.2: "no-cache".
        assert_eq!(
            huffman_decode(&[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]).unwrap(),
            b"no-cache"
        );
        // Indexed :method GET (17), :scheme https (23), :path / (1), then :authority (0) with a
        // Huffman literal value.
        let mut block = vec![
            0,
            0,
            0xc0 | 0x11,
            0xc0 | 0x17,
            0xc0 | 0x01,
            0x50,
            0x80 | 0x0c,
        ];
        block.extend_from_slice(&www);
        let m = map(&block, LIMIT).unwrap();
        assert_eq!(m.header.headers["host"], "www.example.com");
        assert_eq!(m.header.uri.path(), "/");
    }

    #[test]
    fn huffman_padding_and_eos_are_checked() {
        // '0' is 00000 (5 bits): with three 1 bits of padding it is one byte.
        assert_eq!(huffman_decode(&[0x07]).unwrap(), b"0");
        // Padding of zeros.
        assert!(huffman_decode(&[0x00]).is_err());
        // A whole byte of padding (8 ones).
        assert!(huffman_decode(&[0x07, 0xff]).is_err());
        // EOS (30 ones) inside the string.
        assert!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn dynamic_references_and_truncation_are_qpack_errors() {
        for block in [
            vec![1, 0],                                                // Required Insert Count 1
            vec![0, 0, 0x80],                                          // indexed, dynamic
            vec![0, 0, 0x40],                                          // name reference, dynamic
            vec![0, 0, 0x10],                                          // indexed post-base
            vec![0, 0, 0x00],                                          // literal post-base name
            vec![0, 0, 0xff],                                          // truncated integer
            vec![0, 0, 0x25, b'a'],                                    // name longer than the block
            vec![0, 0, 0xc0 | 63, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], // integer overflow
            vec![0, 0, 0xc0 | 0x3e, 0x10],                             // static index 110
            // An over-long integer: continuation bytes that add nothing (found by the fuzzer).
            [vec![0, 0xff], vec![0x80; 88], vec![0xff]].concat(),
        ] {
            let err = map(&block, LIMIT).unwrap_err();
            assert!(err.is_connection_error(), "{block:?}: {err:?}");
        }
    }

    /// h3 builds a `HeaderMap` with one slot per field, which panics from 24,577 fields: at
    /// the ceiling of `max_header_size` that many fields (the smallest, `a:` with no value) are
    /// over the limit already (review fix L1).
    #[test]
    fn the_header_size_ceiling_admits_too_few_fields_to_panic_h3() {
        let ceiling = rdock_model::config::ListenerHttp3::MAX_HEADER_SIZE_CEILING.as_u64();
        let fields: Vec<(&[u8], &[u8])> =
            std::iter::repeat_n((&b"a"[..], &b""[..]), 24_577).collect();
        let block = encode::section(&fields);
        assert!(
            matches!(decode(&block, ceiling), Err(Malformed::TooLarge { .. })),
            "24,577 fields fit within {ceiling} bytes"
        );
    }

    #[test]
    fn the_size_limit_counts_32_bytes_per_field_and_stops_early() {
        let big = vec![b'a'; 1000];
        let fields = get(&[(b"x-big", Box::leak(big.into_boxed_slice()))]);
        assert!(mapped(&fields).is_ok());
        assert_eq!(
            map(&encode::section(&fields), 1000).unwrap_err(),
            Malformed::TooLarge { limit: 1000 }
        );
        // Many empty fields: each still counts 32 bytes.
        let mut many: Vec<(&[u8], &[u8])> = get(&[]);
        many.extend(std::iter::repeat_n((&b"x"[..], &b""[..]), 3000));
        assert!(matches!(
            map(&encode::section(&many), LIMIT),
            Err(Malformed::TooLarge { .. })
        ));
    }

    type Case = (Vec<(&'static [u8], &'static [u8])>, &'static str);

    #[test]
    #[allow(clippy::too_many_lines, reason = "a table of cases")]
    fn pseudo_header_rules() {
        let cases: Vec<Case> = vec![
            (
                vec![
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                ],
                "authority",
            ),
            (
                vec![
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                ],
                "missing",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                ],
                "missing",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                ],
                "missing",
            ),
            (
                get(&[(b"x", b"y"), (b":method", b"POST")]),
                "after a regular field",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                ],
                "repeated",
            ),
            (
                vec![
                    (b":status", b"200"),
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                ],
                ":status",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":protocol", b"websocket"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                ],
                ":protocol",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":foo", b"x"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                ],
                "unknown",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":scheme", b"http"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                ],
                "https",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"a/b"),
                ],
                "origin form",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"*"),
                ],
                "OPTIONS",
            ),
            (
                vec![
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"/a#b"),
                ],
                "invalid character",
            ),
            (
                vec![
                    (b":method", b"G ET"),
                    (b":scheme", b"https"),
                    (b":authority", b"a"),
                    (b":path", b"/"),
                ],
                ":method",
            ),
        ];
        for (fields, fragment) in cases {
            let err = mapped(&fields).unwrap_err();
            assert!(
                err.to_string().contains(fragment),
                "{fields:?}: {err} lacks {fragment}"
            );
            assert!(!err.is_connection_error());
        }
        let options = vec![
            (&b":method"[..], &b"OPTIONS"[..]),
            (b":scheme", b"https"),
            (b":authority", b"a"),
            (b":path", b"*"),
        ];
        assert!(mapped(&options).is_ok());
    }

    #[test]
    fn connect_is_refused() {
        let fields = vec![
            (&b":method"[..], &b"CONNECT"[..]),
            (b":authority", b"a:443"),
        ];
        assert_eq!(mapped(&fields).unwrap_err(), Malformed::Connect);
    }

    #[test]
    fn field_names_and_values() {
        for (name, value, label) in [
            (&b"X-Upper"[..], &b"v"[..], "field_name"),
            (b"bad name", b"v", "field_name"),
            (b"a\x00", b"v", "field_name"),
            (b"x", b"a\r\nb: c", "field_value"),
            (b"x", b"a\x00", "field_value"),
            (b"x", b" lead", "field_value"),
            (b"x", b"trail\t", "field_value"),
            (b"x", b"bell\x07", "field_value"),
            (b"connection", b"close", "connection_specific"),
            (b"keep-alive", b"5", "connection_specific"),
            (b"proxy-connection", b"x", "connection_specific"),
            (b"transfer-encoding", b"chunked", "connection_specific"),
            (b"upgrade", b"websocket", "connection_specific"),
            (b"te", b"gzip", "connection_specific"),
            (b"content-length", b"1, 1", "content_length"),
            (b"content-length", b"-1", "content_length"),
            (
                b"content-length",
                b"99999999999999999999999",
                "content_length",
            ),
        ] {
            let err = mapped(&get(&[(name, value)])).unwrap_err();
            assert_eq!(err.label(), label, "{name:?}={value:?}: {err}");
        }
        assert!(mapped(&get(&[(b"te", b"trailers"), (b"x", b"a\tb obs\xff")])).is_ok());
        let twice = get(&[(b"content-length", b"1"), (b"content-length", b"1")]);
        assert_eq!(mapped(&twice).unwrap_err(), Malformed::ContentLength);
    }

    #[test]
    fn authority_rules() {
        let with_authority = |a: &'static [u8]| {
            vec![
                (&b":method"[..], &b"GET"[..]),
                (b":scheme", b"https"),
                (b":authority", a),
                (b":path", b"/"),
            ]
        };
        for bad in [
            &b"user@host"[..],
            b"host:",
            b"host:99999",
            b"host:8a",
            b"[::1",
            b"[zz]",
            b"[::1]x",
            b"ho st",
            b":443",
        ] {
            assert_eq!(
                mapped(&with_authority(bad)).unwrap_err().label(),
                "authority",
                "{bad:?}"
            );
        }
        for good in [
            &b"host"[..],
            b"host:8443",
            b"[::1]:443",
            b"[::1]",
            b"10.0.0.1:1",
        ] {
            assert!(mapped(&with_authority(good)).is_ok(), "{good:?}");
        }
        // `host` alone, equal to `:authority`, or differing; twice.
        let host_only = vec![
            (&b":method"[..], &b"GET"[..]),
            (b":scheme", b"https"),
            (b":path", b"/"),
            (b"host", b"h.example"),
        ];
        assert_eq!(
            mapped(&host_only).unwrap().header.headers["host"],
            "h.example"
        );
        assert!(mapped(&get(&[(b"host", b"app.example.com")])).is_ok());
        assert_eq!(
            mapped(&get(&[(b"host", b"other.example.com")]))
                .unwrap_err()
                .label(),
            "authority"
        );
        assert_eq!(
            mapped(&get(&[
                (b"host", b"app.example.com"),
                (b"host", b"app.example.com")
            ]))
            .unwrap_err()
            .label(),
            "authority"
        );
    }

    #[test]
    fn cookies_are_joined_for_http1() {
        let m = mapped(&get(&[
            (b"cookie", b"a=1"),
            (b"x", b"y"),
            (b"cookie", b"b=2"),
        ]))
        .unwrap();
        assert_eq!(m.header.headers.get_all("cookie").iter().count(), 1);
        assert_eq!(m.header.headers["cookie"], "a=1; b=2");
    }

    #[test]
    fn the_canonical_code_matches_rfc_7541() {
        // Spot checks against Appendix B: ' ' 010100 (6), 'a' 00011 (5), 0x00 1111111111000 (13).
        let code_of = |symbol: u16| {
            let i = CANONICAL.symbols.iter().position(|&s| s == symbol).unwrap();
            let len = (1..=MAX_CODE)
                .find(|&l| {
                    let first = usize::from(CANONICAL.first_index[l]);
                    (first..first + usize::from(CANONICAL.count[l])).contains(&i)
                })
                .unwrap();
            let offset = i - usize::from(CANONICAL.first_index[len]);
            (
                CANONICAL.first_code[len] + u32::try_from(offset).unwrap(),
                len,
            )
        };
        assert_eq!(code_of(u16::from(b' ')), (0x14, 6));
        assert_eq!(code_of(u16::from(b'a')), (0x3, 5));
        assert_eq!(code_of(0), (0x1ff8, 13));
        assert_eq!(code_of(255), (0x3ff_ffee, 26));
        assert_eq!(code_of(EOS), (0x3fff_ffff, 30));
    }
}
