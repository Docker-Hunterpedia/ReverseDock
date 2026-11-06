//! Reads the TLS ClientHello at the start of a connection without terminating TLS, for SNI
//! passthrough and `ALPN()` matching on TCP routes ([ADR-0026]).
//!
//! rustls's `Acceptor` keeps the bytes it consumes, so passthrough needs its own parser.
//! [`parse`] is pure and synchronous: it looks at the bytes read so far and says whether more
//! are needed, whether they are TLS at all, or what the ClientHello asks for. [`peek`] reads
//! from a stream until [`parse`] decides and hands back every byte it read, which the caller
//! puts back in front of the stream (Pingora's `L4Stream::rewind`): nothing is consumed.
//!
//! Wire format: [RFC 8446] §5.1 (records), §4 and §4.1.2 (handshake header and ClientHello),
//! [RFC 6066] §3 (`server_name`), [RFC 7301] §3.1 (ALPN). Every length is checked against the
//! bytes present, and nothing is allocated beyond the bytes given or [`MAX_PEEK`].
//!
//! [ADR-0026]: https://github.com/Docker-Hunterpedia/ReverseDock/blob/main/docs/decisions/0026-swarm-l4-static.md
//! [RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446.html
//! [RFC 6066]: https://www.rfc-editor.org/rfc/rfc6066.html#section-3
//! [RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1

use std::borrow::Cow;
use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

/// Most bytes [`peek`] reads, and the largest ClientHello (with its record headers) [`parse`]
/// accepts: nginx's `preread_buffer_size` default.
pub const MAX_PEEK: usize = 16 * 1024;

const RECORD_HEADER: usize = 5;
const HANDSHAKE_HEADER: usize = 4;
const CONTENT_HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
/// RFC 8446 §5.1: "The length MUST NOT exceed 2^14 bytes."
const MAX_RECORD: usize = 1 << 14;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const NAME_TYPE_HOST_NAME: u8 = 0;
const MAX_SESSION_ID: usize = 32;

/// What a ClientHello asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// The `server_name` host name in lower case. `None` when the client sent none, and also
    /// when the name breaks RFC 6066 §3: not ASCII, a trailing dot, an IP literal, or more than
    /// one `host_name` in the list. Such a name can only match `HostSNI(*)`.
    pub sni: Option<String>,
    /// The ALPN protocols in the client's order; empty when the client sent no ALPN extension.
    pub alpn: Vec<Vec<u8>>,
}

/// The result of [`parse`] on the bytes read so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Undecided: at least `total` bytes (more than were given, at most [`MAX_PEEK`]) are needed.
    NeedMore {
        /// The smallest buffer length at which parsing can make progress.
        total: usize,
    },
    /// The bytes do not start with a TLS handshake record (`16 03 01` or `16 03 03`).
    NotTls,
    /// A complete ClientHello.
    Hello {
        /// What it asks for.
        hello: ClientHello,
        /// Length of the records that carry it, never more than the bytes given.
        len: usize,
    },
}

/// Why bytes that start like TLS are not an acceptable ClientHello.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HelloError {
    /// A record longer than RFC 8446 allows.
    #[error("a TLS record of {len} bytes exceeds the limit of 16384")]
    RecordTooLong {
        /// The declared record length.
        len: usize,
    },
    /// The ClientHello and its record headers would need more than [`MAX_PEEK`] bytes.
    #[error("the ClientHello does not fit in {MAX_PEEK} bytes")]
    TooLarge,
    /// The first handshake message is not a ClientHello.
    #[error("the first handshake message has type {msg_type}, not ClientHello (1)")]
    NotClientHello {
        /// The handshake message type.
        msg_type: u8,
    },
    /// A length, a list or a record breaks the wire format.
    #[error("malformed ClientHello: {0}")]
    Malformed(&'static str),
}

/// Parses the bytes read so far from the start of a connection.
///
/// Handles a ClientHello coalesced into one record or fragmented across several, and bytes
/// that arrive in any number of reads. The ClientHello must fit in [`MAX_PEEK`] bytes.
pub fn parse(buf: &[u8]) -> Result<Parsed, HelloError> {
    if !starts_like_tls(buf) {
        return Ok(Parsed::NotTls);
    }
    match reassemble(buf)? {
        Reassembled::NeedMore(total) => Ok(Parsed::NeedMore { total }),
        Reassembled::Complete {
            message,
            total,
            len,
        } => {
            let body = message
                .get(HANDSHAKE_HEADER..total)
                .ok_or(HelloError::Malformed("truncated handshake message"))?;
            Ok(Parsed::Hello {
                hello: parse_client_hello(body)?,
                len,
            })
        }
    }
}

/// True while the bytes present match `16 03 01` or `16 03 03`: a handshake record with the
/// `legacy_record_version` RFC 8446 §5.1 allows for an initial ClientHello.
fn starts_like_tls(buf: &[u8]) -> bool {
    buf.first().is_none_or(|&b| b == CONTENT_HANDSHAKE)
        && buf.get(1).is_none_or(|&b| b == 3)
        && buf.get(2).is_none_or(|&b| b == 1 || b == 3)
}

enum Reassembled<'a> {
    NeedMore(usize),
    /// The handshake message (at least `total` bytes of it) and the length of its records.
    Complete {
        message: Cow<'a, [u8]>,
        total: usize,
        len: usize,
    },
}

/// Joins the fragments of the first handshake message from consecutive handshake records.
/// The common case, one record holding the whole message, borrows instead of copying.
fn reassemble(buf: &[u8]) -> Result<Reassembled<'_>, HelloError> {
    let mut message: Cow<'_, [u8]> = Cow::Borrowed(&[]);
    let mut pos = 0;
    loop {
        let header_end = within_cap(pos + RECORD_HEADER)?;
        let Some([content, major, minor, len_hi, len_lo]) = array(buf, pos) else {
            return Ok(Reassembled::NeedMore(header_end));
        };
        if content != CONTENT_HANDSHAKE {
            return Err(HelloError::Malformed(
                "another record type inside the ClientHello",
            ));
        }
        if !matches!((major, minor), (3, 1 | 3)) {
            return Err(HelloError::Malformed("unexpected record version"));
        }
        let len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        if len > MAX_RECORD {
            return Err(HelloError::RecordTooLong { len });
        }
        if len == 0 {
            return Err(HelloError::Malformed("empty handshake record"));
        }
        let end = within_cap(header_end + len)?;
        let Some(fragment) = buf.get(header_end..end) else {
            return Ok(Reassembled::NeedMore(end));
        };
        append(&mut message, fragment);
        if let Some(total) = message_len(&message)?
            && message.len() >= total
        {
            return Ok(Reassembled::Complete {
                message,
                total,
                len: end,
            });
        }
        pos = end;
    }
}

/// `end` when the ClientHello's records may extend that far.
fn within_cap(end: usize) -> Result<usize, HelloError> {
    if end > MAX_PEEK {
        return Err(HelloError::TooLarge);
    }
    Ok(end)
}

fn append<'a>(message: &mut Cow<'a, [u8]>, fragment: &'a [u8]) {
    if message.is_empty() {
        *message = Cow::Borrowed(fragment);
    } else {
        message.to_mut().extend_from_slice(fragment);
    }
}

/// The length of the handshake message with its header, once the header is present.
fn message_len(message: &[u8]) -> Result<Option<usize>, HelloError> {
    let Some([msg_type, len @ ..]) = array::<HANDSHAKE_HEADER>(message, 0) else {
        return Ok(None);
    };
    if msg_type != CLIENT_HELLO {
        return Err(HelloError::NotClientHello { msg_type });
    }
    let total = HANDSHAKE_HEADER + u24(len);
    if total + RECORD_HEADER > MAX_PEEK {
        return Err(HelloError::TooLarge);
    }
    Ok(Some(total))
}

/// RFC 8446 §4.1.2, skipping everything up to the extensions.
fn parse_client_hello(body: &[u8]) -> Result<ClientHello, HelloError> {
    let mut hello = Reader(body);
    hello.take(2 + 32, "legacy_version and random")?;
    if hello.vec_u8("legacy_session_id")?.len() > MAX_SESSION_ID {
        return Err(HelloError::Malformed(
            "legacy_session_id longer than 32 bytes",
        ));
    }
    let suites = hello.vec_u16("cipher_suites")?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(HelloError::Malformed("cipher_suites"));
    }
    if hello.vec_u8("legacy_compression_methods")?.is_empty() {
        return Err(HelloError::Malformed("legacy_compression_methods"));
    }
    if hello.is_empty() {
        // A ClientHello before TLS 1.3 may end here.
        return Ok(ClientHello::default());
    }
    let extensions = hello.vec_u16("extensions")?;
    hello.finish("bytes after the extensions")?;
    parse_extensions(extensions)
}

/// Walks the extensions. A second `server_name` or ALPN extension is refused (RFC 8446 §4.2):
/// the router and the backend could otherwise read different ones.
fn parse_extensions(extensions: &[u8]) -> Result<ClientHello, HelloError> {
    let mut extensions = Reader(extensions);
    let mut sni = None;
    let mut alpn = None;
    while !extensions.is_empty() {
        let kind = extensions.u16("extension type")?;
        let data = extensions.vec_u16("extension data")?;
        match kind {
            EXT_SERVER_NAME if sni.is_some() => {
                return Err(HelloError::Malformed("duplicate server_name extension"));
            }
            EXT_SERVER_NAME => sni = Some(server_name(data)?),
            EXT_ALPN if alpn.is_some() => {
                return Err(HelloError::Malformed("duplicate ALPN extension"));
            }
            EXT_ALPN => alpn = Some(protocols(data)?),
            _ => {}
        }
    }
    Ok(ClientHello {
        sni: sni.flatten(),
        alpn: alpn.unwrap_or_default(),
    })
}

/// RFC 6066 §3 `ServerNameList`; the one valid `host_name`, if there is one.
fn server_name(data: &[u8]) -> Result<Option<String>, HelloError> {
    let mut extension = Reader(data);
    let mut list = Reader(extension.vec_u16("server_name_list")?);
    extension.finish("bytes after server_name_list")?;
    if list.is_empty() {
        return Err(HelloError::Malformed("empty server_name_list"));
    }
    let mut host = None;
    let mut host_names = 0_usize;
    while !list.is_empty() {
        if list.u8("name_type")? != NAME_TYPE_HOST_NAME {
            // Other name types have no known length, so the list cannot be read further;
            // rustls stops the same way.
            break;
        }
        let name = list.vec_u16("host_name")?;
        if name.is_empty() {
            return Err(HelloError::Malformed("empty host_name"));
        }
        host = Some(name);
        host_names += 1;
    }
    Ok(host.filter(|_| host_names == 1).and_then(valid_host_name))
}

/// The name in lower case when RFC 6066 §3 allows it: printable ASCII, no trailing dot and
/// not an IPv4 or IPv6 literal.
fn valid_host_name(name: &[u8]) -> Option<String> {
    if !name.iter().all(u8::is_ascii_graphic) || name.ends_with(b".") {
        return None;
    }
    let name = std::str::from_utf8(name).ok()?;
    if name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// RFC 7301 §3.1 `ProtocolNameList`.
fn protocols(data: &[u8]) -> Result<Vec<Vec<u8>>, HelloError> {
    let mut extension = Reader(data);
    let mut list = Reader(extension.vec_u16("protocol_name_list")?);
    extension.finish("bytes after protocol_name_list")?;
    if list.is_empty() {
        return Err(HelloError::Malformed("empty protocol_name_list"));
    }
    let mut protocols = Vec::new();
    while !list.is_empty() {
        let protocol = list.vec_u8("protocol name")?;
        if protocol.is_empty() {
            return Err(HelloError::Malformed("empty protocol name"));
        }
        protocols.push(protocol.to_vec());
    }
    Ok(protocols)
}

/// `N` bytes of `buf` starting at `at`, if they are all present.
fn array<const N: usize>(buf: &[u8], at: usize) -> Option<[u8; N]> {
    buf.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn u24([a, b, c]: [u8; 3]) -> usize {
    (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c)
}

/// A bounds-checked cursor; `what` names the field in the error when bytes are missing.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], HelloError> {
        let (head, rest) = self
            .0
            .split_at_checked(n)
            .ok_or(HelloError::Malformed(what))?;
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, HelloError> {
        let [b] = self.array(what)?;
        Ok(b)
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, HelloError> {
        Ok(u16::from_be_bytes(self.array(what)?))
    }

    fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], HelloError> {
        self.take(N, what)?
            .try_into()
            .map_err(|_| HelloError::Malformed(what))
    }

    /// An `opaque field<0..2^8-1>`.
    fn vec_u8(&mut self, what: &'static str) -> Result<&'a [u8], HelloError> {
        let len = self.u8(what)?;
        self.take(usize::from(len), what)
    }

    /// An `opaque field<0..2^16-1>`.
    fn vec_u16(&mut self, what: &'static str) -> Result<&'a [u8], HelloError> {
        let len = self.u16(what)?;
        self.take(usize::from(len), what)
    }

    fn finish(&self, what: &'static str) -> Result<(), HelloError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(HelloError::Malformed(what))
        }
    }
}

/// What [`peek`] found at the start of the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detected {
    /// The stream does not start with a TLS handshake record.
    NotTls,
    /// A complete ClientHello.
    Hello(ClientHello),
}

/// Why [`peek`] found neither a ClientHello nor non-TLS bytes.
#[derive(Debug, thiserror::Error)]
pub enum PeekError {
    /// The bytes start like TLS but are not an acceptable ClientHello.
    #[error(transparent)]
    Hello(#[from] HelloError),
    /// The deadline passed first.
    #[error("no complete ClientHello before the deadline")]
    TimedOut,
    /// The client closed its side first.
    #[error("the client closed the connection before its ClientHello was complete")]
    Closed,
    /// Reading failed.
    #[error("reading the ClientHello failed: {0}")]
    Io(#[from] std::io::Error),
}

/// The outcome of [`peek`] and every byte it read, in every case: the caller puts `bytes` back
/// in front of the stream before relaying or terminating it.
#[derive(Debug)]
pub struct Peeked {
    /// What the bytes are, or why that could not be decided.
    pub result: Result<Detected, PeekError>,
    /// Every byte read from the stream, at most [`MAX_PEEK`]; may extend past the ClientHello.
    pub bytes: Vec<u8>,
}

/// Reads from `stream` until [`parse`] decides, at most [`MAX_PEEK`] bytes and no later than
/// `deadline`, and returns the result with all the bytes read.
pub async fn peek<R>(stream: &mut R, deadline: Instant) -> Peeked
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = vec![0; MAX_PEEK];
    let mut filled = 0;
    // Parse only once a read could have changed the answer.
    let mut need = 1;
    let result = loop {
        if filled >= need {
            match parse(buf.get(..filled).unwrap_or_default()) {
                Ok(Parsed::NeedMore { total }) => need = total,
                Ok(Parsed::NotTls) => break Ok(Detected::NotTls),
                Ok(Parsed::Hello { hello, .. }) => break Ok(Detected::Hello(hello)),
                Err(e) => break Err(e.into()),
            }
        }
        // `parse` never asks for more than MAX_PEEK bytes, so the spare space is not empty.
        let Some(spare) = buf.get_mut(filled..).filter(|spare| !spare.is_empty()) else {
            break Err(HelloError::TooLarge.into());
        };
        match tokio::time::timeout_at(deadline, stream.read(spare)).await {
            Err(_elapsed) => break Err(PeekError::TimedOut),
            Ok(Ok(0)) => break Err(PeekError::Closed),
            Ok(Ok(n)) => filled += n,
            Ok(Err(e)) => break Err(e.into()),
        }
    };
    buf.truncate(filled);
    Peeked { result, bytes: buf }
}
