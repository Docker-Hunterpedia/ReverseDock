//! Inbound PROXY protocol, v1 and v2 (M-L4-03, ADR-0026).
//!
//! The first step of every accepted connection, before the TLS handshake or the HTTP/2 preface,
//! and written for any listener type. The rules, from the specification
//! (<https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>, revision 2020/03/05):
//!
//! - Without `proxy_protocol` on the listener, no byte is inspected: the receiver "must never
//!   try to guess".
//! - From a `trusted` source a header must come first (unless `optional`); the connection is
//!   not processed until the header is complete and valid.
//! - From any other source, a connection that starts with either signature is closed.
//! - `LOCAL` headers, `UNKNOWN`/`UNSPEC` families and non-TCP transports keep the real
//!   endpoints.
//!
//! A header is read under the listener's `timeouts.request_header` and within 16 KiB; the bytes
//! after it are put back into the stream.

use std::net::{IpAddr, SocketAddr};

use pingora::http::ResponseHeader;
use pingora::protocols::Digest;
use pingora::protocols::GetProxyDigest;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::raw_connect::ProxyDigest;
use proxy_header::{ParseConfig, Protocol, ProxyHeader};
use rdock_model::config::ProxyProtocolIn;
use rdock_observability::Metrics;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

/// Most bytes read while looking for a header.
pub const MAX_HEADER: usize = 16 * 1024;
/// Longest v1 header, CRLF included (specification §2.1).
const V1_MAX: usize = 107;
const V1_SIGNATURE: &[u8] = b"PROXY ";
const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
/// TLVs are not used: they are skipped, not decoded.
const PARSE: ParseConfig = ParseConfig {
    include_tlvs: false,
    allow_v1: true,
    allow_v2: true,
};

/// What the first bytes of a connection must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// A trusted source: a header comes first.
    Header,
    /// A trusted source on a listener with `optional: true`: a header may come first.
    MaybeHeader,
    /// Any other source: a header is refused.
    NoHeader,
}

impl Expect {
    /// What the listener expects from `peer`; `None` when it has no `proxy_protocol`, and the
    /// bytes are then never inspected.
    #[must_use]
    pub fn for_peer(config: Option<&ProxyProtocolIn>, peer: IpAddr) -> Option<Self> {
        let config = config?;
        let peer = crate::forwarded::canonical(peer);
        Some(if !config.trusted.iter().any(|n| n.contains(&peer)) {
            Self::NoHeader
        } else if config.optional {
            Self::MaybeHeader
        } else {
            Self::Header
        })
    }
}

/// What the first bytes of a connection were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A complete, valid header. `source` is the original client; `None` keeps the real
    /// endpoints (`LOCAL`, `UNKNOWN`, `UNSPEC`, non-TCP). `rest` are the bytes after it.
    Header {
        /// The original client.
        source: Option<SocketAddr>,
        /// Bytes read after the header.
        rest: Vec<u8>,
    },
    /// No header; `read` are the bytes read, to be put back.
    Plain {
        /// Bytes read.
        read: Vec<u8>,
    },
    /// The peer closed the connection, or stopped sending, before anything was refused.
    Closed,
}

/// Why a connection was closed; the `reason` label of `rdock_proxy_protocol_rejected_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    /// A source outside `trusted` sent a header.
    #[error("PROXY header from an untrusted source")]
    Untrusted,
    /// A trusted source sent something else first.
    #[error("no PROXY header from a trusted source")]
    Missing,
    /// The header is invalid or was cut short.
    #[error("malformed PROXY header")]
    Malformed,
    /// The header was not complete within the listener's `timeouts.request_header`.
    #[error("PROXY header not received in time")]
    Timeout,
    /// The header is larger than [`MAX_HEADER`].
    #[error("PROXY header larger than 16 KiB")]
    TooLarge,
}

impl Rejection {
    /// The metric label.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Timeout => "timeout",
            Self::TooLarge => "too_large",
        }
    }
}

/// The connection is to be closed; the rejection, if any, is already counted and logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

/// The PROXY protocol step of a new connection on `listener`: reads a header when `config`
/// expects one from `peer`, puts back the bytes that follow, and counts rejections. `Ok` holds
/// the original client when a header named one.
///
/// # Errors
///
/// [`Closed`] when the connection must not go on.
pub async fn accept(
    listener: &str,
    config: Option<&ProxyProtocolIn>,
    peer: SocketAddr,
    stream: &mut L4Stream,
    deadline: Instant,
    metrics: &Metrics,
) -> Result<Option<SocketAddr>, Closed> {
    let Some(expect) = Expect::for_peer(config, peer.ip()) else {
        return Ok(None);
    };
    match read(stream, expect, deadline).await {
        Ok(Outcome::Header { source, rest }) => {
            stream.rewind(&rest);
            if source.is_some() {
                stream.set_proxy_digest(relayed_by(peer));
            }
            Ok(source)
        }
        Ok(Outcome::Plain { read }) => {
            stream.rewind(&read);
            Ok(None)
        }
        Ok(Outcome::Closed) => Err(Closed),
        Err(rejection) => {
            tracing::debug!(listener, peer = %peer, reason = rejection.reason(), "{rejection}");
            metrics
                .proxy_protocol_rejected
                .with_label_values(&[listener, rejection.reason()])
                .inc();
            Err(Closed)
        }
    }
}

/// Reads the first bytes of a connection until `expect` is settled, at most [`MAX_HEADER`]
/// bytes and until `deadline`.
///
/// # Errors
///
/// The [`Rejection`] when the connection must be closed for it.
pub async fn read<S: AsyncRead + Unpin>(
    stream: &mut S,
    expect: Expect,
    deadline: Instant,
) -> Result<Outcome, Rejection> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(settled) = settle(&buf, expect) {
            return settled;
        }
        if buf.len() >= MAX_HEADER {
            return Err(Rejection::TooLarge);
        }
        let room = (MAX_HEADER - buf.len()).min(chunk.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..room])).await {
            Ok(Ok(0) | Err(_)) => return stalled(expect, &buf, false),
            Err(_) => return stalled(expect, &buf, true),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The outcome of the bytes read so far, or `None` while more are needed.
fn settle(buf: &[u8], expect: Expect) -> Option<Result<Outcome, Rejection>> {
    match (signature(buf), expect) {
        (Signature::Partial, _) => None,
        (Signature::Absent, Expect::Header) => Some(Err(Rejection::Missing)),
        (Signature::Absent, _) => Some(Ok(Outcome::Plain { read: buf.to_vec() })),
        (Signature::Present, Expect::NoHeader) => Some(Err(Rejection::Untrusted)),
        (Signature::Present, _) => match parse(buf) {
            Err(proxy_header::Error::BufferTooShort) => None,
            Err(_) => Some(Err(Rejection::Malformed)),
            Ok((source, len)) => Some(Ok(Outcome::Header {
                source,
                rest: buf[len..].to_vec(),
            })),
        },
    }
}

/// The peer closed the connection (`timed_out` false) or went quiet before the bytes settled
/// anything.
fn stalled(expect: Expect, buf: &[u8], timed_out: bool) -> Result<Outcome, Rejection> {
    match expect {
        // Nothing to refuse: the peer did not even finish a signature.
        Expect::NoHeader => Ok(Outcome::Closed),
        // A header was started and not finished.
        _ if !buf.is_empty() && timed_out => Err(Rejection::Timeout),
        _ if !buf.is_empty() => Err(Rejection::Malformed),
        // A trusted source that connects and sends nothing.
        Expect::Header if timed_out => Err(Rejection::Timeout),
        _ => Ok(Outcome::Closed),
    }
}

/// Whether `buf` starts with a PROXY protocol signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signature {
    /// Too few bytes to tell.
    Partial,
    /// Neither signature.
    Absent,
    /// The v1 or the v2 signature.
    Present,
}

fn signature(buf: &[u8]) -> Signature {
    let mut partial = false;
    for signature in [V1_SIGNATURE, V2_SIGNATURE] {
        if buf.starts_with(signature) {
            return Signature::Present;
        }
        partial |= signature.starts_with(buf);
    }
    if partial {
        Signature::Partial
    } else {
        Signature::Absent
    }
}

/// Parses a header that starts with a signature: the original client, if it names one, and the
/// header's length.
fn parse(buf: &[u8]) -> Result<(Option<SocketAddr>, usize), proxy_header::Error> {
    let (header, len) = ProxyHeader::parse(buf, PARSE)?;
    // proxy-header accepts a longer v1 line when it arrives in one read.
    if buf.starts_with(V1_SIGNATURE) && len > V1_MAX {
        return Err(proxy_header::Error::Invalid);
    }
    let source = header
        .proxied_address()
        .filter(|a| a.protocol == Protocol::Stream)
        .map(|a| a.source);
    Ok((source, len))
}

/// The TCP peer of a connection whose address a PROXY header replaced, kept in its Pingora
/// `ProxyDigest`: the one per-connection slot for our own data that a downstream session's
/// digest carries for plain and TLS connections alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayedBy(SocketAddr);

fn relayed_by(peer: SocketAddr) -> ProxyDigest {
    // The digest needs a response header; nothing reads it for a downstream connection.
    let (unused, ()) = http::Response::new(()).into_parts();
    ProxyDigest::new(
        Box::new(ResponseHeader::from(unused)),
        Some(Box::new(RelayedBy(SocketAddr::new(
            crate::forwarded::canonical(peer.ip()),
            peer.port(),
        )))),
    )
}

/// The address that sent the PROXY header, when one replaced the connection's peer address.
#[must_use]
pub fn proxy_peer(digest: &Digest) -> Option<SocketAddr> {
    let user_data = digest.proxy_digest.as_ref()?.user_data.as_ref()?;
    user_data.downcast_ref::<RelayedBy>().map(|r| r.0)
}

/// The original client named by a header, as the connection's peer address in Pingora's socket
/// digest (`session.client_addr()`).
#[cfg(unix)]
pub(crate) fn set_peer(digest: &pingora::protocols::SocketDigest, source: SocketAddr) {
    // A fresh digest's cell is empty, so this cannot fail.
    let _ = digest
        .peer_addr
        .set(Some(pingora::protocols::l4::socket::SocketAddr::Inet(
            source,
        )));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rdock_testkit::proxy_protocol as pp;
    use tokio::io::AsyncWriteExt;

    use super::*;

    const SRC: &str = "192.168.0.1:56324";
    const DST: &str = "192.168.0.11:443";

    fn src() -> SocketAddr {
        SRC.parse().unwrap()
    }

    fn dst() -> SocketAddr {
        DST.parse().unwrap()
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_millis(500)
    }

    /// Reads from a peer that writes `chunks` one by one, then closes (or stays open).
    async fn read_chunks(
        chunks: Vec<Vec<u8>>,
        expect: Expect,
        close: bool,
    ) -> Result<Outcome, Rejection> {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let writer = tokio::spawn(async move {
            for chunk in chunks {
                client.write_all(&chunk).await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if !close {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            drop(client);
        });
        let outcome = read(&mut server, expect, soon()).await;
        writer.abort();
        outcome
    }

    async fn read_all(bytes: &[u8], expect: Expect) -> Result<Outcome, Rejection> {
        read_chunks(vec![bytes.to_vec()], expect, false).await
    }

    fn header(source: Option<SocketAddr>, rest: &[u8]) -> Outcome {
        Outcome::Header {
            source,
            rest: rest.to_vec(),
        }
    }

    #[tokio::test]
    async fn v1_spec_vector_with_the_request_after_it() {
        let line = b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n";
        let request = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(
            read_all(&[line.as_slice(), request].concat(), Expect::Header).await,
            Ok(header(Some(src()), request))
        );
        assert_eq!(pp::v1(src(), dst()), line, "the testkit encoder agrees");
    }

    #[tokio::test]
    async fn v2_ipv4_and_ipv6() {
        let mut bytes = pp::v2(src(), dst());
        assert_eq!(bytes[..12], pp::V2_SIGNATURE);
        bytes.extend_from_slice(b"\x16\x03\x01");
        assert_eq!(
            read_all(&bytes, Expect::Header).await,
            Ok(header(Some(src()), b"\x16\x03\x01"))
        );

        let v6: SocketAddr = "[2001:db8::1]:51234".parse().unwrap();
        let bytes = pp::v2(v6, "[2001:db8::2]:443".parse().unwrap());
        assert_eq!(
            read_all(&bytes, Expect::Header).await,
            Ok(header(Some(v6), b""))
        );
        let bytes = pp::v1(v6, "[2001:db8::2]:443".parse().unwrap());
        assert_eq!(
            read_all(&bytes, Expect::Header).await,
            Ok(header(Some(v6), b""))
        );
    }

    #[tokio::test]
    async fn split_across_reads_byte_by_byte() {
        let mut bytes = pp::v2(src(), dst());
        bytes.extend_from_slice(b"GET");
        let chunks = bytes.iter().map(|b| vec![*b]).collect();
        // Each read takes what has arrived; the header is complete before "GET" or with it.
        match read_chunks(chunks, Expect::Header, false).await.unwrap() {
            Outcome::Header { source, rest } => {
                assert_eq!(source, Some(src()));
                assert!(b"GET".starts_with(&rest), "{rest:?}");
            }
            other => panic!("{other:?}"),
        }
        let v1 = pp::v1(src(), dst());
        let chunks = v1.chunks(7).map(<[u8]>::to_vec).collect();
        assert_eq!(
            read_chunks(chunks, Expect::Header, false).await,
            Ok(header(Some(src()), b""))
        );
    }

    #[tokio::test]
    async fn local_unknown_and_tlvs_keep_or_skip() {
        assert_eq!(
            read_all(&pp::v2_local(), Expect::Header).await,
            Ok(header(None, b""))
        );
        assert_eq!(
            read_all(b"PROXY UNKNOWN\r\nGET", Expect::Header).await,
            Ok(header(None, b"GET"))
        );
        let with_tlvs = pp::v2_with_tlvs(src(), dst());
        assert!(with_tlvs.len() > pp::v2(src(), dst()).len());
        assert_eq!(
            read_all(&with_tlvs, Expect::Header).await,
            Ok(header(Some(src()), b""))
        );
        // UNSPEC family with the PROXY command: real endpoints.
        let unspec = [pp::V2_SIGNATURE.as_slice(), &[0x21, 0x00, 0x00, 0x00]].concat();
        assert_eq!(
            read_all(&unspec, Expect::Header).await,
            Ok(header(None, b""))
        );
    }

    #[tokio::test]
    async fn malformed_headers() {
        // Bad v2 version/command byte.
        let mut bad = pp::v2(src(), dst());
        bad[12] = 0x31;
        assert_eq!(
            read_all(&bad, Expect::Header).await,
            Err(Rejection::Malformed)
        );
        // Not a valid address.
        let bytes = b"PROXY TCP4 999.0.0.1 192.168.0.11 56324 443\r\n";
        assert_eq!(
            read_all(bytes, Expect::Header).await,
            Err(Rejection::Malformed)
        );
        // A v1 line of 108 bytes (the limit is 107), whole or in pieces.
        let line = |len: usize| {
            let head = "PROXY TCP4 192.168.0.1 192.168.0.11 ";
            let width = len - head.len() - " 443\r\n".len();
            format!("{head}{:0>width$} 443\r\n", "56324")
        };
        let long = line(108);
        assert_eq!(long.len(), 108);
        assert_eq!(
            read_all(long.as_bytes(), Expect::Header).await,
            Err(Rejection::Malformed)
        );
        let chunks = long.as_bytes().chunks(10).map(<[u8]>::to_vec).collect();
        assert_eq!(
            read_chunks(chunks, Expect::Header, false).await,
            Err(Rejection::Malformed)
        );
        // A line of exactly 107 bytes is accepted.
        let max = line(107);
        assert_eq!(
            read_all(max.as_bytes(), Expect::Header).await,
            Ok(header(Some(src()), b""))
        );
    }

    #[tokio::test]
    async fn truncated_headers() {
        let v2 = pp::v2(src(), dst());
        let cut = v2[..v2.len() - 3].to_vec();
        assert_eq!(
            read_chunks(vec![cut.clone()], Expect::Header, true).await,
            Err(Rejection::Malformed)
        );
        assert_eq!(
            read_chunks(vec![cut], Expect::Header, false).await,
            Err(Rejection::Timeout)
        );
        assert_eq!(
            read_chunks(
                vec![b"PROXY TCP4 192.168.0.1".to_vec()],
                Expect::Header,
                true
            )
            .await,
            Err(Rejection::Malformed)
        );
    }

    #[tokio::test]
    async fn oversized_header() {
        // A v2 header whose length claims 32 KiB.
        let mut big = [pp::V2_SIGNATURE.as_slice(), &[0x21, 0x11, 0x80, 0x00]].concat();
        big.resize(MAX_HEADER + 100, 0);
        assert_eq!(
            read_all(&big, Expect::Header).await,
            Err(Rejection::TooLarge)
        );
    }

    #[tokio::test]
    async fn trusted_source_without_a_header() {
        let request = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(
            read_all(request, Expect::Header).await,
            Err(Rejection::Missing)
        );
        assert_eq!(
            read_all(request, Expect::MaybeHeader).await,
            Ok(Outcome::Plain {
                read: request.to_vec()
            })
        );
        // Leading bytes of a signature that turn out not to be one.
        assert_eq!(
            read_all(b"PROPFIND /", Expect::Header).await,
            Err(Rejection::Missing)
        );
        assert_eq!(
            read_all(b"\r\nGET /", Expect::Header).await,
            Err(Rejection::Missing)
        );
        // Connects and sends nothing.
        assert_eq!(
            read_chunks(vec![], Expect::Header, false).await,
            Err(Rejection::Timeout)
        );
        assert_eq!(
            read_chunks(vec![], Expect::MaybeHeader, false).await,
            Ok(Outcome::Closed)
        );
        assert_eq!(
            read_chunks(vec![], Expect::Header, true).await,
            Ok(Outcome::Closed)
        );
    }

    #[tokio::test]
    async fn untrusted_sources() {
        assert_eq!(
            read_all(&pp::v1(src(), dst()), Expect::NoHeader).await,
            Err(Rejection::Untrusted)
        );
        assert_eq!(
            read_all(&pp::v2(src(), dst()), Expect::NoHeader).await,
            Err(Rejection::Untrusted)
        );
        // The signature alone is enough, valid header or not.
        assert_eq!(
            read_all(b"PROXY garbage", Expect::NoHeader).await,
            Err(Rejection::Untrusted)
        );
        let request = b"POST / HTTP/1.1\r\n";
        assert_eq!(
            read_all(request, Expect::NoHeader).await,
            Ok(Outcome::Plain {
                read: request.to_vec()
            })
        );
        let hello = b"\x16\x03\x01\x02\x00";
        assert_eq!(
            read_all(hello, Expect::NoHeader).await,
            Ok(Outcome::Plain {
                read: hello.to_vec()
            })
        );
        assert_eq!(
            read_chunks(vec![b"PRO".to_vec()], Expect::NoHeader, false).await,
            Ok(Outcome::Closed)
        );
    }

    #[test]
    fn trust_follows_the_configuration() {
        let config = ProxyProtocolIn {
            trusted: vec!["10.0.0.0/8".parse().unwrap()],
            optional: false,
        };
        let inside: IpAddr = "10.1.2.3".parse().unwrap();
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        let outside: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(Expect::for_peer(None, inside), None);
        assert_eq!(
            Expect::for_peer(Some(&config), inside),
            Some(Expect::Header)
        );
        assert_eq!(
            Expect::for_peer(Some(&config), mapped),
            Some(Expect::Header)
        );
        assert_eq!(
            Expect::for_peer(Some(&config), outside),
            Some(Expect::NoHeader)
        );
        let optional = ProxyProtocolIn {
            optional: true,
            ..config
        };
        assert_eq!(
            Expect::for_peer(Some(&optional), inside),
            Some(Expect::MaybeHeader)
        );
    }

    #[test]
    fn proxy_peer_round_trips_through_the_digest() {
        let peer: SocketAddr = "10.0.0.2:40000".parse().unwrap();
        let digest = Digest {
            proxy_digest: Some(Arc::new(relayed_by(peer))),
            ..Digest::default()
        };
        assert_eq!(proxy_peer(&digest), Some(peer));
        assert_eq!(proxy_peer(&Digest::default()), None);
        let mapped: SocketAddr = "[::ffff:10.0.0.2]:40000".parse().unwrap();
        let digest = Digest {
            proxy_digest: Some(Arc::new(relayed_by(mapped))),
            ..Digest::default()
        };
        assert_eq!(proxy_peer(&digest), Some(peer), "logged as IPv4");
    }
}
