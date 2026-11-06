//! The ClientHello peek against hellos written by rustls, hand-built edge cases and the
//! rustls server `Acceptor` as an oracle.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use proptest::prelude::*;
use rdock_tls::clienthello::{
    ClientHello, Detected, HelloError, MAX_PEEK, Parsed, PeekError, parse, peek,
};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup, ring};
use rustls::pki_types::ServerName;
use rustls::server::Acceptor;
use rustls::{ClientConfig, ClientConnection, NamedGroup, RootCertStore};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::time::Instant;

const H2: &[u8] = b"h2";
const HTTP1: &[u8] = b"http/1.1";

// ---- ClientHellos written by rustls ----

fn client_config(provider: CryptoProvider, alpn: &[&[u8]]) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// The exact bytes a rustls client sends first.
fn first_flight(config: ClientConfig, server: ServerName<'static>) -> Vec<u8> {
    let mut conn = ClientConnection::new(Arc::new(config), server).unwrap();
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).unwrap();
    }
    out
}

fn rustls_hello(server: &str, alpn: &[&[u8]]) -> Vec<u8> {
    let server = ServerName::try_from(server.to_owned()).unwrap();
    first_flight(client_config(ring::default_provider(), alpn), server)
}

/// A key-share group with the size of X25519MLKEM768 (1216 bytes), which the ring provider
/// does not offer: it makes rustls write a ClientHello as large as a post-quantum one.
#[derive(Debug)]
struct PostQuantumSized;

impl SupportedKxGroup for PostQuantumSized {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(PostQuantumShare(vec![0x42; 1216])))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

struct PostQuantumShare(Vec<u8>);

impl ActiveKeyExchange for PostQuantumShare {
    fn complete(self: Box<Self>, _peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        Err(rustls::Error::General("test key share".into()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.0
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

fn post_quantum_sized_hello(server: &str) -> Vec<u8> {
    let provider = CryptoProvider {
        kx_groups: vec![&PostQuantumSized, ring::kx_group::X25519],
        ..ring::default_provider()
    };
    let server = ServerName::try_from(server.to_owned()).unwrap();
    first_flight(client_config(provider, &[H2, HTTP1, b"postgresql"]), server)
}

// ---- ClientHellos built by hand ----

fn record(content: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![content, 3, 1];
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![msg_type];
    out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn vec16(data: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(data.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// `legacy_version`, random, an empty session id, one suite and the null compression method.
fn hello_prefix() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    body
}

/// A ClientHello body carrying `extensions` as (type, data).
fn hello_body(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut list = Vec::new();
    for (kind, data) in extensions {
        list.extend_from_slice(&kind.to_be_bytes());
        list.extend_from_slice(&vec16(data));
    }
    let mut body = hello_prefix();
    body.extend_from_slice(&vec16(&list));
    body
}

/// One handshake record holding a ClientHello with `extensions`.
fn hand_hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    record(22, &handshake(1, &hello_body(extensions)))
}

fn sni(names: &[&[u8]]) -> (u16, Vec<u8>) {
    let mut list = Vec::new();
    for name in names {
        list.push(0);
        list.extend_from_slice(&vec16(name));
    }
    (0, vec16(&list))
}

fn alpn(protocols: &[&[u8]]) -> (u16, Vec<u8>) {
    let mut list = Vec::new();
    for protocol in protocols {
        list.push(u8::try_from(protocol.len()).unwrap());
        list.extend_from_slice(protocol);
    }
    (16, vec16(&list))
}

/// The handshake bytes of a run of records, re-framed into records of `size` bytes.
fn reframe(records: &[u8], size: usize) -> Vec<u8> {
    let mut message = Vec::new();
    let mut rest = records;
    while !rest.is_empty() {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        message.extend_from_slice(&rest[5..5 + len]);
        rest = &rest[5 + len..];
    }
    message
        .chunks(size)
        .flat_map(|chunk| record(22, chunk))
        .collect()
}

// ---- Assertions ----

fn expect_hello(bytes: &[u8]) -> ClientHello {
    match parse(bytes) {
        Ok(Parsed::Hello { hello, len }) => {
            assert_eq!(len, bytes.len(), "the hello ends where its records end");
            hello
        }
        other => panic!("expected a ClientHello, got {other:?}"),
    }
}

fn expect_error(bytes: &[u8]) -> HelloError {
    match parse(bytes) {
        Err(error) => error,
        other => panic!("expected an error, got {other:?}"),
    }
}

/// Every proper prefix asks for more bytes than it has.
fn assert_prefixes_need_more(bytes: &[u8]) {
    for cut in 0..bytes.len() {
        match parse(&bytes[..cut]) {
            Ok(Parsed::NeedMore { total }) => {
                assert!(
                    total > cut && total <= bytes.len(),
                    "cut {cut}: total {total}"
                );
            }
            other => panic!("cut {cut}: expected NeedMore, got {other:?}"),
        }
    }
}

fn hello(sni: Option<&str>, alpn: &[&[u8]]) -> ClientHello {
    ClientHello {
        sni: sni.map(str::to_owned),
        alpn: alpn.iter().map(|p| p.to_vec()).collect(),
    }
}

// ---- A stream that hands out chunks ----

/// Returns one queued chunk per read, then end of stream.
struct Chunks(VecDeque<Vec<u8>>);

impl Chunks {
    fn split(bytes: &[u8], at: &[usize]) -> Self {
        let mut chunks = VecDeque::new();
        let mut start = 0;
        for &end in at.iter().chain([&bytes.len()]) {
            chunks.push_back(bytes[start..end].to_vec());
            start = end;
        }
        Self(chunks)
    }
}

impl AsyncRead for Chunks {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut chunk) = self.0.pop_front() {
            let n = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..n]);
            if n < chunk.len() {
                self.0.push_front(chunk.split_off(n));
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

async fn peek_chunks(mut stream: Chunks) -> (Result<Detected, PeekError>, Vec<u8>) {
    let peeked = peek(&mut stream, soon()).await;
    (peeked.result, peeked.bytes)
}

// ---- Real ClientHellos ----

#[test]
fn reads_a_rustls_hello_whole_and_prefix_by_prefix() {
    let bytes = rustls_hello("api.example.com", &[H2, HTTP1]);
    assert_eq!(
        expect_hello(&bytes),
        hello(Some("api.example.com"), &[H2, HTTP1])
    );
    assert_prefixes_need_more(&bytes);
}

#[tokio::test]
async fn peek_reads_byte_by_byte_and_split_at_every_offset() {
    let bytes = rustls_hello("api.example.com", &[H2]);
    let expected = Detected::Hello(hello(Some("api.example.com"), &[H2]));
    let every_byte: Vec<usize> = (1..bytes.len()).collect();
    let (result, read) = peek_chunks(Chunks::split(&bytes, &every_byte)).await;
    assert_eq!(result.unwrap(), expected);
    assert_eq!(read, bytes);
    for at in 1..bytes.len() {
        let (result, read) = peek_chunks(Chunks::split(&bytes, &[at])).await;
        assert_eq!(result.unwrap(), expected, "split at {at}");
        assert_eq!(read, bytes, "split at {at}");
    }
}

#[test]
fn reassembles_a_hello_fragmented_across_records() {
    let bytes = rustls_hello("db.example.com", &[b"postgresql"]);
    let expected = hello(Some("db.example.com"), &[b"postgresql"]);
    for size in [100, 7, 1] {
        let fragmented = reframe(&bytes, size);
        assert!(fragmented.len() > bytes.len());
        assert_eq!(expect_hello(&fragmented), expected, "fragments of {size}");
    }
    assert_prefixes_need_more(&reframe(&bytes, 100));
}

#[test]
fn an_ip_address_sends_no_sni() {
    let bytes = rustls_hello("192.0.2.7", &[H2]);
    assert_eq!(expect_hello(&bytes), hello(None, &[H2]));
}

#[test]
fn keeps_every_alpn_protocol_in_order() {
    let protocols: [&[u8]; 4] = [b"imap", H2, HTTP1, b"acme-tls/1"];
    let bytes = rustls_hello("mail.example.com", &protocols);
    assert_eq!(expect_hello(&bytes).alpn, protocols.map(<[u8]>::to_vec));
    assert_eq!(
        expect_hello(&rustls_hello("a.example.com", &[])).alpn,
        Vec::<Vec<u8>>::new()
    );
}

#[tokio::test]
async fn reads_a_post_quantum_sized_hello_over_several_segments() {
    let name = "postgres-primary.eu-central.db.example.com";
    let bytes = post_quantum_sized_hello(name);
    assert!(
        bytes.len() > 1460,
        "larger than one TCP segment: {}",
        bytes.len()
    );
    let expected = hello(Some(name), &[H2, HTTP1, b"postgresql"]);
    assert_eq!(expect_hello(&bytes), expected);
    assert_eq!(oracle(&bytes), expected);
    let (result, read) = peek_chunks(Chunks::split(&bytes, &[1460])).await;
    assert_eq!(result.unwrap(), Detected::Hello(expected));
    assert_eq!(read, bytes);
}

// ---- Not TLS ----

#[test]
fn http_and_other_protocols_are_not_tls() {
    let cases: [&[u8]; 8] = [
        b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"G",
        b"SSH-2.0-OpenSSH_9.9\r\n",
        b"\x00\x00\x00\x08\x04\xd2\x16\x2f", // PostgreSQL SSLRequest
        b"\x15\x03\x03\x00\x02\x02\x28",     // a TLS alert record
        b"\x16\x02",                         // not version 3
        b"\x16\x03\x02\x00\x10",             // TLS 1.1 record version
        b"\x16\x03\x00\x00\x10",             // SSL 3.0 record version
    ];
    for bytes in cases {
        assert_eq!(parse(bytes), Ok(Parsed::NotTls), "{bytes:?}");
    }
}

#[tokio::test]
async fn peek_returns_non_tls_bytes_untouched() {
    let bytes = b"GET / HTTP/1.1\r\n\r\n";
    let (result, read) = peek_chunks(Chunks::split(bytes, &[3])).await;
    assert_eq!(result.unwrap(), Detected::NotTls);
    assert_eq!(read, &bytes[..3], "decided on the first read");
}

// ---- SNI rules (RFC 6066 §3) ----

#[test]
fn lower_cases_the_server_name() {
    let bytes = hand_hello(&[sni(&[b"API.Example.COM"])]);
    assert_eq!(expect_hello(&bytes).sni.as_deref(), Some("api.example.com"));
}

#[test]
fn names_rfc_6066_forbids_give_no_sni() {
    let cases: [&[&[u8]]; 6] = [
        &[b"example.com."],
        &[b"\xc3\xa9xample.com"],
        &[b"exa mple.com"],
        &[b"192.0.2.1"],
        &[b"2001:db8::1"],
        &[b"a.example.com", b"b.example.com"],
    ];
    for names in cases {
        let bytes = hand_hello(&[sni(names), alpn(&[H2])]);
        assert_eq!(expect_hello(&bytes), hello(None, &[H2]), "{names:?}");
    }
}

#[test]
fn stops_at_an_unknown_name_type() {
    // name_type 1 has no defined encoding, so nothing after it can be read.
    let parts: [&[u8]; 4] = [&[1, 0, 3], b"abc", &[0, 0, 5], b"x.com"];
    let list = parts.concat();
    let bytes = hand_hello(&[(0, vec16(&list))]);
    assert_eq!(expect_hello(&bytes).sni, None);
}

#[test]
fn a_hello_without_extensions_has_no_sni_or_alpn() {
    let bytes = record(22, &handshake(1, &hello_prefix()));
    assert_eq!(expect_hello(&bytes), ClientHello::default());
}

// ---- Malformed input ----

#[test]
fn refuses_records_longer_than_16_kib() {
    assert_eq!(
        expect_error(b"\x16\x03\x01\x40\x01"),
        HelloError::RecordTooLong { len: 16385 }
    );
}

#[test]
fn refuses_declared_lengths_that_overflow() {
    let malformed = |body: Vec<u8>| expect_error(&record(22, &handshake(1, &body)));
    let mut long_session = vec![3, 3];
    long_session.extend_from_slice(&[0; 32]);
    long_session.push(33);
    long_session.extend_from_slice(&[0; 40]);
    assert!(matches!(malformed(long_session), HelloError::Malformed(_)));

    let mut suites_overflow = hello_prefix();
    suites_overflow.truncate(35);
    suites_overflow.extend_from_slice(&[0xff, 0xff, 0x13, 0x01]);
    assert!(matches!(
        malformed(suites_overflow),
        HelloError::Malformed(_)
    ));

    let mut extensions_overflow = hello_prefix();
    extensions_overflow.extend_from_slice(&[0x10, 0x00, 0, 0]);
    assert!(matches!(
        malformed(extensions_overflow),
        HelloError::Malformed(_)
    ));

    let sni_overflow = hello_body(&[(0, vec![0x00, 0x09, 0, 0xff, 0xff, b'a'])]);
    assert!(matches!(malformed(sni_overflow), HelloError::Malformed(_)));

    let alpn_overflow = hello_body(&[(16, vec![0x00, 0x03, 0x20, b'h', b'2'])]);
    assert!(matches!(malformed(alpn_overflow), HelloError::Malformed(_)));

    let handshake_overflow = b"\x16\x03\x01\x00\x04\x01\xff\xff\xff";
    assert_eq!(expect_error(handshake_overflow), HelloError::TooLarge);
}

#[test]
fn refuses_duplicate_and_empty_extensions() {
    for extensions in [
        vec![sni(&[b"a.com"]), sni(&[b"b.com"])],
        vec![alpn(&[H2]), alpn(&[HTTP1])],
        vec![(0, vec16(&[]))],
        vec![sni(&[b""])],
        vec![(16, vec16(&[]))],
        vec![alpn(&[b""])],
    ] {
        let error = expect_error(&hand_hello(&extensions));
        assert!(matches!(error, HelloError::Malformed(_)), "{extensions:?}");
    }
}

#[test]
fn refuses_other_messages_and_interleaved_records() {
    let server_hello = record(22, &handshake(2, &hello_prefix()));
    assert_eq!(
        expect_error(&server_hello),
        HelloError::NotClientHello { msg_type: 2 }
    );

    let message = handshake(1, &hello_body(&[sni(&[b"a.com"])]));
    let mut interleaved = record(22, &message[..20]);
    interleaved.extend_from_slice(&record(23, &message[20..]));
    assert!(matches!(
        expect_error(&interleaved),
        HelloError::Malformed(_)
    ));

    assert!(matches!(
        expect_error(b"\x16\x03\x01\x00\x00"),
        HelloError::Malformed(_)
    ));
}

#[tokio::test]
async fn stops_at_the_16_kib_cap() {
    // A hello that declares 15000 bytes (within the cap) but arrives in 10-byte records:
    // the record headers push it past 16 KiB.
    let body = vec![0; 15_000];
    let records = reframe(&record(22, &handshake(1, &body)[..9000]), 10);
    let records = [records.clone(), records].concat();
    assert!(records.len() > 20 * 1024);
    assert_eq!(expect_error(&records), HelloError::TooLarge);

    let (result, read) = peek_chunks(Chunks::split(&records, &[4096, 8192, 12288])).await;
    assert!(matches!(
        result,
        Err(PeekError::Hello(HelloError::TooLarge))
    ));
    assert!(read.len() <= MAX_PEEK && records.starts_with(&read));
}

// ---- Peek: deadlines and closed connections ----

#[tokio::test]
async fn peek_gives_back_the_bytes_when_the_client_closes() {
    let bytes = rustls_hello("a.example.com", &[]);
    let (result, read) = peek_chunks(Chunks::split(&bytes[..40], &[])).await;
    assert!(matches!(result, Err(PeekError::Closed)));
    assert_eq!(read, &bytes[..40]);
}

#[tokio::test]
async fn peek_gives_back_the_bytes_at_the_deadline() {
    let bytes = rustls_hello("a.example.com", &[]);
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    tokio::io::AsyncWriteExt::write_all(&mut client, &bytes[..40])
        .await
        .unwrap();
    let peeked = peek(&mut server, Instant::now() + Duration::from_millis(50)).await;
    assert!(matches!(peeked.result, Err(PeekError::TimedOut)));
    assert_eq!(peeked.bytes, &bytes[..40]);
}

#[tokio::test]
async fn peek_keeps_bytes_read_past_the_hello() {
    let bytes = rustls_hello("a.example.com", &[H2]);
    let with_early_data = [&bytes[..], b"\x17\x03\x03\x00\x01x"].concat();
    let (result, read) = peek_chunks(Chunks::split(&with_early_data, &[])).await;
    assert_eq!(
        result.unwrap(),
        Detected::Hello(hello(Some("a.example.com"), &[H2]))
    );
    assert_eq!(read, with_early_data);
}

// ---- Properties ----

/// What the rustls server `Acceptor` reads from the same bytes.
fn oracle(bytes: &[u8]) -> ClientHello {
    let mut acceptor = Acceptor::default();
    let mut rest = bytes;
    while !rest.is_empty() {
        acceptor.read_tls(&mut rest).unwrap();
    }
    let accepted = acceptor.accept().map_err(|(e, _)| e).unwrap().unwrap();
    let client_hello = accepted.client_hello();
    ClientHello {
        sni: client_hello.server_name().map(str::to_ascii_lowercase),
        alpn: client_hello
            .alpn()
            .map(|protocols| protocols.map(<[u8]>::to_vec).collect())
            .unwrap_or_default(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn agrees_with_the_rustls_acceptor(
        name in "[a-zA-Z0-9]{1,12}(\\.[a-z0-9]{1,12}){0,3}\\.[a-z]{2,6}",
        protocols in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..20), 0..6),
        fragment in proptest::option::of(32_usize..600),
    ) {
        let alpn: Vec<&[u8]> = protocols.iter().map(Vec::as_slice).collect();
        let mut config = client_config(ring::default_provider(), &alpn);
        config.max_fragment_size = fragment;
        let bytes = first_flight(config, ServerName::try_from(name.clone()).unwrap());
        let ours = expect_hello(&bytes);
        prop_assert_eq!(ours.sni.clone(), Some(name.to_ascii_lowercase()));
        prop_assert_eq!(ours, oracle(&bytes));
    }

    #[test]
    fn random_bytes_not_starting_with_a_handshake_record_are_not_tls(
        first in any::<u8>().prop_filter("not a handshake record", |b| *b != 22),
        rest in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let bytes = [&[first][..], &rest].concat();
        prop_assert_eq!(parse(&bytes), Ok(Parsed::NotTls));
    }

    #[test]
    fn random_record_bodies_never_claim_more_than_given(
        body in proptest::collection::vec(any::<u8>(), 0..400),
    ) {
        let bytes = record(22, &body);
        match parse(&bytes) {
            Ok(Parsed::NeedMore { total }) => prop_assert!(total > bytes.len() && total <= MAX_PEEK),
            Ok(Parsed::Hello { len, .. }) => prop_assert!(len <= bytes.len()),
            Ok(Parsed::NotTls) | Err(_) => {}
        }
    }
}
