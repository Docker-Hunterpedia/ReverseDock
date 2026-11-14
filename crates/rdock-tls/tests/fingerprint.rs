//! JA4 and JA3 from ClientHello bytes on the wire: FoxIO's worked example rebuilt as a real
//! hello (with GREASE), split across records, without SNI or ALPN, and the parser's bounds.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use rdock_tls::clienthello::{self, HelloError, MAX_EXTENSIONS, Parsed};
use rdock_tls::fingerprint::{Transport, ja3, ja4};
use rustls::crypto::ring;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

fn record(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![22, 3, 1];
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn vec8(data: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(data.len()).unwrap()];
    out.extend_from_slice(data);
    out
}

fn vec16(data: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(data.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

fn u16s(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// The handshake message (type 1) of a ClientHello with `ciphers` and `extensions`.
fn message(ciphers: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&vec16(&u16s(ciphers)));
    body.extend_from_slice(&[1, 0]);
    let mut list = Vec::new();
    for (kind, data) in extensions {
        list.extend_from_slice(&kind.to_be_bytes());
        list.extend_from_slice(&vec16(data));
    }
    body.extend_from_slice(&vec16(&list));
    let mut out = vec![1];
    out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    out.extend_from_slice(&body);
    out
}

fn sni(name: &[u8]) -> (u16, Vec<u8>) {
    let mut entry = vec![0];
    entry.extend_from_slice(&vec16(name));
    (0x0000, vec16(&entry))
}

fn alpn(protocols: &[&[u8]]) -> (u16, Vec<u8>) {
    let list: Vec<u8> = protocols.iter().flat_map(|p| vec8(p)).collect();
    (0x0010, vec16(&list))
}

/// The cipher suites and extensions of JA4.md's worked example (commit 8eda4ce4), in its wire
/// order, with GREASE values inserted the way Chrome sends them.
fn spec_hello(with_sni: bool, with_alpn: bool) -> Vec<u8> {
    let ciphers = [
        0x8a8a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let sigalgs = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let mut extensions = vec![(0x1a1a, Vec::new()), (0x001b, vec![2, 0, 2])];
    if with_sni {
        extensions.push(sni(b"example.com"));
    }
    extensions.push((0x0033, vec16(&[])));
    if with_alpn {
        extensions.push(alpn(&[b"h2", b"http/1.1"]));
    }
    extensions.extend([
        (0x4469, vec16(&vec8(b"h2"))),
        (0x0017, Vec::new()),
        (0x002d, vec8(&[1])),
        (0x000d, vec16(&u16s(&sigalgs))),
        (0x0005, vec![1, 0, 0, 0, 0]),
        (0x0023, Vec::new()),
        (0x0012, Vec::new()),
        (0x002b, vec8(&u16s(&[0x3a3a, 0x0304, 0x0303]))),
        (0xff01, vec![0]),
        (0x000b, vec8(&[0])),
        (0x000a, vec16(&u16s(&[0x4a4a, 0x001d, 0x0017, 0x0018]))),
        (0x0015, vec![0; 8]),
        (0x2a2a, vec![0]),
    ]);
    record(&message(&ciphers, &extensions))
}

fn fingerprint(bytes: &[u8]) -> String {
    ja4(&clienthello::facts(bytes).unwrap(), Transport::Tcp)
}

#[test]
fn the_specification_example_on_the_wire() {
    assert_eq!(
        fingerprint(&spec_hello(true, true)),
        "t13d1516h2_8daaf6152771_e5627efa2ab1"
    );
}

#[test]
fn a_hello_split_across_records_gives_the_same_fingerprint() {
    let whole = spec_hello(true, true);
    let message = &whole[5..];
    for size in [1, 7, 50, 200] {
        let split: Vec<u8> = message.chunks(size).flat_map(record).collect();
        assert_eq!(
            fingerprint(&split),
            fingerprint(&whole),
            "records of {size}"
        );
    }
}

#[test]
fn no_sni_and_no_alpn() {
    let fp = fingerprint(&spec_hello(false, false));
    assert!(fp.starts_with("t13i151400_8daaf6152771_"), "{fp}");
    // SNI and ALPN are not part of the third section.
    assert!(fp.ends_with("_e5627efa2ab1"), "{fp}");
}

#[test]
fn incomplete_or_foreign_bytes_have_no_fingerprint() {
    let whole = spec_hello(true, true);
    assert!(clienthello::facts(&whole[..whole.len() - 1]).is_none());
    assert!(clienthello::facts(b"GET / HTTP/1.1\r\n\r\n").is_none());
    assert!(clienthello::facts(&[]).is_none());
}

#[test]
fn duplicate_and_excess_extensions_are_refused() {
    let duplicate = record(&message(
        &[0x1301],
        &[(0x0017, Vec::new()), (0x0017, Vec::new())],
    ));
    assert_eq!(
        clienthello::parse(&duplicate),
        Err(HelloError::Malformed("duplicate extension"))
    );
    assert!(clienthello::facts(&duplicate).is_none());
    let many: Vec<(u16, Vec<u8>)> = (0..=u16::try_from(MAX_EXTENSIONS).unwrap())
        .map(|i| (0x7000 + i, Vec::new()))
        .collect();
    let too_many = record(&message(&[0x1301], &many));
    assert_eq!(
        clienthello::parse(&too_many),
        Err(HelloError::Malformed("too many extensions"))
    );
    let just_enough = record(&message(&[0x1301], &many[..MAX_EXTENSIONS]));
    assert!(matches!(
        clienthello::parse(&just_enough),
        Ok(Parsed::Hello { .. })
    ));
}

#[test]
fn a_rustls_client_hello() {
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server = ServerName::try_from("a.example.com").unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server).unwrap();
    let mut bytes = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut bytes).unwrap();
    }
    let facts = clienthello::facts(&bytes).unwrap();
    let fp = ja4(&facts, Transport::Tcp);
    assert!(fp.starts_with("t13d") && fp.contains("h2_"), "{fp}");
    assert_eq!(fp.len(), 36);
    assert_eq!(ja3(&facts).len(), 32);
    // The same client always gives the same JA4.
    assert_eq!(fingerprint(&bytes), fp);
}
