//! PROXY protocol headers for tests, encoded with proxy-header
//! (<https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>).

use std::net::SocketAddr;

use proxy_header::{ProxiedAddress, ProxyHeader, Tlv};

/// The v2 signature (specification §2.2).
pub const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// A v1 header (`PROXY TCP4|TCP6 …\r\n`).
pub fn v1(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    ProxyHeader::with_address(ProxiedAddress::stream(source, destination))
        .encode_v1(&mut out)
        .unwrap();
    out
}

/// A v2 header with the PROXY command over TCP.
pub fn v2(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    ProxyHeader::with_address(ProxiedAddress::stream(source, destination))
        .encode_v2(&mut out)
        .unwrap();
    out
}

/// A v2 header with the LOCAL command, as health checks send it.
pub fn v2_local() -> Vec<u8> {
    let mut out = Vec::new();
    ProxyHeader::with_local().encode_v2(&mut out).unwrap();
    out
}

/// A v2 PROXY header carrying ALPN, authority and a custom TLV.
pub fn v2_with_tlvs(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    ProxyHeader::with_tlvs(
        Some(ProxiedAddress::stream(source, destination)),
        [
            Tlv::Alpn(b"h2".as_slice().into()),
            Tlv::Authority("app.test".into()),
            Tlv::Custom(0xE0, b"opaque".as_slice().into()),
        ],
    )
    .encode_v2(&mut out)
    .unwrap();
    out
}
