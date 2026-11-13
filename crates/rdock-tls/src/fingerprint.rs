//! TLS client fingerprints computed from the ClientHello (H-SEC-03, ADR-0031): **JA4** and,
//! as an explicit option, the legacy **JA3**.
//!
//! JA4 follows FoxIO's specification `technical_details/JA4.md` at commit
//! `8eda4ce45426b639774158f7ab8bc873af69237f` of <https://github.com/FoxIO-LLC/ja4> (the
//! repository's `HEAD` on 2026-11-13). JA4 (TLS client fingerprinting) is licensed under the
//! BSD 3-Clause licence (`LICENSE-JA4`, "Copyright (c) 2026 FoxIO"); the notice is in `NOTICE`.
//! Only JA4 is implemented: the rest of the JA4+ family (JA4S, JA4H, JA4X, JA4T, …) is under
//! the FoxIO License 1.1, which is not an open-source licence, and is not part of ReverseDock.
//!
//! JA3 follows Salesforce's description (<https://github.com/salesforce/ja3>, BSD 3-Clause,
//! "Copyright (c) 2017, Salesforce.com, Inc."): `version,ciphers,extensions,groups,formats` in
//! decimal, GREASE removed, MD5 in hex. It hashes the extension *order*, which Chrome 110 and
//! later randomise (chromestatus feature 5124606246518784), so one browser has many JA3 values.
//!
//! Both are computed from the outer ClientHello: with Encrypted Client Hello the inner hello is
//! never seen.

use std::fmt::Write as _;

use md5::{Digest as _, Md5};

use crate::clienthello::HelloFacts;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;

/// Whether `value` is a GREASE value (RFC 8701 §2: `0x?a?a` with both bytes equal).
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

/// The transport the ClientHello came over: JA4's first character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TLS over TCP (`t`).
    Tcp,
    /// QUIC (`q`).
    Quic,
    /// DTLS (`d`).
    Dtls,
}

/// The JA4 fingerprint, for example `t13d1516h2_8daaf6152771_e5627efa2ab1`.
#[must_use]
pub fn ja4(facts: &HelloFacts, transport: Transport) -> String {
    let ciphers: Vec<u16> = facts
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let extensions: Vec<u16> = facts
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let version = facts
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .filter(|_| facts.extensions.contains(&0x002b))
        .unwrap_or(facts.version);
    let mut out = String::with_capacity(36);
    out.push(match transport {
        Transport::Tcp => 't',
        Transport::Quic => 'q',
        Transport::Dtls => 'd',
    });
    out.push_str(version_code(version));
    out.push(if facts.has_sni() { 'd' } else { 'i' });
    let _ = write!(
        out,
        "{:02}{:02}",
        ciphers.len().min(99),
        extensions.len().min(99)
    );
    out.push_str(&alpn_code(facts.first_alpn.as_deref()));
    out.push('_');

    let mut sorted = ciphers;
    sorted.sort_unstable();
    out.push_str(&truncated_sha256(&hex_list(&sorted)));
    out.push('_');

    let mut sorted: Vec<u16> = extensions
        .into_iter()
        .filter(|e| *e != EXT_SERVER_NAME && *e != EXT_ALPN)
        .collect();
    sorted.sort_unstable();
    if sorted.is_empty() {
        out.push_str(EMPTY);
    } else {
        let mut text = hex_list(&sorted);
        let algorithms: Vec<u16> = facts
            .signature_algorithms
            .iter()
            .copied()
            .filter(|a| !is_grease(*a))
            .collect();
        if !algorithms.is_empty() {
            text.push('_');
            text.push_str(&hex_list(&algorithms));
        }
        out.push_str(&truncated_sha256(&text));
    }
    out
}

/// The JA3 string before hashing: `version,ciphers,extensions,groups,formats`.
#[must_use]
pub fn ja3_text(facts: &HelloFacts) -> String {
    fn join<T: Copy + Into<u16>>(values: &[T]) -> String {
        let mut out = String::new();
        for v in values
            .iter()
            .map(|v| (*v).into())
            .filter(|v| !is_grease(*v))
        {
            if !out.is_empty() {
                out.push('-');
            }
            let _ = write!(out, "{v}");
        }
        out
    }
    format!(
        "{},{},{},{},{}",
        facts.version,
        join(&facts.cipher_suites),
        join(&facts.extensions),
        join(&facts.groups),
        join(&facts.point_formats),
    )
}

/// The JA3 fingerprint: MD5 of [`ja3_text`], lower-case hex.
#[must_use]
pub fn ja3(facts: &HelloFacts) -> String {
    // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes -- JA3 is defined as MD5 of the ClientHello summary; it identifies, it does not protect anything
    let digest = Md5::digest(ja3_text(facts).as_bytes());
    hex(&digest)
}

const EMPTY: &str = "000000000000";

fn version_code(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// First and last character of the first ALPN value; their hex digits when either byte is not
/// ASCII alphanumeric; `00` without a value.
fn alpn_code(first: Option<&[u8]>) -> String {
    let Some((&a, &z)) = first.and_then(|v| Some((v.first()?, v.last()?))) else {
        return "00".to_owned();
    };
    if a.is_ascii_alphanumeric() && z.is_ascii_alphanumeric() {
        [char::from(a), char::from(z)].iter().collect()
    } else {
        let hex_a = format!("{a:02x}");
        let hex_z = format!("{z:02x}");
        let first = hex_a.chars().next().unwrap_or('0');
        let last = hex_z.chars().last().unwrap_or('0');
        [first, last].iter().collect()
    }
}

fn hex_list(values: &[u16]) -> String {
    let mut out = String::with_capacity(values.len() * 5);
    for v in values {
        if !out.is_empty() {
            out.push(',');
        }
        let _ = write!(out, "{v:04x}");
    }
    out
}

fn truncated_sha256(text: &str) -> String {
    if text.is_empty() {
        return EMPTY.to_owned();
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
    let mut out = hex(digest.as_ref());
    out.truncate(12);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example of JA4.md (commit 8eda4ce4): ciphers and extensions in wire order,
    /// with GREASE values the spec says to drop.
    fn spec_example() -> HelloFacts {
        HelloFacts {
            version: 0x0303,
            cipher_suites: vec![
                0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x0a0a, 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005,
                0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015, 0xfafa,
            ],
            supported_versions: vec![0x7a7a, 0x0304, 0x0303],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            groups: vec![0x3a3a, 0x001d, 0x0017, 0x0018],
            point_formats: vec![0],
            first_alpn: Some(b"h2".to_vec()),
        }
    }

    #[test]
    fn the_specification_example() {
        assert_eq!(
            ja4(&spec_example(), Transport::Tcp),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
    }

    #[test]
    fn the_spec_hash_without_signature_algorithms() {
        let mut facts = spec_example();
        facts.signature_algorithms.clear();
        assert!(ja4(&facts, Transport::Tcp).ends_with("_6d807ffa2a79"));
    }

    #[test]
    fn grease_is_ignored_everywhere() {
        let mut plain = spec_example();
        plain.cipher_suites.retain(|c| !is_grease(*c));
        plain.extensions.retain(|e| !is_grease(*e));
        plain.supported_versions.retain(|v| !is_grease(*v));
        assert_eq!(
            ja4(&plain, Transport::Tcp),
            ja4(&spec_example(), Transport::Tcp)
        );
        assert_eq!(ja3(&plain), ja3(&spec_example()));
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && !is_grease(0x0a1a));
    }

    #[test]
    fn no_sni_no_alpn_and_no_supported_versions() {
        let mut facts = spec_example();
        facts.extensions.retain(|e| ![0, 0x10, 0x2b].contains(e));
        facts.first_alpn = None;
        let fp = ja4(&facts, Transport::Tcp);
        // TLS 1.2 from legacy_version, `i` for no SNI, 13 extensions, `00` for no ALPN.
        assert!(fp.starts_with("t12i151300_8daaf6152771_"), "{fp}");
    }

    #[test]
    fn empty_lists_hash_to_zeros_and_quic_dtls_prefixes() {
        let facts = HelloFacts {
            version: 0x0301,
            cipher_suites: vec![0x0a0a],
            ..HelloFacts::default()
        };
        assert_eq!(
            ja4(&facts, Transport::Quic),
            "q10i000000_000000000000_000000000000"
        );
        assert!(ja4(&facts, Transport::Dtls).starts_with("d10"));
        let unknown = HelloFacts {
            version: 0x1234,
            ..HelloFacts::default()
        };
        assert!(ja4(&unknown, Transport::Tcp).starts_with("t00"));
    }

    #[test]
    fn alpn_rules_of_the_specification() {
        for (value, code) in [
            (&[0xab][..], "ab"),
            (&[0x20], "20"),
            (&[0xab, 0xcd], "ad"),
            (&[0x20, 0x61], "21"),
            (&[0x30, 0xab], "3b"),
            (&[0x61, 0x20], "60"),
            (&[0x30, 0x31, 0xab, 0xcd], "3d"),
            (&[0x30, 0xab, 0xcd, 0x31], "01"),
            (b"http/1.1", "h1"),
            (b"h", "hh"),
        ] {
            assert_eq!(alpn_code(Some(value)), code, "{value:?}");
        }
        assert_eq!(alpn_code(Some(b"")), "00");
        assert_eq!(alpn_code(None), "00");
    }

    #[test]
    fn counts_saturate_at_99() {
        let facts = HelloFacts {
            version: 0x0303,
            cipher_suites: (1..=150).collect(),
            ..HelloFacts::default()
        };
        assert!(ja4(&facts, Transport::Tcp).starts_with("t12i9900"));
    }

    /// The example in Salesforce's JA3 README.
    #[test]
    fn the_ja3_readme_example() {
        let facts = HelloFacts {
            version: 769,
            cipher_suites: vec![47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
            extensions: vec![0, 10, 11],
            groups: vec![23, 24, 25],
            point_formats: vec![0],
            ..HelloFacts::default()
        };
        assert_eq!(
            ja3_text(&facts),
            "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
        );
        assert_eq!(ja3(&facts), "ada70206e40642a3e4461f35503241d5");
    }

    #[test]
    fn ja3_text_and_hash() {
        let facts = spec_example();
        assert_eq!(
            ja3_text(&facts),
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
             27-0-51-16-17513-23-45-13-5-35-18-43-65281-11-10-21,29-23-24,0"
        );
        let hash = ja3(&facts);
        assert_eq!(hash.len(), 32);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        // Reordering extensions changes JA3 but not JA4 (why JA3 is legacy).
        let mut shuffled = facts.clone();
        shuffled.extensions.reverse();
        assert_ne!(ja3(&shuffled), hash);
        assert_eq!(ja4(&shuffled, Transport::Tcp), ja4(&facts, Transport::Tcp));
    }
}
