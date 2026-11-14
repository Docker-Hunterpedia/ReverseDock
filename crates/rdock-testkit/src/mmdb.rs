//! A tiny MaxMind DB writer for test fixtures, written from the format specification
//! (<https://maxmind.github.io/MaxMind-DB/>, format 2.0): an IPv6 search tree with 24-bit
//! records, a data section and the metadata map. Enough for country and ASN records; no
//! pointers, no deduplication. Generated in the test so no third-party database is vendored.

// Sizes and record values are bounded by the small fixtures this writes.
#![allow(clippy::cast_possible_truncation)]

use std::net::IpAddr;

/// A value in the data section.
#[derive(Debug, Clone)]
pub enum Value {
    /// A UTF-8 string.
    Str(String),
    /// An unsigned 32-bit integer.
    U32(u32),
    /// An unsigned 16-bit integer.
    U16(u16),
    /// An unsigned 64-bit integer.
    U64(u64),
    /// A map with string keys.
    Map(Vec<(String, Value)>),
    /// An array.
    Array(Vec<Value>),
}

impl Value {
    /// A map from `(key, value)` pairs.
    pub fn map(pairs: &[(&str, Value)]) -> Self {
        Self::Map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    /// A string.
    pub fn str(s: &str) -> Self {
        Self::Str(s.to_owned())
    }
}

fn control(out: &mut Vec<u8>, kind: u8, size: usize) {
    let (first, extra): (u8, Vec<u8>) = if size < 29 {
        (size as u8, Vec::new())
    } else if size < 29 + 256 {
        (29, vec![(size - 29) as u8])
    } else if size < 285 + 65_536 {
        let n = size - 285;
        (30, vec![(n >> 8) as u8, n as u8])
    } else {
        let n = size - 65_821;
        (31, vec![(n >> 16) as u8, (n >> 8) as u8, n as u8])
    };
    if kind <= 7 {
        out.push((kind << 5) | first);
    } else {
        out.push(first);
        out.push(kind - 7);
    }
    out.extend(extra);
}

fn uint(out: &mut Vec<u8>, kind: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    control(out, kind, 8 - skip);
    out.extend_from_slice(&bytes[skip..]);
}

/// Encodes `value` in the data-section format.
pub fn encode(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Str(s) => {
            control(out, 2, s.len());
            out.extend_from_slice(s.as_bytes());
        }
        Value::U16(v) => uint(out, 5, u64::from(*v)),
        Value::U32(v) => uint(out, 6, u64::from(*v)),
        Value::U64(v) => uint(out, 9, *v),
        Value::Map(pairs) => {
            control(out, 7, pairs.len());
            for (k, v) in pairs {
                encode(out, &Value::Str(k.clone()));
                encode(out, v);
            }
        }
        Value::Array(items) => {
            control(out, 11, items.len());
            for v in items {
                encode(out, v);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Rec {
    Empty,
    Node(usize),
    Data(usize),
}

/// Builds a database: `networks` are `(address, prefix length, record)`; IPv4 networks live
/// at `::a.b.c.d` like in MaxMind's IPv6 databases. Networks must not overlap.
pub fn build(database_type: &str, build_epoch: u64, networks: &[(IpAddr, u8, Value)]) -> Vec<u8> {
    let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty, Rec::Empty]];
    let mut data = Vec::new();
    for (ip, len, value) in networks {
        let (bits, len) = match ip {
            IpAddr::V4(v4) => (u128::from(u32::from(*v4)), 96 + u32::from(*len)),
            IpAddr::V6(v6) => (u128::from(*v6), u32::from(*len)),
        };
        let offset = data.len();
        encode(&mut data, value);
        let mut node = 0;
        for i in 0..len {
            let bit = ((bits >> (127 - i)) & 1) as usize;
            if i + 1 == len {
                nodes[node][bit] = Rec::Data(offset);
            } else {
                node = if let Rec::Node(next) = nodes[node][bit] {
                    next
                } else {
                    nodes.push([Rec::Empty, Rec::Empty]);
                    let next = nodes.len() - 1;
                    nodes[node][bit] = Rec::Node(next);
                    next
                };
            }
        }
    }
    let count = nodes.len();
    let mut out = Vec::new();
    for node in &nodes {
        for rec in node {
            let value = match *rec {
                Rec::Empty => count,
                Rec::Node(n) => n,
                Rec::Data(offset) => count + 16 + offset,
            };
            let value = u32::try_from(value).unwrap();
            out.extend_from_slice(&value.to_be_bytes()[1..]);
        }
    }
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&data);
    out.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    let metadata = Value::map(&[
        ("binary_format_major_version", Value::U16(2)),
        ("binary_format_minor_version", Value::U16(0)),
        ("build_epoch", Value::U64(build_epoch)),
        ("database_type", Value::str(database_type)),
        (
            "description",
            Value::map(&[("en", Value::str("rdock test fixture"))]),
        ),
        ("ip_version", Value::U16(6)),
        ("languages", Value::Array(vec![Value::str("en")])),
        ("node_count", Value::U32(u32::try_from(count).unwrap())),
        ("record_size", Value::U16(24)),
    ]);
    encode(&mut out, &metadata);
    out
}

/// A GeoIP2-shaped country record.
pub fn country(iso: &str, continent: &str) -> Value {
    Value::map(&[
        ("continent", Value::map(&[("code", Value::str(continent))])),
        ("country", Value::map(&[("iso_code", Value::str(iso))])),
    ])
}

/// A GeoLite2-ASN-shaped record.
pub fn asn(number: u32) -> Value {
    Value::map(&[("autonomous_system_number", Value::U32(number))])
}

/// Seconds since the Unix epoch, `days` ago.
pub fn days_ago(days: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(days * 86_400)
}
