//! The disk store's file format.
//!
//! ```text
//! prefix (32 bytes, little endian):
//!   0..8    magic "RDKCACHE"
//!   8..10   format version (1)
//!   10..12  flags (0)
//!   12..16  header length
//!   16..24  body length
//!   24..28  CRC-32 of the header block
//!   28..32  CRC-32 of bytes 0..28
//! header block:
//!   id (16), variance flag (1) [+ variance (16)],
//!   url (u32 length + bytes), tags (u16 count, each u16 length + bytes),
//!   meta internal (u32 length + bytes), meta header (u32 length + bytes)
//! body (body length bytes)
//! ```
//!
//! The meta parts are pingora-cache's own `CacheMeta::serialize` output. A file whose prefix,
//! checksums or lengths do not add up is damaged and is dropped at start.

use super::super::Id;

/// File magic.
pub(crate) const MAGIC: [u8; 8] = *b"RDKCACHE";
/// Current format version.
pub(crate) const VERSION: u16 = 1;
/// Length of the fixed prefix.
pub(crate) const PREFIX_LEN: usize = 32;
/// Largest header block accepted (URL, tags and metadata together).
pub(crate) const MAX_HEADER: u32 = 4 << 20;
/// Longest URL accepted.
const MAX_URL: u32 = 64 << 10;
/// Most tags accepted.
const MAX_TAGS: u16 = 64;
/// Longest tag accepted.
const MAX_TAG: u16 = 1024;

/// Why bytes are not a valid object file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FormatError {
    /// Too short for what it claims.
    #[error("truncated")]
    Truncated,
    /// Not an rdock cache file.
    #[error("bad magic")]
    Magic,
    /// A format this build does not read.
    #[error("unsupported version {0}")]
    Version(u16),
    /// A checksum does not match.
    #[error("checksum mismatch")]
    Checksum,
    /// A length is over its limit or inconsistent.
    #[error("bad length")]
    Length,
    /// Text that is not UTF-8.
    #[error("bad text")]
    Text,
}

/// The decoded prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Prefix {
    pub header_len: u32,
    pub body_len: u64,
    pub header_crc: u32,
}

impl Prefix {
    /// Offset of the body in the file.
    pub(crate) fn body_offset(&self) -> u64 {
        PREFIX_LEN as u64 + u64::from(self.header_len)
    }

    /// Length the file must have.
    pub(crate) fn file_len(&self) -> u64 {
        self.body_offset() + self.body_len
    }

    pub(crate) fn encode(&self) -> [u8; PREFIX_LEN] {
        let mut out = [0u8; PREFIX_LEN];
        out[0..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_le_bytes());
        out[12..16].copy_from_slice(&self.header_len.to_le_bytes());
        out[16..24].copy_from_slice(&self.body_len.to_le_bytes());
        out[24..28].copy_from_slice(&self.header_crc.to_le_bytes());
        let crc = crc32fast::hash(&out[0..28]);
        out[28..32].copy_from_slice(&crc.to_le_bytes());
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let bytes = bytes.get(..PREFIX_LEN).ok_or(FormatError::Truncated)?;
        if bytes[0..8] != MAGIC {
            return Err(FormatError::Magic);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != VERSION {
            return Err(FormatError::Version(version));
        }
        if crc32fast::hash(&bytes[0..28]) != u32_at(bytes, 28) {
            return Err(FormatError::Checksum);
        }
        let header_len = u32_at(bytes, 12);
        if header_len > MAX_HEADER {
            return Err(FormatError::Length);
        }
        let mut body = [0u8; 8];
        body.copy_from_slice(&bytes[16..24]);
        Ok(Self {
            header_len,
            body_len: u64::from_le_bytes(body),
            header_crc: u32_at(bytes, 24),
        })
    }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(b)
}

/// The decoded header block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    pub id: Id,
    pub variance: Option<Id>,
    pub url: String,
    pub tags: Vec<String>,
    pub internal: Vec<u8>,
    pub meta_head: Vec<u8>,
}

impl Header {
    /// The encoded block (its CRC goes in the prefix).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(64 + self.url.len() + self.internal.len() + self.meta_head.len());
        out.extend_from_slice(&self.id);
        match self.variance {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v);
            }
            None => out.push(0),
        }
        let url = &self.url.as_bytes()[..self.url.len().min(MAX_URL as usize)];
        put_u32_bytes(&mut out, url);
        let tags: Vec<&String> = self
            .tags
            .iter()
            .filter(|t| t.len() <= usize::from(MAX_TAG))
            .take(usize::from(MAX_TAGS))
            .collect();
        out.extend_from_slice(&u16::try_from(tags.len()).unwrap_or(0).to_le_bytes());
        for tag in tags {
            out.extend_from_slice(&u16::try_from(tag.len()).unwrap_or(0).to_le_bytes());
            out.extend_from_slice(tag.as_bytes());
        }
        put_u32_bytes(&mut out, &self.internal);
        put_u32_bytes(&mut out, &self.meta_head);
        out
    }

    /// Decodes a header block whose CRC must be `crc`.
    pub(crate) fn decode(bytes: &[u8], crc: u32) -> Result<Self, FormatError> {
        if crc32fast::hash(bytes) != crc {
            return Err(FormatError::Checksum);
        }
        Self::decode_unchecked(bytes)
    }

    /// Decodes a header block without checking its CRC (the fuzz target reaches every branch
    /// this way).
    pub(crate) fn decode_unchecked(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut r = Reader { bytes, at: 0 };
        let mut id = [0u8; 16];
        id.copy_from_slice(r.take(16)?);
        let variance = match r.take(1)?[0] {
            0 => None,
            1 => {
                let mut v = [0u8; 16];
                v.copy_from_slice(r.take(16)?);
                Some(v)
            }
            _ => return Err(FormatError::Length),
        };
        let url_len = r.u32()?;
        if url_len > MAX_URL {
            return Err(FormatError::Length);
        }
        let url = text(r.take(url_len as usize)?)?;
        let count = r.u16()?;
        if count > MAX_TAGS {
            return Err(FormatError::Length);
        }
        let mut tags = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let len = r.u16()?;
            if len > MAX_TAG {
                return Err(FormatError::Length);
            }
            tags.push(text(r.take(usize::from(len))?)?);
        }
        let len = r.u32()?;
        let internal = r.take(len as usize)?.to_vec();
        let len = r.u32()?;
        let meta_head = r.take(len as usize)?.to_vec();
        if r.at != bytes.len() {
            return Err(FormatError::Length);
        }
        Ok(Self {
            id,
            variance,
            url,
            tags,
            internal,
            meta_head,
        })
    }
}

fn put_u32_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes.get(..len as usize).unwrap_or(bytes));
}

fn text(bytes: &[u8]) -> Result<String, FormatError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| FormatError::Text)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        let end = self.at.checked_add(n).ok_or(FormatError::Length)?;
        let out = self.bytes.get(self.at..end).ok_or(FormatError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, FormatError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, FormatError> {
        Ok(u32_at(self.take(4)?, 0))
    }
}

/// Encodes a whole object file head: prefix and header block for a body of `body_len`.
pub(crate) fn encode_head(header: &Header, body_len: u64) -> Vec<u8> {
    let block = header.encode();
    let prefix = Prefix {
        header_len: u32::try_from(block.len()).unwrap_or(u32::MAX),
        body_len,
        header_crc: crc32fast::hash(&block),
    };
    let mut out = prefix.encode().to_vec();
    out.extend_from_slice(&block);
    out
}

/// What the fuzz target exercises: the prefix decoder on the input, the header decoder with
/// and without its checksum, and pingora-cache's meta decoder on any header that decodes.
pub(crate) fn fuzz(bytes: &[u8]) {
    if let Ok(prefix) = Prefix::decode(bytes) {
        let block = bytes.get(PREFIX_LEN..).unwrap_or_default();
        let _ = Header::decode(block, prefix.header_crc);
    }
    if let Ok(header) = Header::decode_unchecked(bytes) {
        let _ = pingora::cache::CacheMeta::deserialize(&header.internal, &header.meta_head);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> Header {
        Header {
            id: [7; 16],
            variance: Some([9; 16]),
            url: "https://a.test/x?y=1".into(),
            tags: vec!["t1".into(), "t2".into()],
            internal: vec![1, 2, 3],
            meta_head: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
        }
    }

    #[test]
    fn round_trips_prefix_and_header() {
        let header = sample();
        let head = encode_head(&header, 1234);
        let prefix = Prefix::decode(&head).unwrap();
        assert_eq!(prefix.body_len, 1234);
        assert_eq!(prefix.body_offset(), head.len() as u64);
        let decoded = Header::decode(&head[PREFIX_LEN..], prefix.header_crc).unwrap();
        assert_eq!(decoded, header);
        let plain = Header {
            variance: None,
            tags: Vec::new(),
            ..sample()
        };
        let head = encode_head(&plain, 0);
        let prefix = Prefix::decode(&head).unwrap();
        assert_eq!(
            Header::decode(&head[PREFIX_LEN..], prefix.header_crc).unwrap(),
            plain
        );
    }

    #[test]
    fn rejects_damage() {
        let head = encode_head(&sample(), 10);
        assert_eq!(Prefix::decode(&head[..10]), Err(FormatError::Truncated));
        let mut bad = head.clone();
        bad[0] = b'X';
        assert_eq!(Prefix::decode(&bad), Err(FormatError::Magic));
        let mut bad = head.clone();
        bad[8] = 9;
        assert_eq!(Prefix::decode(&bad), Err(FormatError::Version(9)));
        let mut bad = head.clone();
        bad[17] ^= 1;
        assert_eq!(Prefix::decode(&bad), Err(FormatError::Checksum));
        let prefix = Prefix::decode(&head).unwrap();
        let mut block = head[PREFIX_LEN..].to_vec();
        let last = block.len() - 1;
        block[last] ^= 0xff;
        assert_eq!(
            Header::decode(&block, prefix.header_crc),
            Err(FormatError::Checksum)
        );
        // A block with trailing bytes is not accepted even with a matching checksum.
        let mut longer = head[PREFIX_LEN..].to_vec();
        longer.push(0);
        assert_eq!(Header::decode_unchecked(&longer), Err(FormatError::Length));
    }

    proptest! {
        /// Arbitrary bytes never panic the decoders, and whatever decodes re-encodes to the
        /// same block.
        #[test]
        fn decoders_never_panic_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = Prefix::decode(&bytes);
            if let Ok(header) = Header::decode_unchecked(&bytes) {
                prop_assert_eq!(header.encode(), bytes);
            }
        }

        /// Any single flipped bit in an encoded head is detected.
        #[test]
        fn single_bit_flips_are_detected(at in 0usize..200, bit in 0u8..8) {
            let head = encode_head(&sample(), 99);
            let at = at % head.len();
            let mut bad = head.clone();
            bad[at] ^= 1 << bit;
            let ok = Prefix::decode(&bad).ok().and_then(|p| {
                Header::decode(bad.get(PREFIX_LEN..).unwrap_or_default(), p.header_crc).ok().map(|h| (p, h))
            });
            if let Some((prefix, header)) = ok {
                // Only the unused flag bytes may change without detection.
                prop_assert!((10..12).contains(&at), "undetected flip at {at}");
                prop_assert_eq!(prefix.body_len, 99);
                prop_assert_eq!(header, sample());
            }
        }

        /// Round trip for arbitrary contents.
        #[test]
        fn round_trips_arbitrary_headers(
            url in "[ -~]{0,100}",
            tags in proptest::collection::vec("[a-z0-9]{1,20}", 0..10),
            internal in proptest::collection::vec(any::<u8>(), 0..100),
            meta in proptest::collection::vec(any::<u8>(), 0..100),
            body_len in any::<u64>(),
        ) {
            let header = Header { id: [1; 16], variance: None, url, tags, internal, meta_head: meta };
            let head = encode_head(&header, body_len);
            let prefix = Prefix::decode(&head).unwrap();
            prop_assert_eq!(prefix.body_len, body_len);
            prop_assert_eq!(Header::decode(&head[PREFIX_LEN..], prefix.header_crc).unwrap(), header);
        }
    }
}
