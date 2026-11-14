#![doc = include_str!("../README.md")]

use std::fmt;

pub mod minisign;

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

/// The Base62 alphabet of IDs, secrets and checksums.
pub const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// Length of the checksum: CRC32 in Base62 (62^6 > 2^32).
pub const CHECK_LEN: usize = 6;

/// A credential format: a prefix, then the ID, `_`, the secret and the checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format {
    /// The fixed start, ending in `_`.
    pub prefix: &'static str,
    /// Characters of the public ID.
    pub id_len: usize,
    /// Characters of the secret.
    pub secret_len: usize,
}

/// Admin API tokens (ADR-0024).
pub const ADMIN_TOKEN: Format = Format {
    prefix: "rdk_pat_",
    id_len: 10,
    secret_len: 32,
};

/// Consumer API keys (F-GW-01, ADR-0030). The 12-character ID (71 bits) keeps keys apart from
/// admin tokens for scanners (`rdk_` then twelve Base62 characters and `_` never matches
/// `rdk_pat_`) and makes an ID collision across millions of keys negligible.
pub const API_KEY: Format = Format {
    prefix: "rdk_",
    id_len: 12,
    secret_len: 32,
};

/// Join tokens of a cluster's control plane (ADR-0031): single use, short-lived.
pub const JOIN_TOKEN: Format = Format {
    prefix: "rdk_join_",
    id_len: 10,
    secret_len: 32,
};

/// A clear-text credential, shown once. `Debug` and `Display` print it redacted so it cannot
/// reach a log or a panic message by accident; [`Secret::expose`] gives the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// The clear-text value.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Consumes the secret and returns the value.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A freshly generated credential.
#[derive(Debug, Clone)]
pub struct Generated {
    /// The full value, given to its owner once.
    pub value: Secret,
    /// The public ID.
    pub id: String,
    /// SHA-256 of the secret, lower-case hex: what is stored.
    pub secret_sha256: String,
}

/// Uniform Base62 characters by rejection sampling, so no character is more likely; `None`
/// when the system random generator fails.
#[must_use]
pub fn random_base62(len: usize) -> Option<String> {
    let rng = SystemRandom::new();
    let mut out = String::with_capacity(len);
    let mut buffer = [0u8; 64];
    while out.len() < len {
        rng.fill(&mut buffer).ok()?;
        for &byte in &buffer {
            if byte < 248 && out.len() < len {
                out.push(char::from(BASE62[usize::from(byte % 62)]));
            }
        }
    }
    Some(out)
}

/// The CRC32 of `body` in [`CHECK_LEN`] Base62 characters.
#[must_use]
pub fn checksum(body: &str) -> String {
    let mut value = u64::from(crc32fast::hash(body.as_bytes()));
    let mut out = [b'0'; CHECK_LEN];
    for slot in out.iter_mut().rev() {
        *slot = BASE62[usize::try_from(value % 62).unwrap_or(0)];
        value /= 62;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Lower-case hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// SHA-256 of a secret, lower-case hex.
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    hex(digest(&SHA256, secret.as_bytes()).as_ref())
}

/// Whether two hashes are equal, in time that does not depend on where they differ.
#[must_use]
pub fn hashes_match(presented: &str, stored: &str) -> bool {
    bool::from(presented.as_bytes().ct_eq(stored.as_bytes()))
}

/// Whether `value` is a SHA-256 in lower-case hex (what configurations store).
#[must_use]
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Format {
    /// Total length of a credential.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.prefix.len() + self.id_len + 1 + self.secret_len + CHECK_LEN
    }

    /// Never true: a format always has characters.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Generates a credential; `None` when the system random generator fails.
    #[must_use]
    pub fn generate(&self) -> Option<Generated> {
        let chars = random_base62(self.id_len + self.secret_len)?;
        let (id, secret) = chars.split_at(self.id_len);
        let body = format!("{}{id}_{secret}", self.prefix);
        let value = format!("{body}{}", checksum(&body));
        Some(Generated {
            value: Secret(value),
            id: id.to_owned(),
            secret_sha256: hash_secret(secret),
        })
    }

    /// The ID and secret of a well-formed credential with a correct checksum.
    #[must_use]
    pub fn parse<'a>(&self, value: &'a str) -> Option<(&'a str, &'a str)> {
        let rest = value.strip_prefix(self.prefix)?;
        let (id, tail) = rest.split_once('_')?;
        if id.len() != self.id_len || tail.len() != self.secret_len + CHECK_LEN || !tail.is_ascii()
        {
            return None;
        }
        let (secret, check) = tail.split_at(self.secret_len);
        let base62 = |s: &str| s.bytes().all(|b| b.is_ascii_alphanumeric());
        if !base62(id) || !base62(secret) {
            return None;
        }
        let body = &value[..value.len() - CHECK_LEN];
        (checksum(body) == check).then_some((id, secret))
    }

    /// Whether `id` has the shape of this format's IDs.
    #[must_use]
    pub fn is_id(&self, id: &str) -> bool {
        id.len() == self.id_len && id.bytes().all(|b| b.is_ascii_alphanumeric())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_parse_and_typos_do_not() {
        for format in [ADMIN_TOKEN, API_KEY] {
            let made = format.generate().unwrap();
            let value = made.value.expose();
            assert_eq!(value.len(), format.len());
            let (id, secret) = format.parse(value).unwrap();
            assert_eq!(id, made.id);
            assert_eq!(hash_secret(secret), made.secret_sha256);
            assert!(is_sha256_hex(&made.secret_sha256));
            // Any changed character breaks the checksum.
            let mut typo = value.to_owned().into_bytes();
            let at = format.prefix.len() + format.id_len + 3;
            typo[at] = if typo[at] == b'a' { b'b' } else { b'a' };
            assert_eq!(format.parse(std::str::from_utf8(&typo).unwrap()), None);
        }
        let key = API_KEY.generate().unwrap();
        assert_eq!(ADMIN_TOKEN.parse(key.value.expose()), None);
        let token = ADMIN_TOKEN.generate().unwrap();
        assert_eq!(API_KEY.parse(token.value.expose()), None);
        assert_eq!(API_KEY.len(), 55);
    }

    #[test]
    fn secrets_never_print() {
        let made = API_KEY.generate().unwrap();
        let printed = format!("{made:?} {}", made.value);
        assert!(!printed.contains(made.value.expose()), "{printed}");
        assert!(printed.contains("redacted"));
    }

    #[test]
    fn comparison_and_hex() {
        assert!(hashes_match("ab", "ab"));
        assert!(!hashes_match("ab", "ac"));
        assert!(!hashes_match("ab", "abc"));
        assert_eq!(hex(&[0, 15, 255]), "000fff");
        assert!(!is_sha256_hex(&"A".repeat(64)));
    }
}
