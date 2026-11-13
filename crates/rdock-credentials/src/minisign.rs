//! Minisign signature verification on `ring` (Ed25519) and `blake2` (BLAKE2b-512).
//!
//! The format is the one the `minisign` tool writes
//! (<https://jedisct1.github.io/minisign/>, read 2026-11-12):
//!
//! - a public key is base64 of `"Ed"` ‖ key ID (8 bytes) ‖ Ed25519 public key (32 bytes),
//!   optionally preceded by an `untrusted comment:` line;
//! - a signature file has four lines: `untrusted comment: …`, base64 of signature algorithm
//!   (2 bytes) ‖ key ID (8 bytes) ‖ Ed25519 signature (64 bytes), `trusted comment: …`, and
//!   base64 of the global signature (64 bytes), an Ed25519 signature of the first signature
//!   followed by the trusted comment's text.
//!
//! Accepted signature algorithms: **`ED`** (`0x45 0x44`, the signature covers the BLAKE2b-512
//! digest of the file; what `minisign -S` writes by default) and **`Ed`** (`0x45 0x64`, the
//! legacy mode where the signature covers the file itself; `minisign -S -l`). Both are Ed25519;
//! any other algorithm ID is refused. The global signature is always checked, so the trusted
//! comment cannot be altered.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use blake2::{Blake2b512, Digest as _};
use ring::signature::{ED25519, UnparsedPublicKey};

/// Why a key or a signature was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The public key is not a minisign public key.
    #[error("not a minisign public key: {0}")]
    InvalidKey(&'static str),
    /// The signature file is not in minisign's format.
    #[error("not a minisign signature: {0}")]
    InvalidSignature(&'static str),
    /// The signature uses an algorithm this verifier does not implement.
    #[error(
        "unsupported minisign signature algorithm {0:?} (accepted: `ED`, Ed25519 over BLAKE2b-512, and the legacy `Ed`, Ed25519 over the file)"
    )]
    UnsupportedAlgorithm(String),
    /// The signature was made with a key that is not among the trusted keys.
    #[error("signed by key {0}, which is not among the trusted keys")]
    UntrustedKey(String),
    /// The signature does not match the file.
    #[error("the signature does not match the file (signed by key {0})")]
    Mismatch(String),
    /// The trusted comment was changed after signing.
    #[error("the trusted comment does not match its global signature (key {0})")]
    TrustedCommentMismatch(String),
}

/// A minisign public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    id: [u8; 8],
    key: [u8; 32],
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("id", &self.id_hex())
            .finish_non_exhaustive()
    }
}

impl PublicKey {
    /// Parses a public key: the base64 line (`RWQ…`), or the whole `.pub` file with its
    /// `untrusted comment:` line.
    pub fn parse(text: &str) -> Result<Self, SignatureError> {
        let line = text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with("untrusted comment:"))
            .ok_or(SignatureError::InvalidKey("empty"))?;
        let bytes = STANDARD
            .decode(line)
            .map_err(|_| SignatureError::InvalidKey("not base64"))?;
        if bytes.len() != 42 {
            return Err(SignatureError::InvalidKey("wrong length"));
        }
        if &bytes[..2] != b"Ed" {
            return Err(SignatureError::InvalidKey("not an Ed25519 key"));
        }
        let mut id = [0; 8];
        id.copy_from_slice(&bytes[2..10]);
        let mut key = [0; 32];
        key.copy_from_slice(&bytes[10..]);
        Ok(Self { id, key })
    }

    /// The key ID as minisign prints it (16 upper-case hex digits; the bytes are stored
    /// little-endian).
    #[must_use]
    pub fn id_hex(&self) -> String {
        key_id_hex(self.id)
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, &self.key)
            .verify(message, signature)
            .is_ok()
    }
}

fn key_id_hex(id: [u8; 8]) -> String {
    use std::fmt::Write as _;
    id.iter()
        .rev()
        .fold(String::with_capacity(16), |mut out, b| {
            let _ = write!(out, "{b:02X}");
            out
        })
}

/// A parsed minisign signature file.
#[derive(Clone)]
pub struct Signature {
    prehashed: bool,
    key_id: [u8; 8],
    sig: [u8; 64],
    trusted_comment: String,
    global: [u8; 64],
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("key_id", &key_id_hex(self.key_id))
            .field("prehashed", &self.prehashed)
            .field("trusted_comment", &self.trusted_comment)
            .finish_non_exhaustive()
    }
}

impl Signature {
    /// Parses a `.minisig` file.
    pub fn parse(text: &str) -> Result<Self, SignatureError> {
        let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
        let untrusted = lines
            .next()
            .ok_or(SignatureError::InvalidSignature("empty"))?;
        if !untrusted.starts_with("untrusted comment:") {
            return Err(SignatureError::InvalidSignature(
                "the first line is not an `untrusted comment:`",
            ));
        }
        let first = lines
            .next()
            .and_then(|l| STANDARD.decode(l.trim()).ok())
            .ok_or(SignatureError::InvalidSignature(
                "the second line is not base64",
            ))?;
        if first.len() != 74 {
            return Err(SignatureError::InvalidSignature(
                "the signature has the wrong length",
            ));
        }
        let trusted_comment = lines
            .next()
            .and_then(|l| l.strip_prefix("trusted comment: "))
            .ok_or(SignatureError::InvalidSignature(
                "the third line is not a `trusted comment:`",
            ))?
            .to_owned();
        let global = lines
            .next()
            .and_then(|l| STANDARD.decode(l.trim()).ok())
            .ok_or(SignatureError::InvalidSignature(
                "the fourth line is not base64",
            ))?;
        if global.len() != 64 {
            return Err(SignatureError::InvalidSignature(
                "the global signature has the wrong length",
            ));
        }
        let prehashed = match &first[..2] {
            b"ED" => true,
            b"Ed" => false,
            other => {
                return Err(SignatureError::UnsupportedAlgorithm(
                    String::from_utf8_lossy(other).into_owned(),
                ));
            }
        };
        let mut key_id = [0; 8];
        key_id.copy_from_slice(&first[2..10]);
        let mut sig = [0; 64];
        sig.copy_from_slice(&first[10..]);
        let mut global_sig = [0; 64];
        global_sig.copy_from_slice(&global);
        Ok(Self {
            prehashed,
            key_id,
            sig,
            trusted_comment,
            global: global_sig,
        })
    }

    /// The ID of the key that made the signature.
    #[must_use]
    pub fn key_id_hex(&self) -> String {
        key_id_hex(self.key_id)
    }

    /// The trusted comment (signed; usually a timestamp and the file name).
    #[must_use]
    pub fn trusted_comment(&self) -> &str {
        &self.trusted_comment
    }

    /// Whether the signature covers the file's BLAKE2b-512 digest (`ED`) rather than the
    /// file (`Ed`).
    #[must_use]
    pub fn is_prehashed(&self) -> bool {
        self.prehashed
    }

    /// Checks the signature of `data` against `trusted`; returns the key that made it.
    pub fn verify<'k>(
        &self,
        data: &[u8],
        trusted: &'k [PublicKey],
    ) -> Result<&'k PublicKey, SignatureError> {
        let key = trusted
            .iter()
            .find(|k| k.id == self.key_id)
            .ok_or_else(|| SignatureError::UntrustedKey(self.key_id_hex()))?;
        let ok = if self.prehashed {
            let digest = Blake2b512::digest(data);
            key.verify(&digest, &self.sig)
        } else {
            key.verify(data, &self.sig)
        };
        if !ok {
            return Err(SignatureError::Mismatch(self.key_id_hex()));
        }
        let mut signed = Vec::with_capacity(64 + self.trusted_comment.len());
        signed.extend_from_slice(&self.sig);
        signed.extend_from_slice(self.trusted_comment.as_bytes());
        if !key.verify(&signed, &self.global) {
            return Err(SignatureError::TrustedCommentMismatch(self.key_id_hex()));
        }
        Ok(key)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Signatures made by the `minisign` tool, published as test vectors of the
    // `minisign-verify` crate (MIT, version 0.2.4, `src/lib.rs`).
    const KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const LEGACY: &str = "untrusted comment: signature from minisign secret key\nRWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\ntrusted comment: timestamp:1555779966\tfile:test\nQtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==\n";
    const PREHASHED: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==\n";

    #[test]
    fn verifies_minisign_tool_signatures() {
        let keys = [PublicKey::parse(KEY).unwrap()];
        assert_eq!(keys[0].id_hex(), "E7620F1842B4E81F");
        for text in [LEGACY, PREHASHED] {
            let sig = Signature::parse(text).unwrap();
            assert_eq!(sig.key_id_hex(), "E7620F1842B4E81F");
            assert_eq!(
                sig.verify(b"test", &keys).unwrap().id_hex(),
                "E7620F1842B4E81F"
            );
            assert_eq!(
                sig.verify(b"Test", &keys).unwrap_err(),
                SignatureError::Mismatch("E7620F1842B4E81F".into())
            );
        }
        assert!(Signature::parse(PREHASHED).unwrap().is_prehashed());
        assert!(!Signature::parse(LEGACY).unwrap().is_prehashed());
    }

    #[test]
    fn a_public_key_file_with_its_comment_parses() {
        let file = format!("untrusted comment: minisign public key E7620F1842B4E81F\n{KEY}\n");
        assert_eq!(
            PublicKey::parse(&file).unwrap(),
            PublicKey::parse(KEY).unwrap()
        );
    }

    #[test]
    fn a_changed_trusted_comment_is_refused() {
        let altered = PREHASHED.replace("file:test", "file:evil");
        let sig = Signature::parse(&altered).unwrap();
        let keys = [PublicKey::parse(KEY).unwrap()];
        assert!(matches!(
            sig.verify(b"test", &keys),
            Err(SignatureError::TrustedCommentMismatch(_))
        ));
    }

    #[test]
    fn an_unknown_key_is_refused() {
        // The same key bytes under another ID.
        let mut bytes = STANDARD.decode(KEY).unwrap();
        bytes[2] ^= 1;
        let other = PublicKey::parse(&STANDARD.encode(bytes)).unwrap();
        let sig = Signature::parse(PREHASHED).unwrap();
        assert_eq!(
            sig.verify(b"test", &[other]).unwrap_err(),
            SignatureError::UntrustedKey("E7620F1842B4E81F".into())
        );
    }

    #[test]
    fn malformed_inputs_are_refused() {
        assert!(PublicKey::parse("").is_err());
        assert!(PublicKey::parse("not base64!").is_err());
        assert!(PublicKey::parse(&STANDARD.encode([0u8; 42])).is_err());
        assert!(Signature::parse("").is_err());
        assert!(Signature::parse(&PREHASHED.replace("untrusted comment", "comment")).is_err());
        assert!(Signature::parse(&PREHASHED.replace("trusted comment: ", "x")).is_err());
        let lines: Vec<&str> = PREHASHED.lines().collect();
        assert!(Signature::parse(&lines[..3].join("\n")).is_err());
        // Another algorithm ID.
        let mut first = STANDARD.decode(lines[1]).unwrap();
        first[1] = b'X';
        let text = format!(
            "{}\n{}\n{}\n{}\n",
            lines[0],
            STANDARD.encode(first),
            lines[2],
            lines[3]
        );
        assert!(matches!(
            Signature::parse(&text),
            Err(SignatureError::UnsupportedAlgorithm(_))
        ));
    }
}
