//! Reading a plugin module and checking its digest pin and signature before anything else
//! looks at it (ADR-0030).

use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::minisign::{PublicKey, Signature, SignatureError};

/// The largest module file read (32 MiB).
pub const MAX_MODULE_BYTES: u64 = 32 * 1024 * 1024;

/// The largest signature file read (4 KiB; a minisign signature is about 300 bytes).
const MAX_SIGNATURE_BYTES: u64 = 4096;

/// Where a module comes from and what it must match.
#[derive(Debug, Clone)]
pub struct Source<'a> {
    /// The module file.
    pub path: &'a Path,
    /// The pinned SHA-256 digest of the file, 64 hex digits.
    pub sha256: &'a str,
    /// The minisign signature file; `None` means `<path>.minisig`.
    pub signature: Option<&'a Path>,
    /// Trusted minisign public keys.
    pub trusted_keys: &'a [String],
    /// Accept a module without a signature (unsafe; the digest pin still applies).
    pub allow_unsigned: bool,
}

/// Why a module was refused before compilation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The module or signature file could not be read.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// The module file is larger than [`MAX_MODULE_BYTES`].
    #[error("{} is larger than {} bytes", path.display(), MAX_MODULE_BYTES)]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// The pin is not 64 hex digits.
    #[error("`sha256` must be 64 hex digits")]
    InvalidPin,
    /// The file does not match its pin.
    #[error("{} has SHA-256 {actual}, but the configuration pins {expected}", path.display())]
    DigestMismatch {
        /// The file.
        path: PathBuf,
        /// The pinned digest (lower case).
        expected: String,
        /// The file's digest.
        actual: String,
    },
    /// A trusted key does not parse.
    #[error("trusted_keys[{index}]: {source}")]
    Key {
        /// Its position in the list.
        index: usize,
        /// Why.
        source: SignatureError,
    },
    /// Signatures are required but no key is trusted.
    #[error("no trusted keys: a signed module needs at least one entry in `trusted_keys`")]
    NoTrustedKeys,
    /// Signatures are required and the signature file does not exist.
    #[error("missing signature {}", path.display())]
    MissingSignature {
        /// The expected signature file.
        path: PathBuf,
    },
    /// The signature does not verify.
    #[error("signature {}: {source}", path.display())]
    Signature {
        /// The signature file.
        path: PathBuf,
        /// Why.
        source: SignatureError,
    },
}

/// A module that passed its checks.
#[derive(Debug)]
pub struct Verified {
    /// The file's content.
    pub bytes: Vec<u8>,
    /// The key that signed it (minisign key ID), or `None` for an accepted unsigned module.
    pub signer: Option<String>,
    /// The signature's trusted comment.
    pub trusted_comment: Option<String>,
}

/// Lower-case hex SHA-256 of `data`.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Whether `pin` is a well-formed SHA-256 pin.
#[must_use]
pub fn is_valid_pin(pin: &str) -> bool {
    pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The default signature file of `path`: `<path>.minisig`, minisign's own default.
#[must_use]
pub fn default_signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".minisig");
    PathBuf::from(name)
}

fn read_capped(path: &Path, max: u64) -> Result<Option<Vec<u8>>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// Reads the module and checks, in this order, its size, its digest pin and its signature.
/// Nothing is compiled; a module that fails any check is never parsed.
pub fn load(source: &Source<'_>) -> Result<Verified, LoadError> {
    if !is_valid_pin(source.sha256) {
        return Err(LoadError::InvalidPin);
    }
    let keys = source
        .trusted_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            PublicKey::parse(key).map_err(|source| LoadError::Key { index, source })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = read_capped(source.path, MAX_MODULE_BYTES)
        .map_err(|e| LoadError::Read {
            path: source.path.to_owned(),
            source: e,
        })?
        .ok_or_else(|| LoadError::TooLarge {
            path: source.path.to_owned(),
        })?;
    let actual = sha256_hex(&bytes);
    let expected = source.sha256.to_ascii_lowercase();
    if actual != expected {
        return Err(LoadError::DigestMismatch {
            path: source.path.to_owned(),
            expected,
            actual,
        });
    }
    let signature_path = source
        .signature
        .map_or_else(|| default_signature_path(source.path), Path::to_owned);
    let text = match read_capped(&signature_path, MAX_SIGNATURE_BYTES) {
        Ok(Some(bytes)) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Ok(None) => {
            return Err(LoadError::Signature {
                path: signature_path,
                source: SignatureError::InvalidSignature("the file is too large"),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(LoadError::Read {
                path: signature_path,
                source: e,
            });
        }
    };
    let Some(text) = text else {
        if source.allow_unsigned {
            return Ok(Verified {
                bytes,
                signer: None,
                trusted_comment: None,
            });
        }
        if keys.is_empty() {
            return Err(LoadError::NoTrustedKeys);
        }
        return Err(LoadError::MissingSignature {
            path: signature_path,
        });
    };
    // A signature that is present is checked even when unsigned modules are allowed: a bad
    // one means the file is not what its publisher signed.
    if keys.is_empty() {
        if source.allow_unsigned {
            return Ok(Verified {
                bytes,
                signer: None,
                trusted_comment: None,
            });
        }
        return Err(LoadError::NoTrustedKeys);
    }
    let fail = |source| LoadError::Signature {
        path: signature_path.clone(),
        source,
    };
    let signature = Signature::parse(&text).map_err(fail)?;
    let key = signature.verify(&bytes, &keys).map_err(fail)?;
    Ok(Verified {
        signer: Some(key.id_hex()),
        trusted_comment: Some(signature.trusted_comment().to_owned()),
        bytes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::testing::TestKey;

    struct Files {
        _dir: tempfile::TempDir,
        module: PathBuf,
        sha256: String,
        key: TestKey,
    }

    fn files(signed: bool) -> Files {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("plugin.wasm");
        let bytes = b"\0asm-not-really".to_vec();
        std::fs::write(&module, &bytes).unwrap();
        let key = TestKey::new(7);
        if signed {
            std::fs::write(default_signature_path(&module), key.sign(&bytes, true)).unwrap();
        }
        Files {
            sha256: sha256_hex(&bytes),
            module,
            key,
            _dir: dir,
        }
    }

    fn source<'a>(f: &'a Files, keys: &'a [String]) -> Source<'a> {
        Source {
            path: &f.module,
            sha256: &f.sha256,
            signature: None,
            trusted_keys: keys,
            allow_unsigned: false,
        }
    }

    #[test]
    fn a_signed_pinned_module_loads() {
        let f = files(true);
        let keys = [f.key.public()];
        let v = load(&source(&f, &keys)).unwrap();
        assert_eq!(v.signer.as_deref(), Some(f.key.id_hex().as_str()));
        assert_eq!(v.bytes, b"\0asm-not-really");
        // Upper-case pins are fine.
        let upper = f.sha256.to_ascii_uppercase();
        let mut s = source(&f, &keys);
        s.sha256 = &upper;
        assert!(load(&s).is_ok());
    }

    #[test]
    fn a_wrong_digest_is_refused_before_the_signature() {
        let f = files(true);
        let keys = [f.key.public()];
        let wrong = "0".repeat(64);
        let mut s = source(&f, &keys);
        s.sha256 = &wrong;
        assert!(matches!(load(&s), Err(LoadError::DigestMismatch { .. })));
        s.sha256 = "abc";
        assert!(matches!(load(&s), Err(LoadError::InvalidPin)));
    }

    #[test]
    fn a_missing_signature_is_refused_unless_unsigned_is_allowed() {
        let f = files(false);
        let keys = [f.key.public()];
        let err = load(&source(&f, &keys)).unwrap_err();
        assert!(matches!(err, LoadError::MissingSignature { .. }), "{err}");
        assert!(err.to_string().ends_with("plugin.wasm.minisig"), "{err}");
        let mut s = source(&f, &keys);
        s.allow_unsigned = true;
        let v = load(&s).unwrap();
        assert_eq!(v.signer, None);
        // No keys at all: refused with its own message.
        assert!(matches!(
            load(&source(&f, &[])),
            Err(LoadError::NoTrustedKeys)
        ));
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let f = files(true);
        let other = [TestKey::new(9).public()];
        let err = load(&source(&f, &other)).unwrap_err();
        assert!(
            matches!(
                err,
                LoadError::Signature {
                    source: SignatureError::UntrustedKey(_),
                    ..
                }
            ),
            "{err}"
        );
        // Even with `allow_unsigned`, a present signature must verify.
        let mut s = source(&f, &other);
        s.allow_unsigned = true;
        assert!(load(&s).is_err());
    }

    #[test]
    fn a_tampered_module_with_a_matching_pin_fails_its_signature() {
        let f = files(true);
        let tampered = b"\0asm-tampered".to_vec();
        std::fs::write(&f.module, &tampered).unwrap();
        let pin = sha256_hex(&tampered);
        let keys = [f.key.public()];
        let mut s = source(&f, &keys);
        s.sha256 = &pin;
        assert!(matches!(
            load(&s),
            Err(LoadError::Signature {
                source: SignatureError::Mismatch(_),
                ..
            })
        ));
    }

    #[test]
    fn legacy_signatures_and_explicit_paths_work() {
        let f = files(false);
        let bytes = std::fs::read(&f.module).unwrap();
        let sig = f.module.with_extension("sig");
        std::fs::write(&sig, f.key.sign(&bytes, false)).unwrap();
        let keys = [f.key.public()];
        let mut s = source(&f, &keys);
        s.signature = Some(&sig);
        assert!(load(&s).is_ok());
    }

    #[test]
    fn bad_keys_and_unreadable_files_are_reported() {
        let f = files(true);
        let keys = ["nope".to_owned()];
        assert!(matches!(
            load(&source(&f, &keys)),
            Err(LoadError::Key { index: 0, .. })
        ));
        let keys = [f.key.public()];
        let missing = f.module.with_file_name("absent.wasm");
        let mut s = source(&f, &keys);
        s.path = &missing;
        assert!(matches!(load(&s), Err(LoadError::Read { .. })));
    }
}
