//! Password hash verification for basic authentication: argon2id and bcrypt, plus the Apache
//! MD5 (`$apr1$`), MD5-crypt (`$1$`) and SHA-1 (`{SHA}`) formats that `htpasswd` and Traefik use.

use argon2::{Argon2, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use md5::{Digest, Md5};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// Whether `password` matches `hash`. Unknown formats never match.
pub(crate) fn verify(password: &str, hash: &str) -> bool {
    if hash.starts_with("$argon2id$") {
        Argon2::default()
            .verify_password(password.as_bytes(), hash)
            .is_ok()
    } else if ["$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .any(|p| hash.starts_with(p))
    {
        bcrypt::verify(password, hash).unwrap_or(false)
    } else if let Some(rest) = hash.strip_prefix("$apr1$") {
        constant_time_eq(&md5_crypt(password.as_bytes(), rest, "$apr1$"), hash)
    } else if let Some(rest) = hash.strip_prefix("$1$") {
        constant_time_eq(&md5_crypt(password.as_bytes(), rest, "$1$"), hash)
    } else if let Some(expected) = hash.strip_prefix("{SHA}") {
        let digest = Sha1::digest(password.as_bytes());
        constant_time_eq(&STANDARD.encode(digest), expected)
    } else {
        false
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

const CRYPT_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The MD5-crypt algorithm (Poul-Henning Kamp's, as used by Apache with the `$apr1$` magic).
/// `salt_and_hash` is the part after the magic; the salt ends at the next `$` and is at most
/// eight characters.
fn md5_crypt(password: &[u8], salt_and_hash: &str, magic: &str) -> String {
    let salt = salt_and_hash.split('$').next().unwrap_or_default();
    let salt = &salt.as_bytes()[..salt.len().min(8)];

    // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes -- verifies legacy htpasswd hashes only (ADR-0014)
    let mut alternate = Md5::new();
    alternate.update(password);
    alternate.update(salt);
    alternate.update(password);
    let alternate = alternate.finalize();

    // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes -- verifies legacy htpasswd hashes only (ADR-0014)
    let mut context = Md5::new();
    context.update(password);
    context.update(magic.as_bytes());
    context.update(salt);
    let mut remaining = password.len();
    while remaining > 0 {
        let take = remaining.min(16);
        context.update(&alternate[..take]);
        remaining -= take;
    }
    let mut bits = password.len();
    while bits > 0 {
        if bits & 1 == 1 {
            context.update([0u8]);
        } else {
            context.update(&password[..1]);
        }
        bits >>= 1;
    }
    let mut digest = context.finalize();

    for round in 0..1000 {
        // nosemgrep: rust.lang.security.insecure-hashes.insecure-hashes -- verifies legacy htpasswd hashes only (ADR-0014)
        let mut next = Md5::new();
        if round & 1 == 1 {
            next.update(password);
        } else {
            next.update(digest);
        }
        if round % 3 != 0 {
            next.update(salt);
        }
        if round % 7 != 0 {
            next.update(password);
        }
        if round & 1 == 1 {
            next.update(digest);
        } else {
            next.update(password);
        }
        digest = next.finalize();
    }

    let mut out = format!("{magic}{}$", String::from_utf8_lossy(salt));
    let d = digest;
    for (a, b, c) in [(0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)] {
        push_crypt64(
            &mut out,
            (u32::from(d[a]) << 16) | (u32::from(d[b]) << 8) | u32::from(d[c]),
            4,
        );
    }
    push_crypt64(&mut out, u32::from(d[11]), 2);
    out
}

fn push_crypt64(out: &mut String, mut value: u32, chars: usize) {
    for _ in 0..chars {
        out.push(char::from(CRYPT_ALPHABET[(value & 0x3f) as usize]));
        value >>= 6;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_legacy_formats_against_openssl_vectors() {
        // `openssl passwd -apr1 -salt saltsalt password` and `-1`.
        assert!(verify("password", "$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/"));
        assert!(verify("password", "$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/"));
        assert!(!verify("passw0rd", "$apr1$saltsalt$yAAkm4libquA.ZWLHbSBq/"));
        assert!(verify("password", "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="));
        assert!(!verify("password", "{SHA}AAAA"));
    }

    #[test]
    fn verifies_bcrypt_and_argon2id() {
        let bcrypt_hash = bcrypt::hash("s3cret", 4).unwrap();
        assert!(verify("s3cret", &bcrypt_hash));
        assert!(!verify("other", &bcrypt_hash));

        let argon_hash = argon2::PasswordHasher::hash_password_with_salt(
            &Argon2::default(),
            b"s3cret",
            b"somesalt12345678",
        )
        .unwrap()
        .to_string();
        assert!(argon_hash.starts_with("$argon2id$"), "{argon_hash}");
        assert!(verify("s3cret", &argon_hash));
        assert!(!verify("other", &argon_hash));
        assert!(!verify("anything", "plain-text"));
    }
}
