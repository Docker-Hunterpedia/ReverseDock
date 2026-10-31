//! Time-based one-time passwords (RFC 6238: HMAC-SHA1, 6 digits, 30-second steps, one step of
//! clock skew either way) and single-use recovery codes (ADR-0024).

use ring::digest::{SHA256, digest};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

const STEP_SECONDS: u64 = 30;
const DIGITS: u32 = 6;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn random<const N: usize>() -> Option<[u8; N]> {
    let mut bytes = [0u8; N];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(bytes)
}

/// RFC 4648 base32 without padding, as authenticator apps expect.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = BASE32.iter().position(|&b| b == c.to_ascii_uppercase())?;
        buffer = (buffer << 5) | u32::try_from(value).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// A new 160-bit secret, base32-encoded (the form stored and shown to the user).
pub fn new_secret() -> Option<String> {
    random::<20>().map(|bytes| base32(&bytes))
}

/// The `otpauth://` URI an authenticator app reads from a QR code. User names are restricted
/// to characters that need no escaping.
pub fn uri(user: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/ReverseDock:{user}?secret={secret}&issuer=ReverseDock&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
}

/// The HOTP value (RFC 4226) for one counter.
fn code_at(key: &[u8], counter: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let mac = tag.as_ref();
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let word = u32::from_be_bytes([
        mac[offset],
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    (word & 0x7fff_ffff) % 10u32.pow(DIGITS)
}

/// The time step a correct `code` belongs to, if it is within one step of `now_unix` and newer
/// than `last_step` (each code works once).
pub fn verify(secret: &str, code: &str, now_unix: u64, last_step: u64) -> Option<u64> {
    let key = base32_decode(secret)?;
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = now_unix / STEP_SECONDS;
    let mut matched = None;
    for step in [now.saturating_sub(1), now, now + 1] {
        let expected = format!("{:0width$}", code_at(&key, step), width = DIGITS as usize);
        let equal = bool::from(expected.as_bytes().ct_eq(code.as_bytes()));
        if equal && step > last_step && matched.is_none() {
            matched = Some(step);
        }
    }
    matched
}

/// Ten recovery codes as shown once to the user (`xxxxx-xxxxx`, 50 bits each), and their
/// SHA-256 hashes as stored.
pub fn recovery_codes() -> Option<(Vec<String>, Vec<String>)> {
    let mut shown = Vec::new();
    let mut stored = Vec::new();
    for _ in 0..10 {
        let code = base32(&random::<7>()?).to_lowercase();
        let code = format!("{}-{}", &code[..5], &code[5..10]);
        stored.push(recovery_hash(&code));
        shown.push(code);
    }
    Some((shown, stored))
}

fn recovery_hash(code: &str) -> String {
    let normal: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    crate::hex(digest(&SHA256, normal.as_bytes()).as_ref())
}

/// The index of the stored recovery code that `code` matches, compared in constant time.
pub fn match_recovery(stored: &[String], code: &str) -> Option<usize> {
    let presented = recovery_hash(code);
    let mut found = None;
    for (i, hash) in stored.iter().enumerate() {
        if bool::from(hash.as_bytes().ct_eq(presented.as_bytes())) && found.is_none() {
            found = Some(i);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B, SHA-1 key "12345678901234567890", last six of the eight digits.
    const RFC_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn base32_round_trips_the_rfc_key() {
        assert_eq!(base32(b"12345678901234567890"), RFC_KEY);
        assert_eq!(base32_decode(RFC_KEY).unwrap(), b"12345678901234567890");
        assert_eq!(new_secret().unwrap().len(), 32);
    }

    #[test]
    fn rfc_6238_vectors_verify_once_within_one_step() {
        assert_eq!(verify(RFC_KEY, "287082", 59, 0), Some(1));
        assert_eq!(
            verify(RFC_KEY, "081804", 1_111_111_109, 0),
            Some(37_037_036)
        );
        // One step either side is accepted, two are not.
        assert_eq!(
            verify(RFC_KEY, "081804", 1_111_111_109 + 30, 0),
            Some(37_037_036)
        );
        assert_eq!(verify(RFC_KEY, "081804", 1_111_111_109 + 60, 0), None);
        // A code already used (its step is not newer than the last one) is refused.
        assert_eq!(verify(RFC_KEY, "081804", 1_111_111_109, 37_037_036), None);
        assert_eq!(verify(RFC_KEY, "08180", 1_111_111_109, 0), None);
        assert_eq!(verify(RFC_KEY, "o81804", 1_111_111_109, 0), None);
    }

    #[test]
    fn recovery_codes_match_ignoring_case_and_dashes() {
        let (shown, stored) = recovery_codes().unwrap();
        assert_eq!(shown.len(), 10);
        assert_eq!(match_recovery(&stored, &shown[3].to_uppercase()), Some(3));
        assert_eq!(match_recovery(&stored, &shown[3].replace('-', "")), Some(3));
        assert_eq!(match_recovery(&stored, "aaaaa-aaaaa"), None);
        assert!(uri("root", RFC_KEY).starts_with("otpauth://totp/ReverseDock:root?secret="));
    }
}
