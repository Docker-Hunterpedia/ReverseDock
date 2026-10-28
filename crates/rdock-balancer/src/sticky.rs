//! Sticky-session cookie values: `HMAC-SHA256(secret, backend id)`, truncated to 16 bytes and
//! hex-encoded (ADR-0022). The cookie never reveals the backend address, and a client cannot
//! forge one to pick a backend of its choice.

use ring::hmac;

/// Bytes of the MAC kept in the cookie.
const TOKEN_BYTES: usize = 16;

/// The current key and the keys of earlier rotations, which are still accepted.
pub struct StickyKeys {
    current: hmac::Key,
    previous: Vec<hmac::Key>,
}

impl std::fmt::Debug for StickyKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StickyKeys")
            .field("previous", &self.previous.len())
            .finish_non_exhaustive()
    }
}

/// Which key a cookie was made with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// The current key: keep the cookie.
    Current,
    /// An earlier key: the backend is right, but the cookie should be replaced.
    Previous,
}

impl StickyKeys {
    /// Keys from secrets; the first is current.
    #[must_use]
    pub fn new(current: &[u8], previous: &[&[u8]]) -> Self {
        Self {
            current: hmac::Key::new(hmac::HMAC_SHA256, current),
            previous: previous
                .iter()
                .map(|s| hmac::Key::new(hmac::HMAC_SHA256, s))
                .collect(),
        }
    }

    /// The cookie value for backend `id`.
    #[must_use]
    pub fn token(&self, id: &str) -> String {
        token_with(&self.current, id)
    }

    /// Whether `cookie` names backend `id`, and with which key.
    #[must_use]
    pub fn matches(&self, cookie: &str, id: &str) -> Option<Match> {
        if verify(&self.current, cookie, id) {
            Some(Match::Current)
        } else if self.previous.iter().any(|key| verify(key, cookie, id)) {
            Some(Match::Previous)
        } else {
            None
        }
    }
}

fn token_with(key: &hmac::Key, id: &str) -> String {
    use std::fmt::Write;
    let tag = hmac::sign(key, id.as_bytes());
    tag.as_ref()[..TOKEN_BYTES]
        .iter()
        .fold(String::with_capacity(TOKEN_BYTES * 2), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

fn verify(key: &hmac::Key, cookie: &str, id: &str) -> bool {
    use subtle::ConstantTimeEq;
    let expected = token_with(key, id);
    expected.len() == cookie.len() && bool::from(expected.as_bytes().ct_eq(cookie.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_stable_opaque_and_keyed() {
        let keys = StickyKeys::new(b"secret-one", &[]);
        let token = keys.token("10.0.0.5:8080");
        assert_eq!(token.len(), TOKEN_BYTES * 2);
        assert_eq!(token, keys.token("10.0.0.5:8080"));
        assert!(!token.contains("10.0.0.5"));
        assert_ne!(token, StickyKeys::new(b"other", &[]).token("10.0.0.5:8080"));
        assert_eq!(keys.matches(&token, "10.0.0.5:8080"), Some(Match::Current));
        assert_eq!(keys.matches(&token, "10.0.0.6:8080"), None);
        assert_eq!(keys.matches("10.0.0.5:8080", "10.0.0.5:8080"), None);
        assert_eq!(keys.matches("", "10.0.0.5:8080"), None);
    }

    #[test]
    fn rotation_accepts_previous_keys() {
        let old = StickyKeys::new(b"old", &[]);
        let cookie = old.token("a");
        let rotated = StickyKeys::new(b"new", &[b"old"]);
        assert_eq!(rotated.matches(&cookie, "a"), Some(Match::Previous));
        assert_eq!(
            rotated.matches(&rotated.token("a"), "a"),
            Some(Match::Current)
        );
    }
}
