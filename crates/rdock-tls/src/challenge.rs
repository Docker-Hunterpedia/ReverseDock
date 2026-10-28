//! ACME challenge answers. The certificate manager writes them; the data plane only reads.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::sign::CertifiedKey;

/// Path prefix of HTTP-01 challenge requests.
pub const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";
/// The ALPN protocol of TLS-ALPN-01 validation handshakes (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Answers for challenges in progress: HTTP-01 by token, TLS-ALPN-01 by name.
#[derive(Debug, Default)]
pub struct Challenges {
    http01: ArcSwap<HashMap<String, Arc<str>>>,
    tls_alpn01: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
}

impl Challenges {
    /// Answers requests for `token` with `key_authorization` until removed.
    pub fn add_http01(&self, token: &str, key_authorization: &str) {
        let answer: Arc<str> = Arc::from(key_authorization);
        self.http01.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.insert(token.to_owned(), answer.clone());
            next
        });
    }

    /// Stops answering for `token`.
    pub fn remove_http01(&self, token: &str) {
        self.http01.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.remove(token);
            next
        });
    }

    /// Serves `certificate` to TLS-ALPN-01 validation handshakes for `name` until removed.
    pub fn add_tls_alpn01(&self, name: &str, certificate: &Arc<CertifiedKey>) {
        let name = name.to_ascii_lowercase();
        self.tls_alpn01.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.insert(name.clone(), certificate.clone());
            next
        });
    }

    /// Stops serving the validation certificate for `name`.
    pub fn remove_tls_alpn01(&self, name: &str) {
        let name = name.to_ascii_lowercase();
        self.tls_alpn01.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.remove(&name);
            next
        });
    }

    /// The validation certificate for a TLS-ALPN-01 handshake asking for `name`.
    #[must_use]
    pub fn tls_alpn01(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.tls_alpn01
            .load()
            .get(&name.trim_end_matches('.').to_ascii_lowercase())
            .cloned()
    }

    /// The key authorization for a request path, when it asks for an HTTP-01 token in progress.
    #[must_use]
    pub fn http01_answer(&self, path: &str) -> Option<Arc<str>> {
        let token = path.strip_prefix(HTTP01_PREFIX)?;
        self.http01.load().get(token).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_only_tokens_in_progress() {
        let challenges = Challenges::default();
        challenges.add_http01("abc", "abc.thumbprint");
        assert_eq!(
            challenges
                .http01_answer("/.well-known/acme-challenge/abc")
                .as_deref(),
            Some("abc.thumbprint")
        );
        assert_eq!(
            challenges.http01_answer("/.well-known/acme-challenge/x"),
            None
        );
        assert_eq!(challenges.http01_answer("/abc"), None);
        challenges.remove_http01("abc");
        assert_eq!(
            challenges.http01_answer("/.well-known/acme-challenge/abc"),
            None
        );
    }
}
