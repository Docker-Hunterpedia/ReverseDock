//! Client certificates on TLS listeners (M-TLS-01, W-CF-08). A certificate is always verified
//! against the configured roots; modes that accept unverified certificates are not offered
//! (ADR-0022).

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

/// Cloudflare's CA for global Authenticated Origin Pulls, from
/// <https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem> (downloaded
/// 2026-10-29; `CN=origin-pull.cloudflare.net`, valid until 2029-11-01). Every Cloudflare
/// account shares it; Cloudflare recommends zone-level or per-hostname pulls with your own
/// certificate for stricter checks.
pub const CLOUDFLARE_ORIGIN_PULL_CA: &str = include_str!("../certs/cloudflare-origin-pull-ca.pem");

/// Why client authentication could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum ClientAuthError {
    /// A CA file could not be read or holds no certificate.
    #[error("{0}")]
    Roots(String),
    /// rustls refused the roots.
    #[error("cannot build the client certificate verifier: {0}")]
    Verifier(String),
}

/// Client certificate checks of one listener.
#[derive(Clone)]
pub struct ClientAuth {
    /// Refuse connections without a certificate (otherwise a certificate is optional, but
    /// verified when sent).
    pub required: bool,
    roots: Arc<RootCertStore>,
    fingerprint: u64,
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("required", &self.required)
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for ClientAuth {
    fn eq(&self, other: &Self) -> bool {
        self.required == other.required && self.fingerprint == other.fingerprint
    }
}

impl ClientAuth {
    /// Roots from PEM bundles (`(name, text)` pairs, for error messages).
    pub fn new(required: bool, bundles: &[(String, String)]) -> Result<Self, ClientAuthError> {
        let mut roots = RootCertStore::empty();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for (name, pem) in bundles {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|e| ClientAuthError::Roots(format!("invalid PEM in `{name}`: {e}")))?;
            if certs.is_empty() {
                return Err(ClientAuthError::Roots(format!(
                    "`{name}` holds no certificate"
                )));
            }
            for cert in certs {
                cert.as_ref().hash(&mut hasher);
                roots
                    .add(cert)
                    .map_err(|e| ClientAuthError::Roots(format!("`{name}`: {e}")))?;
            }
        }
        Ok(Self {
            required,
            roots: Arc::new(roots),
            fingerprint: hasher.finish(),
        })
    }

    /// The rustls verifier for these settings.
    pub fn verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, ClientAuthError> {
        let builder = WebPkiClientVerifier::builder_with_provider(
            self.roots.clone(),
            Arc::new(rustls::crypto::ring::default_provider()),
        );
        let builder = if self.required {
            builder
        } else {
            builder.allow_unauthenticated()
        };
        builder
            .build()
            .map_err(|e| ClientAuthError::Verifier(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cloudflare_ca_loads_and_settings_compare_by_content() {
        let cf = (
            "cloudflare".to_owned(),
            CLOUDFLARE_ORIGIN_PULL_CA.to_owned(),
        );
        let a = ClientAuth::new(true, std::slice::from_ref(&cf)).unwrap();
        let b = ClientAuth::new(true, std::slice::from_ref(&cf)).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, ClientAuth::new(false, &[cf]).unwrap());
        assert!(a.verifier().is_ok());
        let empty = ClientAuth::new(true, &[("x".into(), String::new())]);
        assert!(
            empty
                .unwrap_err()
                .to_string()
                .contains("holds no certificate")
        );
    }
}
