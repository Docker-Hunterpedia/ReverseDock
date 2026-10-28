//! ACME directory URLs of the certificate authorities known by name.

use rdock_model::acme::{Acme, CaRef, KnownCa};

/// Let's Encrypt production and staging directories.
const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// ZeroSSL has no staging directory.
const ZEROSSL: &str = "https://acme.zerossl.com/v2/DV90";
/// Google Trust Services production and staging directories.
const GOOGLE: &str = "https://dv.acme-v02.api.pki.goog/directory";
const GOOGLE_STAGING: &str = "https://dv.acme-v02.test-api.pki.goog/directory";

/// Why no directory can be used.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DirectoryError {
    /// The CA no longer issues certificates.
    #[error("Buypass stopped issuing certificates on 2025-10-16")]
    Discontinued,
    /// `staging: true` with a CA that has no staging environment.
    #[error("{0} has no staging environment")]
    NoStaging(&'static str),
}

/// The directory URL that `acme` points at.
pub fn directory_url(acme: &Acme) -> Result<String, DirectoryError> {
    let url = match (&acme.ca, acme.staging) {
        (CaRef::Directory(url), _) => return Ok(url.to_string()),
        (CaRef::Known(KnownCa::Letsencrypt), false) => LETSENCRYPT,
        (CaRef::Known(KnownCa::Letsencrypt), true) => LETSENCRYPT_STAGING,
        (CaRef::Known(KnownCa::Google), false) => GOOGLE,
        (CaRef::Known(KnownCa::Google), true) => GOOGLE_STAGING,
        (CaRef::Known(KnownCa::Zerossl), false) => ZEROSSL,
        (CaRef::Known(KnownCa::Zerossl), true) => return Err(DirectoryError::NoStaging("ZeroSSL")),
        (CaRef::Known(KnownCa::Buypass), _) => return Err(DirectoryError::Discontinued),
    };
    Ok(url.to_owned())
}

/// The Let's Encrypt staging directory, when `url` is Let's Encrypt production.
#[must_use]
pub fn staging_for(url: &str) -> Option<&'static str> {
    (url == LETSENCRYPT).then_some(LETSENCRYPT_STAGING)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_cas_and_staging() {
        let mut acme = Acme::default();
        assert_eq!(directory_url(&acme).as_deref(), Ok(LETSENCRYPT));
        assert_eq!(staging_for(LETSENCRYPT), Some(LETSENCRYPT_STAGING));
        acme.staging = true;
        assert_eq!(directory_url(&acme).as_deref(), Ok(LETSENCRYPT_STAGING));
        assert_eq!(staging_for(LETSENCRYPT_STAGING), None);
        acme.ca = CaRef::Known(KnownCa::Zerossl);
        assert_eq!(
            directory_url(&acme),
            Err(DirectoryError::NoStaging("ZeroSSL"))
        );
        acme.ca = CaRef::Known(KnownCa::Buypass);
        assert_eq!(directory_url(&acme), Err(DirectoryError::Discontinued));
    }
}
