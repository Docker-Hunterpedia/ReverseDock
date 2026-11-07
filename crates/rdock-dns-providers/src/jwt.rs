//! JSON Web Tokens signed with an RSA key on ring: RS256 for Google service accounts
//! (RFC 7523) and PS256 for Azure certificate assertions.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rdock_acme::dns::DnsError;
use ring::rand::SystemRandom;
use ring::rsa::KeyPair;
use ring::signature::{RSA_PKCS1_SHA256, RSA_PSS_SHA256, RsaEncoding};
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use serde_json::Value;

/// The JWS algorithm (RFC 7518 §3.1).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// RSASSA-PSS with SHA-256.
    Ps256,
}

impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
        }
    }

    fn padding(self) -> &'static dyn RsaEncoding {
        match self {
            Self::Rs256 => &RSA_PKCS1_SHA256,
            Self::Ps256 => &RSA_PSS_SHA256,
        }
    }
}

/// An RSA private key.
#[derive(Debug)]
pub(crate) struct RsaKey(KeyPair);

impl RsaKey {
    /// The first private key in `pem`, PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1
    /// (`BEGIN RSA PRIVATE KEY`). `field` names the setting in errors; the key never appears.
    pub(crate) fn from_pem(pem: &[u8], field: &str) -> Result<Self, DnsError> {
        let der = PrivateKeyDer::from_pem_slice(pem)
            .map_err(|_| DnsError(format!("{field}: no private key in PEM form")))?;
        let key = match &der {
            PrivateKeyDer::Pkcs8(key) => KeyPair::from_pkcs8(key.secret_pkcs8_der()),
            PrivateKeyDer::Pkcs1(key) => KeyPair::from_der(key.secret_pkcs1_der()),
            _ => {
                return Err(DnsError(format!(
                    "{field}: the private key is not an RSA key"
                )));
            }
        }
        .map_err(|e| DnsError(format!("{field}: the RSA key cannot be used: {e}")))?;
        Ok(Self(key))
    }

    /// `header.claims.signature`, each part base64url without padding (RFC 7515 §7.1). `alg`
    /// and `typ` are added to `header`.
    pub(crate) fn sign(
        &self,
        algorithm: Algorithm,
        header: &Value,
        claims: &Value,
    ) -> Result<String, DnsError> {
        let mut header = header.clone();
        header["alg"] = algorithm.name().into();
        header["typ"] = "JWT".into();
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self.signature(algorithm, input.as_bytes())?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// The signature of `input`.
    fn signature(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, DnsError> {
        let mut signature = vec![0; self.0.public().modulus_len()];
        self.0
            .sign(
                algorithm.padding(),
                &SystemRandom::new(),
                input,
                &mut signature,
            )
            .map_err(|_| DnsError("signing the token failed".to_owned()))?;
        Ok(signature)
    }

    /// The public key, DER `RSAPublicKey`, for checking signatures in tests.
    #[cfg(test)]
    pub(crate) fn public_der(&self) -> Vec<u8> {
        self.0.public().as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests;
