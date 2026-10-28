//! Loading certificates and private keys from PEM files.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::ring::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// A certificate chain with its key, ready to serve.
#[derive(Debug, Clone)]
pub struct LoadedCert {
    /// Name of the certificate in the configuration.
    pub name: String,
    /// Chain and signing key.
    pub key: Arc<CertifiedKey>,
    /// DNS names and IP addresses of the leaf certificate (subject alternative names),
    /// lower-cased. Wildcards keep their `*.` prefix.
    pub names: Vec<String>,
    /// Start of the leaf certificate's validity, in seconds since the Unix epoch.
    pub not_before: i64,
    /// Expiry of the leaf certificate, in seconds since the Unix epoch.
    pub not_after: i64,
}

/// Why a certificate could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// A file could not be read.
    #[error("cannot read `{}`: {source}", path.display())]
    Read {
        /// File that was read.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The certificate file has no usable certificate.
    #[error("`{}` contains no PEM certificate", .0.display())]
    NoCertificate(PathBuf),
    /// The key file has no usable key.
    #[error("`{}` contains no PEM private key (PKCS#8, PKCS#1 or SEC1)", .0.display())]
    NoKey(PathBuf),
    /// The key is encrypted but no password is configured, or the password is wrong.
    #[error("cannot decrypt `{}`: {reason}", path.display())]
    Decrypt {
        /// Key file.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The key type is not supported or does not belong to the certificate.
    #[error("the key in `{}` cannot be used with this certificate: {reason}", path.display())]
    KeyMismatch {
        /// Key file.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The leaf certificate could not be parsed.
    #[error("cannot parse the certificate in `{}`: {reason}", path.display())]
    Parse {
        /// Certificate file.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
}

const ENCRYPTED_KEY_LABEL: &str = "ENCRYPTED PRIVATE KEY";

/// Loads a PEM chain (leaf first) and its private key. `password` decrypts an encrypted PKCS#8
/// key.
pub fn load_certificate(
    name: &str,
    cert_file: &Path,
    key_file: &Path,
    password: Option<&str>,
) -> Result<LoadedCert, CertError> {
    let chain = read_chain(cert_file)?;
    let key = read_key(key_file, password)?;
    let signing_key = any_supported_type(&key).map_err(|e| CertError::KeyMismatch {
        path: key_file.to_owned(),
        reason: e.to_string(),
    })?;
    let certified = CertifiedKey::new(chain, signing_key);
    certified.keys_match().map_err(|e| CertError::KeyMismatch {
        path: key_file.to_owned(),
        reason: e.to_string(),
    })?;
    let leaf = leaf_facts(cert_file, &certified.cert[0])?;
    Ok(LoadedCert {
        name: name.to_owned(),
        key: Arc::new(certified),
        names: leaf.names,
        not_before: leaf.not_before,
        not_after: leaf.not_after,
    })
}

fn read(path: &Path) -> Result<Vec<u8>, CertError> {
    std::fs::read(path).map_err(|source| CertError::Read {
        path: path.to_owned(),
        source,
    })
}

fn read_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, CertError> {
    let bytes = read(path)?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<_, _>>()
        .map_err(|_| CertError::NoCertificate(path.to_owned()))?;
    if chain.is_empty() {
        return Err(CertError::NoCertificate(path.to_owned()));
    }
    Ok(chain)
}

fn read_key(path: &Path, password: Option<&str>) -> Result<PrivateKeyDer<'static>, CertError> {
    let bytes = read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    if text.contains(&format!("-----BEGIN {ENCRYPTED_KEY_LABEL}-----")) {
        return decrypt_key(path, &bytes, password);
    }
    if text.contains("Proc-Type: 4,ENCRYPTED") {
        return Err(CertError::Decrypt {
            path: path.to_owned(),
            reason: "legacy OpenSSL encryption is not supported; convert the key with \
                     `openssl pkcs8 -topk8 -in old.key -out new.key`"
                .to_owned(),
        });
    }
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|_| CertError::NoKey(path.to_owned()))
}

fn decrypt_key(
    path: &Path,
    pem: &[u8],
    password: Option<&str>,
) -> Result<PrivateKeyDer<'static>, CertError> {
    let fail = |reason: String| CertError::Decrypt {
        path: path.to_owned(),
        reason,
    };
    let password =
        password.ok_or_else(|| fail("the key is encrypted; set `key_password`".into()))?;
    let (label, der) = pkcs8::der::pem::decode_vec(pem).map_err(|e| fail(e.to_string()))?;
    if label != ENCRYPTED_KEY_LABEL {
        return Err(fail(format!("unexpected PEM section `{label}`")));
    }
    let info = pkcs8::EncryptedPrivateKeyInfoRef::try_from(der.as_slice())
        .map_err(|e| fail(e.to_string()))?;
    let document = info
        .decrypt(password)
        .map_err(|_| fail("wrong password or unsupported encryption".into()))?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        document.as_bytes().to_vec(),
    )))
}

struct LeafFacts {
    names: Vec<String>,
    not_before: i64,
    not_after: i64,
}

/// Subject alternative names and validity of the leaf.
fn leaf_facts(path: &Path, leaf: &CertificateDer<'_>) -> Result<LeafFacts, CertError> {
    let fail = |reason: String| CertError::Parse {
        path: path.to_owned(),
        reason,
    };
    let (_, cert) = X509Certificate::from_der(leaf.as_ref()).map_err(|e| fail(e.to_string()))?;
    let mut names = Vec::new();
    if let Some(san) = cert
        .subject_alternative_name()
        .map_err(|e| fail(e.to_string()))?
    {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    names.push(dns.trim_end_matches('.').to_ascii_lowercase());
                }
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ip_from_bytes(bytes) {
                        names.push(ip.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    Ok(LeafFacts {
        names,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
    })
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}
