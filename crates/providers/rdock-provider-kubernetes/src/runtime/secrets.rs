//! What the translator may learn about a Secret or a ConfigMap, and the bytes the runtime
//! keeps for the files (ADR-0029, "Key material never enters a fragment").
//!
//! A `kubernetes.io/tls` Secret is checked the way the file loader checks certificate files
//! (`rdock-tls`): the chain parses as PEM, the key parses as PKCS#8, PKCS#1 or SEC1, ring can
//! sign with it, it belongs to the leaf, and the leaf parses as X.509. The loader reads from
//! files only, so the same checks are repeated here on bytes. Encrypted keys are refused: a
//! Secret has no place for a password.

use std::collections::BTreeMap;
use std::fmt;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::inventory::{ConfigMapInfo, SecretInfo};

/// The Secret type whose certificates Gateways and Ingresses use.
pub const TLS_SECRET_TYPE: &str = "kubernetes.io/tls";
/// The certificate chain key of a TLS Secret.
pub const TLS_CRT: &str = "tls.crt";
/// The private key key of a TLS Secret.
pub const TLS_KEY: &str = "tls.key";
/// The CA bundle key of a ConfigMap (BackendTLSPolicy).
pub const CA_CRT: &str = "ca.crt";

/// A Secret as the runtime keeps it: what the translator may know, and the two files' bytes.
/// `Debug` never prints the bytes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StoredSecret {
    pub info: SecretInfo,
    pub crt: Option<Vec<u8>>,
    pub key: Option<Vec<u8>>,
}

impl fmt::Debug for StoredSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredSecret")
            .field("info", &self.info)
            .field(
                "crt",
                &self.crt.as_ref().map(|b| format!("{} bytes", b.len())),
            )
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A ConfigMap as the runtime keeps it: what the translator may know, and `ca.crt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredConfigMap {
    pub info: ConfigMapInfo,
    pub ca: Option<Vec<u8>>,
}

fn bytes(data: Option<&BTreeMap<String, ByteString>>, key: &str) -> Option<Vec<u8>> {
    data.and_then(|d| d.get(key)).map(|b| b.0.clone())
}

/// Reduces a Secret to what the runtime keeps. The bytes of Secrets of other types are
/// dropped at once.
pub(crate) fn reduce_secret(secret: &Secret) -> StoredSecret {
    let namespace = secret.metadata.namespace.clone().unwrap_or_default();
    let name = secret.metadata.name.clone().unwrap_or_default();
    let kind = secret.type_.clone().unwrap_or_else(|| "Opaque".to_owned());
    let data = secret.data.as_ref();
    let (crt, key, valid) = if kind == TLS_SECRET_TYPE {
        let crt = bytes(data, TLS_CRT);
        let key = bytes(data, TLS_KEY);
        let valid = tls_validity(crt.as_deref(), key.as_deref());
        (crt, key, valid)
    } else {
        (
            None,
            None,
            Err(format!(
                "the Secret is of type `{kind}`, not `{TLS_SECRET_TYPE}`"
            )),
        )
    };
    StoredSecret {
        info: SecretInfo {
            namespace,
            name,
            kind,
            valid,
        },
        crt,
        key,
    }
}

/// Reduces a ConfigMap to its `ca.crt` and whether it holds a certificate.
pub(crate) fn reduce_config_map(config_map: &ConfigMap) -> StoredConfigMap {
    let namespace = config_map.metadata.namespace.clone().unwrap_or_default();
    let name = config_map.metadata.name.clone().unwrap_or_default();
    let ca = config_map
        .data
        .as_ref()
        .and_then(|d| d.get(CA_CRT))
        .map(|s| s.as_bytes().to_vec())
        .or_else(|| bytes(config_map.binary_data.as_ref(), CA_CRT));
    let ca_bundle = ca_validity(ca.as_deref());
    StoredConfigMap {
        info: ConfigMapInfo {
            namespace,
            name,
            ca_bundle,
        },
        ca,
    }
}

/// Whether `tls.crt` and `tls.key` make a usable certificate; otherwise why not, worded for a
/// `ResolvedRefs` message. Never includes the bytes.
pub fn tls_validity(crt: Option<&[u8]>, key: Option<&[u8]>) -> Result<(), String> {
    let crt = crt.ok_or_else(|| format!("the Secret has no `{TLS_CRT}`"))?;
    let key = key.ok_or_else(|| format!("the Secret has no `{TLS_KEY}`"))?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(crt)
        .collect::<Result<_, _>>()
        .map_err(|_| format!("`{TLS_CRT}` is not a PEM certificate chain"))?;
    let Some(leaf) = chain.first().cloned() else {
        return Err(format!("`{TLS_CRT}` holds no PEM certificate"));
    };
    if String::from_utf8_lossy(key).contains("ENCRYPTED") {
        return Err(format!(
            "`{TLS_KEY}` is encrypted; a Secret has no place for its password"
        ));
    }
    let private = PrivateKeyDer::from_pem_slice(key)
        .map_err(|_| format!("`{TLS_KEY}` holds no PEM private key (PKCS#8, PKCS#1 or SEC1)"))?;
    let signing =
        any_supported_type(&private).map_err(|e| format!("`{TLS_KEY}` cannot be used: {e}"))?;
    CertifiedKey::new(chain, signing)
        .keys_match()
        .map_err(|e| format!("`{TLS_KEY}` does not belong to the certificate: {e}"))?;
    X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| format!("cannot parse the certificate in `{TLS_CRT}`: {e}"))?;
    Ok(())
}

/// Whether `ca.crt` holds at least one PEM certificate that parses.
pub fn ca_validity(ca: Option<&[u8]>) -> Result<(), String> {
    let ca = ca.ok_or_else(|| format!("the ConfigMap has no `{CA_CRT}`"))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(ca)
        .collect::<Result<_, _>>()
        .map_err(|_| format!("`{CA_CRT}` is not a PEM certificate bundle"))?;
    if certs.is_empty() {
        return Err(format!("`{CA_CRT}` holds no PEM certificate"));
    }
    for cert in &certs {
        X509Certificate::from_der(cert.as_ref())
            .map_err(|e| format!("cannot parse a certificate in `{CA_CRT}`: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(name: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn a_matching_chain_and_key_are_valid() {
        let (crt, key) = pair("a.example");
        assert_eq!(
            tls_validity(Some(crt.as_bytes()), Some(key.as_bytes())),
            Ok(())
        );
        // A chain of two certificates: the leaf first.
        let (other, _) = pair("ca.example");
        let chain = format!("{crt}{other}");
        assert_eq!(
            tls_validity(Some(chain.as_bytes()), Some(key.as_bytes())),
            Ok(())
        );
    }

    #[test]
    fn a_key_of_another_certificate_is_refused() {
        let (crt, _) = pair("a.example");
        let (_, other_key) = pair("b.example");
        let err = tls_validity(Some(crt.as_bytes()), Some(other_key.as_bytes())).unwrap_err();
        assert!(err.contains("does not belong"), "{err}");
        assert!(!err.contains("PRIVATE"), "{err}");
    }

    #[test]
    fn garbage_and_missing_keys_are_refused() {
        let (crt, key) = pair("a.example");
        let hello = b"Hello world\n".as_slice();
        assert!(
            tls_validity(Some(hello), Some(hello))
                .unwrap_err()
                .contains("tls.crt")
        );
        assert!(
            tls_validity(Some(crt.as_bytes()), Some(hello))
                .unwrap_err()
                .contains("no PEM private key")
        );
        assert!(
            tls_validity(None, Some(key.as_bytes()))
                .unwrap_err()
                .contains("no `tls.crt`")
        );
        assert!(
            tls_validity(Some(crt.as_bytes()), None)
                .unwrap_err()
                .contains("no `tls.key`")
        );
        let encrypted =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(
            tls_validity(Some(crt.as_bytes()), Some(encrypted.as_bytes()))
                .unwrap_err()
                .contains("encrypted")
        );
    }

    #[test]
    fn secrets_are_reduced_without_keeping_other_types_bytes() {
        let (crt, key) = pair("a.example");
        let mut secret = Secret {
            metadata: kube::api::ObjectMeta {
                namespace: Some("apps".to_owned()),
                name: Some("web".to_owned()),
                ..Default::default()
            },
            type_: Some(TLS_SECRET_TYPE.to_owned()),
            data: Some(BTreeMap::from([
                (TLS_CRT.to_owned(), ByteString(crt.clone().into_bytes())),
                (TLS_KEY.to_owned(), ByteString(key.clone().into_bytes())),
            ])),
            ..Default::default()
        };
        let stored = reduce_secret(&secret);
        assert_eq!(stored.info.valid, Ok(()));
        assert_eq!(stored.info.kind, TLS_SECRET_TYPE);
        assert_eq!(stored.crt.as_deref(), Some(crt.as_bytes()));
        assert!(!format!("{stored:?}").contains("PRIVATE KEY"));
        secret.type_ = Some("Opaque".to_owned());
        let opaque = reduce_secret(&secret);
        assert!(opaque.info.valid.unwrap_err().contains("Opaque"));
        assert_eq!(opaque.crt, None);
        assert_eq!(opaque.key, None);
    }

    #[test]
    fn config_maps_need_a_ca_certificate() {
        let (crt, _) = pair("ca.example");
        assert_eq!(ca_validity(Some(crt.as_bytes())), Ok(()));
        assert!(ca_validity(None).unwrap_err().contains("no `ca.crt`"));
        assert!(ca_validity(Some(b"nope")).unwrap_err().contains("no PEM"));
        let config_map = ConfigMap {
            metadata: kube::api::ObjectMeta {
                namespace: Some("apps".to_owned()),
                name: Some("ca".to_owned()),
                ..Default::default()
            },
            data: Some(BTreeMap::from([
                (CA_CRT.to_owned(), crt.clone()),
                ("other".to_owned(), "dropped".to_owned()),
            ])),
            ..Default::default()
        };
        let stored = reduce_config_map(&config_map);
        assert_eq!(stored.info.ca_bundle, Ok(()));
        assert_eq!(stored.ca.as_deref(), Some(crt.as_bytes()));
    }
}
