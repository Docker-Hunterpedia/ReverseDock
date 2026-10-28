//! A throw-away certificate authority for TLS tests.

use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, SanType};

pub struct TestCa {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

/// PEM files of an issued certificate.
pub struct Issued {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub cert_pem: String,
    pub key_pem: String,
}

impl Default for TestCa {
    fn default() -> Self {
        Self::new()
    }
}

impl TestCa {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "rdock test CA");
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        Self { issuer }
    }

    pub fn pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn der(&self) -> rustls_pki_types::CertificateDer<'static> {
        self.issuer.der().clone()
    }

    /// Writes the CA certificate to `dir/ca.pem`.
    pub fn write(&self, dir: &Path) -> PathBuf {
        let path = dir.join("ca.pem");
        std::fs::write(&path, self.pem()).unwrap();
        path
    }

    /// Issues a certificate for `names` (DNS names or IPs) and writes it to `dir/<file>.crt|key`.
    pub fn issue(&self, dir: &Path, file: &str, names: &[&str]) -> Issued {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = names
            .iter()
            .map(|n| match n.parse() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName((*n).try_into().unwrap()),
            })
            .collect();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let cert_path = dir.join(format!("{file}.crt"));
        let key_path = dir.join(format!("{file}.key"));
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        Issued {
            cert: cert_path,
            key: key_path,
            cert_pem,
            key_pem,
        }
    }

    /// A rustls client configuration trusting this CA, offering `alpn` and presenting the
    /// client certificate `client`.
    pub fn client_config_with_cert(
        &self,
        alpn: &[&[u8]],
        client: &Issued,
    ) -> std::sync::Arc<rustls::ClientConfig> {
        use rustls_pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der()).unwrap();
        let chain = rustls_pki_types::CertificateDer::pem_slice_iter(client.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key =
            rustls_pki_types::PrivateKeyDer::from_pem_slice(client.key_pem.as_bytes()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        std::sync::Arc::new(config)
    }

    /// A rustls client configuration trusting this CA, offering `alpn`.
    pub fn client_config(&self, alpn: &[&[u8]]) -> std::sync::Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        std::sync::Arc::new(config)
    }
}
