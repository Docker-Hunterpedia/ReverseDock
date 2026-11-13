//! The cluster CA (ECDSA P-256, rcgen on ring): created on the control plane's first start in
//! `<data>/control/ca/`, it signs the control plane's server certificate and every data plane's
//! client certificate. Its key is written with mode 0600 and never leaves the control plane.

use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use time::OffsetDateTime;

use crate::Error;

/// Lifetime of the cluster CA: ten years. Rotation is planned (ADR-0031).
const CA_LIFETIME_DAYS: i64 = 3650;
/// Lifetime of the control plane's server certificate, issued again at every start.
const SERVER_LIFETIME_DAYS: i64 = 90;

/// The cluster CA.
pub struct ClusterCa {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
    der: CertificateDer<'static>,
}

impl std::fmt::Debug for ClusterCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterCa")
            .field("pin", &self.pin())
            .finish_non_exhaustive()
    }
}

fn io(path: &Path, error: impl std::fmt::Display) -> Error {
    Error::State(format!("{}: {error}", path.display()))
}

fn serial() -> Result<SerialNumber, Error> {
    let mut bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
        .map_err(|_| Error::State("the system random generator failed".to_owned()))?;
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

impl ClusterCa {
    /// Loads the CA from `dir`, or creates it there named after `cluster_id`.
    pub fn load_or_create(dir: &Path, cluster_id: &str) -> Result<Self, Error> {
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca-key.pem");
        if cert_path.exists() {
            let pem = std::fs::read_to_string(&cert_path).map_err(|e| io(&cert_path, e))?;
            let key_pem = std::fs::read_to_string(&key_path).map_err(|e| io(&key_path, e))?;
            let key = KeyPair::from_pem(&key_pem).map_err(|e| io(&key_path, e))?;
            let der =
                CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|e| io(&cert_path, e))?;
            let issuer = Issuer::from_ca_cert_der(&der, key).map_err(|e| io(&cert_path, e))?;
            return Ok(Self { issuer, pem, der });
        }
        let key = KeyPair::generate().map_err(|e| Error::Certificate(e.to_string()))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| Error::Certificate(e.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, format!("rdock cluster CA {cluster_id}"));
        params.distinguished_name = name;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(CA_LIFETIME_DAYS);
        params.serial_number = Some(serial()?);
        let cert = params
            .self_signed(&key)
            .map_err(|e| Error::Certificate(e.to_string()))?;
        rdock_cluster::dir::write_private(&key_path, key.serialize_pem().as_bytes())
            .map_err(|e| io(&key_path, e))?;
        rdock_cluster::dir::write_private(&cert_path, cert.pem().as_bytes())
            .map_err(|e| io(&cert_path, e))?;
        let pem = cert.pem();
        let der = cert.der().clone();
        let issuer = Issuer::from_ca_cert_der(&der, key).map_err(|e| io(&cert_path, e))?;
        Ok(Self { issuer, pem, der })
    }

    /// The CA certificate (PEM).
    #[must_use]
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// The CA certificate (DER).
    #[must_use]
    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// `sha256:<hex>` of the CA certificate's DER: what `cluster.control.ca_pin` holds.
    #[must_use]
    pub fn pin(&self) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, self.der.as_ref());
        format!("sha256:{}", rdock_credentials::hex(digest.as_ref()))
    }

    /// A server certificate for `names` (DNS names and IP addresses), with its key, as PEM.
    pub fn server_certificate(&self, names: &[String]) -> Result<(String, String), Error> {
        let key = KeyPair::generate().map_err(|e| Error::Certificate(e.to_string()))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| Error::Certificate(e.to_string()))?;
        params.subject_alt_names = names
            .iter()
            .map(|n| match n.parse() {
                Ok(ip) => Ok(SanType::IpAddress(ip)),
                Err(_) => n
                    .clone()
                    .try_into()
                    .map(SanType::DnsName)
                    .map_err(|e: rcgen::Error| Error::Certificate(e.to_string())),
            })
            .collect::<Result<_, _>>()?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "rdock control plane");
        params.distinguished_name = name;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(SERVER_LIFETIME_DAYS);
        params.serial_number = Some(serial()?);
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| Error::Certificate(e.to_string()))?;
        Ok((format!("{}{}", cert.pem(), self.pem), key.serialize_pem()))
    }

    /// Signs a data plane's request: a client certificate naming `instance` of `cluster_id`,
    /// valid for `lifetime`. Whatever else the request asks for is ignored. Returns the
    /// certificate (PEM), its serial (hex) and its expiry (Unix seconds).
    pub fn client_certificate(
        &self,
        csr_pem: &str,
        cluster_id: &str,
        instance: &str,
        lifetime: std::time::Duration,
    ) -> Result<(String, String, i64), Error> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| Error::Refused(format!("not a valid signing request: {e}")))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| Error::Certificate(e.to_string()))?;
        let uri = format!(
            "{}{cluster_id}:{instance}",
            rdock_cluster::protocol::INSTANCE_URI_PREFIX
        );
        params.subject_alt_names = vec![SanType::URI(
            uri.try_into()
                .map_err(|e: rcgen::Error| Error::Certificate(e.to_string()))?,
        )];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, instance);
        params.distinguished_name = name;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        let lifetime =
            time::Duration::try_from(lifetime).map_err(|e| Error::Certificate(e.to_string()))?;
        params.not_after = now + lifetime;
        let serial = serial()?;
        let serial_hex = rdock_credentials::hex(serial.as_ref());
        params.serial_number = Some(serial);
        csr.params = params;
        let cert = csr
            .signed_by(&self.issuer)
            .map_err(|e| Error::Certificate(e.to_string()))?;
        Ok((cert.pem(), serial_hex, (now + lifetime).unix_timestamp()))
    }
}

/// The instance a client certificate names, when it is one of `cluster_id`'s.
#[must_use]
pub fn instance_of(cert: &CertificateDer<'_>, cluster_id: &str) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let san = parsed.subject_alternative_name().ok()??;
    let prefix = format!(
        "{}{cluster_id}:",
        rdock_cluster::protocol::INSTANCE_URI_PREFIX
    );
    san.value.general_names.iter().find_map(|name| match name {
        x509_parser::extensions::GeneralName::URI(uri) => {
            uri.strip_prefix(&prefix).map(str::to_owned)
        }
        _ => None,
    })
}

/// Where the CA lives in the data directory.
#[must_use]
pub fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join("control").join("ca")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_client_certificates_that_name_the_instance() {
        let dir = tempfile::tempdir().unwrap();
        let ca = ClusterCa::load_or_create(dir.path(), "c1").unwrap();
        let again = ClusterCa::load_or_create(dir.path(), "c1").unwrap();
        assert_eq!(ca.pin(), again.pin(), "the CA is kept");
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(vec!["ignored.example.com".to_owned()])
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let (pem, serial, not_after) = ca
            .client_certificate(&csr, "c1", "edge-1", std::time::Duration::from_secs(3600))
            .unwrap();
        assert_eq!(serial.len(), 32);
        assert!(not_after > OffsetDateTime::now_utc().unix_timestamp());
        let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        assert_eq!(instance_of(&der, "c1").as_deref(), Some("edge-1"));
        assert_eq!(instance_of(&der, "c2"), None, "another cluster's id");
        assert!(
            ca.client_certificate("not a csr", "c1", "x", std::time::Duration::from_secs(60))
                .is_err()
        );
        let (server, _) = ca
            .server_certificate(&["127.0.0.1".to_owned(), "cp.example.com".to_owned()])
            .unwrap();
        assert!(server.contains("BEGIN CERTIFICATE"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("ca-key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
