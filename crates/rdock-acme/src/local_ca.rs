//! The local certificate authority for names public CAs will not sign (ADR-0020):
//!
//! ```text
//! <dir>/root.pem               P-256 root, 10 years, name-constrained
//! <dir>/root-key.pem           0600, used only to sign intermediates
//! <dir>/intermediate.pem       30 days, path length 0, signs the leaves
//! <dir>/intermediate-key.pem   0600
//! ```
//!
//! The root's name constraints permit only the reserved suffixes of
//! [`rdock_tls::PRIVATE_SUFFIXES`] and loopback, private and link-local addresses, so even a
//! leaked root key cannot produce a certificate a browser accepts for a public name. Leaves
//! live only in memory: issuing one is a local signature, cheaper than keeping files in step.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, SanType,
};
use rdock_tls::LoadedCert;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::storage::{create_dir, write_private, write_public};

const DAY: i64 = 24 * 3600;
/// Lifetime of the root.
pub const ROOT_LIFETIME: i64 = 3650 * DAY;
/// Lifetime of an intermediate.
pub const INTERMEDIATE_LIFETIME: i64 = 30 * DAY;
/// Lifetime of a leaf.
pub const LEAF_LIFETIME: i64 = 7 * DAY;
/// Certificates start this far in the past, so a client whose clock runs a little behind
/// accepts a certificate issued a moment ago.
const BACKDATE: i64 = 3600;

/// Address ranges the root permits: IPv4 loopback, RFC 1918 and link-local; IPv6 loopback,
/// unique local and link-local. The same ranges [`rdock_tls::is_private_name`] accepts.
const PERMITTED_RANGES: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// Why the local CA cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum LocalCaError {
    /// A file of the CA could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// File or directory involved.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A stored certificate or key is unusable.
    #[error("{}: {reason}", path.display())]
    Invalid {
        /// File involved.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
    /// A certificate could not be generated.
    #[error("cannot generate a certificate: {0}")]
    Generate(#[from] rcgen::Error),
    /// The name cannot be certified by the local CA.
    #[error("`{0}` is not a name the local CA can certify")]
    NotLocal(String),
}

/// A CA certificate with the key that signs with it.
struct Authority {
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
    not_before: i64,
    not_after: i64,
}

impl Authority {
    /// When this authority should be replaced: with a third of its lifetime left.
    fn renew_at(&self) -> i64 {
        self.not_after - (self.not_after - self.not_before) / 3
    }
}

/// The local CA: its root, and the intermediate that signs leaves.
pub struct LocalCa {
    dir: PathBuf,
    name: String,
    root: Authority,
    intermediate: Authority,
}

impl std::fmt::Debug for LocalCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCa")
            .field("dir", &self.dir)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl LocalCa {
    /// Loads the CA in `dir`, creating the root and intermediate when missing and replacing an
    /// intermediate that is due (see [`LocalCa::rotate_if_due`]).
    pub fn open(dir: &Path, now: i64) -> Result<Self, LocalCaError> {
        create_dir(dir).map_err(|source| io_error(dir, source))?;
        let (root, name) = match load_authority(dir, "root")? {
            Some(root) if root.not_after > now => {
                let name = common_name(&root.der).unwrap_or_default();
                (root, name)
            }
            expired => {
                if expired.is_some() {
                    warn!(dir = %dir.display(), "the local CA root expired; creating a new one, run `rdock trust` again");
                }
                create_root(dir, now)?
            }
        };
        let intermediate = match load_authority(dir, "intermediate")? {
            Some(intermediate) => intermediate,
            None => create_intermediate(dir, &root, now)?,
        };
        let mut ca = Self {
            dir: dir.to_owned(),
            name,
            root,
            intermediate,
        };
        ca.rotate_if_due(now)?;
        Ok(ca)
    }

    /// The common name of the root, `ReverseDock Local CA <year>`, as trust stores list it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The root certificate (PEM), the file `rdock trust` installs.
    #[must_use]
    pub fn root_path(&self) -> PathBuf {
        self.dir.join("root.pem")
    }

    /// The root certificate (DER).
    #[must_use]
    pub fn root_der(&self) -> &CertificateDer<'static> {
        &self.root.der
    }

    /// Replaces the intermediate when a third of its lifetime is left, or when it was not
    /// signed by the current root. Returns whether it was replaced.
    pub fn rotate_if_due(&mut self, now: i64) -> Result<bool, LocalCaError> {
        if now < self.intermediate.renew_at() && self.signed_by_root(&self.intermediate) {
            return Ok(false);
        }
        self.intermediate = create_intermediate(&self.dir, &self.root, now)?;
        info!(
            not_after = self.intermediate.not_after,
            "rotated the local CA intermediate"
        );
        Ok(true)
    }

    /// When the intermediate is next due for rotation, in Unix seconds.
    #[must_use]
    pub fn rotate_at(&self) -> i64 {
        self.intermediate.renew_at()
    }

    /// Issues a leaf for `name` (a DNS name, or an IP address in a permitted range), valid for
    /// seven days but never beyond the intermediate. The chain is leaf, then intermediate.
    pub fn issue(&self, name: &str, now: i64) -> Result<LoadedCert, LocalCaError> {
        if !rdock_tls::is_local_ca_name(name) {
            return Err(LocalCaError::NotLocal(name.to_owned()));
        }
        let literal = name.trim_start_matches('[').trim_end_matches(']');
        let (san, canonical) = if let Ok(ip) = literal.parse::<IpAddr>() {
            (SanType::IpAddress(ip), ip.to_string())
        } else {
            let dns = name.trim_end_matches('.').to_ascii_lowercase();
            (SanType::DnsName(dns.as_str().try_into()?), dns)
        };
        let not_before = now - BACKDATE;
        let not_after = (now + LEAF_LIFETIME).min(self.intermediate.not_after);
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name(&canonical);
        params.subject_alt_names = vec![san];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = datetime(not_before);
        params.not_after = datetime(not_after);
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.intermediate.issuer)?;
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = any_supported_type(&private).map_err(|e| LocalCaError::Invalid {
            path: self.dir.clone(),
            reason: e.to_string(),
        })?;
        let chain = vec![cert.der().clone(), self.intermediate.der.clone()];
        Ok(LoadedCert {
            name: canonical.clone(),
            key: Arc::new(CertifiedKey::new(chain, signing_key)),
            names: vec![canonical],
            not_before,
            not_after,
        })
    }

    fn signed_by_root(&self, authority: &Authority) -> bool {
        issuer_matches(&authority.der, &self.root.der)
    }
}

/// The root's name, read from `<dir>/root.pem`, or `None` when there is no CA.
pub fn root_name(dir: &Path) -> Result<Option<String>, LocalCaError> {
    let path = dir.join("root.pem");
    match std::fs::read(&path) {
        Ok(pem) => {
            let der = first_certificate(&path, &pem)?;
            Ok(Some(common_name(&der).unwrap_or_default()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error(&path, source)),
    }
}

fn create_root(dir: &Path, now: i64) -> Result<(Authority, String), LocalCaError> {
    let name = format!("ReverseDock Local CA {}", datetime(now).year());
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name(&name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(name_constraints()?);
    params.not_before = datetime(now - BACKDATE);
    params.not_after = datetime(now + ROOT_LIFETIME);
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    store(dir, "root", &cert.pem(), &key)?;
    info!(dir = %dir.display(), name = %name, "created the local CA; `rdock trust` installs its root");
    let root = authority(dir, "root", cert.der().clone(), key)?;
    Ok((root, name))
}

fn create_intermediate(dir: &Path, root: &Authority, now: i64) -> Result<Authority, LocalCaError> {
    let date = datetime(now).date();
    let mut params = CertificateParams::default();
    params.distinguished_name =
        distinguished_name(&format!("ReverseDock Local Intermediate {date}"));
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.use_authority_key_identifier_extension = true;
    params.not_before = datetime(now - BACKDATE);
    // An intermediate never outlives the root that signed it.
    params.not_after = datetime((now + INTERMEDIATE_LIFETIME).min(root.not_after));
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &root.issuer)?;
    store(dir, "intermediate", &cert.pem(), &key)?;
    authority(dir, "intermediate", cert.der().clone(), key)
}

/// DNS subtrees match the name itself and every name below it (RFC 5280 §4.2.1.10), so
/// `localhost` permits `localhost` and `app.localhost`.
fn name_constraints() -> Result<NameConstraints, LocalCaError> {
    let mut permitted: Vec<GeneralSubtree> = rdock_tls::PRIVATE_SUFFIXES
        .iter()
        .map(|suffix| GeneralSubtree::DnsName((*suffix).to_owned()))
        .collect();
    for range in PERMITTED_RANGES {
        let subnet = range
            .parse::<CidrSubnet>()
            .map_err(|()| LocalCaError::NotLocal((*range).to_owned()))?;
        permitted.push(GeneralSubtree::IpAddress(subnet));
    }
    Ok(NameConstraints {
        permitted_subtrees: permitted,
        excluded_subtrees: Vec::new(),
    })
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "ReverseDock");
    dn.push(DnType::CommonName, common_name);
    dn
}

/// Writes the key first and the certificate last: a certificate on disk always has its key.
fn store(dir: &Path, stem: &str, cert_pem: &str, key: &KeyPair) -> Result<(), LocalCaError> {
    let key_path = dir.join(format!("{stem}-key.pem"));
    write_private(&key_path, key.serialize_pem().as_bytes())
        .map_err(|source| io_error(&key_path, source))?;
    let cert_path = dir.join(format!("{stem}.pem"));
    write_public(&cert_path, cert_pem.as_bytes()).map_err(|source| io_error(&cert_path, source))
}

/// The stored authority `<stem>.pem` with `<stem>-key.pem`, or `None` when either is missing.
fn load_authority(dir: &Path, stem: &str) -> Result<Option<Authority>, LocalCaError> {
    let cert_path = dir.join(format!("{stem}.pem"));
    let key_path = dir.join(format!("{stem}-key.pem"));
    let (Some(cert_pem), Some(key_pem)) = (read_optional(&cert_path)?, read_optional(&key_path)?)
    else {
        return Ok(None);
    };
    let der = first_certificate(&cert_path, &cert_pem)?;
    let key_text = String::from_utf8_lossy(&key_pem);
    let key = KeyPair::from_pem(&key_text).map_err(|e| invalid(&key_path, &e))?;
    authority(dir, stem, der, key).map(Some)
}

fn authority(
    dir: &Path,
    stem: &str,
    der: CertificateDer<'static>,
    key: KeyPair,
) -> Result<Authority, LocalCaError> {
    let path = dir.join(format!("{stem}.pem"));
    let (_, cert) =
        x509_parser::parse_x509_certificate(der.as_ref()).map_err(|e| invalid(&path, &e))?;
    if cert.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
        return Err(LocalCaError::Invalid {
            path,
            reason: format!("the certificate does not belong to {stem}-key.pem"),
        });
    }
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    // Rebuilding the issuer from the certificate itself keeps the subject and key identifier
    // byte-for-byte what verifiers compare against the issuer of the certificates it signs.
    let issuer = Issuer::from_ca_cert_der(&der, key).map_err(|e| invalid(&path, &e))?;
    Ok(Authority {
        issuer,
        der,
        not_before,
        not_after,
    })
}

fn first_certificate(path: &Path, pem: &[u8]) -> Result<CertificateDer<'static>, LocalCaError> {
    use rustls_pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem)
        .next()
        .and_then(Result::ok)
        .ok_or_else(|| LocalCaError::Invalid {
            path: path.to_owned(),
            reason: "no PEM certificate".to_owned(),
        })
}

fn common_name(der: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned)
}

/// Whether `cert` was issued by `root`: same issuer name and an authority key identifier equal
/// to the root's subject key identifier, so a root re-created with the same name does not
/// count.
fn issuer_matches(cert: &CertificateDer<'_>, root: &CertificateDer<'_>) -> bool {
    use x509_parser::extensions::ParsedExtension;
    let (Ok((_, cert)), Ok((_, root))) = (
        x509_parser::parse_x509_certificate(cert.as_ref()),
        x509_parser::parse_x509_certificate(root.as_ref()),
    ) else {
        return false;
    };
    let authority_key = cert
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|k| k.0)
            }
            _ => None,
        });
    let subject_key = root
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ski) => Some(ski.0),
            _ => None,
        });
    cert.issuer().as_raw() == root.subject().as_raw()
        && authority_key.is_some()
        && authority_key == subject_key
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, LocalCaError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error(path, source)),
    }
}

fn datetime(unix: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(unix).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn io_error(path: &Path, source: std::io::Error) -> LocalCaError {
    LocalCaError::Io {
        path: path.to_owned(),
        source,
    }
}

fn invalid(path: &Path, error: &dyn std::fmt::Display) -> LocalCaError {
    LocalCaError::Invalid {
        path: path.to_owned(),
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls_pki_types::{ServerName, UnixTime};

    use super::*;

    const NOW: i64 = 1_800_000_000;

    /// Verifies `leaf` against the CA's root with rustls's webpki verifier at time `now`.
    fn verify(ca: &LocalCa, leaf: &LoadedCert, host: &str, now: i64) -> Result<(), rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.root_der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .unwrap();
        let chain = &leaf.key.cert;
        let at = UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(now).unwrap()));
        verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &ServerName::try_from(host.to_owned()).unwrap(),
                &[],
                at,
            )
            .map(|_| ())
    }

    #[test]
    fn creates_a_private_name_constrained_ca_and_reloads_it() {
        let dir = tempfile::tempdir().unwrap();
        let pki = dir.path().join("pki");
        let ca = LocalCa::open(&pki, NOW).unwrap();
        assert_eq!(ca.name(), "ReverseDock Local CA 2027");
        assert_eq!(root_name(&pki).unwrap().as_deref(), Some(ca.name()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |p: &str| std::fs::metadata(pki.join(p)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(""), 0o700);
            assert_eq!(mode("root-key.pem"), 0o600);
            assert_eq!(mode("intermediate-key.pem"), 0o600);
        }

        let reopened = LocalCa::open(&pki, NOW + 60).unwrap();
        assert_eq!(reopened.root_der(), ca.root_der(), "the root is reused");
        assert_eq!(reopened.intermediate.der, ca.intermediate.der);
        let leaf = reopened.issue("app.localhost", NOW + 60).unwrap();
        verify(&ca, &leaf, "app.localhost", NOW + 120).unwrap();
        assert_eq!(leaf.names, ["app.localhost"]);
        assert_eq!(leaf.not_after - leaf.not_before, LEAF_LIFETIME + BACKDATE);
    }

    #[test]
    fn leaves_verify_for_private_names_and_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let ca = LocalCa::open(dir.path(), NOW).unwrap();
        for name in [
            "localhost",
            "app.localhost",
            "nas.home.arpa",
            "db.internal",
            "10.1.2.3",
            "::1",
        ] {
            let leaf = ca.issue(name, NOW).unwrap();
            assert!(verify(&ca, &leaf, name, NOW).is_ok(), "{name}");
        }
        assert!(matches!(
            ca.issue("example.com", NOW),
            Err(LocalCaError::NotLocal(_))
        ));
        assert!(matches!(
            ca.issue("nas", NOW),
            Err(LocalCaError::NotLocal(_))
        ));
    }

    #[test]
    fn name_constraints_reject_a_public_name_even_from_the_real_intermediate() {
        let dir = tempfile::tempdir().unwrap();
        let ca = LocalCa::open(dir.path(), NOW).unwrap();
        // Sign directly with the intermediate key, bypassing `issue`'s own check: only the
        // root's name constraints stand between this certificate and a client.
        for public in ["example.com", "203.0.113.7"] {
            let mut params = CertificateParams::default();
            params.subject_alt_names = vec![match public.parse::<IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName(public.try_into().unwrap()),
            }];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.use_authority_key_identifier_extension = true;
            params.not_before = datetime(NOW - BACKDATE);
            params.not_after = datetime(NOW + LEAF_LIFETIME);
            let key = KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, &ca.intermediate.issuer).unwrap();
            let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
            let leaf = LoadedCert {
                name: public.to_owned(),
                key: Arc::new(CertifiedKey::new(
                    vec![cert.der().clone(), ca.intermediate.der.clone()],
                    any_supported_type(&private).unwrap(),
                )),
                names: vec![public.to_owned()],
                not_before: NOW,
                not_after: NOW + LEAF_LIFETIME,
            };
            let error = verify(&ca, &leaf, public, NOW).unwrap_err();
            assert!(
                format!("{error:?}").contains("NameConstraintViolation"),
                "{public}: {error:?}"
            );
        }
    }

    #[test]
    fn rotates_the_intermediate_with_a_third_left_and_caps_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let mut ca = LocalCa::open(dir.path(), NOW).unwrap();
        let first = ca.intermediate.der.clone();
        let due = ca.rotate_at();
        let lifetime = INTERMEDIATE_LIFETIME + BACKDATE;
        assert_eq!(due, NOW - BACKDATE + lifetime - lifetime / 3);
        assert!(!ca.rotate_if_due(due - 1).unwrap());
        let late = ca.issue("app.localhost", due - 1).unwrap();
        assert!(late.not_after <= ca.intermediate.not_after);
        assert!(ca.rotate_if_due(due).unwrap());
        assert_ne!(ca.intermediate.der, first);
        let leaf = ca.issue("app.localhost", due).unwrap();
        verify(&ca, &leaf, "app.localhost", due).unwrap();
        let reopened = LocalCa::open(dir.path(), due + 1).unwrap();
        assert_eq!(
            reopened.intermediate.der, ca.intermediate.der,
            "the rotation is stored"
        );
    }

    #[test]
    fn a_new_root_replaces_the_intermediate_it_did_not_sign() {
        let dir = tempfile::tempdir().unwrap();
        let ca = LocalCa::open(dir.path(), NOW).unwrap();
        for file in ["root.pem", "root-key.pem"] {
            std::fs::remove_file(dir.path().join(file)).unwrap();
        }
        let renewed = LocalCa::open(dir.path(), NOW).unwrap();
        assert_ne!(renewed.root_der(), ca.root_der());
        assert_ne!(renewed.intermediate.der, ca.intermediate.der);
        let leaf = renewed.issue("app.localhost", NOW).unwrap();
        verify(&renewed, &leaf, "app.localhost", NOW).unwrap();
    }
}
