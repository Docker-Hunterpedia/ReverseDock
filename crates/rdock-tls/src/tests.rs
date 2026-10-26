use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, SanType};
use rdock_model::config::TlsPolicy;

use crate::{CertError, CertIndex, SniResolver, load_certificate, server_config};

/// Writes a self-signed certificate for `names` and returns (cert path, key path, key PEM).
fn self_signed(dir: &Path, file: &str, names: &[&str]) -> (PathBuf, PathBuf, String) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = names
        .iter()
        .map(|n| match n.parse() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName((*n).try_into().unwrap()),
        })
        .collect();
    let cert = params.self_signed(&key).unwrap();
    let cert_path = dir.join(format!("{file}.crt"));
    let key_path = dir.join(format!("{file}.key"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (cert_path, key_path, key.serialize_pem())
}

#[test]
fn loads_names_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = self_signed(dir.path(), "a", &["A.test", "*.wild.test", "10.0.0.1"]);
    let loaded = load_certificate("a", &cert, &key, None).unwrap();
    assert_eq!(loaded.names, vec!["a.test", "*.wild.test", "10.0.0.1"]);
    assert!(loaded.not_after > 0);
}

#[test]
fn rejects_mismatched_and_missing_material() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, _, _) = self_signed(dir.path(), "a", &["a.test"]);
    let (_, other_key, _) = self_signed(dir.path(), "b", &["b.test"]);
    assert!(matches!(
        load_certificate("a", &cert, &other_key, None),
        Err(CertError::KeyMismatch { .. })
    ));
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    assert!(matches!(
        load_certificate("a", &empty, &other_key, None),
        Err(CertError::NoCertificate(_))
    ));
    assert!(matches!(
        load_certificate("a", &cert, &empty, None),
        Err(CertError::NoKey(_))
    ));
    assert!(matches!(
        load_certificate("a", &dir.path().join("nope"), &empty, None),
        Err(CertError::Read { .. })
    ));
}

#[test]
fn decrypts_encrypted_pkcs8_keys() {
    use pkcs8::der::pem::LineEnding;
    use pkcs8::pkcs5::pbes2::Parameters;

    let dir = tempfile::tempdir().unwrap();
    let (cert, _, key_pem) = self_signed(dir.path(), "a", &["a.test"]);
    let (_, der) = pkcs8::der::pem::decode_vec(key_pem.as_bytes()).unwrap();
    let info = pkcs8::PrivateKeyInfoRef::try_from(der.as_slice()).unwrap();
    let params =
        Parameters::generate_pbkdf2_sha256_aes256cbc(1_000, b"0123456789abcdef", [7; 16]).unwrap();
    let encrypted = info.encrypt_with_params(params, "correct horse").unwrap();
    let encrypted_path = dir.path().join("encrypted.key");
    std::fs::write(
        &encrypted_path,
        encrypted
            .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();

    assert!(load_certificate("a", &cert, &encrypted_path, Some("correct horse")).is_ok());
    let wrong = load_certificate("a", &cert, &encrypted_path, Some("wrong")).unwrap_err();
    assert!(wrong.to_string().contains("wrong password"), "{wrong}");
    let missing = load_certificate("a", &cert, &encrypted_path, None).unwrap_err();
    assert!(
        missing.to_string().contains("set `key_password`"),
        "{missing}"
    );
}

#[test]
fn index_prefers_exact_then_wildcard_then_default() {
    let dir = tempfile::tempdir().unwrap();
    let (c1, k1, _) = self_signed(dir.path(), "exact", &["app.example.com"]);
    let (c2, k2, _) = self_signed(dir.path(), "wild", &["*.example.com"]);
    let (c3, k3, _) = self_signed(dir.path(), "fallback", &["fallback.test"]);
    let certs = vec![
        load_certificate("exact", &c1, &k1, None).unwrap(),
        load_certificate("wild", &c2, &k2, None).unwrap(),
        load_certificate("fallback", &c3, &k3, None).unwrap(),
    ];
    let index = CertIndex::build(&certs, Some("fallback"));
    let same = |name: Option<&str>, want: usize| {
        Arc::ptr_eq(&index.lookup(name).unwrap(), &certs[want].key)
    };
    assert!(same(Some("app.example.com"), 0));
    assert!(same(Some("APP.example.com."), 0));
    assert!(same(Some("api.example.com"), 1));
    assert!(
        same(Some("deep.api.example.com"), 2),
        "wildcards cover one label"
    );
    assert!(same(None, 2));
    assert!(index.covers("api.example.com"));
    assert!(!index.covers("example.com"));
    assert!(
        CertIndex::build(&certs, None)
            .lookup(Some("nope.test"))
            .is_none()
    );
}

#[test]
fn policies_build_and_resolver_swaps() {
    let dir = tempfile::tempdir().unwrap();
    let (c, k, _) = self_signed(dir.path(), "a", &["a.test"]);
    let certs = vec![load_certificate("a", &c, &k, None).unwrap()];
    let resolver = Arc::new(SniResolver::new(CertIndex::default()));
    assert!(!resolver.index().covers("a.test"));
    resolver.swap(CertIndex::build(&certs, None));
    assert!(resolver.index().covers("a.test"));
    for policy in [TlsPolicy::Modern, TlsPolicy::Intermediate] {
        let config = server_config(policy, resolver.clone()).unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert!(config.ticketer.enabled());
    }
}
