//! End-to-end for the local CA (ADR-0020, B-TLS-13): a `tls: auto` route for a private name
//! is served with a certificate that chains to `$RDOCK_DATA_DIR/pki/root.pem`, without any
//! network access or configured certificate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const HOST: &str = "app.localhost";

/// A client trusting only the local CA's root, once rdock has written it.
async fn trusting_root(rdock: &Rdock) -> Arc<rustls::ClientConfig> {
    let path = rdock.data_dir().join("pki/root.pem");
    let started = Instant::now();
    let pem = loop {
        if let Ok(pem) = std::fs::read(&path) {
            break pem;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no {}\n{}",
            path.display(),
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

#[tokio::test]
async fn serves_a_private_name_with_a_local_ca_certificate() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(
        RDOCK,
        &format!(
            r#"listeners:
  websecure: {{ address: "127.0.0.1:{port}", tls: {{}} }}
routes:
  app: {{ match: "Host(`{HOST}`)", service: app }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
            backend = backend.addr
        ),
    );
    let https: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let trust = trusting_root(&rdock).await;

    let started = Instant::now();
    let stream = loop {
        if let Ok(stream) = client::tls_connect(https, HOST, trust.clone()).await {
            break stream;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no certificate for {HOST} chaining to the local root\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let chain = stream.get_ref().1.peer_certificates().unwrap().len();
    assert_eq!(chain, 2, "leaf and intermediate are served");
    drop(stream);

    let reply = client::tls(https, HOST, trust, get(HOST, "/")).await;
    assert_eq!(reply.status, 200, "{}", rdock.log());
    assert_eq!(backend.requests(), 1);
    assert!(
        !rdock.log().contains("public certificate authorities"),
        "private names are no longer warned about\n{}",
        rdock.log()
    );
}
