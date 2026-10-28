//! End-to-end against Pebble, Let's Encrypt's test CA (v0.3 acceptance, ADR-0020): a route
//! with `tls: auto` gets a certificate through HTTP-01 and serves it, and a restart reuses the
//! stored certificate instead of ordering again.
//!
//! Needs Docker (Pebble runs in containers and reaches `rdock` on the host) and
//! `RDOCK_ACME_TESTS=1`; CI sets both. Skipped otherwise.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::pebble::Pebble;
use rdock_testkit::rdock::Rdock;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const HOST: &str = "app.example.com";

fn enabled() -> bool {
    let on = std::env::var("RDOCK_ACME_TESTS").is_ok_and(|v| v == "1");
    if !on {
        eprintln!("skipped: set RDOCK_ACME_TESTS=1 to run against Pebble in Docker");
    }
    on
}

/// A client trusting only the CA that Pebble issues from.
fn client_config(root_pem: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(root_pem.as_bytes()) {
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

/// The leaf certificate served for `HOST`, once a verified handshake succeeds.
async fn wait_for_certificate(
    addr: SocketAddr,
    config: &Arc<rustls::ClientConfig>,
    limit: Duration,
    rdock: &Rdock,
) -> Vec<u8> {
    let started = Instant::now();
    loop {
        if let Ok(stream) = client::tls_connect(addr, HOST, config.clone()).await {
            let leaf = stream.get_ref().1.peer_certificates().unwrap()[0].clone();
            return leaf.as_ref().to_vec();
        }
        assert!(
            started.elapsed() < limit,
            "no valid certificate for {HOST} within {limit:?}\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn issues_through_http01_serves_and_reuses_after_restart() {
    if !enabled() {
        return;
    }
    let backend = Backend::start("app").await;
    let http_port = free_port();
    let tls_port = free_port();
    let pebble = Pebble::start(http_port);
    let config = format!(
        r#"listeners:
  web: {{ address: "0.0.0.0:{http_port}" }}
  websecure: {{ address: "127.0.0.1:{tls_port}", tls: {{}} }}
acme:
  ca: "{directory}"
  ca_root: "{root}"
  challenges: [http-01]
routes:
  app: {{ match: "Host(`{HOST}`)", service: app }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        directory = pebble.directory,
        root = pebble.endpoint_root().display(),
        backend = backend.addr,
    );
    let mut rdock = Rdock::start(RDOCK, &config);
    let https: SocketAddr = format!("127.0.0.1:{tls_port}").parse().unwrap();
    let trust = client_config(&pebble.issuing_root());

    let issued = wait_for_certificate(https, &trust, Duration::from_secs(60), &rdock).await;
    let reply = client::tls(https, HOST, trust.clone(), get(HOST, "/")).await;
    assert_eq!(reply.status, 200, "{}", rdock.log());
    assert_eq!(backend.requests(), 1);
    let stored = rdock.data_dir().join("acme/certs").join(HOST);
    for file in ["cert.pem", "key.pem", "meta.json"] {
        assert!(stored.join(file).exists(), "missing {file}");
    }

    rdock.restart().unwrap();
    let reused = wait_for_certificate(https, &trust, Duration::from_secs(5), &rdock).await;
    assert_eq!(
        reused, issued,
        "the stored certificate is served after a restart"
    );
}
