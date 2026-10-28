//! End-to-end against Pebble, Let's Encrypt's test CA (v0.3 acceptance, ADR-0020): a route
//! with `tls: auto` gets a certificate through HTTP-01 or TLS-ALPN-01 and serves it, and a restart reuses the
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
use rdock_testkit::pebble::{BLOCKED, Pebble};
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

/// A client that accepts any certificate, to probe what the server offers.
fn insecure_client() -> Arc<rustls::ClientConfig> {
    #[derive(Debug)]
    struct AcceptAll;
    impl rustls::client::danger::ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &rustls_pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAll))
    .with_no_client_auth();
    Arc::new(config)
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

/// The leaf certificate served for `host`, once a verified handshake succeeds.
async fn wait_for_certificate(
    addr: SocketAddr,
    host: &str,
    config: &Arc<rustls::ClientConfig>,
    rdock: &Rdock,
) -> Vec<u8> {
    let limit = Duration::from_secs(60);
    let started = Instant::now();
    loop {
        if let Ok(stream) = client::tls_connect(addr, host, config.clone()).await {
            let leaf = stream.get_ref().1.peer_certificates().unwrap()[0].clone();
            return leaf.as_ref().to_vec();
        }
        assert!(
            started.elapsed() < limit,
            "no valid certificate for {host} within {limit:?}\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A configuration ordering a certificate for `host` from `pebble` with only `challenge`.
fn config(
    pebble: &Pebble,
    ports: (u16, u16),
    challenge: &str,
    host: &str,
    backend: SocketAddr,
) -> String {
    let (http_port, tls_port) = ports;
    format!(
        r#"listeners:
  web: {{ address: "0.0.0.0:{http_port}" }}
  websecure: {{ address: "0.0.0.0:{tls_port}", tls: {{}} }}
acme:
  ca: "{directory}"
  ca_root: "{root}"
  challenges: [{challenge}]
routes:
  app: {{ match: "Host(`{host}`)", service: app }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        directory = pebble.directory,
        root = pebble.endpoint_root().display(),
    )
}

#[tokio::test]
async fn issues_through_http01_serves_and_reuses_after_restart() {
    if !enabled() {
        return;
    }
    let backend = Backend::start("app").await;
    let ports = (free_port(), free_port());
    let pebble = Pebble::start(ports.0, ports.1);
    let mut rdock = Rdock::start(
        RDOCK,
        &config(&pebble, ports, "http-01", HOST, backend.addr),
    );
    let https: SocketAddr = format!("127.0.0.1:{}", ports.1).parse().unwrap();
    let trust = client_config(&pebble.issuing_root());

    let issued = wait_for_certificate(https, HOST, &trust, &rdock).await;
    let reply = client::tls(https, HOST, trust.clone(), get(HOST, "/")).await;
    assert_eq!(reply.status, 200, "{}", rdock.log());
    assert_eq!(backend.requests(), 1);
    let stored = rdock.data_dir().join("acme/certs").join(HOST);
    for file in ["cert.pem", "key.pem", "meta.json"] {
        assert!(stored.join(file).exists(), "missing {file}");
    }

    rdock.restart().unwrap();
    let reused = wait_for_certificate(https, HOST, &trust, &rdock).await;
    assert_eq!(
        reused, issued,
        "the stored certificate is served after a restart"
    );
}

#[tokio::test]
async fn issues_through_tls_alpn01_and_hides_validation_certificates() {
    if !enabled() {
        return;
    }
    let host = "alpn.example.com";
    let backend = Backend::start("app").await;
    let ports = (free_port(), free_port());
    let pebble = Pebble::start(ports.0, ports.1);
    let rdock = Rdock::start(
        RDOCK,
        &config(&pebble, ports, "tls-alpn-01", host, backend.addr),
    );
    let https: SocketAddr = format!("127.0.0.1:{}", ports.1).parse().unwrap();
    let trust = client_config(&pebble.issuing_root());

    wait_for_certificate(https, host, &trust, &rdock).await;
    let reply = client::tls(https, host, trust.clone(), get(host, "/")).await;
    assert_eq!(reply.status, 200, "{}", rdock.log());

    // A client offering only acme-tls/1 outside a validation gets no certificate at all.
    let mut probe = (*insecure_client()).clone();
    probe.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let refused = client::tls_connect(https, host, Arc::new(probe)).await;
    assert!(
        refused.is_err(),
        "a validation handshake without a challenge must fail"
    );
}

#[tokio::test]
async fn renews_inside_the_ari_window_and_survives_a_ca_outage() {
    if !enabled() {
        return;
    }
    let host = "ari.example.com";
    let backend = Backend::start("app").await;
    let ports = (free_port(), free_port());
    let pebble = Pebble::start(ports.0, ports.1);
    let mut rdock = Rdock::start(
        RDOCK,
        &config(&pebble, ports, "http-01", host, backend.addr),
    );
    let https: SocketAddr = format!("127.0.0.1:{}", ports.1).parse().unwrap();
    let trust = client_config(&pebble.issuing_root());
    let first = wait_for_certificate(https, host, &trust, &rdock).await;

    // The CA moves the renewal window into the past: the next check renews at once.
    rdock.stop(Duration::from_secs(15));
    let stored = std::fs::read_to_string(
        rdock
            .data_dir()
            .join("acme/certs")
            .join(host)
            .join("cert.pem"),
    )
    .unwrap();
    pebble.set_renewal_window(&stored, "2020-01-01T00:00:00Z", "2020-01-02T00:00:00Z");
    rdock.restart().unwrap();
    let started = Instant::now();
    let renewed = loop {
        let leaf = wait_for_certificate(https, host, &trust, &rdock).await;
        if leaf != first {
            break leaf;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "not renewed\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert!(rdock.log().contains("certificate issued"));

    // Without the CA, a restart still serves the stored certificate.
    pebble.stop_ca();
    rdock.restart().unwrap();
    let served = wait_for_certificate(https, host, &trust, &rdock).await;
    assert_eq!(served, renewed);
}

#[tokio::test]
async fn failures_show_in_metrics_and_status() {
    if !enabled() {
        return;
    }
    let backend = Backend::start("app").await;
    let ports = (free_port(), free_port());
    let pebble = Pebble::start(ports.0, ports.1);
    let rdock = Rdock::start(
        RDOCK,
        &config(&pebble, ports, "http-01", BLOCKED, backend.addr),
    );
    let started = Instant::now();
    loop {
        let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
        if metrics.contains(&format!(
            "rdock_cert_renewal_failures_total{{name=\"{BLOCKED}\"}} 1"
        )) {
            assert!(metrics.contains("rdock_acme_orders_total"), "{metrics}");
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "no failure metric\n{metrics}\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let (status, body) = rdock.get_admin("/api/v1/status").unwrap();
    assert_eq!(status, 200);
    let status: serde_json::Value = serde_json::from_str(&body).unwrap();
    let cert = &status["certificates"][0];
    assert_eq!(cert["names"][0], BLOCKED);
    assert_eq!(cert["failures"], 1);
    assert!(
        cert["last_error"].as_str().is_some_and(|e| !e.is_empty()),
        "{cert}"
    );
}
