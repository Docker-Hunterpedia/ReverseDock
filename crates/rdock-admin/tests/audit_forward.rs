//! Audit records forwarded over TLS reach a verified server, and only a verified one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use rdock_admin::audit::{Audit, Event};
use rdock_model::settings::{AuditForward, SyslogTransport};
use rdock_testkit::certs::TestCa;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A TLS server on a free port; whatever it decrypts comes out of the receiver.
fn tls_server(ca: &TestCa, dir: &std::path::Path) -> (String, Receiver<String>) {
    let issued = ca.issue(dir, "syslog", &["localhost"]);
    let chain = CertificateDer::pem_file_iter(&issued.cert)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_file(&issued.key).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let connection = rustls::ServerConnection::new(Arc::new(config.clone())).unwrap();
            let mut tls = rustls::StreamOwned::new(connection, stream.unwrap());
            let mut buffer = [0u8; 4096];
            while let Ok(n) = tls.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let _ = tx.send(String::from_utf8_lossy(&buffer[..n]).into_owned());
            }
        }
    });
    (format!("localhost:{port}"), rx)
}

fn send_one(dir: &std::path::Path, forward: &AuditForward) -> Audit {
    let audit = Audit::open(
        &dir.join("audit"),
        1 << 20,
        Duration::from_secs(86_400),
        Some(forward),
    )
    .unwrap();
    audit.record(Event::new("root", "password", "login"));
    audit
}

#[test]
fn records_reach_a_server_signed_by_the_given_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new();
    let (syslog, received) = tls_server(&ca, dir.path());
    let forward = AuditForward {
        syslog,
        transport: SyslogTransport::Tls,
        ca_file: Some(ca.write(dir.path())),
    };
    let _audit = send_one(dir.path(), &forward);
    let message = received
        .recv_timeout(Duration::from_secs(10))
        .expect("a forwarded record");
    assert!(message.contains("rdock - audit"), "{message}");
    assert!(message.contains("login"), "{message}");
}

#[test]
fn nothing_reaches_a_server_signed_by_another_ca() {
    let dir = tempfile::tempdir().unwrap();
    let (syslog, received) = tls_server(&TestCa::new(), dir.path());
    let forward = AuditForward {
        syslog,
        transport: SyslogTransport::Tls,
        ca_file: Some(TestCa::new().write(dir.path())),
    };
    let _audit = send_one(dir.path(), &forward);
    assert!(received.recv_timeout(Duration::from_secs(2)).is_err());
}
