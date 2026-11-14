//! End-to-end: TLS session resumption shared by the listeners of one security class, kept
//! across reloads, and never across client-authentication settings (H-PERF-02, ADR-0031).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rdock_testkit::backend::Backend;
use rdock_testkit::certs::{Issued, TestCa};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rustls::HandshakeKind;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

/// One request over a new TLS connection to `port`; how the handshake went. Reading the whole
/// answer also takes in the session tickets the server sends after the handshake.
fn handshake(port: u16, config: &Arc<rustls::ClientConfig>) -> HandshakeKind {
    let mut conn =
        rustls::ClientConnection::new(config.clone(), "app.test".try_into().unwrap()).unwrap();
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut socket);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer);
    assert!(
        answer.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    conn.handshake_kind().unwrap()
}

fn certificates(cert: &Issued) -> String {
    format!(
        "certificates:\n  app: {{ cert_file: \"{}\", key_file: \"{}\" }}\n",
        cert.cert.display(),
        cert.key.display()
    )
}

fn routes(backend: std::net::SocketAddr, listeners: &str) -> String {
    format!(
        r#"
defaults: {{ tls: off }}
routes:
  app: {{ match: "Host(`app.test`)", service: app, listeners: [{listeners}], tls: {{ certificate: app }} }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumption_crosses_listeners_of_one_class_and_survives_a_reload() {
    let backend = Backend::start("app").await;
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "app", &["app.test"]);
    let (a, b, moved) = (free_port(), free_port(), free_port());
    let config = |b_port: u16| {
        format!(
            "listeners:\n  a: {{ address: \"127.0.0.1:{a}\", tls: {{}} }}\n  b: {{ address: \"127.0.0.1:{b_port}\", tls: {{}} }}\n{}{}",
            certificates(&cert),
            routes(backend.addr, "a, b")
        )
    };
    let rdock = Rdock::start(RDOCK, &config(b));
    let client = ca.client_config(&[b"http/1.1"]);
    assert_eq!(handshake(a, &client), HandshakeKind::Full);
    assert_eq!(
        handshake(b, &client),
        HandshakeKind::Resumed,
        "a ticket from listener a resumes on listener b"
    );

    // Moving listener b builds a new socket and a new TLS acceptor; the class keeps its keys.
    rdock.write_config(&config(moved));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let fresh = ca.client_config(&[b"http/1.1"]);
    assert_eq!(handshake(a, &fresh), HandshakeKind::Full);
    assert_eq!(
        handshake(moved, &fresh),
        HandshakeKind::Resumed,
        "the rebuilt acceptor uses the class's keys"
    );
}

/// The attack rustls warns about: a session started on a listener without client
/// authentication must not resume on one that requires a client certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_without_client_authentication_never_resumes_where_it_is_required() {
    let backend = Backend::start("app").await;
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "app", &["app.test"]);
    let client_cert = ca.issue(dir.path(), "client", &["client.test"]);
    let ca_file = ca.write(dir.path());
    let (open, mtls, mtls2) = (free_port(), free_port(), free_port());
    let auth = format!(
        "{{ client_auth: {{ mode: required, ca_files: [\"{}\"] }} }}",
        ca_file.display()
    );
    let config = format!(
        "listeners:\n  open: {{ address: \"127.0.0.1:{open}\", tls: {{}} }}\n  mtls: {{ address: \"127.0.0.1:{mtls}\", tls: {auth} }}\n  mtls2: {{ address: \"127.0.0.1:{mtls2}\", tls: {auth} }}\n{}{}",
        certificates(&cert),
        routes(backend.addr, "open, mtls, mtls2")
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let client = ca.client_config_with_cert(&[b"http/1.1"], &client_cert);
    assert_eq!(handshake(open, &client), HandshakeKind::Full);
    assert_eq!(
        handshake(mtls, &client),
        HandshakeKind::Full,
        "the ticket from the listener without client authentication is not accepted"
    );
    // Two listeners with the same client-authentication settings do share.
    assert_eq!(handshake(mtls2, &client), HandshakeKind::Resumed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tickets_off_issues_no_tickets() {
    let backend = Backend::start("app").await;
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "app", &["app.test"]);
    let port = free_port();
    let config = format!(
        "listeners:\n  a: {{ address: \"127.0.0.1:{port}\", tls: {{ policy: modern, tickets: {{ enabled: false }} }} }}\n{}{}",
        certificates(&cert),
        routes(backend.addr, "a")
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let client = ca.client_config(&[b"http/1.1"]);
    assert_eq!(handshake(port, &client), HandshakeKind::Full);
    assert_eq!(
        handshake(port, &client),
        HandshakeKind::Full,
        "TLS 1.3 without tickets cannot resume"
    );
}

/// Keys from a key file: two processes reading the same file accept each other's tickets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instances_with_one_key_file_accept_each_others_tickets() {
    use base64::Engine as _;
    let backend = Backend::start("app").await;
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "app", &["app.test"]);
    let keys = dir.path().join("ticket.keys");
    std::fs::write(
        &keys,
        format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode([9u8; 32])
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = |port: u16| {
        format!(
            "listeners:\n  a: {{ address: \"127.0.0.1:{port}\", tls: {{ tickets: {{ key_file: \"{}\" }} }} }}\n{}{}",
            keys.display(),
            certificates(&cert),
            routes(backend.addr, "a")
        )
    };
    let (one, two) = (free_port(), free_port());
    let _first = Rdock::start(RDOCK, &config(one));
    let _second = Rdock::start(RDOCK, &config(two));
    let client = ca.client_config(&[b"http/1.1"]);
    assert_eq!(handshake(one, &client), HandshakeKind::Full);
    assert_eq!(handshake(two, &client), HandshakeKind::Resumed);

    // A key file other users may read is refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = Rdock::try_start(RDOCK, &config(free_port()));
        let log = refused.err().expect("refused");
        assert!(log.contains("chmod 600"), "{log}");
    }
}
