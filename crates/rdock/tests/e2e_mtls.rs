//! End-to-end: client certificates on listeners and routes, and towards backends (M-TLS-01).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use rdock_testkit::backend::Backend;
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn a_required_client_certificate_is_verified() {
    let server_ca = TestCa::new();
    let client_ca = TestCa::new();
    let stranger_ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let site = server_ca.issue(dir.path(), "site", &["app.test"]);
    let client = client_ca.issue(dir.path(), "client", &["billing.clients.test"]);
    let stranger = stranger_ca.issue(dir.path(), "stranger", &["billing.clients.test"]);
    let client_ca_file = dir.path().join("clients.pem");
    std::fs::write(&client_ca_file, client_ca.pem()).unwrap();
    let backend = Backend::start("app").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  websecure:
    address: "127.0.0.1:{port}"
    tls: {{ client_auth: {{ mode: required, ca_files: ["{}"] }} }}
certificates:
  site: {{ cert_file: "{}", key_file: "{}" }}
routes:
  app: {{ match: "Host(`app.test`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        client_ca_file.display(),
        site.cert.display(),
        site.key.display(),
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let anonymous = server_ca.client_config(&[b"http/1.1"]);
    let refused = client::tls_connect(addr(port), "app.test", anonymous).await;
    // TLS 1.3 reports the refusal on the first read; either way no request gets through.
    if let Ok(stream) = refused {
        let mut stream = stream;
        let mut buf = [0u8; 1];
        let read = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        assert!(
            read.is_err() || read.unwrap() == 0,
            "a connection without a certificate"
        );
    }
    let wrong = server_ca.client_config_with_cert(&[b"http/1.1"], &stranger);
    let wrong = client::tls_connect(addr(port), "app.test", wrong).await;
    if let Ok(mut stream) = wrong {
        let mut buf = [0u8; 1];
        let read = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        assert!(
            read.is_err() || read.unwrap() == 0,
            "a certificate from another CA"
        );
    }
    let good = server_ca.client_config_with_cert(&[b"h2"], &client);
    let reply = client::tls(addr(port), "app.test", good, get("app.test", "/")).await;
    assert_eq!(reply.status, 200);
}

#[tokio::test]
async fn optional_listeners_let_routes_decide_and_forward_the_identity() {
    let server_ca = TestCa::new();
    let client_ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let site = server_ca.issue(dir.path(), "site", &["app.test"]);
    let billing = client_ca.issue(dir.path(), "billing", &["billing.clients.test"]);
    let other = client_ca.issue(dir.path(), "other", &["other.partners.test"]);
    let client_ca_file = dir.path().join("clients.pem");
    std::fs::write(&client_ca_file, client_ca.pem()).unwrap();
    let backend = Backend::start("app").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  websecure:
    address: "127.0.0.1:{port}"
    tls: {{ client_auth: {{ mode: optional, ca_files: ["{}"] }} }}
certificates:
  site: {{ cert_file: "{}", key_file: "{}" }}
routes:
  public: {{ match: "Host(`app.test`)", service: app }}
  private:
    match: "Host(`app.test`) && PathPrefix(`/private`)"
    service: app
    middlewares: [clients]
middlewares:
  clients:
    type: client_cert
    allow: ["*.clients.test"]
    forward: xfcc
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        client_ca_file.display(),
        site.cert.display(),
        site.key.display(),
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let anonymous = server_ca.client_config(&[b"http/1.1"]);
    let mut spoofed = get("app.test", "/");
    spoofed
        .headers_mut()
        .insert("x-forwarded-client-cert", "Hash=forged".parse().unwrap());
    let public = client::tls(addr(port), "app.test", anonymous.clone(), spoofed).await;
    assert_eq!(public.status, 200, "no certificate needed outside /private");
    assert!(
        public.json()["headers"]
            .get("x-forwarded-client-cert")
            .is_none(),
        "a client cannot send its own identity header"
    );
    let private = client::tls(
        addr(port),
        "app.test",
        anonymous,
        get("app.test", "/private"),
    )
    .await;
    assert_eq!(private.status, 403);

    let partner = server_ca.client_config_with_cert(&[b"http/1.1"], &other);
    let refused = client::tls(addr(port), "app.test", partner, get("app.test", "/private")).await;
    assert_eq!(
        refused.status, 403,
        "a valid certificate with a name not allowed"
    );

    let allowed = server_ca.client_config_with_cert(&[b"http/1.1"], &billing);
    let reply = client::tls(addr(port), "app.test", allowed, get("app.test", "/private")).await;
    assert_eq!(reply.status, 200);
    let xfcc = reply.json()["headers"]["x-forwarded-client-cert"][0]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(xfcc.starts_with("Hash="), "{xfcc}");
    assert!(xfcc.contains("DNS=\"billing.clients.test\""), "{xfcc}");
}

#[tokio::test]
async fn services_present_a_client_certificate_to_backends() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let backend_cert = ca.issue(dir.path(), "backend", &["backend.test"]);
    let rdock_cert = ca.issue(dir.path(), "rdock", &["rdock.clients.test"]);
    let ca_file = ca.write(dir.path());
    let backend = Backend::start_mtls(
        "secure",
        &backend_cert.cert_pem,
        &backend_cert.key_pem,
        &ca.pem(),
    )
    .await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: secure }}
services:
  secure:
    scheme: https
    backends: [{{ address: "{}" }}]
    tls:
      server_name: backend.test
      ca_file: "{}"
      cert_file: "{}"
      key_file: "{}"
"#,
        backend.addr,
        ca_file.display(),
        rdock_cert.cert.display(),
        rdock_cert.key.display()
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let reply = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(reply.header("x-backend"), Some("secure"));
}

#[test]
fn validate_refuses_client_auth_without_roots() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    std::fs::write(
        &file,
        "listeners:\n  websecure: { address: \":8443\", tls: { client_auth: { mode: required } } }\nroutes:\n  app: { match: \"Host(`a.test`)\", service: app }\nservices:\n  app: { backends: [{ address: \"127.0.0.1:1\" }] }\n",
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .arg("validate")
        .arg(&file)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("listeners.websecure.tls.client_auth"),
        "{text}"
    );
}
