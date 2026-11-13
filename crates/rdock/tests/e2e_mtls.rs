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

/// One request over TLS; `Err` when the handshake or the exchange fails (a refused client
/// certificate shows up at the first read in TLS 1.3).
async fn try_tls(
    addr: SocketAddr,
    server_name: &str,
    config: std::sync::Arc<rustls::ClientConfig>,
    req: http::Request<http_body_util::Full<bytes::Bytes>>,
) -> Result<rdock_testkit::client::Reply, ()> {
    let name = server_name.to_owned();
    tokio::spawn(async move { client::tls(addr, &name, config, req).await })
        .await
        .map_err(|_| ())
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

#[tokio::test]
#[allow(clippy::too_many_lines)] // one scenario: accepted, refused, then rotated
async fn spiffe_ids_are_checked_and_a_rotated_ca_bundle_is_picked_up() {
    let server_ca = TestCa::new();
    let old_ca = TestCa::new();
    let new_ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let site = server_ca.issue(dir.path(), "site", &["app.test"]);
    let api = old_ca.issue_svid(
        dir.path(),
        "api",
        &["spiffe://prod.example.com/ns/web/sa/api"],
        false,
    );
    let other = old_ca.issue_svid(
        dir.path(),
        "other",
        &["spiffe://prod.example.com/ns/web/sa/batch"],
        false,
    );
    let foreign = old_ca.issue_svid(
        dir.path(),
        "foreign",
        &["spiffe://staging.example.com/ns/web/sa/api"],
        false,
    );
    let two = old_ca.issue_svid(
        dir.path(),
        "two",
        &[
            "spiffe://prod.example.com/ns/web/sa/api",
            "spiffe://prod.example.com/ns/web/sa/batch",
        ],
        false,
    );
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, old_ca.pem()).unwrap();
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
  app: {{ match: "Host(`app.test`)", service: app, middlewares: [workloads] }}
middlewares:
  workloads:
    type: client_cert
    spiffe:
      trust_domains: [prod.example.com]
      ids: ["spiffe://prod.example.com/ns/web/sa/api"]
      consumer: true
    forward: xfcc
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        bundle.display(),
        site.cert.display(),
        site.key.display(),
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let call = |client: &rdock_testkit::certs::Issued| {
        let config = server_ca.client_config_with_cert(&[b"http/1.1"], client);
        client::tls(addr(port), "app.test", config, get("app.test", "/"))
    };
    let allowed = call(&api).await;
    assert_eq!(allowed.status, 200);
    let xfcc = allowed.json()["headers"]["x-forwarded-client-cert"][0]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        xfcc.contains("URI=\"spiffe://prod.example.com/ns/web/sa/api\""),
        "{xfcc}"
    );
    assert_eq!(call(&other).await.status, 403, "another ID");
    assert_eq!(call(&foreign).await.status, 403, "another trust domain");
    assert_eq!(call(&two).await.status, 403, "two URI SANs");
    let mut logged = false;
    for _ in 0..100 {
        if rdock.access_log().iter().any(|l| {
            l["consumer"] == "spiffe://prod.example.com/ns/web/sa/api"
                && l["spiffe_id"] == "spiffe://prod.example.com/ns/web/sa/api"
        }) {
            logged = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(logged, "{:?}", rdock.access_log());

    // The trust bundle rotates (as spiffe-helper or csi-driver-spiffe write it): the new CA's
    // SVID is accepted without a restart, the old CA's is not.
    let rotated = new_ca.issue_svid(
        dir.path(),
        "rotated",
        &["spiffe://prod.example.com/ns/web/sa/api"],
        false,
    );
    let tmp = dir.path().join("bundle.tmp");
    std::fs::write(&tmp, new_ca.pem()).unwrap();
    std::fs::rename(&tmp, &bundle).unwrap();
    let started = std::time::Instant::now();
    loop {
        let config = server_ca.client_config_with_cert(&[b"http/1.1"], &rotated);
        if let Ok(reply) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            try_tls(addr(port), "app.test", config, get("app.test", "/")),
        )
        .await
            && reply.is_ok_and(|r| r.status == 200)
        {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the rotated bundle was not loaded:\n{}",
            rdock.log()
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let old = server_ca.client_config_with_cert(&[b"http/1.1"], &api);
    let refused = try_tls(addr(port), "app.test", old, get("app.test", "/")).await;
    assert!(
        refused.is_err() || refused.is_ok_and(|r| r.status != 200),
        "the old CA's SVID after the rotation"
    );
}

#[tokio::test]
async fn an_upstream_client_certificate_rotates_and_a_half_written_pair_is_not_applied() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let backend_cert = ca.issue(dir.path(), "backend", &["backend.test"]);
    let first = ca.issue_svid(
        dir.path(),
        "svid",
        &["spiffe://prod.example.com/rdock"],
        false,
    );
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
    tls: {{ server_name: backend.test, ca_file: "{}", cert_file: "{}", key_file: "{}" }}
"#,
        backend.addr,
        ca_file.display(),
        first.cert.display(),
        first.key.display()
    );
    let rdock = Rdock::start(RDOCK, &config);
    assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);

    // A rotation that has written the new certificate but not yet its key.
    let next = ca.issue_svid(
        dir.path(),
        "next",
        &["spiffe://prod.example.com/rdock"],
        false,
    );
    let tmp = dir.path().join("svid.tmp");
    std::fs::write(&tmp, &next.cert_pem).unwrap();
    std::fs::rename(&tmp, &first.cert).unwrap();
    let started = std::time::Instant::now();
    while !rdock.log().contains("does not belong to the certificate") {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the mismatched pair was not noticed:\n{}",
            rdock.log()
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert_eq!(
        client::http1(addr(port), get("a", "/")).await.status,
        200,
        "the running pair stays in use"
    );
    // The key lands: the next reload applies the new pair.
    let reloads = |log: &str| log.matches("configuration applied").count();
    let before = reloads(&rdock.log());
    std::fs::write(&tmp, &next.key_pem).unwrap();
    std::fs::rename(&tmp, &first.key).unwrap();
    let started = std::time::Instant::now();
    while reloads(&rdock.log()) <= before {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the completed pair was not applied:\n{}",
            rdock.log()
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert_eq!(client::http1(addr(port), get("a", "/")).await.status, 200);
}
