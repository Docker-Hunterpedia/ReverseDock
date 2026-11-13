//! End-to-end: JA4 and JA3 TLS client fingerprints on an HTTPS listener (H-SEC-03): the header
//! to the backend (client copies removed), `ClientFingerprint` routing and the access log.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use rdock_testkit::backend::Backend;
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// The JA4 and JA3 a client with `config` sends to `server`.
fn fingerprints(config: &Arc<rustls::ClientConfig>, server: &str) -> (String, String) {
    let name = rustls_pki_types::ServerName::try_from(server.to_owned()).unwrap();
    let mut conn = rustls::ClientConnection::new(config.clone(), name).unwrap();
    let mut bytes = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut bytes).unwrap();
    }
    let facts = rdock_tls::clienthello::facts(&bytes).unwrap();
    (
        rdock_tls::fingerprint::ja4(&facts, rdock_tls::fingerprint::Transport::Tcp),
        rdock_tls::fingerprint::ja3(&facts),
    )
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn fingerprints_reach_the_backend_route_and_log() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let site = ca.issue(dir.path(), "site", &["app.test"]);
    let h2_client = ca.client_config(&[b"h2", b"http/1.1"]);
    let h1_client = ca.client_config(&[b"http/1.1"]);
    let (h2_ja4, h2_ja3) = fingerprints(&h2_client, "app.test");
    let (h1_ja4, _) = fingerprints(&h1_client, "app.test");
    assert_ne!(h2_ja4, h1_ja4, "the ALPN is part of JA4");
    let app = Backend::start("app").await;
    let known = Backend::start("known").await;
    let port = free_port();
    let plain = free_port();
    let config = format!(
        r#"
listeners:
  websecure:
    address: "127.0.0.1:{port}"
    tls:
      fingerprint: {{ ja3: true, header: X-JA4, ja3_header: X-JA3 }}
  web: {{ address: "127.0.0.1:{plain}" }}
certificates:
  site: {{ cert_file: "{}", key_file: "{}" }}
routes:
  app: {{ match: "Host(`app.test`)", service: app, priority: 1, listeners: [websecure, web] }}
  known:
    match: "Host(`app.test`) && ClientFingerprint(`{h2_ja4}`)"
    service: known
    priority: 10
services:
  app: {{ backends: [{{ address: "{}" }}] }}
  known: {{ backends: [{{ address: "{}" }}] }}
"#,
        site.cert.display(),
        site.key.display(),
        app.addr,
        known.addr,
    );
    let rdock = Rdock::start(RDOCK, &config);

    let mut spoofed = get("app.test", "/");
    spoofed.headers_mut().insert(
        "x-ja4",
        "t13d0000h2_000000000000_000000000000".parse().unwrap(),
    );
    let reply = client::tls(addr(port), "app.test", h2_client.clone(), spoofed).await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.header("x-backend"),
        Some("known"),
        "ClientFingerprint matched"
    );
    let headers = &reply.json()["headers"];
    assert_eq!(
        headers["x-ja4"][0].as_str(),
        Some(h2_ja4.as_str()),
        "{headers}"
    );
    assert_eq!(
        headers["x-ja4"].as_array().map(Vec::len),
        Some(1),
        "the client's copy is gone"
    );
    // rustls, like Chrome since 110, varies the order of its ClientHello extensions, which JA3
    // hashes: the value differs from one connection to the next, JA4 does not.
    let ja3 = headers["x-ja3"][0].as_str().unwrap().to_owned();
    assert!(
        ja3.len() == 32 && ja3.bytes().all(|b| b.is_ascii_hexdigit()),
        "{ja3}"
    );
    let _ = h2_ja3;

    let other = client::tls(addr(port), "app.test", h1_client, get("app.test", "/")).await;
    assert_eq!(other.status, 200);
    assert_eq!(
        other.header("x-backend"),
        Some("app"),
        "another fingerprint"
    );
    assert_eq!(
        other.json()["headers"]["x-ja4"][0].as_str(),
        Some(h1_ja4.as_str())
    );

    let mut logged = false;
    for _ in 0..100 {
        let lines = rdock.access_log();
        if lines.iter().any(|l| {
            l["ja4"].as_str() == Some(h2_ja4.as_str()) && l["ja3"].as_str() == Some(ja3.as_str())
        }) {
            logged = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        logged,
        "the access log carries ja4 and ja3: {:?}",
        rdock.access_log()
    );

    // L4 of the tenants review: on a listener that computes no fingerprint, a client's copy of
    // another listener's fingerprint headers is removed too.
    let mut forged = get("app.test", "/");
    forged
        .headers_mut()
        .insert("x-ja4", "forged".parse().unwrap());
    forged
        .headers_mut()
        .insert("x-ja3", "forged".parse().unwrap());
    let reply = client::http1(addr(plain), forged).await;
    assert_eq!(reply.status, 200);
    let headers = &reply.json()["headers"];
    assert!(
        headers.get("x-ja4").is_none() && headers.get("x-ja3").is_none(),
        "{headers}"
    );
}

#[tokio::test]
async fn without_the_setting_nothing_is_computed_and_the_rule_is_refused() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let site = ca.issue(dir.path(), "site", &["app.test"]);
    let config_file = dir.path().join("rdock.yaml");
    std::fs::write(
        &config_file,
        format!(
            r#"
listeners:
  websecure: {{ address: "127.0.0.1:1", tls: {{}} }}
certificates:
  site: {{ cert_file: "{}", key_file: "{}" }}
routes:
  known:
    match: "Host(`app.test`) && ClientFingerprint(`t13d1516h2_8daaf6152771_e5627efa2ab1`)"
    service: app
services:
  app: {{ backends: [{{ address: "127.0.0.1:2" }}] }}
"#,
            site.cert.display(),
            site.key.display(),
        ),
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .arg("validate")
        .arg(&config_file)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("computes fingerprints"), "{text}");

    let app = Backend::start("app").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  websecure: {{ address: "127.0.0.1:{port}", tls: {{}} }}
certificates:
  site: {{ cert_file: "{}", key_file: "{}" }}
routes:
  app: {{ match: "Host(`app.test`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        site.cert.display(),
        site.key.display(),
        app.addr,
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let mut spoofed = get("app.test", "/");
    spoofed
        .headers_mut()
        .insert("x-ja4", "forged".parse().unwrap());
    let reply = client::tls(addr(port), "app.test", ca.client_config(&[b"h2"]), spoofed).await;
    assert_eq!(reply.status, 200);
    // Without `tls.fingerprint` no header is configured, so the request passes untouched.
    assert_eq!(reply.json()["headers"]["x-ja4"][0].as_str(), Some("forged"));
}
