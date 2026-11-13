//! End-to-end: GeoIP matchers on the client address the trusted-proxy logic computes, the
//! opt-in access-log fields, a database replaced on disk, and a missing database refused
//! (H-SEC-04). Fixtures are generated with `rdock_testkit::mmdb`; no database is vendored.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::mmdb;
use rdock_testkit::rdock::Rdock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn write_db(path: &Path, gb_is: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(
        &tmp,
        mmdb::build(
            "GeoLite2-Country",
            mmdb::days_ago(1),
            &[
                (ip("81.2.69.0"), 24, mmdb::country(gb_is, "EU")),
                (ip("89.160.20.0"), 24, mmdb::country("SE", "EU")),
            ],
        ),
    )
    .unwrap();
    std::fs::rename(tmp, path).unwrap();
}

async fn backend_for(port: u16, forwarded_for: Option<&str>) -> String {
    let mut req = get("geo.test", "/");
    if let Some(xff) = forwarded_for {
        req.headers_mut()
            .insert("x-forwarded-for", xff.parse().unwrap());
    }
    let reply = client::http1(addr(port), req).await;
    assert_eq!(reply.status, 200);
    reply.header("x-backend").unwrap().to_owned()
}

/// A request from 127.0.0.2, which is not a trusted proxy.
async fn from_untrusted(port: u16, forwarded_for: &str) -> String {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::from(([127, 0, 0, 2], 0))).unwrap();
    let mut stream = socket.connect(addr(port)).await.unwrap();
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: geo.test\r\nX-Forwarded-For: {forwarded_for}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).await.unwrap();
    out.lines()
        .find_map(|l| l.strip_prefix("x-backend: "))
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn country_rules_follow_the_resolved_client_and_a_new_database() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("country.mmdb");
    write_db(&db, "GB");
    let uk = Backend::start("uk").await;
    let rest = Backend::start("rest").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
security: {{ trusted_proxies: ["127.0.0.1/32"] }}
geoip:
  database: "{}"
  log: {{ country: true }}
routes:
  uk: {{ match: "Host(`geo.test`) && ClientCountry(`GB`)", service: uk, priority: 10 }}
  rest: {{ match: "Host(`geo.test`)", service: rest, priority: 1 }}
services:
  uk: {{ backends: [{{ address: "{}" }}] }}
  rest: {{ backends: [{{ address: "{}" }}] }}
"#,
        db.display(),
        uk.addr,
        rest.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    assert_eq!(backend_for(port, Some("81.2.69.142")).await, "uk");
    assert_eq!(backend_for(port, Some("89.160.20.112")).await, "rest");
    assert_eq!(backend_for(port, None).await, "rest", "loopback is unknown");
    assert_eq!(
        backend_for(port, Some("8.8.4.4")).await,
        "rest",
        "not in the database"
    );
    // An untrusted peer's X-Forwarded-For is ignored: the client is the peer, 127.0.0.2.
    assert_eq!(from_untrusted(port, "81.2.69.142").await, "rest");

    let mut logged = false;
    for _ in 0..100 {
        if rdock
            .access_log()
            .iter()
            .any(|l| l["country"].as_str() == Some("GB") && l["client_ip"] == "81.2.69.142")
        {
            logged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(logged, "{:?}", rdock.access_log());
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(
        metrics.contains("rdock_geoip_database_age_seconds{database=\"country\"}"),
        "{metrics}"
    );

    // A new release of the database is picked up without a restart.
    write_db(&db, "IE");
    let started = Instant::now();
    while backend_for(port, Some("81.2.69.142")).await != "rest" {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the new database was not loaded:\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[test]
fn a_geo_rule_without_a_database_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    std::fs::write(
        &file,
        "routes:\n  r: { match: \"Host(`a.test`) && !ClientCountry(`DE`)\", service: s }\nservices:\n  s: { backends: [{ address: \"127.0.0.1:1\" }] }\n",
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .arg("validate")
        .arg(&file)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("needs a GeoIP database"), "{text}");
}
