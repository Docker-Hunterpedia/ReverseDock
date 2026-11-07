//! End-to-end: TCP listeners and routes through the real binary (M-L4-01, M-L4-02, outbound
//! M-L4-03, ADR-0026).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::certs::{Issued, TestCa};
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::proxy_protocol as pp;
use rdock_testkit::rdock::Rdock;
use rdock_testkit::tcp::{EOF_REPLY, EchoBackend};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// The value of one sample in rdock's metrics, `0` when absent.
fn metric(rdock: &Rdock, series: &str) -> String {
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    metrics
        .lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' ').map(str::to_owned))
        .unwrap_or_else(|| "0".to_owned())
}

fn rejected(rdock: &Rdock, listener: &str, reason: &str) -> String {
    metric(
        rdock,
        &format!("rdock_tcp_rejected_total{{listener=\"{listener}\",reason=\"{reason}\"}}"),
    )
}

fn der(issued: &Issued) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(issued.cert_pem.as_bytes()).unwrap()
}

/// `certificates:` with one entry.
fn certificate(name: &str, issued: &Issued) -> String {
    format!(
        "certificates:\n  {name}: {{ cert_file: \"{}\", key_file: \"{}\" }}\n",
        issued.cert.display(),
        issued.key.display()
    )
}

/// Writes `bytes` and reads exactly as many back.
async fn echo<S: AsyncReadExt + AsyncWriteExt + Unpin>(stream: &mut S, bytes: &[u8]) -> Vec<u8> {
    stream.write_all(bytes).await.unwrap();
    let mut back = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("echo in time")
        .unwrap();
    back
}

/// Reads until the server closes; `None` if it is still open after `wait`.
async fn read_to_close<S: AsyncReadExt + Unpin>(stream: &mut S, wait: Duration) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let read = tokio::time::timeout(wait, async {
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    read.is_ok().then_some(out)
}

#[tokio::test]
async fn passthrough_routes_by_server_name_to_the_backends_own_tls() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let a = ca.issue(dir.path(), "a", &["a.test"]);
    let b = ca.issue(dir.path(), "b", &["b.test"]);
    let backend_a = Backend::start_tls("a", &a.cert_pem, &a.key_pem).await;
    let backend_b = Backend::start_tls("b", &b.cert_pem, &b.key_pem).await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  edge: {{ address: "127.0.0.1:{port}", protocol: tcp }}
tcp_routes:
  a: {{ match: "HostSNI(`a.test`)", listeners: [edge], service: a, tls: {{ passthrough: true }} }}
  b: {{ match: "HostSNI(`*.test`)", listeners: [edge], service: b, tls: {{ passthrough: true }} }}
tcp_services:
  a: {{ backends: [{{ address: "{}" }}] }}
  b: {{ backends: [{{ address: "{}" }}] }}
"#,
        backend_a.addr, backend_b.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let tls = ca.client_config(&[b"h2", b"http/1.1"]);
    for (name, backend) in [("a.test", "a"), ("b.test", "b")] {
        let reply = client::tls(addr(port), name, tls.clone(), get(name, "/")).await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.json()["backend"], backend, "{name}");
    }
    // The client talks TLS with the backend itself: its certificate, its ALPN choice.
    let stream = client::tls_connect(addr(port), "a.test", tls.clone())
        .await
        .unwrap();
    let session = stream.get_ref().1;
    assert_eq!(session.peer_certificates().unwrap()[0], der(&a));
    assert_eq!(session.alpn_protocol(), Some(b"h2".as_slice()));
    assert_eq!(
        metric(
            &rdock,
            "rdock_tcp_connections{listener=\"edge\",route=\"a\"}"
        ),
        "1"
    );
    drop(stream);
    // A name no route matches is closed: `*.test` is one label deep.
    assert!(
        client::tls_connect(addr(port), "x.b.test", tls)
            .await
            .is_err()
    );
    assert_eq!(rejected(&rdock, "edge", "no_route"), "1");
    let started = Instant::now();
    while metric(
        &rdock,
        "rdock_tcp_connections{listener=\"edge\",route=\"a\"}",
    ) != "0"
    {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "closed relays are not counted"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn an_https_listener_shares_its_port_with_passthrough_routes() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let app_cert = ca.issue(dir.path(), "app", &["app.test"]);
    let db_cert = ca.issue(dir.path(), "db", &["db.test"]);
    let app = Backend::start("app").await;
    let db = Backend::start_tls("db", &db_cert.cert_pem, &db_cert.key_pem).await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  websecure: {{ address: "127.0.0.1:{port}", tls: {{}} }}
{}
routes:
  app: {{ match: "Host(`app.test`)", service: app }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
tcp_routes:
  db: {{ match: "HostSNI(`db.test`)", listeners: [websecure], service: db, tls: {{ passthrough: true }} }}
tcp_services:
  db: {{ backends: [{{ address: "{}" }}] }}
"#,
        certificate("app", &app_cert),
        app.addr,
        db.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let tls = ca.client_config(&[b"http/1.1"]);
    let reply = client::tls(addr(port), "app.test", tls.clone(), get("app.test", "/")).await;
    assert_eq!(reply.json()["backend"], "app", "HTTP routes keep working");
    let reply = client::tls(addr(port), "db.test", tls.clone(), get("db.test", "/")).await;
    assert_eq!(reply.json()["backend"], "db");
    let stream = client::tls_connect(addr(port), "db.test", tls)
        .await
        .unwrap();
    assert_eq!(
        stream.get_ref().1.peer_certificates().unwrap()[0],
        der(&db_cert)
    );
}

#[tokio::test]
async fn termination_serves_rdocks_certificate_and_relays_plaintext() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "term", &["term.test"]);
    let backend = EchoBackend::start().await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  edge: {{ address: "127.0.0.1:{port}", protocol: tcp, tls: {{}} }}
{}
tcp_routes:
  term: {{ match: "HostSNI(`term.test`)", listeners: [edge], service: echo, tls: {{}} }}
tcp_services:
  echo: {{ backends: [{{ address: "{}" }}] }}
"#,
        certificate("term", &cert),
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let mut stream = client::tls_connect(addr(port), "term.test", ca.client_config(&[b"mqtt"]))
        .await
        .unwrap();
    let session = stream.get_ref().1;
    assert_eq!(session.peer_certificates().unwrap()[0], der(&cert));
    assert_eq!(
        session.alpn_protocol(),
        Some(b"mqtt".as_slice()),
        "the client's own protocol"
    );
    // The echo backend speaks plaintext: an encrypted relay would garble this.
    assert_eq!(echo(&mut stream, b"hello").await, b"hello");
    assert_eq!(
        metric(
            &rdock,
            "rdock_tcp_connections{listener=\"edge\",route=\"term\"}"
        ),
        "1"
    );
    drop(stream);
    let bytes_in = metric(
        &rdock,
        "rdock_tcp_bytes_total{direction=\"in\",route=\"term\"}",
    );
    assert_eq!(bytes_in, "5");
}

#[tokio::test]
async fn host_sni_star_relays_bytes_that_are_not_tls() {
    let backend = EchoBackend::start().await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  edge: {{ address: "127.0.0.1:{port}", protocol: tcp }}
tcp_routes:
  any: {{ match: "HostSNI(`*`)", listeners: [edge], service: echo }}
tcp_services:
  echo: {{ backends: [{{ address: "{}" }}] }}
"#,
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let mut stream = TcpStream::connect(addr(port)).await.unwrap();
    assert_eq!(
        echo(&mut stream, b"GET / HTTP/1.1\r\n\r\n").await,
        b"GET / HTTP/1.1\r\n\r\n"
    );
    // A half-close reaches the backend, and its answer still comes back.
    stream.write_all(b"bye").await.unwrap();
    stream.shutdown().await.unwrap();
    let rest = read_to_close(&mut stream, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(rest, [b"bye".as_slice(), EOF_REPLY].concat());
}

#[tokio::test]
async fn a_server_that_speaks_first_is_relayed_without_waiting_for_the_client() {
    // A MySQL-like backend greets first; no route reads the ClientHello, so nothing waits for
    // the client before connecting.
    let greeter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let greeter_addr = greeter.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = greeter.accept().await {
            let _ = stream.write_all(b"220 ready\r\n").await;
        }
    });
    let port = free_port();
    let config = format!(
        r#"
listeners:
  edge: {{ address: "127.0.0.1:{port}", protocol: tcp }}
tcp_routes:
  any: {{ match: "HostSNI(`*`)", listeners: [edge], service: smtp }}
tcp_services:
  smtp: {{ backends: [{{ address: "{greeter_addr}" }}] }}
"#
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let mut stream = TcpStream::connect(addr(port)).await.unwrap();
    let mut greeting = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut greeting))
        .await
        .expect("greeting before the client sent anything")
        .unwrap();
    assert_eq!(&greeting, b"220 ready\r\n");
}

#[tokio::test]
async fn outbound_proxy_protocol_names_the_client_in_v1_and_v2() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "term", &["term.test"]);
    let backend = EchoBackend::start_proxy_protocol().await;
    let (plain, terminated) = (free_port(), free_port());
    let config = format!(
        r#"
listeners:
  plain: {{ address: "127.0.0.1:{plain}", protocol: tcp }}
  terminated: {{ address: "127.0.0.1:{terminated}", protocol: tcp, tls: {{}} }}
{}
tcp_routes:
  plain: {{ match: "HostSNI(`*`)", listeners: [plain], service: v1 }}
  terminated: {{ match: "HostSNI(`term.test`)", listeners: [terminated], service: v2, tls: {{}} }}
tcp_services:
  v1: {{ backends: [{{ address: "{addr}" }}], proxy_protocol: v1 }}
  v2: {{ backends: [{{ address: "{addr}" }}], proxy_protocol: v2 }}
"#,
        certificate("term", &cert),
        addr = backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let mut stream = TcpStream::connect(addr(plain)).await.unwrap();
    let client_v1 = stream.local_addr().unwrap();
    assert_eq!(echo(&mut stream, b"one").await, b"one");

    let tcp = TcpStream::connect(addr(terminated)).await.unwrap();
    let client_v2 = tcp.local_addr().unwrap();
    let config = ca.client_config(&[b"x-test"]);
    let mut tls = client::tls_on(tcp, "term.test", config).await.unwrap();
    assert_eq!(echo(&mut tls, b"two").await, b"two");

    let headers = backend.headers();
    assert_eq!(headers.len(), 2, "{headers:?}");
    assert_eq!(
        (headers[0].version, headers[0].source),
        (1, Some(client_v1))
    );
    let v2 = &headers[1];
    assert_eq!((v2.version, v2.source), (2, Some(client_v2)));
    assert_eq!(v2.alpn.as_deref(), Some(b"x-test".as_slice()));
    assert_eq!(v2.authority.as_deref(), Some("term.test"));
    assert_eq!(v2.ssl_version.as_deref(), Some("TLSv1.3"));
}

#[tokio::test]
async fn inbound_proxy_protocol_and_ip_deny_judge_the_original_client() {
    let backend = EchoBackend::start_proxy_protocol().await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  edge: {{ address: "127.0.0.1:{port}", protocol: tcp, proxy_protocol: {{ trusted: [127.0.0.0/8], optional: true }} }}
tcp_routes:
  any: {{ match: "HostSNI(`*`)", listeners: [edge], service: echo, middlewares: [deny] }}
tcp_services:
  echo: {{ backends: [{{ address: "{}" }}], proxy_protocol: v1 }}
middlewares:
  deny: {{ type: ip_deny, cidrs: [198.51.100.0/24] }}
"#,
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let allowed: SocketAddr = "203.0.113.7:51234".parse().unwrap();
    let mut stream = client::connect_sending(addr(port), &pp::v2(allowed, addr(port))).await;
    assert_eq!(echo(&mut stream, b"hi").await, b"hi");
    assert_eq!(backend.headers()[0].source, Some(allowed));

    let denied: SocketAddr = "198.51.100.9:1000".parse().unwrap();
    let sent = [pp::v1(denied, addr(port)).as_slice(), b"hi"].concat();
    let answer = client::raw(addr(port), &sent, Duration::from_secs(3)).await;
    assert_eq!(answer, b"", "closed without relaying");
    assert_eq!(rejected(&rdock, "edge", "denied"), "1");
    assert_eq!(backend.connections(), 1);
}

#[tokio::test]
async fn in_flight_limits_connections_per_client() {
    let backend = EchoBackend::start().await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  edge: {{ address: "127.0.0.1:{port}", protocol: tcp }}
tcp_routes:
  any: {{ match: "HostSNI(`*`)", listeners: [edge], service: echo, middlewares: [one] }}
tcp_services:
  echo: {{ backends: [{{ address: "{}" }}] }}
middlewares:
  one: {{ type: in_flight, amount: 1 }}
"#,
        backend.addr
    );
    let rdock = Rdock::start(RDOCK, &config);
    let mut first = TcpStream::connect(addr(port)).await.unwrap();
    assert_eq!(echo(&mut first, b"a").await, b"a");
    let answer = client::raw(addr(port), b"b", Duration::from_secs(3)).await;
    assert_eq!(
        answer, b"",
        "a second connection from the same client is closed"
    );
    assert_eq!(rejected(&rdock, "edge", "in_flight"), "1");
    drop(first);
    let started = Instant::now();
    loop {
        let mut again = TcpStream::connect(addr(port)).await.unwrap();
        again.write_all(b"c").await.unwrap();
        let mut one = [0u8; 1];
        if matches!(again.read(&mut one).await, Ok(1)) {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the slot is freed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn an_idle_relay_is_closed() {
    let backend = EchoBackend::start().await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  edge: {{ address: "127.0.0.1:{port}", protocol: tcp }}
tcp_routes:
  any: {{ match: "HostSNI(`*`)", listeners: [edge], service: echo }}
tcp_services:
  echo: {{ backends: [{{ address: "{}" }}], timeouts: {{ idle: 400ms }} }}
"#,
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let mut stream = TcpStream::connect(addr(port)).await.unwrap();
    assert_eq!(echo(&mut stream, b"x").await, b"x");
    let quiet = Instant::now();
    let rest = read_to_close(&mut stream, Duration::from_secs(5)).await;
    assert_eq!(rest, Some(Vec::new()), "closed, with nothing more sent");
    assert!(
        quiet.elapsed() >= Duration::from_millis(350),
        "{:?}",
        quiet.elapsed()
    );
}

#[tokio::test]
async fn starttls_postgres_answers_the_ssl_request_before_routing_by_name() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "db", &["db.test"]);
    let backend = EchoBackend::start().await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  pg: {{ address: "127.0.0.1:{port}", protocol: tcp, tls: {{}}, starttls: postgres }}
{}
tcp_routes:
  db: {{ match: "HostSNI(`db.test`) && ALPN(`postgresql`)", listeners: [pg], service: echo, tls: {{}} }}
tcp_services:
  echo: {{ backends: [{{ address: "{}" }}] }}
"#,
        certificate("db", &cert),
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let mut tcp = TcpStream::connect(addr(port)).await.unwrap();
    tcp.write_all(&SSL_REQUEST).await.unwrap();
    let mut answer = [0u8; 1];
    tcp.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"S");
    let config = ca.client_config(&[b"postgresql"]);
    let mut tls = client::tls_on(tcp, "db.test", config.clone())
        .await
        .unwrap();
    assert_eq!(echo(&mut tls, b"startup").await, b"startup");
    // `sslnegotiation=direct`: the ClientHello comes first, on the same listener.
    let mut direct = client::tls_connect(addr(port), "db.test", config)
        .await
        .unwrap();
    assert_eq!(echo(&mut direct, b"direct").await, b"direct");
}

#[tokio::test]
async fn a_reload_keeps_open_relays_and_new_connections_follow_it() {
    let one = EchoBackend::start().await;
    let two = EchoBackend::start().await;
    let port = free_port();
    let config = |backend: SocketAddr| {
        format!(
            r#"
listeners:
  edge: {{ address: "127.0.0.1:{port}", protocol: tcp }}
tcp_routes:
  any: {{ match: "HostSNI(`*`)", listeners: [edge], service: echo }}
tcp_services:
  echo: {{ backends: [{{ address: "{backend}" }}] }}
"#
        )
    };
    let rdock = Rdock::start(RDOCK, &config(one.addr));
    let mut open = TcpStream::connect(addr(port)).await.unwrap();
    assert_eq!(echo(&mut open, b"before").await, b"before");
    rdock.write_config(&config(two.addr));
    let (status, body) = rdock.reload();
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        echo(&mut open, b"after").await,
        b"after",
        "the relay survives"
    );
    let mut fresh = TcpStream::connect(addr(port)).await.unwrap();
    assert_eq!(echo(&mut fresh, b"new").await, b"new");
    assert_eq!((one.connections(), two.connections()), (1, 1));
}

fn docker_tests() -> bool {
    let enabled = std::env::var("RDOCK_DOCKER_TESTS").is_ok_and(|v| v == "1");
    if !enabled {
        eprintln!("skipped: set RDOCK_DOCKER_TESTS=1 (needs Docker)");
    }
    enabled
}

/// `psql … -tAc` through rdock; the output, or the error text.
fn psql(port: u16, options: &str, sql: &str) -> Result<String, String> {
    let conninfo = format!("host=db.test port={port} user=postgres dbname=postgres {options}");
    let out = rdock_testkit::postgres::psql("db.test", &conninfo, sql);
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// PostgreSQL 17 by server name, passthrough and termination, with `sslnegotiation=direct`
/// and with `starttls: postgres` (ADR-0026's acceptance test). Needs Docker and
/// `RDOCK_DOCKER_TESTS=1`, as in CI.
#[tokio::test]
async fn postgres_17_through_tcp_routes() {
    if !docker_tests() {
        return;
    }
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "db", &["db.test"]);
    let server_cert = ca.issue(dir.path(), "server", &["db.test"]);
    let postgres = rdock_testkit::postgres::Postgres::start(&server_cert);
    let (direct, starttls, terminated) = (free_port(), free_port(), free_port());
    let backend = format!("127.0.0.1:{}", postgres.port);
    // psql runs in a container and reaches rdock through the Docker host.
    let config = format!(
        r#"
listeners:
  direct: {{ address: ":{direct}", protocol: tcp }}
  starttls: {{ address: ":{starttls}", protocol: tcp, starttls: postgres }}
  terminated: {{ address: ":{terminated}", protocol: tcp, tls: {{}} }}
{}
tcp_routes:
  passthrough: {{ match: "HostSNI(`db.test`)", listeners: [direct, starttls], service: db, tls: {{ passthrough: true }} }}
  terminated: {{ match: "HostSNI(`db.test`)", listeners: [terminated], service: db, tls: {{}} }}
tcp_services:
  db: {{ backends: [{{ address: "{backend}" }}] }}
"#,
        certificate("db", &cert)
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let ssl = "select ssl from pg_stat_ssl where pid = pg_backend_pid()";
    let direct_tls = "sslmode=require sslnegotiation=direct";
    assert_eq!(
        psql(direct, direct_tls, ssl),
        Ok("t".to_owned()),
        "passthrough: TLS to the server"
    );
    assert_eq!(
        psql(starttls, "sslmode=require", ssl),
        Ok("t".to_owned()),
        "starttls: postgres"
    );
    assert_eq!(
        psql(terminated, direct_tls, ssl),
        Ok("f".to_owned()),
        "terminated: the server sees plaintext"
    );
    // Without `starttls`, the default negotiation sends no ClientHello first.
    assert!(psql(direct, "sslmode=require", ssl).is_err());
}
