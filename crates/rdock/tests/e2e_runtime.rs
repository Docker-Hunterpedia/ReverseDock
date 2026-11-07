//! End-to-end: the `per_core` runtime model (ADR-0026, #176) proxies HTTP and HTTPS, keeps,
//! re-binds and closes listener sockets on reloads, and drains on shutdown. The other suites
//! run under it with `RDOCK_TEST_RUNTIME=per_core`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

struct Ports {
    web: u16,
    secure: u16,
}

/// `web` (HTTP) always, `websecure` (HTTPS) when `secure` is set, both routed to `backend`
/// with an `X-Generation: <generation>` response header.
fn config(
    ports: &Ports,
    secure: Option<&rdock_testkit::certs::Issued>,
    backend: SocketAddr,
    generation: &str,
) -> String {
    let (secure_listener, certificates, route_listeners) = match secure {
        Some(cert) => (
            format!(
                "  websecure: {{ address: \"127.0.0.1:{}\", tls: {{}} }}\n",
                ports.secure
            ),
            format!(
                "certificates:\n  main: {{ cert_file: \"{}\", key_file: \"{}\" }}\ndefaults: {{ certificate: main }}\n",
                cert.cert.display(),
                cert.key.display()
            ),
            "web, websecure",
        ),
        None => (String::new(), String::new(), "web"),
    };
    format!(
        "runtime: {{ model: per_core }}\n\
         listeners:\n  web: {{ address: \"127.0.0.1:{web}\" }}\n{secure_listener}{certificates}\
         routes:\n  app: {{ match: \"PathPrefix(`/`)\", service: app, listeners: [{route_listeners}], tls: off, middlewares: [tag] }}\n\
         services:\n  app: {{ backends: [{{ address: \"{backend}\" }}] }}\n\
         middlewares:\n  tag: {{ type: headers, response: {{ set: {{ X-Generation: \"{generation}\" }} }} }}\n",
        web = ports.web,
    )
}

async fn generation(port: u16) -> Option<String> {
    let reply = client::http1(addr(port), get("x", "/")).await;
    assert_eq!(reply.status, 200);
    reply.header("x-generation").map(str::to_owned)
}

#[tokio::test]
async fn per_core_proxies_http_and_https_across_reloads_and_drains_on_shutdown() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "cert", &["a.test"]);
    let backend = Backend::start("app").await;
    let ports = Ports {
        web: free_port(),
        secure: free_port(),
    };
    let mut rdock = Rdock::start(RDOCK, &config(&ports, Some(&cert), backend.addr, "1"));
    let threads = std::thread::available_parallelism().unwrap().get();
    assert!(
        rdock.log().contains(&format!("\"threads\":{threads}")),
        "one thread per available CPU by default\n{}",
        rdock.log()
    );

    // Every new connection lands on one of the per-thread sockets and is served there.
    for _ in 0..32 {
        assert_eq!(generation(ports.web).await.as_deref(), Some("1"));
    }
    for alpn in [&b"h2"[..], &b"http/1.1"[..]] {
        let reply = client::tls(
            addr(ports.secure),
            "a.test",
            ca.client_config(&[alpn]),
            get("a.test", "/"),
        )
        .await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("x-generation"), Some("1"));
    }
    assert_eq!(
        client::h2c(addr(ports.web), get("x", "/")).await.status,
        200,
        "h2c preface"
    );

    // A reload that keeps both addresses keeps their sockets and serves the new routes.
    rdock.write_config(&config(&ports, Some(&cert), backend.addr, "2"));
    assert_eq!(rdock.reload().0, 200);
    assert_eq!(generation(ports.web).await.as_deref(), Some("2"));

    // A reload that removes a listener closes every one of its sockets.
    rdock.write_config(&config(&ports, None, backend.addr, "3"));
    assert_eq!(rdock.reload().0, 200);
    tokio::time::sleep(Duration::from_millis(200)).await;
    for _ in 0..8 {
        assert!(
            tokio::net::TcpStream::connect(addr(ports.secure))
                .await
                .is_err(),
            "removed listener closed"
        );
    }
    assert_eq!(generation(ports.web).await.as_deref(), Some("3"));

    // A reload that moves a listener re-binds it on the new address.
    let moved = Ports {
        web: free_port(),
        secure: ports.secure,
    };
    rdock.write_config(&config(&moved, None, backend.addr, "4"));
    assert_eq!(rdock.reload().0, 200);
    assert_eq!(generation(moved.web).await.as_deref(), Some("4"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        tokio::net::TcpStream::connect(addr(ports.web))
            .await
            .is_err()
    );

    // Shutdown waits for the open request, not the whole drain time.
    let slow = tokio::spawn(client::http1(addr(moved.web), get("x", "/slow/1500")));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    let stopped = tokio::task::spawn_blocking(move || rdock.stop(Duration::from_secs(10)));
    assert_eq!(slow.await.unwrap().status, 200, "the open request finished");
    assert!(stopped.await.unwrap().success());
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(1000), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
}

#[tokio::test]
async fn per_core_refuses_an_address_another_reuseport_socket_holds() {
    let backend = Backend::start("app").await;
    let ports = Ports {
        web: free_port(),
        secure: 0,
    };
    let rdock = Rdock::start(RDOCK, &config(&ports, None, backend.addr, "1"));
    // Another process's per-core sockets would accept SO_REUSEPORT company; rdock must not
    // silently share the address with them.
    let other = tokio::net::TcpSocket::new_v4().unwrap();
    other.set_reuseport(true).unwrap();
    other.bind(addr(0)).unwrap();
    let other = other.listen(16).unwrap();
    let taken = Ports {
        web: other.local_addr().unwrap().port(),
        secure: 0,
    };
    rdock.write_config(&config(&taken, None, backend.addr, "2"));
    let (status, report) = rdock.reload();
    assert_eq!(status, 422, "{report}");
    assert!(
        report["error"].as_str().unwrap().contains("cannot listen"),
        "{report}"
    );
    assert_eq!(generation(ports.web).await.as_deref(), Some("1"));
}

#[tokio::test]
async fn changing_the_runtime_model_needs_a_restart() {
    let backend = Backend::start("app").await;
    let ports = Ports {
        web: free_port(),
        secure: 0,
    };
    let mut rdock = Rdock::start(RDOCK, &config(&ports, None, backend.addr, "1"));
    let steal = config(&ports, None, backend.addr, "2").replace("model: per_core", "model: steal");
    rdock.write_config(&steal);
    assert_eq!(rdock.reload().0, 200);
    assert_eq!(generation(ports.web).await.as_deref(), Some("2"));
    assert!(
        rdock
            .log()
            .contains("restart rdock to apply the new runtime settings"),
        "{}",
        rdock.log()
    );
    rdock.restart().unwrap();
    assert_eq!(generation(ports.web).await.as_deref(), Some("2"));
}
