//! End-to-end: reloads, listener changes, draining, last-known-good and certificate swaps
//! (v0.1 acceptance: reload under load without failed requests, listener changes).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

fn config(listeners: &[(&str, u16)], backend: SocketAddr, header: &str) -> String {
    use std::fmt::Write;
    let mut text = String::from("listeners:\n");
    for (name, port) in listeners {
        writeln!(text, "  {name}: {{ address: \"127.0.0.1:{port}\" }}").unwrap();
    }
    let names: Vec<&str> = listeners.iter().map(|(n, _)| *n).collect();
    write!(
        text,
        "defaults: {{ listeners: [{}], tls: off }}\nroutes:\n  app: {{ match: \"PathPrefix(`/`)\", service: app, middlewares: [tag] }}\nservices:\n  app: {{ backends: [{{ address: \"{backend}\" }}] }}\nmiddlewares:\n  tag: {{ type: headers, response: {{ set: {{ X-Generation: \"{header}\" }} }} }}\n",
        names.join(", ")
    )
    .unwrap();
    text
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_under_load_drops_no_requests() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(&[("web", port)], backend.addr, "0"));
    let stop = Arc::new(AtomicBool::new(false));
    let ok = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let (stop, ok, failed) = (stop.clone(), ok.clone(), failed.clone());
        workers.push(tokio::spawn(async move {
            // Keep-alive connections, re-opened when the server closes them.
            while !stop.load(Ordering::SeqCst) {
                let Ok(stream) = tokio::net::TcpStream::connect(addr(port)).await else {
                    failed.fetch_add(1, Ordering::SeqCst);
                    continue;
                };
                let io = hyper_util_io(stream);
                let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(io).await else {
                    failed.fetch_add(1, Ordering::SeqCst);
                    continue;
                };
                tokio::spawn(conn);
                while !stop.load(Ordering::SeqCst) {
                    if sender.ready().await.is_err() {
                        break;
                    }
                    match sender.send_request(get("a", "/")).await {
                        Ok(resp) if resp.status() == 200 => {
                            let _ = http_body_util_collect(resp).await;
                            ok.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(resp) => {
                            failed.fetch_add(1, Ordering::SeqCst);
                            eprintln!("status {}", resp.status());
                        }
                        Err(err)
                            if err.is_canceled()
                                || err.is_closed()
                                || err.is_incomplete_message() =>
                        {
                            break;
                        }
                        Err(err) => {
                            failed.fetch_add(1, Ordering::SeqCst);
                            eprintln!("error {err}");
                        }
                    }
                }
            }
        }));
    }
    let started = Instant::now();
    for i in 1..=20 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        if i % 2 == 0 {
            rdock.signal("HUP");
        } else {
            rdock.write_config(&config(&[("web", port)], backend.addr, &i.to_string()));
            let (status, report) = rdock.reload();
            assert_eq!(status, 200, "{report}");
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.store(true, Ordering::SeqCst);
    for worker in workers {
        let _ = tokio::time::timeout(Duration::from_secs(5), worker).await;
    }
    let ok = ok.load(Ordering::SeqCst);
    let failed = failed.load(Ordering::SeqCst);
    eprintln!("{ok} requests in {:?} during 20 reloads", started.elapsed());
    assert_eq!(failed, 0, "failed requests during reloads ({ok} succeeded)");
    assert!(ok > 200, "too few requests: {ok}");
    let reply = client::http1(addr(port), get("a", "/")).await;
    assert_eq!(reply.header("x-generation"), Some("19"));
}

fn hyper_util_io(stream: tokio::net::TcpStream) -> hyper_util::rt::TokioIo<tokio::net::TcpStream> {
    hyper_util::rt::TokioIo::new(stream)
}

async fn http_body_util_collect(resp: http::Response<hyper::body::Incoming>) -> bytes::Bytes {
    use http_body_util::BodyExt;
    resp.into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default()
}

#[tokio::test]
async fn listeners_are_added_and_removed_without_a_restart() {
    let backend = Backend::start("app").await;
    let (a, b) = (free_port(), free_port());
    let rdock = Rdock::start(RDOCK, &config(&[("web", a)], backend.addr, "1"));
    assert_eq!(client::http1(addr(a), get("x", "/")).await.status, 200);
    assert!(tokio::net::TcpStream::connect(addr(b)).await.is_err());

    rdock.write_config(&config(&[("web", a), ("extra", b)], backend.addr, "2"));
    assert_eq!(rdock.reload().0, 200);
    assert_eq!(
        client::http1(addr(b), get("x", "/")).await.status,
        200,
        "new listener serves"
    );
    let pid = rdock.pid();

    rdock.write_config(&config(&[("extra", b)], backend.addr, "3"));
    assert_eq!(rdock.reload().0, 200);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        tokio::net::TcpStream::connect(addr(a)).await.is_err(),
        "removed listener closed"
    );
    assert_eq!(
        client::http1(addr(b), get("x", "/"))
            .await
            .header("x-generation"),
        Some("3")
    );
    assert_eq!(rdock.pid(), pid, "same process");

    // A port that is taken fails the reload and changes nothing.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = taken.local_addr().unwrap().port();
    rdock.write_config(&config(&[("extra", b), ("busy", busy)], backend.addr, "4"));
    let (status, report) = rdock.reload();
    assert_eq!(status, 422);
    assert!(
        report["error"].as_str().unwrap().contains("cannot listen"),
        "{report}"
    );
    assert_eq!(
        client::http1(addr(b), get("x", "/"))
            .await
            .header("x-generation"),
        Some("3")
    );
}

#[tokio::test]
async fn invalid_reloads_keep_the_running_configuration() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(&[("web", port)], backend.addr, "good"));
    rdock.write_config("routes:\n  broken: { match: \"Host(\", service: nope }\n");
    let (status, report) = rdock.reload();
    assert_eq!(status, 422);
    assert_eq!(report["result"], "rejected");
    assert_ne!(report["diagnostics"].as_array().unwrap().len(), 0);
    assert_eq!(
        client::http1(addr(port), get("x", "/"))
            .await
            .header("x-generation"),
        Some("good")
    );
    let output = rdock.command(&["reload"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("rejected"));
    let status = rdock.command(&["status"]);
    assert!(status.status.success());
    let text = String::from_utf8_lossy(&status.stdout);
    assert!(text.contains("last reload  rejected by api"), "{text}");
}

#[tokio::test]
async fn shutdown_drains_open_requests() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let mut rdock = Rdock::start(RDOCK, &config(&[("web", port)], backend.addr, "1"));
    let slow = tokio::spawn(client::http1(addr(port), get("x", "/slow/1500")));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    let status = tokio::task::spawn_blocking(move || {
        let status = rdock.stop(Duration::from_secs(10));
        (status, rdock)
    });
    let reply = slow.await.unwrap();
    assert_eq!(reply.status, 200, "the open request finished");
    let (status, _rdock) = status.await.unwrap();
    assert!(status.success(), "{status:?}");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1000),
        "waited for the request: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "did not wait for the whole drain time: {elapsed:?}"
    );
}

#[tokio::test]
async fn last_known_good_is_served_when_the_file_breaks() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let mut rdock = Rdock::start(RDOCK, &config(&[("web", port)], backend.addr, "lkg"));
    std::fs::write(rdock.config_path(), "routes: [this is not valid").unwrap();
    rdock.restart().unwrap();
    let reply = client::http1(addr(port), get("x", "/")).await;
    assert_eq!(reply.header("x-generation"), Some("lkg"));
    assert!(rdock.log().contains("last-known-good"), "{}", rdock.log());
    let history = std::fs::read_dir(rdock.data_dir().join("state/history"))
        .unwrap()
        .count();
    assert!(history >= 1);
    let lkg = std::fs::read_to_string(rdock.data_dir().join("state/lkg.json")).unwrap();
    assert!(lkg.contains("lkg"));
}

#[tokio::test]
async fn certificate_files_are_reloaded_when_they_change() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let first = ca.issue(dir.path(), "cert", &["a.test"]);
    let backend = Backend::start("app").await;
    let port = free_port();
    let config = format!(
        r#"
listeners:
  websecure: {{ address: "127.0.0.1:{port}", tls: {{}} }}
certificates:
  main: {{ cert_file: "{}", key_file: "{}" }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
defaults: {{ certificate: main }}
services:
  app: {{ backends: [{{ address: "{}" }}] }}
"#,
        first.cert.display(),
        first.key.display(),
        backend.addr
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let reply = client::tls(
        addr(port),
        "a.test",
        ca.client_config(&[b"h2"]),
        get("a.test", "/"),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert!(
        client::tls_connect(addr(port), "b.test", ca.client_config(&[b"h2"]))
            .await
            .is_err(),
        "the default certificate does not cover b.test yet"
    );
    // Replace the certificate files in place: the new names are served without a reload command.
    let second = ca.issue(dir.path(), "next", &["a.test", "b.test"]);
    std::fs::rename(&second.cert, &first.cert).unwrap();
    std::fs::rename(&second.key, &first.key).unwrap();
    let started = Instant::now();
    while client::tls_connect(addr(port), "b.test", ca.client_config(&[b"h2"]))
        .await
        .is_err()
    {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "certificate not swapped"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn one_file_change_reloads_once() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(&[("web", port)], backend.addr, "before"));
    let reloads = |rdock: &Rdock| rdock.log().matches("\"trigger\":\"file change\"").count();
    rdock.write_config(&config(&[("web", port)], backend.addr, "after"));
    let started = Instant::now();
    while reloads(&rdock) == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no reload\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Reading the file during the reload must not count as another change.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(reloads(&rdock), 1, "{}", rdock.log());
    assert_eq!(
        client::http1(addr(port), get("x", "/"))
            .await
            .header("x-generation"),
        Some("after")
    );
}

#[tokio::test]
async fn files_added_next_to_a_pattern_are_loaded() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let main = format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\nproviders:\n  file: {{ paths: [\"conf.d/*.yaml\"] }}\n"
    );
    let rdock = Rdock::start(RDOCK, &main);
    assert_eq!(
        client::http1(addr(port), get("app.example.com", "/"))
            .await
            .status,
        404
    );
    let conf = rdock.config_path().parent().unwrap().join("conf.d");
    std::fs::create_dir_all(&conf).unwrap();
    std::fs::write(
        conf.join("app.yaml"),
        format!(
            "routes:\n  app: {{ match: \"Host(`app.example.com`)\", service: app }}\nservices:\n  app: {{ backends: [{{ address: \"{}\" }}] }}\n",
            backend.addr
        ),
    )
    .unwrap();
    let started = Instant::now();
    while client::http1(addr(port), get("app.example.com", "/"))
        .await
        .status
        != 200
    {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the new file was not loaded\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
