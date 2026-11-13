//! End-to-end: in-place binary upgrade by peer handover, and a listener change by reload, under
//! load (H-PERF-04, ADR-0031 "Proof"). Linux only.
//!
//! A held set of long-lived connections, opened before the swap and exercised every 100 ms (a
//! WebSocket echo, an SSE stream, a chunked upload trickling one chunk per 100 ms, an HTTP/2
//! stream with a slow response, a TLS-passthrough connection, a UDP echo session), and a
//! connect loop opening new connections as fast as this machine allows on an HTTP, an HTTPS
//! and a TCP listener. Every test asserts zero failed new connections.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::needless_pass_by_value,
    clippy::single_match_else
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rdock_testkit::backend::Backend;
use rdock_testkit::certs::{Issued, TestCa};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rdock_testkit::tcp::EchoBackend;
use rdock_testkit::udp::UdpEcho;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// The ports of one test's listeners.
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
    tcp: u16,
    pass: u16,
    udp: u16,
}

impl Ports {
    fn new() -> Self {
        Self {
            http: free_port(),
            https: free_port(),
            tcp: free_port(),
            pass: free_port(),
            udp: free_port(),
        }
    }
}

/// The backends the listeners route to.
struct Backends {
    http: Backend,
    tls: Backend,
    echo: EchoBackend,
    udp: UdpEcho,
    cert: Issued,
    ca: TestCa,
    _dir: tempfile::TempDir,
}

impl Backends {
    async fn start() -> Self {
        let ca = TestCa::new();
        let dir = tempfile::tempdir().unwrap();
        let cert = ca.issue(dir.path(), "app", &["app.test", "pass.test"]);
        Self {
            http: Backend::start("app").await,
            tls: Backend::start_tls("pass", &cert.cert_pem, &cert.key_pem).await,
            echo: EchoBackend::start().await,
            udp: UdpEcho::start("udp").await,
            cert,
            ca,
            _dir: dir,
        }
    }
}

fn config(ports: Ports, b: &Backends, upgrade: &str, extra_listeners: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{http}", ping: /rdock/ping }}
  websecure: {{ address: "127.0.0.1:{https}", tls: {{}}, ping: /rdock/ping }}
  tcp: {{ address: "127.0.0.1:{tcp}", protocol: tcp }}
  pass: {{ address: "127.0.0.1:{pass}", protocol: tcp }}
  udp: {{ address: "127.0.0.1:{udp}", protocol: udp }}
{extra_listeners}
defaults: {{ listeners: [web, websecure], tls: off, redirect_http_to_https: false }}
certificates:
  app: {{ cert_file: "{cert}", key_file: "{key}" }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app, tls: {{ certificate: app }} }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
tcp_routes:
  echo: {{ match: "HostSNI(`*`)", listeners: [tcp], service: echo }}
  pass: {{ match: "HostSNI(`pass.test`)", listeners: [pass], service: pass, tls: {{ passthrough: true }} }}
tcp_services:
  echo: {{ backends: [{{ address: "{echo}" }}] }}
  pass: {{ backends: [{{ address: "{tls}" }}] }}
udp_routes:
  udp: {{ listeners: [udp], service: udp }}
udp_services:
  udp: {{ backends: [{{ address: "{udp_backend}" }}] }}
lifecycle: {{ drain_timeout: 5s }}
{upgrade}
"#,
        http = ports.http,
        https = ports.https,
        tcp = ports.tcp,
        pass = ports.pass,
        udp = ports.udp,
        cert = b.cert.cert.display(),
        key = b.cert.key.display(),
        backend = b.http.addr,
        echo = b.echo.addr,
        tls = b.tls.addr,
        udp_backend = b.udp.addr,
    )
}

/// A copy of the binary under test, as an operator would install it (mode 0755).
fn copy_binary(dir: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::copy(RDOCK, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A copy of the binary under test that runs with an upgrade fault: debug builds read the fault
/// from `<binary>.fault` and pass it to the new process (an upgrade runs the checked file
/// itself, so a wrapper script cannot inject it).
fn faulty_binary(dir: &Path, name: &str, fault: &str) -> PathBuf {
    let path = copy_binary(dir, name);
    std::fs::write(dir.join(format!("{name}.fault")), fault).unwrap();
    path
}

/// `POST /api/v1/upgrade` over the admin socket.
fn upgrade(rdock: &Rdock, binary: Option<&Path>) -> (u16, serde_json::Value) {
    let body = binary.map_or_else(
        || "{}".to_owned(),
        |b| serde_json::json!({ "binary": b }).to_string(),
    );
    // The answer comes when the attempt ends: after `rdock validate` with the new binary, its
    // start and, for a child that stalls, `upgrade.start_timeout`. On a loaded machine that is
    // far more than the helper's usual wait.
    let Some((status, _, text)) = rdock.admin_send_within(
        Duration::from_secs(180),
        "POST",
        "/api/v1/upgrade",
        &[("Content-Type", "application/json")],
        &body,
    ) else {
        panic!("no answer over the admin socket:\n{}", rdock.log());
    };
    (status, serde_json::from_str(&text).unwrap_or_default())
}

fn status_pid(rdock: &Rdock) -> Option<u32> {
    // During the handover a connection waits in the shared backlog until the new process
    // accepts, which takes as long as that process needs to start: over 20 seconds on a
    // loaded CI runner. Waiting is not a failure; a refused or lost request is.
    let (status, _, body) =
        rdock.admin_send_within(Duration::from_secs(180), "GET", "/api/v1/status", &[], "")?;
    if status != 200 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;
    value["pid"].as_u64().and_then(|p| u32::try_from(p).ok())
}

/// Whether another process holds the data directory's lock.
fn lock_held(data_dir: &Path) -> bool {
    let Ok(file) = std::fs::File::options()
        .read(true)
        .write(true)
        .open(data_dir.join("rdock.lock"))
    else {
        return false;
    };
    matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Stops a process that is not this test's child (the new generation) and waits for it.
fn stop_pid(pid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(20);
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Kills the generations that are not the test's child when the test ends, whatever happens.
struct Reaper(Mutex<Vec<u32>>);

impl Drop for Reaper {
    fn drop(&mut self) {
        for pid in self.0.lock().unwrap().drain(..) {
            stop_pid(pid);
        }
    }
}

/// The connect loop: new connections as fast as the workers manage, one request each.
struct Load {
    ok: Arc<AtomicU64>,
    failures: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    started: Instant,
}

impl Load {
    fn start(ports: Ports, tls: Arc<rustls::ClientConfig>) -> Self {
        let ok = Arc::new(AtomicU64::new(0));
        let failures = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut tasks = Vec::new();
        let spawn = |kind: &'static str, tasks: &mut Vec<tokio::task::JoinHandle<()>>| {
            let (ok, failures, stop, tls) =
                (ok.clone(), failures.clone(), stop.clone(), tls.clone());
            tasks.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let attempt = tokio::time::timeout(Duration::from_secs(15), async {
                        match kind {
                            "http" => http_once(ports.http).await,
                            "https" => https_once(ports.https, tls.clone()).await,
                            _ => tcp_once(ports.tcp).await,
                        }
                    })
                    .await;
                    match attempt {
                        Ok(Ok(())) => {
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Err(e)) => failures.lock().unwrap().push(format!("{kind}: {e}")),
                        Err(_) => failures.lock().unwrap().push(format!("{kind}: timed out")),
                    }
                }
            }));
        };
        for _ in 0..8 {
            spawn("http", &mut tasks);
        }
        for _ in 0..4 {
            spawn("https", &mut tasks);
            spawn("tcp", &mut tasks);
        }
        Self {
            ok,
            failures,
            stop,
            tasks,
            started: Instant::now(),
        }
    }

    /// Stops the loop; (connections that succeeded, per second, failures).
    async fn finish(self) -> (u64, f64, Vec<String>) {
        self.stop.store(true, Ordering::Relaxed);
        for task in self.tasks {
            let _ = task.await;
        }
        let ok = self.ok.load(Ordering::Relaxed);
        let rate = ok as f64 / self.started.elapsed().as_secs_f64();
        let failures = std::mem::take(&mut *self.failures.lock().unwrap());
        (ok, rate, failures)
    }
}

async fn read_all<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await?;
    Ok(out)
}

const PING: &[u8] = b"GET /rdock/ping HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n";

async fn http_once(port: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect(addr(port))
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(PING).await.map_err(|e| e.to_string())?;
    let answer = read_all(&mut stream).await.map_err(|e| e.to_string())?;
    if answer.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!("answer {:?}", String::from_utf8_lossy(&answer)))
    }
}

async fn https_once(port: u16, tls: Arc<rustls::ClientConfig>) -> Result<(), String> {
    let mut stream = rdock_testkit::client::tls_connect(addr(port), "app.test", tls)
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(PING).await.map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    // A TLS peer may close without close_notify after `Connection: close`; the answer counts.
    let _ = stream.read_to_end(&mut answer).await;
    if answer.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!("answer {:?}", String::from_utf8_lossy(&answer)))
    }
}

async fn tcp_once(port: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect(addr(port))
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(b"ping").await.map_err(|e| e.to_string())?;
    let mut echo = [0u8; 4];
    stream
        .read_exact(&mut echo)
        .await
        .map_err(|e| e.to_string())?;
    if &echo != b"ping" {
        return Err("wrong echo".into());
    }
    stream.shutdown().await.map_err(|e| e.to_string())?;
    let _ = read_all(&mut stream).await;
    Ok(())
}

/// One held connection's record: when it last worked and when it was found closed.
#[derive(Default)]
struct Track {
    last_ok: Mutex<Option<Instant>>,
    closed: Mutex<Option<Instant>>,
    oks: AtomicU64,
}

impl Track {
    fn ok(&self) {
        *self.last_ok.lock().unwrap() = Some(Instant::now());
        self.oks.fetch_add(1, Ordering::Relaxed);
    }

    fn close(&self) {
        let mut closed = self.closed.lock().unwrap();
        if closed.is_none() {
            *closed = Some(Instant::now());
        }
    }

    fn last_ok(&self) -> Option<Instant> {
        *self.last_ok.lock().unwrap()
    }

    fn closed(&self) -> Option<Instant> {
        *self.closed.lock().unwrap()
    }
}

/// The held set.
struct Held {
    tracks: Vec<(&'static str, Arc<Track>)>,
    /// UDP replies received, and when each datagram was sent (to find losses).
    udp: Arc<Track>,
    udp_sent: Arc<AtomicU64>,
    /// The HTTP/2 connection's request handle, to try a new stream after the handover.
    h2: h2::client::SendRequest<bytes::Bytes>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

const TICK: Duration = Duration::from_millis(100);

impl Held {
    async fn open(ports: Ports, b: &Backends) -> Self {
        let mut tracks = Vec::new();
        let mut tasks = Vec::new();
        let mut track = |name: &'static str| {
            let t = Arc::new(Track::default());
            tracks.push((name, t.clone()));
            t
        };

        // WebSocket echo.
        let ws = track("websocket");
        let tcp = TcpStream::connect(addr(ports.http)).await.unwrap();
        let (mut socket, _) = tokio_tungstenite::client_async("ws://app.test/ws", tcp)
            .await
            .unwrap();
        tasks.push(tokio::spawn(async move {
            loop {
                let sent = socket
                    .send(tokio_tungstenite::tungstenite::Message::text("hi"))
                    .await;
                let got = tokio::time::timeout(Duration::from_secs(5), socket.next()).await;
                match (sent, got) {
                    (Ok(()), Ok(Some(Ok(m)))) if m.is_text() => ws.ok(),
                    _ => {
                        ws.close();
                        return;
                    }
                }
                tokio::time::sleep(TICK).await;
            }
        }));

        // SSE stream (one event per 100 ms for far longer than the test).
        let sse = track("sse");
        let mut stream = TcpStream::connect(addr(ports.http)).await.unwrap();
        stream
            .write_all(b"GET /sse?n=100000&ms=100 HTTP/1.1\r\nHost: app.test\r\n\r\n")
            .await
            .unwrap();
        tasks.push(tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => sse.ok(),
                    _ => {
                        sse.close();
                        return;
                    }
                }
            }
        }));

        // A chunked upload, one chunk per 100 ms, never finished.
        let upload = track("upload");
        let stream = TcpStream::connect(addr(ports.http)).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        writer
            .write_all(
                b"POST /echo-body HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        let upload_reader = upload.clone();
        tasks.push(tokio::spawn(async move {
            // The server answers only at the end of the body: any read result means closed.
            let mut buf = [0u8; 1024];
            let _ = reader.read(&mut buf).await;
            upload_reader.close();
        }));
        tasks.push(tokio::spawn(async move {
            loop {
                if writer.write_all(b"1\r\na\r\n").await.is_err() {
                    upload.close();
                    return;
                }
                upload.ok();
                tokio::time::sleep(TICK).await;
            }
        }));

        // HTTP/2 (h2c) with a slow response.
        let h2_track = track("http2");
        let tcp = TcpStream::connect(addr(ports.http)).await.unwrap();
        let (h2, connection) = h2::client::handshake(tcp).await.unwrap();
        tasks.push(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = http::Request::get("http://app.test/sse?n=100000&ms=100")
            .body(())
            .unwrap();
        let (response, _) = h2.clone().send_request(request, true).unwrap();
        tasks.push(tokio::spawn(async move {
            let Ok(response) = response.await else {
                h2_track.close();
                return;
            };
            let mut body = response.into_body();
            loop {
                match tokio::time::timeout(Duration::from_secs(5), body.data()).await {
                    Ok(Some(Ok(data))) => {
                        let _ = body.flow_control().release_capacity(data.len());
                        h2_track.ok();
                    }
                    _ => {
                        h2_track.close();
                        return;
                    }
                }
            }
        }));

        // TLS passthrough: TLS with the backend itself, keep-alive requests every 100 ms.
        let pass = track("tls-passthrough");
        let mut stream = rdock_testkit::client::tls_connect(
            addr(ports.pass),
            "pass.test",
            b.ca.client_config(&[b"http/1.1"]),
        )
        .await
        .unwrap();
        tasks.push(tokio::spawn(async move {
            loop {
                let request = b"GET /status/200 HTTP/1.1\r\nHost: pass.test\r\n\r\n";
                let mut buf = [0u8; 4096];
                let ok = tokio::time::timeout(Duration::from_secs(5), async {
                    stream.write_all(request).await.ok()?;
                    let n = stream.read(&mut buf).await.ok()?;
                    (n > 0 && buf.starts_with(b"HTTP/1.1 200")).then_some(())
                })
                .await;
                if matches!(ok, Ok(Some(()))) {
                    pass.ok();
                } else {
                    pass.close();
                    return;
                }
                tokio::time::sleep(TICK).await;
            }
        }));

        // A UDP session.
        let udp = Arc::new(Track::default());
        let udp_sent = Arc::new(AtomicU64::new(0));
        let socket = rdock_testkit::udp::client(addr(ports.udp)).await;
        let socket = Arc::new(socket);
        {
            let (sender, sent) = (socket.clone(), udp_sent.clone());
            tasks.push(tokio::spawn(async move {
                loop {
                    let _ = sender.send(b"hello").await;
                    sent.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(TICK).await;
                }
            }));
            let udp = udp.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                while socket.recv(&mut buf).await.is_ok() {
                    udp.ok();
                }
            }));
        }
        // Everything is up before the clock starts.
        tokio::time::sleep(Duration::from_millis(500)).await;
        for (name, t) in &tracks {
            assert!(
                t.oks.load(Ordering::Relaxed) > 0,
                "{name} works before the swap"
            );
        }
        Self {
            tracks,
            udp,
            udp_sent,
            h2,
            tasks,
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// A TLS client whose session cache persists between handshakes; how the next handshake went.
fn handshake(port: u16, config: &Arc<rustls::ClientConfig>) -> rustls::HandshakeKind {
    use std::io::{Read, Write};
    let mut conn =
        rustls::ClientConnection::new(config.clone(), "app.test".try_into().unwrap()).unwrap();
    let mut socket = std::net::TcpStream::connect(addr(port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut socket);
    tls.write_all(PING).unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer);
    assert!(answer.starts_with(b"HTTP/1.1 200"));
    conn.handshake_kind().unwrap()
}

/// Samples, every 100 ms, the pid that answers on the admin socket and whether the lock is
/// held, until stopped.
struct Watch {
    stop: Arc<AtomicBool>,
    task: std::thread::JoinHandle<(Vec<u32>, usize, usize)>,
}

impl Watch {
    fn start(rdock: &Arc<Rdock>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let rdock = rdock.clone();
        let flag = stop.clone();
        let task = std::thread::spawn(move || {
            let mut pids: Vec<u32> = Vec::new();
            let (mut admin_failures, mut lock_free) = (0, 0);
            while !flag.load(Ordering::Relaxed) {
                match status_pid(&rdock) {
                    Some(pid) => {
                        if pids.last() != Some(&pid) {
                            pids.push(pid);
                        }
                    }
                    None => admin_failures += 1,
                }
                if !lock_held(&rdock.data_dir()) {
                    lock_free += 1;
                }
                std::thread::sleep(TICK);
            }
            (pids, admin_failures, lock_free)
        });
        Self { stop, task }
    }

    fn finish(self) -> (Vec<u32>, usize, usize) {
        self.stop.store(true, Ordering::Relaxed);
        self.task.join().unwrap()
    }
}

const DRAIN: Duration = Duration::from_secs(5);

/// (a) A binary upgrade to a copy of the same binary, under load.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_binary_upgrade_drops_nothing_and_drains_within_its_bound() {
    let b = Backends::start().await;
    let ports = Ports::new();
    let bin = tempfile::tempdir().unwrap();
    let new = copy_binary(bin.path(), "rdock-new");
    let rdock = Rdock::start(
        RDOCK,
        &config(
            ports,
            &b,
            &format!("upgrade: {{ drain: 5s, binary: \"{}\" }}", new.display()),
            "",
        ),
    );
    let old_pid = rdock.pid();
    let rdock = Arc::new(rdock);
    let reaper = Reaper(Mutex::new(Vec::new()));
    let resumption = b.ca.client_config(&[b"http/1.1"]);
    assert_eq!(
        handshake(ports.https, &resumption),
        rustls::HandshakeKind::Full
    );

    let held = Held::open(ports, &b).await;
    let watch = Watch::start(&rdock);
    let load = Load::start(ports, b.ca.client_config(&[b"http/1.1"]));
    tokio::time::sleep(Duration::from_secs(2)).await;

    let swap = {
        let rdock = rdock.clone();
        tokio::task::spawn_blocking(move || upgrade(&rdock, None))
            .await
            .unwrap()
    };
    let served_at = Instant::now();
    assert_eq!(swap.0, 200, "{}\n{}", swap.1, rdock.log());
    let new_pid = u32::try_from(swap.1["pid"].as_u64().unwrap()).unwrap();
    reaper.0.lock().unwrap().push(new_pid);
    assert_eq!(swap.1["previous_pid"].as_u64(), Some(u64::from(old_pid)));

    // HTTP/2: the old process sent GOAWAY, so no new stream is accepted on that connection,
    // while the open stream goes on.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let refused = tokio::time::timeout(Duration::from_secs(5), async {
        let mut h2 = held.h2.clone();
        let ready = futures_util::future::poll_fn(|cx| h2.poll_ready(cx)).await;
        if let Err(e) = ready {
            eprintln!("http2: new stream refused at poll_ready: {e}");
            return true;
        }
        let request = http::Request::get("http://app.test/").body(()).unwrap();
        match h2.send_request(request, true) {
            Err(e) => {
                eprintln!("http2: new stream refused at send_request: {e}");
                true
            }
            Ok((response, _)) => match response.await {
                Err(e) => {
                    eprintln!("http2: new stream refused: {e}");
                    true
                }
                Ok(r) => {
                    eprintln!("http2: new stream answered {}", r.status());
                    false
                }
            },
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        refused,
        "a new stream on the draining HTTP/2 connection is refused (GOAWAY)"
    );

    // The old process exits at the end of the drain.
    let exit_deadline = served_at + DRAIN + Duration::from_secs(2);
    let exited_at = loop {
        if !alive(old_pid) || zombie(old_pid) {
            break Instant::now();
        }
        assert!(
            Instant::now() < exit_deadline + Duration::from_secs(10),
            "the old process did not exit\n{}",
            rdock.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        exited_at <= exit_deadline,
        "the old process exited {:?} after the handover; the bound is drain + 2 s",
        exited_at - served_at
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (ok, rate, failures) = load.finish().await;
    let (pids, admin_failures, lock_free) = watch.finish();

    assert!(
        failures.is_empty(),
        "{} failed new connections: {:?}",
        failures.len(),
        &failures[..failures.len().min(10)]
    );
    eprintln!("connect loop: {ok} connections, {rate:.0} per second, over HTTP, HTTPS and TCP");
    assert_eq!(
        pids,
        vec![old_pid, new_pid],
        "the answering process changed once"
    );
    assert_eq!(admin_failures, 0, "the admin socket answered throughout");
    assert_eq!(lock_free, 0, "the data directory stayed locked");

    // Held connections lived until the drain deadline and were closed at it.
    let deadline = served_at + DRAIN;
    for (name, track) in &held.tracks {
        let last = track.last_ok().unwrap();
        assert!(
            last + Duration::from_millis(1500) >= deadline,
            "{name} stopped working {:?} before the drain deadline",
            deadline.saturating_duration_since(last)
        );
        let closed = track
            .closed()
            .unwrap_or_else(|| panic!("{name} was not closed"));
        assert!(
            closed <= deadline + Duration::from_secs(3),
            "{name} was closed {:?} after the deadline",
            closed - deadline
        );
    }
    // The UDP session ended at the handover; the client's next datagrams opened one in the new
    // process, which answers.
    let replies_after = held.udp.last_ok().unwrap();
    assert!(
        replies_after > served_at + Duration::from_secs(3),
        "UDP answers after the swap"
    );
    eprintln!(
        "udp: {} datagrams sent, {} answered",
        held.udp_sent.load(Ordering::Relaxed),
        held.udp.oks.load(Ordering::Relaxed)
    );

    // No zombie, no spool directory of the old process, and resumption across the swap.
    assert!(!alive(old_pid) || zombie(old_pid));
    drop(held);
    let mut rdock = Arc::try_unwrap(rdock).ok().unwrap();
    assert!(
        rdock.try_exit().is_some_and(|s| s.success()),
        "the old process exited cleanly"
    );
    assert!(!alive(old_pid), "reaped: no zombie");
    assert!(
        !rdock
            .data_dir()
            .join("spool")
            .join(old_pid.to_string())
            .exists()
    );
    assert_eq!(
        handshake(ports.https, &resumption),
        rustls::HandshakeKind::Resumed,
        "the ticket keys were handed over"
    );
    assert!(lock_held(&rdock.data_dir()));
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(metrics.contains("rdock_upgrade_generation 1"), "{metrics}");
    assert!(metrics.contains("rdock_upgrade_draining_connections 0"));
    let audit = std::fs::read_dir(rdock.data_dir().join("audit"))
        .unwrap()
        .filter_map(|e| std::fs::read_to_string(e.unwrap().path()).ok())
        .collect::<String>();
    assert!(audit.contains("\"action\":\"upgrade\""), "{audit}");
    assert!(audit.contains(swap.1["sha256"].as_str().unwrap()));
    drop(reaper);
}

/// A process that has exited but was not reaped yet.
fn zombie(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit(')')
            .next()
            .is_some_and(|rest| rest.trim_start().starts_with('Z'))
    })
}

/// (b) A listener-set change by reload, under the same load: unchanged listeners lose nothing,
/// a removed listener's connections live until the drain, a new listener answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listener_change_by_reload_drops_nothing() {
    let b = Backends::start().await;
    let ports = Ports::new();
    let (gone, added) = (free_port(), free_port());
    let before = config(
        ports,
        &b,
        "",
        &format!("  gone: {{ address: \"127.0.0.1:{gone}\" }}"),
    )
    .replace(
        "listeners: [web, websecure]",
        "listeners: [web, websecure, gone]",
    );
    let rdock = Rdock::start(RDOCK, &before);
    let held = Held::open(ports, &b).await;
    // A slow response on the listener the reload removes.
    let mut on_gone = TcpStream::connect(addr(gone)).await.unwrap();
    on_gone
        .write_all(b"GET /sse?n=100000&ms=100 HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await
        .unwrap();
    let load = Load::start(ports, b.ca.client_config(&[b"http/1.1"]));
    tokio::time::sleep(Duration::from_secs(2)).await;

    let after = config(
        ports,
        &b,
        "",
        &format!("  added: {{ address: \"127.0.0.1:{added}\" }}"),
    )
    .replace(
        "listeners: [web, websecure]",
        "listeners: [web, websecure, added]",
    );
    rdock.write_config(&after);
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let reloaded = Instant::now();
    assert!(http_once(added).await.is_ok(), "the new listener answers");
    // The removed listener's connection lives on until the drain (lifecycle.drain_timeout 5s).
    let mut buf = [0u8; 4096];
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        on_gone.read(&mut buf).await.unwrap() > 0,
        "still served while draining"
    );
    let closed = loop {
        match tokio::time::timeout(Duration::from_secs(10), on_gone.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => break Instant::now(),
            Ok(Ok(_)) => {}
        }
    };
    assert!(
        closed - reloaded >= Duration::from_secs(4),
        "closed at the drain deadline"
    );
    assert!(
        TcpStream::connect(addr(gone)).await.is_err(),
        "the removed address is closed"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (ok, rate, failures) = load.finish().await;
    assert!(
        failures.is_empty(),
        "{} failed: {:?}",
        failures.len(),
        &failures[..failures.len().min(10)]
    );
    eprintln!("connect loop: {ok} connections, {rate:.0} per second");
    for (name, track) in &held.tracks {
        assert!(
            track.closed().is_none(),
            "{name} on an unchanged listener was untouched"
        );
        assert!(track.last_ok().unwrap() > reloaded + Duration::from_secs(2));
    }
}

/// Failures: each leaves the old process serving with zero failed connections, and a later
/// upgrade still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_upgrade_leaves_the_old_process_serving() {
    let b = Backends::start().await;
    let ports = Ports::new();
    let bin = tempfile::tempdir().unwrap();
    let rdock = Rdock::start(
        RDOCK,
        &config(ports, &b, "upgrade: { start_timeout: 10s }", ""),
    );
    let old_pid = rdock.pid();
    let held = Held::open(ports, &b).await;
    let load = Load::start(ports, b.ca.client_config(&[b"http/1.1"]));
    tokio::time::sleep(Duration::from_secs(1)).await;

    // The child exits before `ready`.
    let (status, body) = upgrade(
        &rdock,
        Some(&faulty_binary(bin.path(), "early", "exit-before-ready")),
    );
    assert_eq!(status, 500, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("did not become ready"),
        "{body}"
    );
    // The child is gone between `ready` and `serving`.
    let (status, body) = upgrade(
        &rdock,
        Some(&faulty_binary(bin.path(), "late", "exit-after-ready")),
    );
    assert_eq!(status, 500, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("did not start serving"),
        "{body}"
    );
    // A world-writable binary.
    let writable = copy_binary(bin.path(), "writable");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    let (status, body) = upgrade(&rdock, Some(&writable));
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("writable by its group or others")
    );
    // Not over TCP.
    let tcp = rdock_testkit::client::http1(
        rdock.admin,
        rdock_testkit::client::request("POST", "localhost", "/api/v1/upgrade", ""),
    )
    .await;
    assert!(tcp.status == 401 || tcp.status == 403, "{}", tcp.status);

    // The old process still serves, its writers run (a reload applies), nothing was dropped.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(status_pid(&rdock), Some(old_pid));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    for (name, track) in &held.tracks {
        assert!(
            track.closed().is_none(),
            "{name} untouched by the failed upgrades"
        );
    }
    // A bad signature with `trusted_keys` set (a valid minisign signature of other content).
    let signed = copy_binary(bin.path(), "signed");
    std::fs::write(
        bin.path().join("signed.minisig"),
        "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==\n",
    )
    .unwrap();
    rdock.write_config(&config(
        ports,
        &b,
        "upgrade: { start_timeout: 10s, trusted_keys: [RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3] }",
        "",
    ));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let (status, body) = upgrade(&rdock, Some(&signed));
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("does not match"),
        "{body}"
    );

    let (ok, rate, failures) = load.finish().await;
    assert!(
        failures.is_empty(),
        "{} failed: {:?}",
        failures.len(),
        &failures[..failures.len().min(10)]
    );
    eprintln!("connect loop: {ok} connections, {rate:.0} per second");
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(
        metrics.contains("rdock_upgrades_total{result=\"failed\"} 2"),
        "{metrics}"
    );
    assert!(metrics.contains("rdock_upgrades_total{result=\"refused\"} 2"));

    // After all that, an upgrade works.
    rdock.write_config(&config(ports, &b, "upgrade: { drain: 1s }", ""));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let (status, body) = upgrade(&rdock, Some(&copy_binary(bin.path(), "good")));
    assert_eq!(status, 200, "{body}");
    let reaper = Reaper(Mutex::new(vec![
        u32::try_from(body["pid"].as_u64().unwrap()).unwrap(),
    ]));
    assert!(http_once(ports.http).await.is_ok());
    drop(reaper);
}

/// As PID 1 (a container's entry point) the upgrade is refused with the diagnostic; simulated
/// with the debug-build fault, since a test cannot be PID 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pid_1_is_refused() {
    let b = Backends::start().await;
    let ports = Ports::new();
    let rdock = Rdock::try_start_with_env(
        RDOCK,
        &config(ports, &b, "", ""),
        &[("RDOCK_UPGRADE_FAULT", "pid1")],
    )
    .unwrap();
    let load = Load::start(ports, b.ca.client_config(&[b"http/1.1"]));
    let (status, body) = upgrade(&rdock, Some(Path::new(RDOCK)));
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("replace the container"),
        "{body}"
    );
    // SIGUSR2 is refused the same way and changes nothing.
    rdock.signal("USR2");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(status_pid(&rdock), Some(rdock.pid()));
    assert!(rdock.log().contains("PID 1"));
    let (_, _, failures) = load.finish().await;
    assert!(failures.is_empty(), "{failures:?}");
}

/// A second independent `rdock run` on the same data directory is refused, naming the pid; it
/// is accepted once the first one has exited or was killed (the lock is the kernel's, not the
/// file's content).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_run_on_one_data_directory_is_refused() {
    let port = free_port();
    let config = format!("listeners:\n  web: {{ address: \"127.0.0.1:{port}\", ping: /p }}\n");
    let mut first = Rdock::start(RDOCK, &config);
    let second = std::process::Command::new(RDOCK)
        .args(["run", "-c"])
        .arg(first.config_path())
        .arg("--data-dir")
        .arg(first.data_dir())
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(1));
    let text = String::from_utf8_lossy(&second.stderr);
    assert!(text.contains(&format!("(pid {})", first.pid())), "{text}");
    // Commands that only read are unaffected.
    assert!(first.command(&["status"]).status.success());
    // Killed: the file and its pid stay, the lock does not.
    first.signal("KILL");
    while first.try_exit().is_none() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(first.data_dir().join("rdock.lock").exists());
    first.restart().unwrap();
}
