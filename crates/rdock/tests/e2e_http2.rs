//! End-to-end: HTTP/2 listener settings in the SETTINGS frame a client receives, and a slow
//! HTTP/2 reader that must not make the proxy buffer a large response (H-PERF-03, ADR-0031).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");

fn config(port: u16, backend: SocketAddr, http2: &str) -> String {
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}"{http2} }}
defaults: {{ listeners: [web], tls: off, redirect_http_to_https: false }}
routes:
  app: {{ match: "Host(`app.test`)", service: app }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
"#
    )
}

/// What the server announces on an h2c connection: its SETTINGS (identifier → value) and the
/// increment of a connection-level `WINDOW_UPDATE` sent right after, if any.
async fn announced(port: u16) -> (BTreeMap<u16, u32>, Option<u32>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await
        .unwrap();
    let mut settings = None;
    let mut window = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    // Read frames until the SETTINGS frame and anything that follows within a moment.
    loop {
        let mut head = [0u8; 9];
        let read =
            tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut head)).await;
        let Ok(Ok(_)) = read else {
            if settings.is_some() || Instant::now() > deadline {
                break;
            }
            continue;
        };
        let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        let (kind, flags) = (head[3], head[4]);
        let stream_id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        match kind {
            0x4 if flags & 0x1 == 0 => {
                let map = payload
                    .as_chunks::<6>()
                    .0
                    .iter()
                    .map(|c| {
                        (
                            u16::from_be_bytes([c[0], c[1]]),
                            u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                        )
                    })
                    .collect();
                settings = Some(map);
            }
            0x8 if stream_id == 0 => {
                window = Some(
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff,
                );
            }
            _ => {}
        }
    }
    (settings.expect("a SETTINGS frame"), window)
}

const MAX_CONCURRENT_STREAMS: u16 = 0x3;
const INITIAL_WINDOW_SIZE: u16 = 0x4;
const MAX_FRAME_SIZE: u16 = 0x5;
const MAX_HEADER_LIST_SIZE: u16 = 0x6;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_settings_reach_the_client() {
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr, ""));
    let (settings, window) = announced(port).await;
    // The values before v0.9: Pingora's 100 streams and 64 KiB header list, nothing else.
    assert_eq!(
        settings,
        BTreeMap::from([
            (MAX_CONCURRENT_STREAMS, 100),
            (MAX_HEADER_LIST_SIZE, 65_536)
        ])
    );
    assert_eq!(window, None);

    rdock.write_config(&config(
        port,
        backend.addr,
        ", http2: { max_concurrent_streams: 50, initial_stream_window: 1MiB, initial_connection_window: 4MiB, max_frame_size: 32768, max_header_list_size: 128KiB, max_send_buffer: 1MiB, max_pending_accept_reset_streams: 10, max_local_error_reset_streams: 100 }",
    ));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let (settings, window) = announced(port).await;
    assert_eq!(
        settings,
        BTreeMap::from([
            (MAX_CONCURRENT_STREAMS, 50),
            (INITIAL_WINDOW_SIZE, 1 << 20),
            (MAX_FRAME_SIZE, 32_768),
            (MAX_HEADER_LIST_SIZE, 128 << 10),
        ]),
        "a reload builds a new engine for new connections"
    );
    assert_eq!(window, Some((4 << 20) - 65_535));

    rdock.write_config(&config(
        port,
        backend.addr,
        ", http2: { max_concurrent_streams: unlimited }",
    ));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let (settings, _) = announced(port).await;
    assert_eq!(
        settings,
        BTreeMap::from([(MAX_HEADER_LIST_SIZE, 65_536)]),
        "`unlimited` sends no stream limit"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_limit_above_the_ceiling_names_unlimited() {
    let port = free_port();
    let refused = Rdock::try_start(
        RDOCK,
        &config(
            port,
            "127.0.0.1:9".parse().unwrap(),
            ", http2: { max_concurrent_streams: 4000000000 }",
        ),
    );
    let log = refused.err().expect("refused");
    assert!(log.contains("write `unlimited`"), "{log}");
}

fn rss_kib(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap()
}

/// A client that opens a 256 MiB download over HTTP/2 and never reads it: flow control stops
/// the proxy at the client's window plus h2's send buffer, and back-pressure reaches the
/// backend instead of the response piling up in the proxy.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_http2_reader_does_not_grow_proxy_memory() {
    const SIZE: usize = 256 << 20;
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, backend.addr, ""));
    let before = rss_kib(rdock.pid());
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut client, connection) = h2::client::Builder::new()
        .initial_window_size(65_535)
        .handshake::<_, bytes::Bytes>(tcp)
        .await
        .unwrap();
    tokio::spawn(connection);
    let request = http::Request::get(format!("http://app.test/bytes/{SIZE}"))
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(30), response)
        .await
        .expect("headers in time")
        .unwrap();
    assert_eq!(response.status(), 200);
    // Hold the body without reading it while the backend tries to push 256 MiB.
    let _body = response.into_body();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let after = rss_kib(rdock.pid());
    let grown = after.saturating_sub(before);
    eprintln!("proxy RSS {before} KiB -> {after} KiB");
    assert!(
        grown < 64 * 1024,
        "the proxy grew by {grown} KiB for a {} MiB response its client does not read",
        SIZE >> 20
    );
}
