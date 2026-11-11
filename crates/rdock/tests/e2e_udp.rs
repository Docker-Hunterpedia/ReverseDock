//! End-to-end: UDP listeners, routes and sessions through the real binary (M-L4-04,
//! ADR-0030).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;
use rdock_testkit::udp::{self, DnsBackend, UdpEcho, ask, dead_port, receive};
use tokio::net::UdpSocket;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const WAIT: Duration = Duration::from_secs(3);
/// How long a datagram that must not be answered is waited for.
const SILENCE: Duration = Duration::from_millis(400);

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A UDP port that is free now (`free_port` checks TCP).
fn free_udp_port() -> u16 {
    loop {
        let port = free_port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// The value of one sample in rdock's metrics, `0` when absent.
fn metric(rdock: &Rdock, series: &str) -> String {
    let (_, metrics) = rdock.get_admin("/metrics").unwrap_or_default();
    metrics
        .lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' ').map(str::to_owned))
        .unwrap_or_else(|| "0".to_owned())
}

fn sessions(rdock: &Rdock, listener: &str, route: &str) -> String {
    metric(
        rdock,
        &format!("rdock_udp_sessions{{listener=\"{listener}\",route=\"{route}\"}}"),
    )
}

fn dropped(rdock: &Rdock, listener: &str, reason: &str) -> String {
    metric(
        rdock,
        &format!("rdock_udp_dropped_total{{listener=\"{listener}\",reason=\"{reason}\"}}"),
    )
}

fn ends(rdock: &Rdock, route: &str, reason: &str) -> String {
    metric(
        rdock,
        &format!("rdock_udp_session_ends_total{{reason=\"{reason}\",route=\"{route}\"}}"),
    )
}

/// Waits until `f` returns `want` (polling), or panics after `limit`.
fn eventually(limit: Duration, what: &str, want: &str, f: impl Fn() -> String) {
    let started = Instant::now();
    loop {
        let got = f();
        if got == want {
            return;
        }
        assert!(started.elapsed() < limit, "{what}: {got}, want {want}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One `udp` listener `dns` on `port`, one route `r` to service `s` with `backends` (YAML
/// list items) and `service` extra settings, and `extra` top-level YAML.
fn config(port: u16, backends: &str, service: &str, extra: &str) -> String {
    format!(
        r#"
listeners:
  dns: {{ address: "127.0.0.1:{port}", protocol: udp }}
udp_routes:
  r: {{ listeners: [dns], service: s }}
udp_services:
  s:
    backends: [{backends}]
{service}
{extra}
"#
    )
}

fn text(reply: Option<Vec<u8>>) -> String {
    String::from_utf8(reply.expect("a reply")).unwrap()
}

#[tokio::test]
async fn two_clients_get_their_own_sessions_and_only_their_own_replies() {
    let echo = UdpEcho::start("one").await;
    let port = free_udp_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(port, &format!("{{ address: \"{}\" }}", echo.addr), "", ""),
    );
    // A socket that never sends must never receive anything from rdock.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = udp::client(addr(port)).await;
    let b = udp::client(addr(port)).await;
    assert_eq!(text(ask(&a, b"from-a", WAIT).await), "one:from-a");
    assert_eq!(text(ask(&b, b"from-b", WAIT).await), "one:from-b");
    assert_eq!(text(ask(&a, b"again", WAIT).await), "one:again");
    assert_eq!(sessions(&rdock, "dns", "r"), "2");
    assert_eq!(echo.sources().len(), 2, "one upstream socket per session");
    assert_eq!(echo.datagrams(), 3);
    assert_eq!(
        metric(
            &rdock,
            "rdock_udp_datagrams_total{direction=\"in\",route=\"r\"}"
        ),
        "3"
    );
    assert_eq!(
        metric(
            &rdock,
            "rdock_udp_datagrams_total{direction=\"out\",route=\"r\"}"
        ),
        "3"
    );
    assert_eq!(
        metric(
            &rdock,
            "rdock_udp_bytes_total{direction=\"in\",route=\"r\"}"
        ),
        "17"
    );
    assert_eq!(
        metric(
            &rdock,
            "rdock_udp_bytes_total{direction=\"out\",route=\"r\"}"
        ),
        "29"
    );
    // Neither reply crossed over to the other client, and the silent socket got nothing.
    assert_eq!(receive(&a, SILENCE).await, None);
    assert_eq!(receive(&b, Duration::from_millis(50)).await, None);
    assert_eq!(receive(&silent, Duration::from_millis(50)).await, None);
}

#[tokio::test]
async fn an_idle_session_closes_and_a_later_datagram_opens_a_new_one() {
    let echo = UdpEcho::start("one").await;
    let port = free_udp_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            &format!("{{ address: \"{}\" }}", echo.addr),
            "    timeouts: { idle: 300ms }",
            "",
        ),
    );
    let client = udp::client(addr(port)).await;
    assert_eq!(text(ask(&client, b"1", WAIT).await), "one:1");
    // Traffic keeps it open.
    for i in 0..4 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(text(ask(&client, b"x", WAIT).await), "one:x", "{i}");
    }
    assert_eq!(echo.sources().len(), 1);
    eventually(WAIT, "sessions", "0", || sessions(&rdock, "dns", "r"));
    assert_eq!(ends(&rdock, "r", "idle"), "1");
    assert_eq!(text(ask(&client, b"2", WAIT).await), "one:2");
    assert_eq!(
        echo.sources().len(),
        2,
        "a new session, a new upstream socket"
    );
}

#[tokio::test]
async fn responses_one_ends_a_dns_session_with_its_answer() {
    let dns = DnsBackend::start().await;
    let port = free_udp_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            &format!("{{ address: \"{}\" }}", dns.addr),
            "    responses: 1",
            "",
        ),
    );
    let client = udp::client(addr(port)).await;
    let query = udp::dns_query(0x1234, "example.test");
    let answer = ask(&client, &query, WAIT).await.expect("an answer");
    assert_eq!(&answer[..2], &[0x12, 0x34], "the same query ID");
    assert_eq!(answer[2] & 0x80, 0x80, "QR set");
    assert_eq!(&answer[12..], &query[12..], "the question");
    eventually(WAIT, "sessions", "0", || sessions(&rdock, "dns", "r"));
    assert_eq!(ends(&rdock, "r", "responses"), "1");
    let answer = ask(&client, &udp::dns_query(7, "example.test"), WAIT)
        .await
        .expect("a second answer");
    assert_eq!(&answer[..2], &[0, 7]);
    eventually(WAIT, "ends", "2", || ends(&rdock, "r", "responses"));
}

#[tokio::test]
async fn responses_counts_replies_and_requests_detaches_the_client() {
    let echo = UdpEcho::start_with("one", 2).await;
    let port = free_udp_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            &format!("{{ address: \"{}\" }}", echo.addr),
            "    responses: 2\n    requests: 1",
            "",
        ),
    );
    let client = udp::client(addr(port)).await;
    assert_eq!(text(ask(&client, b"a", WAIT).await), "one:a");
    assert_eq!(text(receive(&client, WAIT).await), "one:a");
    eventually(WAIT, "ends", "1", || ends(&rdock, "r", "responses"));
    // `requests: 1`: every datagram is a session of its own.
    client.send(b"b").await.unwrap();
    client.send(b"c").await.unwrap();
    let mut got = Vec::new();
    for _ in 0..4 {
        got.push(text(receive(&client, WAIT).await));
    }
    got.sort();
    assert_eq!(got, ["one:b", "one:b", "one:c", "one:c"]);
    assert_eq!(echo.sources().len(), 3);
}

#[tokio::test]
async fn session_caps_drop_and_count_without_answering() {
    let echo = UdpEcho::start("one").await;
    let (port, per_client) = (free_udp_port(), free_udp_port());
    let rdock = Rdock::start(
        RDOCK,
        &format!(
            r#"
listeners:
  total: {{ address: "127.0.0.1:{port}", protocol: udp, sessions: {{ max: 2, max_per_client: unlimited }} }}
  each: {{ address: "127.0.0.1:{per_client}", protocol: udp, sessions: {{ max: unlimited, max_per_client: 1 }} }}
udp_routes:
  r: {{ listeners: [total, each], service: s }}
udp_services:
  s: {{ backends: [{{ address: "{}" }}] }}
"#,
            echo.addr
        ),
    );
    let one = udp::client(addr(port)).await;
    let two = udp::client(addr(port)).await;
    let three = udp::client(addr(port)).await;
    assert!(ask(&one, b"1", WAIT).await.is_some());
    assert!(ask(&two, b"2", WAIT).await.is_some());
    assert_eq!(ask(&three, b"3", SILENCE).await, None);
    assert_eq!(dropped(&rdock, "total", "session_limit"), "1");
    // A live session still gets through at the cap.
    assert!(ask(&one, b"1", WAIT).await.is_some());
    let first = udp::client(addr(per_client)).await;
    let second = udp::client(addr(per_client)).await;
    assert!(ask(&first, b"a", WAIT).await.is_some());
    assert_eq!(ask(&second, b"b", SILENCE).await, None);
    assert_eq!(dropped(&rdock, "each", "client_limit"), "1");
    assert_eq!(echo.datagrams(), 4);
}

#[tokio::test]
async fn ip_deny_and_unmatched_clients_are_dropped_silently() {
    let echo = UdpEcho::start("one").await;
    let (port, other) = (free_udp_port(), free_udp_port());
    let rdock = Rdock::start(
        RDOCK,
        &format!(
            r#"
listeners:
  dns: {{ address: "127.0.0.1:{port}", protocol: udp }}
  lan: {{ address: "127.0.0.1:{other}", protocol: udp }}
middlewares:
  local: {{ type: ip_deny, cidrs: [127.0.0.0/8] }}
udp_routes:
  r: {{ listeners: [dns], service: s, middlewares: [local] }}
  lan: {{ match: "ClientIP(`10.0.0.0/8`)", listeners: [lan], service: s }}
udp_services:
  s: {{ backends: [{{ address: "{}" }}] }}
"#,
            echo.addr
        ),
    );
    let client = udp::client(addr(port)).await;
    assert_eq!(ask(&client, b"x", SILENCE).await, None);
    assert_eq!(dropped(&rdock, "dns", "denied"), "1");
    let client = udp::client(addr(other)).await;
    assert_eq!(ask(&client, b"x", SILENCE).await, None);
    assert_eq!(dropped(&rdock, "lan", "no_route"), "1");
    assert_eq!(echo.datagrams(), 0);
}

#[tokio::test]
async fn weights_share_new_sessions_between_backends() {
    let heavy = UdpEcho::start("heavy").await;
    let light = UdpEcho::start("light").await;
    let port = free_udp_port();
    let _rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            &format!(
                "{{ address: \"{}\", weight: 3 }}, {{ address: \"{}\", weight: 1 }}",
                heavy.addr, light.addr
            ),
            "    responses: 1",
            "",
        ),
    );
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for _ in 0..40 {
        // A new socket per probe, as the Gateway API's weighted test does.
        let client = udp::client(addr(port)).await;
        let reply = text(ask(&client, b"w", WAIT).await);
        *counts
            .entry(reply.split(':').next().unwrap().to_owned())
            .or_default() += 1;
    }
    assert_eq!(counts["heavy"], 30, "{counts:?}");
    assert_eq!(counts["light"], 10, "{counts:?}");
}

#[tokio::test]
async fn a_refusing_backend_ends_its_session_and_is_ejected() {
    let echo = UdpEcho::start("up").await;
    let dead = dead_port();
    let port = free_udp_port();
    let rdock = Rdock::start(
        RDOCK,
        &config(
            port,
            &format!(
                "{{ address: \"{dead}\" }}, {{ address: \"{}\" }}",
                echo.addr
            ),
            "    health: { passive: { failures: 1 } }",
            "",
        ),
    );
    let mut answered = 0;
    let mut silent = 0;
    for _ in 0..2 {
        let client = udp::client(addr(port)).await;
        match ask(&client, b"x", SILENCE).await {
            Some(reply) => {
                assert_eq!(String::from_utf8(reply).unwrap(), "up:x");
                answered += 1;
            }
            None => silent += 1,
        }
    }
    assert_eq!((answered, silent), (1, 1), "round-robin over both backends");
    eventually(WAIT, "ends", "1", || {
        ends(&rdock, "r", "backend_unreachable")
    });
    assert_eq!(dropped(&rdock, "dns", "backend_unreachable"), "1");
    // The refusing backend is ejected: every new session goes to the other one.
    for i in 0..4 {
        let client = udp::client(addr(port)).await;
        assert_eq!(text(ask(&client, b"y", WAIT).await), "up:y", "{i}");
    }
}

#[tokio::test]
async fn a_reload_keeps_sessions_of_kept_listeners_and_closes_removed_ones() {
    let one = UdpEcho::start("one").await;
    let two = UdpEcho::start("two").await;
    let (kept, removed) = (free_udp_port(), free_udp_port());
    let config = |backend: SocketAddr, with_removed: bool| {
        let extra = if with_removed {
            format!("  gone: {{ address: \"127.0.0.1:{removed}\", protocol: udp }}\n")
        } else {
            String::new()
        };
        let route = if with_removed {
            "  gone: { listeners: [gone], service: s }\n"
        } else {
            ""
        };
        format!(
            r#"
lifecycle: {{ drain_timeout: 1s }}
listeners:
  kept: {{ address: "127.0.0.1:{kept}", protocol: udp }}
{extra}udp_routes:
  r: {{ listeners: [kept], service: s }}
{route}udp_services:
  s: {{ backends: [{{ address: "{backend}" }}] }}
"#
        )
    };
    let rdock = Rdock::start(RDOCK, &config(one.addr, true));
    let open = udp::client(addr(kept)).await;
    assert_eq!(text(ask(&open, b"before", WAIT).await), "one:before");
    let leaving = udp::client(addr(removed)).await;
    assert_eq!(text(ask(&leaving, b"before", WAIT).await), "one:before");
    assert_eq!(sessions(&rdock, "gone", "gone"), "1");
    rdock.write_config(&config(two.addr, false));
    let (status, body) = rdock.reload();
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        text(ask(&open, b"after", WAIT).await),
        "one:after",
        "the session keeps its socket and backend"
    );
    let fresh = udp::client(addr(kept)).await;
    assert_eq!(text(ask(&fresh, b"new", WAIT).await), "two:new");
    // The removed listener's session is closed once the drain time is over.
    eventually(Duration::from_secs(5), "sessions", "0", || {
        sessions(&rdock, "gone", "gone")
    });
    assert_eq!(ends(&rdock, "gone", "closed"), "1");
    let _ = leaving.send(b"late").await;
    assert_eq!(receive(&leaving, SILENCE).await, None);
}

#[tokio::test]
async fn large_datagrams_round_trip_and_oversize_ones_are_counted() {
    let echo = UdpEcho::start("e").await;
    let port = free_udp_port();
    let v6 = std::net::UdpSocket::bind("[::1]:0")
        .ok()
        .map(|s| s.local_addr().unwrap().port());
    let v6_listener = v6.map_or_else(String::new, |p| {
        drop(std::net::UdpSocket::bind(("::1", p)));
        format!("  six: {{ address: \"[::1]:{p}\", protocol: udp }}\n")
    });
    let routes = if v6.is_some() { "[dns, six]" } else { "[dns]" };
    let rdock = Rdock::start(
        RDOCK,
        &format!(
            r#"
listeners:
  dns: {{ address: "127.0.0.1:{port}", protocol: udp }}
{v6_listener}udp_routes:
  r: {{ listeners: {routes}, service: s }}
udp_services:
  s: {{ backends: [{{ address: "{}" }}] }}
"#,
            echo.addr
        ),
    );
    let client = udp::client(addr(port)).await;
    let big = vec![b'z'; 60 * 1024];
    let reply = ask(&client, &big, WAIT).await.expect("a 60 KiB answer");
    assert_eq!(reply.len(), big.len() + 2);
    assert_eq!(&reply[2..], &big[..]);
    let Some(six) = v6 else {
        eprintln!("skipped the oversize part: no IPv6 loopback");
        return;
    };
    // Over IPv6 a datagram may carry 65,527 bytes, over IPv4 only 65,507: this one cannot
    // reach the IPv4 backend, and is counted instead of being cut.
    let client = udp::client(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, six))).await;
    assert_eq!(ask(&client, &vec![b'o'; 65_520], SILENCE).await, None);
    assert_eq!(dropped(&rdock, "six", "oversize"), "1");
    assert_eq!(echo.datagrams(), 1);
}
