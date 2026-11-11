//! UDP backends and clients for UDP-route tests: an echo server that answers every datagram
//! with its name and the datagram (and can answer more than once), a DNS-shaped server, and a
//! port where nothing listens.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;

/// A running UDP echo backend: every datagram is answered `copies` times with
/// `<name>:<datagram>`.
pub struct UdpEcho {
    pub addr: SocketAddr,
    pub name: String,
    seen: Arc<Mutex<Vec<SocketAddr>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for UdpEcho {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl UdpEcho {
    /// An echo backend on `127.0.0.1` that answers once.
    pub async fn start(name: &str) -> Self {
        Self::start_with(name, 1).await
    }

    /// An echo backend on `127.0.0.1` that answers `copies` times.
    pub async fn start_with(name: &str, copies: usize) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        let prefix = format!("{name}:").into_bytes();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                record.lock().unwrap().push(from);
                let mut reply = prefix.clone();
                reply.extend_from_slice(&buf[..n]);
                for _ in 0..copies {
                    let _ = socket.send_to(&reply, from).await;
                }
            }
        });
        Self {
            addr,
            name: name.to_owned(),
            seen,
            task,
        }
    }

    /// Datagrams received so far.
    pub fn datagrams(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// Distinct source addresses seen so far: one per rdock session.
    pub fn sources(&self) -> BTreeSet<SocketAddr> {
        self.seen.lock().unwrap().iter().copied().collect()
    }
}

/// A DNS-shaped backend: answers every query with the same ID, `QR` set, `RCODE` 0, the
/// question copied and no records.
pub struct DnsBackend {
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DnsBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DnsBackend {
    pub async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                if n < 12 {
                    continue;
                }
                let mut answer = buf[..n].to_vec();
                answer[2] |= 0x80; // QR: a response
                answer[3] &= 0xF0; // RCODE 0
                let _ = socket.send_to(&answer, from).await;
            }
        });
        Self { addr, task }
    }
}

/// A DNS query for `name`, type A, class IN, with `id`.
pub fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        q.push(u8::try_from(label.len()).unwrap());
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// A UDP port on `127.0.0.1` where nothing listens: datagrams sent there get ICMP "port
/// unreachable".
pub fn dead_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

/// A client socket on `127.0.0.1` connected to `to`.
pub async fn client(to: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(if to.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .await
    .unwrap();
    socket.connect(to).await.unwrap();
    socket
}

/// Sends `datagram` on `socket` and waits up to `wait` for one answer.
pub async fn ask(socket: &UdpSocket, datagram: &[u8], wait: Duration) -> Option<Vec<u8>> {
    socket.send(datagram).await.unwrap();
    receive(socket, wait).await
}

/// The next datagram on `socket` within `wait`.
pub async fn receive(socket: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 65_536];
    match tokio::time::timeout(wait, socket.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}
