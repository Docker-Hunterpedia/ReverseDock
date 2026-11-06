//! One DNS request and its answer over TCP (two-byte length prefix, RFC 1035 §4.2.2) or UDP,
//! within 30 seconds. A truncated UDP answer is fetched again over TCP.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rdock_model::acme::DnsTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Time allowed for one exchange.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The largest UDP answer read; larger ones arrive truncated and are fetched over TCP.
const UDP_BUFFER: usize = 4096;
/// The TC bit in the third header byte.
const TRUNCATED: u8 = 0b0000_0010;

/// Sends `request` (with message id `id`) to `server` and returns the answer's bytes.
pub(super) async fn exchange(
    transport: DnsTransport,
    server: SocketAddr,
    request: &[u8],
    id: u16,
) -> io::Result<Vec<u8>> {
    tokio::time::timeout(TIMEOUT, async {
        match transport {
            DnsTransport::Tcp => tcp(server, request).await,
            DnsTransport::Udp => {
                let answer = udp(server, request, id).await?;
                if answer.get(2).is_some_and(|flags| flags & TRUNCATED != 0) {
                    tcp(server, request).await
                } else {
                    Ok(answer)
                }
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer within 30 s"))?
}

async fn tcp(server: SocketAddr, request: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(request.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS message too long"))?;
    let mut stream = TcpStream::connect(server).await?;
    let mut framed = Vec::with_capacity(request.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(request);
    stream.write_all(&framed).await?;
    let answer_length = stream.read_u16().await?;
    let mut answer = vec![0; usize::from(answer_length)];
    stream.read_exact(&mut answer).await?;
    Ok(answer)
}

/// Sends one datagram and waits for the answer carrying `id`, ignoring strays.
async fn udp(server: SocketAddr, request: &[u8], id: u16) -> io::Result<Vec<u8>> {
    let local: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(server).await?;
    socket.send(request).await?;
    let mut buffer = vec![0; UDP_BUFFER];
    loop {
        let received = socket.recv(&mut buffer).await?;
        if received >= 2 && buffer[..2] == id.to_be_bytes() {
            buffer.truncate(received);
            return Ok(buffer);
        }
    }
}
