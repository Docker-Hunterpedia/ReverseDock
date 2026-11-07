//! `starttls: postgres`: PostgreSQL's own request to start TLS, answered before the ClientHello
//! is read.
//!
//! With the default `sslnegotiation=postgres`, a client sends the 8-byte `SSLRequest` (length
//! 8, code 80877103) and waits for one byte, `S` or `N`, before its ClientHello; a client that
//! may use GSSAPI encryption first sends a `GSSENCRequest` (code 80877104), which a server
//! without GSSAPI answers with `N` (<https://www.postgresql.org/docs/17/protocol-flow.html>,
//! checked 2026-11-07). Any other first bytes are no request and are put back untouched.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// `SSLRequest`: length 8, then 80877103 (`0x04D2162F`).
pub const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];
/// `GSSENCRequest`: length 8, then 80877104 (`0x04D21630`).
const GSSENC_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x30];

/// What the step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiated {
    /// The client asked for TLS and was told `S`; its ClientHello comes next.
    Tls,
    /// The client sent no `SSLRequest`; `read` are the bytes to put back.
    Plain {
        /// Bytes read.
        read: Vec<u8>,
    },
}

/// The client closed the connection, or did not finish a request before the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

/// Answers a PostgreSQL `SSLRequest` (after declining a `GSSENCRequest`) at the start of
/// `stream`, until `deadline`.
///
/// # Errors
///
/// [`Closed`] when the client went away or stalled in the middle of a request.
pub async fn postgres<S>(stream: &mut S, deadline: Instant) -> Result<Negotiated, Closed>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut declined_gssenc = false;
    loop {
        let read = read_request(stream, deadline).await?;
        let answer = if read == SSL_REQUEST {
            b'S'
        } else if read == GSSENC_REQUEST && !declined_gssenc {
            declined_gssenc = true;
            b'N'
        } else {
            return Ok(Negotiated::Plain { read });
        };
        let written = tokio::time::timeout_at(deadline, async {
            stream.write_all(&[answer]).await?;
            stream.flush().await
        })
        .await;
        if !matches!(written, Ok(Ok(()))) {
            return Err(Closed);
        }
        if answer == b'S' {
            return Ok(Negotiated::Tls);
        }
    }
}

/// Reads until the bytes are a complete request or cannot become one.
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Vec<u8>, Closed> {
    let mut buf = Vec::with_capacity(SSL_REQUEST.len());
    let mut chunk = [0u8; SSL_REQUEST.len()];
    while buf.len() < SSL_REQUEST.len() && could_be_request(&buf) {
        let want = SSL_REQUEST.len() - buf.len();
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..want])).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return Err(Closed),
        }
    }
    Ok(buf)
}

fn could_be_request(buf: &[u8]) -> bool {
    SSL_REQUEST.starts_with(buf) || GSSENC_REQUEST.starts_with(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use tokio::io::duplex;

    use super::*;

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    #[tokio::test]
    async fn answers_an_ssl_request_with_s() {
        let (mut client, mut server) = duplex(64);
        // Sent in two pieces, as a slow client might.
        client.write_all(&SSL_REQUEST[..3]).await.unwrap();
        let step = tokio::spawn(async move { (postgres(&mut server, soon()).await, server) });
        client.write_all(&SSL_REQUEST[3..]).await.unwrap();
        let (result, _server) = step.await.unwrap();
        assert_eq!(result, Ok(Negotiated::Tls));
        let mut answer = [0u8; 1];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"S");
    }

    #[tokio::test]
    async fn declines_gssapi_then_accepts_tls() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&GSSENC_REQUEST).await.unwrap();
        client.write_all(&SSL_REQUEST).await.unwrap();
        assert_eq!(postgres(&mut server, soon()).await, Ok(Negotiated::Tls));
        let mut answers = [0u8; 2];
        client.read_exact(&mut answers).await.unwrap();
        assert_eq!(&answers, b"NS");
    }

    #[tokio::test]
    async fn other_bytes_are_handed_back() {
        let (mut client, mut server) = duplex(64);
        // A TLS ClientHello record header: no request, nothing answered.
        client
            .write_all(&[0x16, 0x03, 0x01, 0x02, 0x00])
            .await
            .unwrap();
        let read = postgres(&mut server, soon()).await.unwrap();
        assert_eq!(
            read,
            Negotiated::Plain {
                read: vec![0x16, 0x03, 0x01, 0x02, 0x00]
            }
        );
        // A startup message (protocol 3.0) starts with its length.
        let (mut client, mut server) = duplex(64);
        client.write_all(&[0, 0, 0, 40, 0, 3, 0, 0]).await.unwrap();
        let read = postgres(&mut server, soon()).await.unwrap();
        assert_eq!(
            read,
            Negotiated::Plain {
                read: vec![0, 0, 0, 40, 0, 3, 0, 0]
            }
        );
        drop(client);
    }

    #[tokio::test]
    async fn a_second_gssenc_request_is_not_answered() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&GSSENC_REQUEST).await.unwrap();
        client.write_all(&GSSENC_REQUEST).await.unwrap();
        let read = postgres(&mut server, soon()).await.unwrap();
        assert_eq!(
            read,
            Negotiated::Plain {
                read: GSSENC_REQUEST.to_vec()
            }
        );
    }

    #[tokio::test]
    async fn a_stalled_or_closed_client_is_closed() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&SSL_REQUEST[..4]).await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(50);
        assert_eq!(postgres(&mut server, deadline).await, Err(Closed));
        drop(client);
        let (client, mut server) = duplex(64);
        drop(client);
        assert_eq!(postgres(&mut server, soon()).await, Err(Closed));
    }
}
