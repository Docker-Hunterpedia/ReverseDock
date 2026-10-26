//! The client connection as Pingora sees it: our accepted stream (TCP or TLS) plus two things
//! Pingora does not do on its own (ADR-0012):
//!
//! - A deadline for HTTP/1 request headers, counted from their first byte. Pingora only has a
//!   per-read timeout, which a client sending one byte at a time defeats (slowloris).
//! - Strict line endings: a bare LF in HTTP/1 request headers ends the connection. Pingora's
//!   parser accepts it, but a backend may split the request differently (RFC 9112 §2.2).
//! - The answer to Pingora's h2c "peek": the accept loop already read the first bytes, so the
//!   answer is immediate, instead of Pingora waiting for 24 bytes that a short HTTP/1.0 request
//!   never sends.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use pingora::protocols::raw_connect::ProxyDigest;
use pingora::protocols::tls::{SslDigest, TlsRef};
use pingora::protocols::{
    ALPN, GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    Stream, TimingDigest, UniqueID, UniqueIDType,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Where an HTTP/1 connection is in its request/response cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Reading request headers; `blank` is true while the current line is still empty, `cr`
    /// when the previous byte was a carriage return.
    Headers { blank: bool, cr: bool },
    /// Headers complete; the request body may follow until the response starts.
    Request,
    /// A final response is being written; the next bytes read start a new request.
    Responding,
    /// No deadlines: HTTP/2, or an upgraded (WebSocket) connection.
    Off,
}

/// A client connection with a header deadline and a prepared h2c answer.
pub struct ConnStream {
    inner: Stream,
    peek: Option<Vec<u8>>,
    phase: Phase,
    header_timeout: Duration,
    deadline: Pin<Box<Sleep>>,
}

impl fmt::Debug for ConnStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnStream")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl ConnStream {
    /// Wraps a connection. `peek` holds the bytes already read (cleartext only); `http1` turns
    /// the header deadline on.
    pub fn new(
        inner: Stream,
        peek: Option<Vec<u8>>,
        http1: bool,
        header_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            peek,
            phase: if http1 {
                Phase::Headers {
                    blank: false,
                    cr: false,
                }
            } else {
                Phase::Off
            },
            header_timeout,
            deadline: Box::pin(tokio::time::sleep(header_timeout)),
        }
    }

    /// Advances the phase over bytes read from the client. Fails on a bare LF in the headers.
    fn on_read(&mut self, data: &[u8]) -> Result<(), ()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.phase == Phase::Responding {
            self.phase = Phase::Headers {
                blank: false,
                cr: false,
            };
            let at = Instant::now() + self.header_timeout;
            self.deadline.as_mut().reset(at);
        }
        if let Phase::Headers { mut blank, mut cr } = self.phase {
            for &byte in data {
                match byte {
                    b'\n' if !cr => return Err(()),
                    b'\n' if blank => {
                        self.phase = Phase::Request;
                        return Ok(());
                    }
                    b'\n' => blank = true,
                    b'\r' => {}
                    _ => blank = false,
                }
                cr = byte == b'\r';
            }
            self.phase = Phase::Headers { blank, cr };
        }
        Ok(())
    }

    /// Advances the phase over bytes written to the client.
    fn on_write(&mut self, data: &[u8]) {
        if self.phase != Phase::Request || !data.starts_with(b"HTTP/1.") {
            return;
        }
        match data.get(9..12) {
            Some(b"101") => self.phase = Phase::Off,
            Some(code) if code.first() == Some(&b'1') => {}
            _ => self.phase = Phase::Responding,
        }
    }
}

impl AsyncRead for ConnStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if matches!(this.phase, Phase::Headers { .. }) && this.deadline.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request headers were not received in time",
            )));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            let filled = buf.filled()[before..].to_vec();
            if this.on_read(&filled).is_err() {
                buf.set_filled(before);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bare LF in request headers",
                )));
            }
        }
        result
    }
}

impl AsyncWrite for ConnStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let result = Pin::new(&mut this.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = result {
            this.on_write(&data[..n]);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl Shutdown for ConnStream {
    async fn shutdown(&mut self) {
        self.inner.shutdown().await;
    }
}

impl UniqueID for ConnStream {
    fn id(&self) -> UniqueIDType {
        self.inner.id()
    }
}

impl Ssl for ConnStream {
    fn get_ssl(&self) -> Option<&TlsRef> {
        self.inner.get_ssl()
    }

    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.inner.get_ssl_digest()
    }

    fn selected_alpn_proto(&self) -> Option<ALPN> {
        self.inner.selected_alpn_proto()
    }
}

impl GetTimingDigest for ConnStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.inner.get_timing_digest()
    }
}

impl GetProxyDigest for ConnStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.inner.get_proxy_digest()
    }
}

impl GetSocketDigest for ConnStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.inner.get_socket_digest()
    }

    fn set_socket_digest(&mut self, socket_digest: SocketDigest) {
        self.inner.set_socket_digest(socket_digest);
    }
}

#[async_trait]
impl Peek for ConnStream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        let Some(seen) = &self.peek else {
            return self.inner.try_peek(buf).await;
        };
        buf.fill(0);
        let n = seen.len().min(buf.len());
        buf[..n].copy_from_slice(&seen[..n]);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream() -> ConnStream {
        let (a, _b) = tokio::io::duplex(64);
        ConnStream::new(Box::new(a), None, true, Duration::from_secs(10))
    }

    #[tokio::test]
    async fn tracks_request_and_response_phases() {
        let mut c = stream();
        c.on_read(b"GET / HTTP/1.1\r\nHost: a\r").unwrap();
        assert!(matches!(c.phase, Phase::Headers { .. }));
        c.on_read(b"\n\r\n").unwrap();
        assert_eq!(c.phase, Phase::Request);
        c.on_write(b"HTTP/1.1 100 Continue\r\n\r\n");
        assert_eq!(c.phase, Phase::Request, "1xx keeps the request open");
        c.on_write(b"HTTP/1.1 200 OK\r\n");
        assert_eq!(c.phase, Phase::Responding);
        c.on_write(b"body bytes");
        assert_eq!(c.phase, Phase::Responding);
        c.on_read(b"GET /next").unwrap();
        assert!(
            matches!(c.phase, Phase::Headers { .. }),
            "a new request starts"
        );
        assert!(c.on_read(b" HTTP/1.1\n\n").is_err(), "bare LF is refused");
        c.phase = Phase::Request;
        c.on_write(b"HTTP/1.1 101 Switching Protocols\r\n");
        assert_eq!(c.phase, Phase::Off);
        c.on_read(b"\nanything").unwrap();
        assert_eq!(c.phase, Phase::Off);
    }

    #[tokio::test]
    async fn header_deadline_fires() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (a, mut b) = tokio::io::duplex(64);
        let mut c = ConnStream::new(Box::new(a), None, true, Duration::from_millis(50));
        b.write_all(b"GET / HT").await.unwrap();
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"GET / HT");
        let err = c.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn peek_answers_from_prefetched_bytes() {
        let (a, _b) = tokio::io::duplex(64);
        let mut c = ConnStream::new(
            Box::new(a),
            Some(b"GET / HTTP/1.0\r\n\r\n".to_vec()),
            true,
            Duration::from_secs(1),
        );
        let mut buf = [0u8; 24];
        assert!(c.try_peek(&mut buf).await.unwrap());
        assert_eq!(&buf[..4], b"GET ");
        assert_eq!(buf[23], 0);
    }
}
