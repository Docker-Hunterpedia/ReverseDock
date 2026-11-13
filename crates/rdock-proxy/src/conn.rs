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
use std::task::{Context, Poll, ready};
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

/// Bytes a response may wait in user space before one write to the socket. Pingora's own
/// listener gives a connection a 1460-byte write buffer, but a `TcpStream` turned into a
/// `Stream` directly has none, so the response header and body left as two writes and two
/// packets (#93). 8 KiB joins the header and a typical page or JSON body into one write; the
/// kernel still cuts it into full segments. Allocated on the first write, so an idle
/// connection costs nothing.
const WRITE_BUFFER: usize = 8 * 1024;

/// A client connection with a header deadline, a prepared h2c answer and a write buffer.
pub struct ConnStream {
    inner: Stream,
    peek: Option<Vec<u8>>,
    /// Bytes accepted but not yet written; the first `sent` of them are already on the socket.
    pending: Vec<u8>,
    sent: usize,
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
            pending: Vec::new(),
            sent: 0,
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

    /// Writes what is pending to the socket. Ready once nothing is pending.
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.sent..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the connection accepts no more bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => self.sent += n,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
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
        // Only headers are scanned, and a response in progress waits for the next request's
        // first byte; a body (`Request`) or a connection without deadlines (`Off`) is not
        // looked at, so its bytes are neither copied nor scanned.
        if let Poll::Ready(Ok(())) = result
            && !matches!(this.phase, Phase::Request | Phase::Off)
            && this.on_read(&buf.filled()[before..]).is_err()
        {
            buf.set_filled(before);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bare LF in request headers",
            )));
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
        let buffered = this.pending.len() - this.sent;
        if buffered > 0 && buffered + data.len() > WRITE_BUFFER {
            ready!(this.flush_pending(cx))?;
        }
        if data.len() >= WRITE_BUFFER {
            let result = Pin::new(&mut this.inner).poll_write(cx, data);
            if let Poll::Ready(Ok(n)) = result {
                this.on_write(&data[..n]);
            }
            return result;
        }
        if this.pending.capacity() == 0 {
            this.pending.reserve_exact(WRITE_BUFFER);
        }
        this.pending.extend_from_slice(data);
        this.on_write(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
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
    async fn header_and_body_leave_in_one_write_at_flush() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let mut c = ConnStream::new(Box::new(a), None, true, Duration::from_secs(1));
        c.phase = Phase::Request;
        let header = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
        c.write_all(header).await.unwrap();
        c.write_all(b"body").await.unwrap();
        assert_eq!(
            c.phase,
            Phase::Responding,
            "the phase follows buffered bytes"
        );
        assert_eq!(
            c.pending.len(),
            header.len() + 4,
            "nothing reached the socket yet"
        );
        let mut buf = vec![0u8; 64 * 1024];
        let early = tokio::time::timeout(Duration::from_millis(20), b.read(&mut buf)).await;
        assert!(early.is_err(), "no bytes before the flush");
        c.flush().await.unwrap();
        assert_eq!(c.pending, Vec::<u8>::new());
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], [&header[..], b"body"].concat());

        // A write of the buffer's size or more goes straight to the socket.
        let big = vec![b'x'; WRITE_BUFFER];
        c.write_all(&big).await.unwrap();
        assert_eq!(c.pending, Vec::<u8>::new());
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(n, WRITE_BUFFER);

        // Smaller writes are joined until the buffer would overflow, then flushed first.
        c.write_all(&big[..WRITE_BUFFER - 10]).await.unwrap();
        c.write_all(&big[..20]).await.unwrap();
        assert_eq!(
            c.pending.len(),
            20,
            "the full buffer was written before the next bytes"
        );
        AsyncWriteExt::shutdown(&mut c).await.unwrap();
        assert_eq!(c.pending, Vec::<u8>::new(), "shutdown flushes");
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
