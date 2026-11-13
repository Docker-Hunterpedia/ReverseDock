//! One HTTP/3 request stream as a Pingora custom server session (`Session::Custom`,
//! ADR-0032): the router, middlewares, cache and access log see it like an HTTP/1 or HTTP/2
//! request.
//!
//! What the session holds the client to:
//! - the request body is read with the listener's `timeouts.read` between DATA frames (Pingora
//!   sets it before the request is routed), so a trickling body ends the request and its
//!   upstream connection instead of holding them;
//! - the DATA received must add up to `content-length` when one was sent (RFC 9114 §4.1.2),
//!   otherwise the stream is reset with `H3_MESSAGE_ERROR` and the request fails;
//! - a client that resets the stream mid-body makes the read fail, which ends the upstream
//!   request (Pingora drops the upstream connection of a request that failed mid-body).
//!
//! Request trailers are read and dropped: Pingora 0.9 forwards none to an HTTP/1 upstream.
//! Response trailers are sent (an h2c or HTTPS backend's gRPC status, for example).

use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use http::HeaderMap;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::protocols::Digest;
use pingora::protocols::http::HttpTask;
use pingora::protocols::http::body_buffer::FixedBuffer;
use pingora::protocols::http::custom::CustomMessageWrite;
use pingora::protocols::http::custom::server::Session as CustomSession;
use pingora::protocols::l4::socket::SocketAddr;
use pingora::{Error, ErrorType};
use tokio::sync::watch;

use super::stream::{RequestIo, StreamFailure, code};

/// Request body kept for a retry on another backend (Pingora's HTTP/1 and HTTP/2 limit).
const RETRY_BUFFER: usize = 64 * 1024;

/// Response fields that only mean something on one HTTP/1.1 connection (RFC 9114 §4.2).
const CONNECTION_SPECIFIC: [&str; 5] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// One HTTP/3 request.
pub struct H3Session {
    /// `Sync` for Pingora's trait; only ever reached through `&mut self` (`get_mut`).
    io: std::sync::Mutex<Box<dyn RequestIo>>,
    header: RequestHeader,
    content_length: Option<u64>,
    body_read: usize,
    body_sent: usize,
    /// The client ended the request body.
    body_ended: bool,
    /// Data read while checking for an empty body, returned by the next read.
    peeked: Option<Bytes>,
    /// An error seen while checking for an empty body, returned by the next read.
    peek_error: Option<String>,
    response: Option<Box<ResponseHeader>>,
    /// The response ended (finished, or the stream was reset).
    ended: bool,
    retry_buffer: Option<FixedBuffer>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    drain_timeout: Option<Duration>,
    digest: Digest,
    client: SocketAddr,
    server: SocketAddr,
    /// Becomes `true` when the QUIC connection is gone.
    closed: watch::Receiver<bool>,
    /// The connection's count of client resets (Rapid Reset style floods).
    resets: Option<Arc<super::endpoint::Resets>>,
    /// When the first piece of the request body was asked for (the minimum-rate clock).
    body_started: Option<std::time::Instant>,
}

impl H3Session {
    /// A session for a validated request on `io`.
    pub fn new(
        io: Box<dyn RequestIo>,
        header: RequestHeader,
        content_length: Option<u64>,
        digest: Digest,
        (client, server): (std::net::SocketAddr, std::net::SocketAddr),
        closed: watch::Receiver<bool>,
    ) -> Self {
        Self {
            io: std::sync::Mutex::new(io),
            header,
            content_length,
            body_read: 0,
            body_sent: 0,
            body_ended: false,
            peeked: None,
            peek_error: None,
            response: None,
            ended: false,
            retry_buffer: None,
            read_timeout: None,
            write_timeout: None,
            drain_timeout: None,
            digest,
            client: SocketAddr::Inet(client),
            server: SocketAddr::Inet(server),
            closed,
            resets: None,
            body_started: None,
        }
    }

    /// Counts the client's resets of this stream in the connection's flood counter.
    #[must_use]
    pub fn with_resets(mut self, resets: Arc<super::endpoint::Resets>) -> Self {
        self.resets = Some(resets);
        self
    }

    fn client_reset(&mut self) {
        self.ended = true;
        if let Some(resets) = &self.resets {
            resets.add();
        }
    }

    fn io(&mut self) -> &mut dyn RequestIo {
        self.io
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
    }

    fn reset(&mut self, code: u64) {
        if !self.ended {
            self.ended = true;
            self.io().reset(code);
        }
    }

    /// Accounts one piece of the request body and holds it to `content-length`.
    fn take_data(&mut self, data: Bytes) -> pingora::Result<Option<Bytes>> {
        self.body_read += data.len();
        if let (Some(started), Some(grace)) = (self.body_started, self.read_timeout)
            && too_slow(self.body_read, started.elapsed(), grace)
        {
            self.reset(code::REQUEST_CANCELLED);
            return Error::e_explain(
                ErrorType::ReadTimedout,
                "HTTP/3 request body slower than 1 KiB/s",
            );
        }
        if self
            .content_length
            .is_some_and(|cl| self.body_read as u64 > cl)
        {
            self.reset(code::MESSAGE_ERROR);
            return Error::e_explain(
                ErrorType::InvalidHTTPHeader,
                "HTTP/3 request body longer than its content-length",
            );
        }
        if let Some(buffer) = self.retry_buffer.as_mut() {
            buffer.write_to_buffer(&data);
        }
        Ok(Some(data))
    }

    /// The body ended: it must have been as long as declared.
    fn end_of_body(&mut self) -> pingora::Result<Option<Bytes>> {
        self.body_ended = true;
        if self
            .content_length
            .is_some_and(|cl| self.body_read as u64 != cl)
        {
            self.reset(code::MESSAGE_ERROR);
            return Error::e_explain(
                ErrorType::InvalidHTTPHeader,
                "HTTP/3 request body shorter than its content-length",
            );
        }
        Ok(None)
    }

    async fn write_timed<F>(&mut self, op: F) -> pingora::Result<()>
    where
        F: AsyncOp,
    {
        let timeout = self.write_timeout;
        let io = self
            .io
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut();
        let done = if let Some(t) = timeout {
            let Ok(done) = tokio::time::timeout(t, op.run(io)).await else {
                self.reset(code::REQUEST_CANCELLED);
                return Error::e_explain(ErrorType::WriteTimedout, "writing to the HTTP/3 client");
            };
            done
        } else {
            op.run(io).await
        };
        done.map_err(|e| {
            self.client_reset();
            Error::because(ErrorType::WriteError, "writing to the HTTP/3 client", e)
        })
    }

    async fn send_header(&mut self, resp: &ResponseHeader, end: bool) -> pingora::Result<()> {
        if self.ended {
            return Error::e_explain(ErrorType::WriteError, "the HTTP/3 response ended");
        }
        let informational = resp.status.is_informational();
        if informational && resp.status == http::StatusCode::SWITCHING_PROTOCOLS {
            return Error::e_explain(ErrorType::InternalError, "101 over HTTP/3");
        }
        if !informational && self.response.is_some() {
            return Error::e_explain(ErrorType::InternalError, "a second HTTP/3 response");
        }
        let mut headers = HeaderMap::with_capacity(resp.headers.len());
        for (name, value) in &resp.headers {
            if !CONNECTION_SPECIFIC.contains(&name.as_str()) {
                headers.append(name.clone(), value.clone());
            }
        }
        let mut response = http::Response::new(());
        *response.status_mut() = resp.status;
        *response.headers_mut() = headers;
        self.write_timed(SendResponse(Some(response))).await?;
        if !informational {
            self.response = Some(Box::new(resp.clone()));
        }
        if end && !informational {
            self.finish_stream().await?;
        }
        Ok(())
    }

    async fn finish_stream(&mut self) -> pingora::Result<()> {
        if self.ended {
            return Ok(());
        }
        self.write_timed(Finish).await?;
        self.ended = true;
        Ok(())
    }

    /// Waits until the QUIC connection is gone.
    async fn idle(&mut self) -> pingora::Result<Option<Bytes>> {
        let _ = self.closed.wait_for(|closed| *closed).await;
        Error::e_explain(ErrorType::ConnectionClosed, "the HTTP/3 connection closed")
    }
}

/// One write on the stream, so `write_timed` can apply the timeout to any of them.
trait AsyncOp {
    fn run(
        self,
        io: &mut dyn RequestIo,
    ) -> impl std::future::Future<Output = Result<(), StreamFailure>> + Send;
}

struct SendResponse(Option<http::Response<()>>);
struct SendData(Bytes);
struct SendTrailers(HeaderMap);
struct Finish;

impl AsyncOp for SendResponse {
    async fn run(mut self, io: &mut dyn RequestIo) -> Result<(), StreamFailure> {
        match self.0.take() {
            Some(response) => io.send_response(response).await,
            None => Ok(()),
        }
    }
}

impl AsyncOp for SendData {
    async fn run(self, io: &mut dyn RequestIo) -> Result<(), StreamFailure> {
        io.send_data(self.0).await
    }
}

impl AsyncOp for SendTrailers {
    async fn run(self, io: &mut dyn RequestIo) -> Result<(), StreamFailure> {
        io.send_trailers(self.0).await
    }
}

impl AsyncOp for Finish {
    async fn run(self, io: &mut dyn RequestIo) -> Result<(), StreamFailure> {
        io.finish().await
    }
}

#[async_trait]
impl CustomSession for H3Session {
    fn req_header(&self) -> &RequestHeader {
        &self.header
    }

    fn req_header_mut(&mut self) -> &mut RequestHeader {
        &mut self.header
    }

    async fn read_body_bytes(&mut self) -> pingora::Result<Option<Bytes>> {
        if let Some(data) = self.peeked.take() {
            return self.take_data(data);
        }
        if let Some(err) = self.peek_error.take() {
            return Error::e_explain(ErrorType::ReadError, err);
        }
        if self.body_ended {
            return Ok(None);
        }
        self.body_started
            .get_or_insert_with(std::time::Instant::now);
        let timeout = self.read_timeout;
        let io = self.io();
        let read = std::future::poll_fn(|cx| io.poll_data(cx));
        let read = if let Some(t) = timeout {
            let Ok(read) = tokio::time::timeout(t, read).await else {
                self.reset(code::REQUEST_CANCELLED);
                return Error::e_explain(
                    ErrorType::ReadTimedout,
                    "reading the HTTP/3 request body",
                );
            };
            read
        } else {
            read.await
        };
        match read {
            Ok(Some(data)) => self.take_data(data),
            Ok(None) => self.end_of_body(),
            Err(err) => {
                self.client_reset();
                Error::e_because(ErrorType::ReadError, "reading the HTTP/3 request body", err)
            }
        }
    }

    async fn drain_request_body(&mut self) -> pingora::Result<()> {
        while self.read_body_bytes().await?.is_some() {}
        Ok(())
    }

    async fn write_response_header(
        &mut self,
        resp: Box<ResponseHeader>,
        end: bool,
    ) -> pingora::Result<()> {
        self.send_header(&resp, end).await
    }

    async fn write_response_header_ref(
        &mut self,
        resp: &ResponseHeader,
        end: bool,
    ) -> pingora::Result<()> {
        self.send_header(resp, end).await
    }

    async fn write_body(&mut self, data: Bytes, end: bool) -> pingora::Result<()> {
        if self.ended {
            return Error::e_explain(ErrorType::WriteError, "the HTTP/3 response ended");
        }
        if !data.is_empty() {
            let n = data.len();
            self.write_timed(SendData(data)).await?;
            self.body_sent += n;
        }
        if end {
            self.finish_stream().await?;
        }
        Ok(())
    }

    async fn write_trailers(&mut self, trailers: HeaderMap) -> pingora::Result<()> {
        if self.ended {
            return Error::e_explain(ErrorType::WriteError, "the HTTP/3 response ended");
        }
        self.write_timed(SendTrailers(trailers)).await?;
        self.finish_stream().await
    }

    async fn response_duplex_vec(&mut self, tasks: Vec<HttpTask>) -> pingora::Result<bool> {
        let mut end_stream = false;
        for task in tasks {
            let end = match task {
                HttpTask::Header(header, end) => {
                    self.send_header(&header, end).await?;
                    end
                }
                HttpTask::Body(data, end) => {
                    self.write_body(data.unwrap_or_default(), end).await?;
                    end
                }
                HttpTask::UpgradedBody(..) => {
                    return Error::e_explain(
                        ErrorType::InternalError,
                        "an upgraded body on an HTTP/3 session",
                    );
                }
                HttpTask::Trailer(Some(trailers)) => {
                    self.write_trailers(*trailers).await?;
                    true
                }
                HttpTask::Trailer(None) | HttpTask::Done => true,
                HttpTask::Failed(e) => return Err(e),
            };
            end_stream = end || end_stream;
        }
        if end_stream {
            self.finish_stream().await?;
        }
        Ok(end_stream)
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    fn get_read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    fn get_write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }

    fn set_total_drain_timeout(&mut self, timeout: Option<Duration>) {
        self.drain_timeout = timeout;
    }

    fn get_total_drain_timeout(&self) -> Option<Duration> {
        self.drain_timeout
    }

    fn request_summary(&self) -> String {
        format!(
            "{} {}, Host: {}",
            self.header.method,
            self.header
                .uri
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str),
            self.header
                .headers
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
        )
    }

    fn response_written(&self) -> Option<&ResponseHeader> {
        self.response.as_deref()
    }

    async fn shutdown(&mut self, _code: u32, _ctx: &str) {
        self.reset(code::INTERNAL_ERROR);
    }

    async fn abandon(&mut self, _ctx: &str) {
        self.reset(code::INTERNAL_ERROR);
    }

    fn is_body_done(&mut self) -> bool {
        self.peeked.is_none() && (self.body_ended || self.is_body_empty())
    }

    async fn finish(&mut self) -> pingora::Result<()> {
        self.finish_stream().await
    }

    fn is_body_empty(&mut self) -> bool {
        if self.body_read > 0 || self.peeked.is_some() || self.peek_error.is_some() {
            return false;
        }
        if self.content_length == Some(0) || self.body_ended {
            return true;
        }
        // The FIN usually arrives with the HEADERS frame of a request without a body: look
        // once without waiting, and keep what was read for the next read.
        let mut cx = Context::from_waker(Waker::noop());
        match self.io().poll_data(&mut cx) {
            Poll::Ready(Ok(None)) => {
                self.body_ended = true;
                // A declared body that never came is reported by the next read.
                if self.content_length.is_some_and(|cl| cl > 0) {
                    self.peek_error =
                        Some("HTTP/3 request body shorter than its content-length".into());
                    return false;
                }
                true
            }
            Poll::Ready(Ok(Some(data))) => {
                if data.is_empty() {
                    // An empty DATA frame says nothing either way.
                    return false;
                }
                self.peeked = Some(data);
                false
            }
            Poll::Ready(Err(err)) => {
                self.peek_error = Some(err.to_string());
                false
            }
            Poll::Pending => false,
        }
    }

    async fn read_body_or_idle(
        &mut self,
        no_body_expected: bool,
    ) -> pingora::Result<Option<Bytes>> {
        if no_body_expected || self.is_body_done() {
            self.idle().await
        } else {
            self.read_body_bytes().await
        }
    }

    fn body_bytes_sent(&self) -> usize {
        self.body_sent
    }

    fn body_bytes_read(&self) -> usize {
        self.body_read
    }

    fn digest(&self) -> Option<&Digest> {
        Some(&self.digest)
    }

    fn digest_mut(&mut self) -> Option<&mut Digest> {
        Some(&mut self.digest)
    }

    fn client_addr(&self) -> Option<&SocketAddr> {
        Some(&self.client)
    }

    fn server_addr(&self) -> Option<&SocketAddr> {
        Some(&self.server)
    }

    fn pseudo_raw_h1_request_header(&self) -> Bytes {
        let mut out = BytesMut::new();
        out.extend_from_slice(self.header.method.as_str().as_bytes());
        out.extend_from_slice(b" ");
        out.extend_from_slice(self.header.raw_path());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        for (name, value) in &self.header.headers {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.freeze()
    }

    fn enable_retry_buffering(&mut self) {
        if self.retry_buffer.is_none() {
            self.retry_buffer = Some(FixedBuffer::new(RETRY_BUFFER));
        }
    }

    fn retry_buffer_truncated(&self) -> bool {
        self.retry_buffer
            .as_ref()
            .is_some_and(FixedBuffer::is_truncated)
    }

    fn get_retry_buffer(&self) -> Option<Bytes> {
        self.retry_buffer.as_ref().and_then(|b| {
            if b.is_truncated() {
                None
            } else {
                b.get_buffer()
            }
        })
    }

    async fn finish_custom(&mut self) -> pingora::Result<()> {
        Ok(())
    }

    fn take_custom_message_reader(
        &mut self,
    ) -> Option<Box<dyn Stream<Item = pingora::Result<Bytes>> + Unpin + Send + Sync + 'static>>
    {
        None
    }

    fn restore_custom_message_reader(
        &mut self,
        _reader: Box<dyn Stream<Item = pingora::Result<Bytes>> + Unpin + Send + Sync + 'static>,
    ) -> pingora::Result<()> {
        Ok(())
    }

    fn take_custom_message_writer(&mut self) -> Option<Box<dyn CustomMessageWrite>> {
        None
    }

    fn restore_custom_message_writer(
        &mut self,
        _writer: Box<dyn CustomMessageWrite>,
    ) -> pingora::Result<()> {
        Ok(())
    }
}

impl Drop for H3Session {
    fn drop(&mut self) {
        // A request that ends without a finished response (an error, a dropped task) is
        // cancelled, never left open for the client to wait on.
        self.reset(code::REQUEST_CANCELLED);
    }
}

/// Least average request body rate once the grace (the listener's `timeouts.read`) is over.
const MIN_BODY_RATE: u64 = 1024;

/// Whether a body that has sent `read` bytes in `elapsed` is below [`MIN_BODY_RATE`] after
/// `grace`.
fn too_slow(read: usize, elapsed: Duration, grace: Duration) -> bool {
    let Some(rated) = elapsed.checked_sub(grace) else {
        return false;
    };
    (read as u64) < MIN_BODY_RATE.saturating_mul(rated.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_minimum_rate_applies_after_the_grace() {
        let grace = Duration::from_secs(60);
        assert!(!too_slow(0, Duration::from_secs(59), grace));
        assert!(!too_slow(0, Duration::from_secs(60), grace));
        assert!(too_slow(1000, Duration::from_secs(61), grace));
        assert!(!too_slow(1024, Duration::from_secs(61), grace));
        assert!(!too_slow(10 << 20, Duration::from_secs(600), grace));
        assert!(too_slow(100 << 10, Duration::from_secs(200), grace));
    }
}
