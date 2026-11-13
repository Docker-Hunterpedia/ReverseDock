//! The thin layer between the HTTP/3 session and the `h3` crate (ADR-0032): everything the
//! session needs from a request stream, so a change of `h3`'s API, or a replacement of `h3`,
//! touches this file only.

use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http::HeaderMap;

/// HTTP/3 error codes (RFC 9114 §8.1).
pub mod code {
    /// No error.
    pub const NO_ERROR: u64 = 0x100;
    /// An internal error.
    pub const INTERNAL_ERROR: u64 = 0x102;
    /// The request was rejected without processing (sent after GOAWAY).
    pub const REQUEST_REJECTED: u64 = 0x10b;
    /// The request was cancelled.
    pub const REQUEST_CANCELLED: u64 = 0x10c;
    /// The client's stream ended before the request was complete.
    pub const REQUEST_INCOMPLETE: u64 = 0x10d;
    /// A malformed message.
    pub const MESSAGE_ERROR: u64 = 0x10e;
    /// The peer generates excessive load.
    pub const EXCESSIVE_LOAD: u64 = 0x107;
    /// QPACK decoding failed (RFC 9204 §6).
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
}

/// A stream operation failed: the client reset or stopped the stream, or the connection ended.
#[derive(Debug, thiserror::Error)]
#[error("HTTP/3 stream: {0}")]
pub struct StreamFailure(pub String);

/// What a request stream offers the session.
#[async_trait]
pub trait RequestIo: Send {
    /// The next piece of the request body; `None` at its end.
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamFailure>>;
    /// The request trailers, after the body ended.
    async fn trailers(&mut self) -> Result<Option<HeaderMap>, StreamFailure>;
    /// Sends the response header (HEADERS).
    async fn send_response(&mut self, response: http::Response<()>) -> Result<(), StreamFailure>;
    /// Sends a piece of the response body (DATA).
    async fn send_data(&mut self, data: Bytes) -> Result<(), StreamFailure>;
    /// Sends trailers; the response ends with them.
    async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamFailure>;
    /// Ends the response.
    async fn finish(&mut self) -> Result<(), StreamFailure>;
    /// Resets both directions of the stream with `code` (RFC 9114 §4.1.1).
    fn reset(&mut self, code: u64);
}

/// The `h3` request stream over quinn.
pub type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

fn failure(err: impl std::fmt::Display) -> StreamFailure {
    StreamFailure(err.to_string())
}

#[async_trait]
impl RequestIo for H3Stream {
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamFailure>> {
        match self.poll_recv_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(mut buf))) => {
                let n = buf.remaining();
                Poll::Ready(Ok(Some(buf.copy_to_bytes(n))))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(failure(err))),
        }
    }

    async fn trailers(&mut self) -> Result<Option<HeaderMap>, StreamFailure> {
        self.recv_trailers().await.map_err(failure)
    }

    async fn send_response(&mut self, response: http::Response<()>) -> Result<(), StreamFailure> {
        h3::server::RequestStream::send_response(self, response)
            .await
            .map_err(failure)
    }

    async fn send_data(&mut self, data: Bytes) -> Result<(), StreamFailure> {
        h3::server::RequestStream::send_data(self, data)
            .await
            .map_err(failure)
    }

    async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamFailure> {
        h3::server::RequestStream::send_trailers(self, trailers)
            .await
            .map_err(failure)
    }

    async fn finish(&mut self) -> Result<(), StreamFailure> {
        h3::server::RequestStream::finish(self)
            .await
            .map_err(failure)
    }

    fn reset(&mut self, code: u64) {
        let code = h3::error::Code::from(code);
        self.stop_stream(code);
        self.stop_sending(code);
    }
}
