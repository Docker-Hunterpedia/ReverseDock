//! h3's QUIC traits over quinn (ADR-0032), in place of the `h3-quinn` adapter, for two things
//! that adapter cannot give (review fixes H1 and M4):
//!
//! - every stream the client opens passes through a [`FrameGuard`] before h3 sees its bytes, so
//!   no frame other than DATA can make h3 buffer more than its limit, the incomplete frames of
//!   a connection stay within one budget, and a frame that trickles in fails at the listener's
//!   `timeouts.request_header`;
//! - each request stream's [`Stopped`] signal (the client's `STOP_SENDING`, or the connection's
//!   loss) is kept for the session, so a client that gives up is seen while the upstream is
//!   still working.
//!
//! The stream and connection types follow h3-quinn 0.0.10 (MIT) otherwise.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::error::Code;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use quinn::VarInt;

use super::frames::{Budget, FrameGuard, StreamKind, Violation};
use super::stream::code;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;
/// A read in progress: the stream comes back with the chunk.
type Reading = BoxFuture<(
    quinn::RecvStream,
    Result<Option<quinn::Chunk>, quinn::ReadError>,
)>;

/// Resolves when the client stops the stream (`Some(code)`), when the response was finished and
/// acknowledged (`None`), or with an error when the connection is lost.
pub type Stopped = BoxFuture<Result<Option<VarInt>, quinn::StoppedError>>;

/// What the guards of one connection share.
pub struct Guarding {
    /// The listener's `max_header_size`.
    pub max_header_size: u64,
    /// The incomplete non-DATA frames the connection may hold (its `receive_window`).
    pub budget: Arc<Budget>,
    /// How long a non-DATA frame may take to arrive once it started (`timeouts.request_header`).
    pub deadline: Duration,
    /// The error code the connection was closed with for a frame limit, or 0.
    pub closed_for: AtomicU64,
    /// Request streams' stop signals, by stream id, until the request task takes them: one for
    /// the session, one for the connection, which waits for it before it closes.
    stopped: Mutex<BTreeMap<u64, (Stopped, Stopped)>>,
    /// Most signals kept at once (streams h3 refuses never reach a request task).
    stopped_cap: usize,
}

impl Guarding {
    /// What a connection with these limits shares.
    #[must_use]
    pub fn new(
        max_header_size: u64,
        receive_window: u64,
        deadline: Duration,
        max_streams: u32,
    ) -> Self {
        Self {
            max_header_size,
            budget: Arc::new(Budget::new(receive_window)),
            deadline,
            closed_for: AtomicU64::new(0),
            stopped: Mutex::new(BTreeMap::new()),
            stopped_cap: usize::try_from(max_streams)
                .unwrap_or(usize::MAX)
                .saturating_mul(2)
                .saturating_add(16),
        }
    }

    fn keep_stopped(&self, id: u64, send: &quinn::SendStream) {
        let mut map = self
            .stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.insert(id, (Box::pin(send.stopped()), Box::pin(send.stopped())));
        while map.len() > self.stopped_cap {
            map.pop_first();
        }
    }

    /// The stop signals of request stream `id` (once): the session's, and the one that
    /// resolves once the response is delivered (finished and acknowledged), stopped by the
    /// client, or the connection is lost.
    pub fn take_stopped(&self, id: u64) -> Option<(Stopped, Stopped)> {
        self.stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id)
    }
}

fn convert_connection_error(e: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match e {
        quinn::ConnectionError::ApplicationClosed(close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: close.error_code.into_inner(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        other => ConnectionErrorIncoming::Undefined(Arc::new(other)),
    }
}

fn connection_failure(e: quinn::ConnectionError) -> StreamErrorIncoming {
    StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: convert_connection_error(e),
    }
}

fn varint(code: u64) -> VarInt {
    VarInt::from_u64(code).unwrap_or(VarInt::MAX)
}

fn stream_id(id: quinn::StreamId) -> Result<StreamId, StreamErrorIncoming> {
    StreamId::try_from(u64::from(id)).map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: ConnectionErrorIncoming::InternalError(e.to_string()),
    })
}

/// A QUIC connection for h3, with guarded incoming streams.
pub struct Conn {
    quinn: quinn::Connection,
    guarding: Arc<Guarding>,
    incoming_bi:
        Option<BoxFuture<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>>,
    incoming_uni: Option<BoxFuture<Result<quinn::RecvStream, quinn::ConnectionError>>>,
    opener: Opener,
}

impl Conn {
    /// h3's view of `conn`.
    #[must_use]
    pub fn new(conn: quinn::Connection, guarding: Arc<Guarding>) -> Self {
        Self {
            opener: Opener::new(conn.clone()),
            quinn: conn,
            guarding,
            incoming_bi: None,
            incoming_uni: None,
        }
    }

    fn guarded(&self, kind: StreamKind, recv: quinn::RecvStream) -> RecvStream {
        RecvStream::new(
            recv,
            Some(Guarded {
                guard: FrameGuard::new(
                    kind,
                    self.guarding.max_header_size,
                    Some(self.guarding.budget.clone()),
                ),
                conn: self.quinn.clone(),
                guarding: self.guarding.clone(),
                deadline: None,
            }),
        )
    }
}

impl<B: Buf> quic::Connection<B> for Conn {
    type RecvStream = RecvStream;
    type OpenStreams = Opener;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let conn = &self.quinn;
        let accept = self.incoming_bi.get_or_insert_with(|| {
            let conn = conn.clone();
            Box::pin(async move { conn.accept_bi().await })
        });
        let accepted = ready!(accept.as_mut().poll(cx));
        self.incoming_bi = None;
        let (send, recv) = accepted.map_err(convert_connection_error)?;
        self.guarding.keep_stopped(u64::from(send.id()), &send);
        let recv = self.guarded(StreamKind::Request, recv);
        Poll::Ready(Ok(BidiStream {
            send: SendStream::new(send),
            recv,
        }))
    }

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        let conn = &self.quinn;
        let accept = self.incoming_uni.get_or_insert_with(|| {
            let conn = conn.clone();
            Box::pin(async move { conn.accept_uni().await })
        });
        let accepted = ready!(accept.as_mut().poll(cx));
        self.incoming_uni = None;
        let recv = accepted.map_err(convert_connection_error)?;
        Poll::Ready(Ok(self.guarded(StreamKind::Unidirectional, recv)))
    }

    fn opener(&self) -> Self::OpenStreams {
        Opener::new(self.quinn.clone())
    }
}

impl<B: Buf> quic::OpenStreams<B> for Conn {
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.opener, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.opener, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.quinn.close(varint(code.value()), reason);
    }
}

/// Opens the streams the server sends on (control, QPACK, GREASE).
pub struct Opener {
    conn: quinn::Connection,
    opening_bi:
        Option<BoxFuture<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>>,
    opening_uni: Option<BoxFuture<Result<quinn::SendStream, quinn::ConnectionError>>>,
}

impl Opener {
    fn new(conn: quinn::Connection) -> Self {
        Self {
            conn,
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl Clone for Opener {
    fn clone(&self) -> Self {
        Self::new(self.conn.clone())
    }
}

impl<B: Buf> quic::OpenStreams<B> for Opener {
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let conn = &self.conn;
        let open = self.opening_bi.get_or_insert_with(|| {
            let conn = conn.clone();
            Box::pin(async move { conn.open_bi().await })
        });
        let opened = ready!(open.as_mut().poll(cx));
        self.opening_bi = None;
        let (send, recv) = opened.map_err(connection_failure)?;
        Poll::Ready(Ok(BidiStream {
            send: SendStream::new(send),
            recv: RecvStream::new(recv, None),
        }))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let conn = &self.conn;
        let open = self.opening_uni.get_or_insert_with(|| {
            let conn = conn.clone();
            Box::pin(async move { conn.open_uni().await })
        });
        let opened = ready!(open.as_mut().poll(cx));
        self.opening_uni = None;
        Poll::Ready(Ok(SendStream::new(opened.map_err(connection_failure)?)))
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(varint(code.value()), reason);
    }
}

/// A request stream: both directions.
pub struct BidiStream<B: Buf> {
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = SendStream<B>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        let polled = self.recv.poll_data(cx);
        if let Some(code) = self.recv.reset_send.take() {
            // A frame over its limit fails the whole stream (RFC 9114 §4.1.1).
            quic::SendStream::<B>::reset(&mut self.send, code);
        }
        polled
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        quic::SendStream::<B>::reset(&mut self.send, reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

/// The guard of a stream the client opened, and what it needs to fail it.
struct Guarded {
    guard: FrameGuard,
    conn: quinn::Connection,
    guarding: Arc<Guarding>,
    /// While a non-DATA frame is partly received: when it must be complete.
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

/// How a guarded stream failed.
enum Failure {
    /// Reset this request stream with the code.
    Stream(u64),
    /// Close the connection with the code.
    Connection(u64),
}

impl Guarded {
    /// What a violation on a stream of this kind fails.
    fn failure(&self, violation: Option<Violation>) -> Failure {
        let request = self.guard.kind() == StreamKind::Request;
        match violation {
            Some(Violation::Unexpected { .. }) => Failure::Connection(code::FRAME_UNEXPECTED),
            // A frame over its limit, or one that trickles in, fails its request stream;
            // on the control stream, and over the connection's budget, the connection.
            Some(Violation::TooLarge { .. }) | None if request => {
                Failure::Stream(code::EXCESSIVE_LOAD)
            }
            _ => Failure::Connection(code::EXCESSIVE_LOAD),
        }
    }
}

/// The receiving side of a stream.
pub struct RecvStream {
    stream: Option<quinn::RecvStream>,
    reading: Option<Reading>,
    guarded: Option<Guarded>,
    /// The stream failed a limit: every later read fails with this code.
    failed: Option<u64>,
    /// The sending side of the request stream must be reset with this code.
    reset_send: Option<u64>,
}

impl RecvStream {
    fn new(stream: quinn::RecvStream, guarded: Option<Guarded>) -> Self {
        Self {
            stream: Some(stream),
            reading: None,
            guarded,
            failed: None,
            reset_send: None,
        }
    }

    /// Fails the stream (or the connection) for `violation` (`None`: the deadline passed).
    fn fail(&mut self, violation: Option<Violation>) -> StreamErrorIncoming {
        let Some(guarded) = &self.guarded else {
            return StreamErrorIncoming::Unknown("no guard".into());
        };
        let reason = violation.map_or_else(
            || "an HTTP/3 frame did not arrive in time".to_owned(),
            |v| v.to_string(),
        );
        tracing::debug!(reason = %reason, "HTTP/3 frame limit");
        match guarded.failure(violation) {
            Failure::Stream(code) => {
                self.failed = Some(code);
                self.reset_send = Some(code);
                if let Some(stream) = self.stream.as_mut() {
                    let _ = stream.stop(varint(code));
                }
                StreamErrorIncoming::StreamTerminated { error_code: code }
            }
            Failure::Connection(code) => {
                self.failed = Some(code);
                guarded.guarding.closed_for.store(code, Ordering::Relaxed);
                guarded.conn.close(varint(code), reason.as_bytes());
                StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: ConnectionErrorIncoming::ApplicationClose {
                        error_code: code,
                    },
                }
            }
        }
    }

    /// Arms, keeps or drops the progress deadline; whether it has passed.
    fn deadline_passed(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(guarded) = self.guarded.as_mut() else {
            return false;
        };
        if !guarded.guard.in_progress() {
            guarded.deadline = None;
            return false;
        }
        let limit = guarded.guarding.deadline;
        let sleep = guarded
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        sleep.as_mut().poll(cx).is_ready()
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if let Some(code) = self.failed {
            return Poll::Ready(Err(StreamErrorIncoming::StreamTerminated {
                error_code: code,
            }));
        }
        if self.reading.is_none() {
            let Some(mut stream) = self.stream.take() else {
                return Poll::Ready(Err(StreamErrorIncoming::Unknown(
                    "the stream is being read".into(),
                )));
            };
            self.reading = Some(Box::pin(async move {
                let chunk = stream.read_chunk(usize::MAX, true).await;
                (stream, chunk)
            }));
        }
        let Some(reading) = self.reading.as_mut() else {
            return Poll::Pending;
        };
        let Poll::Ready((stream, chunk)) = reading.as_mut().poll(cx) else {
            if self.deadline_passed(cx) {
                return Poll::Ready(Err(self.fail(None)));
            }
            return Poll::Pending;
        };
        self.reading = None;
        self.stream = Some(stream);
        let chunk = match chunk {
            Ok(Some(chunk)) => chunk.bytes,
            Ok(None) => return Poll::Ready(Ok(None)),
            Err(err) => return Poll::Ready(Err(read_failure(err))),
        };
        if let Some(guarded) = self.guarded.as_mut()
            && let Err(violation) = guarded.guard.inspect(&chunk)
        {
            return Poll::Ready(Err(self.fail(Some(violation))));
        }
        // A frame still in progress keeps (or starts) its deadline; it is polled with the next
        // read, which h3 makes at once while a frame is incomplete.
        let _ = self.deadline_passed(cx);
        Poll::Ready(Ok(Some(chunk)))
    }

    fn stop_sending(&mut self, error_code: u64) {
        if let Some(stream) = self.stream.as_mut() {
            let _ = stream.stop(varint(error_code));
        }
    }

    fn recv_id(&self) -> StreamId {
        self.stream
            .as_ref()
            .and_then(|s| StreamId::try_from(u64::from(s.id())).ok())
            .unwrap_or_else(|| StreamId::from(h3::proto::varint::VarInt::from_u32(0)))
    }
}

fn read_failure(error: quinn::ReadError) -> StreamErrorIncoming {
    match error {
        quinn::ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::ReadError::ConnectionLost(e) => connection_failure(e),
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}

/// The sending side of a stream.
pub struct SendStream<B: Buf> {
    stream: quinn::SendStream,
    writing: Option<WriteBuf<B>>,
}

impl<B: Buf> SendStream<B> {
    fn new(stream: quinn::SendStream) -> Self {
        Self {
            stream,
            writing: None,
        }
    }
}

fn write_failure(error: quinn::WriteError) -> StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(e) => connection_failure(e),
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}

impl<B: Buf> quic::SendStream<B> for SendStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if let Some(data) = self.writing.as_mut() {
            while data.has_remaining() {
                let written = ready!(Pin::new(&mut self.stream).poll_write(cx, data.chunk()))
                    .map_err(write_failure)?;
                data.advance(written);
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "send_data while a write is pending".into(),
                ),
            });
        }
        self.writing = Some(data.into());
        Ok(())
    }

    fn poll_finish(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(
            self.stream
                .finish()
                .map_err(|e| StreamErrorIncoming::Unknown(Box::new(e))),
        )
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self.stream.reset(varint(reset_code));
    }

    fn send_id(&self) -> StreamId {
        stream_id(self.stream.id())
            .unwrap_or_else(|_| StreamId::from(h3::proto::varint::VarInt::from_u32(0)))
    }
}
