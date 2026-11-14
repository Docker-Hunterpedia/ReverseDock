//! Frame-size limits on the HTTP/3 streams a client opens (ADR-0032, review fix H1).
//!
//! h3 0.0.8 buffers every frame other than DATA until its whole payload has arrived, and the
//! QUIC layer hands the flow-control credit back as soon as h3 has read the bytes, so neither
//! QUIC flow control nor `max_header_size` (checked only once the frame is complete) bounds
//! that buffer. This parser sees every byte before h3 does and reads the frame headers (RFC 9114
//! §7.1: a type and a length, both QUIC variable-length integers): a frame that declares more
//! than its limit fails the stream before any of its payload is passed on.
//!
//! - Request streams: DATA is not limited (it is streamed, and flow control bounds what is
//!   unread); HEADERS (the request head and trailers) at most `max_header_size` plus
//!   [`QPACK_PREFIX_SLACK`]; every other frame type (reserved, GREASE, unknown) at most
//!   [`SMALL_FRAME`]. A WebTransport stream frame (type 0x41, which has no length) is refused:
//!   rdock does not offer WebTransport.
//! - The control stream: every frame at most [`SMALL_FRAME`] (SETTINGS, GOAWAY, `MAX_PUSH_ID`,
//!   reserved and unknown types).
//! - Other unidirectional streams (QPACK encoder and decoder, push, reserved types) are passed
//!   through: h3 never reads them into a buffer of its own (it stops unknown ones), so QUIC flow
//!   control holds them.
//!
//! A [`Budget`] shared by the streams of a connection bounds the sum of the incomplete non-DATA
//! frames it holds at once (the connection's `receive_window`): many streams with a large
//! HEADERS frame each cannot add up beyond it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Largest non-DATA, non-HEADERS frame a client may send: SETTINGS, GOAWAY, reserved and unknown
/// types. Browsers send SETTINGS and GREASE frames of a few dozen bytes.
pub const SMALL_FRAME: u64 = 16 * 1024;
/// What a HEADERS frame may carry beyond `max_header_size`: the QPACK prefix (Required Insert
/// Count and Base). Each field line encodes in fewer bytes than the 32 the size counts per field
/// (RFC 9114 §4.2.2), so an honest encoder's section is never longer than its decoded size.
pub const QPACK_PREFIX_SLACK: u64 = 16;

/// HTTP/3 frame and stream types (RFC 9114 §7.2, §6.2).
const DATA: u64 = 0x0;
const HEADERS: u64 = 0x1;
const WEBTRANSPORT_STREAM: u64 = 0x41;
const CONTROL_STREAM: u64 = 0x0;

/// What kind of stream the guard reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// A client-initiated bidirectional stream: a request.
    Request,
    /// A client-initiated unidirectional stream; its first integer is the stream type.
    Unidirectional,
}

/// Why a stream fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// A frame declares a payload over its limit.
    TooLarge {
        /// The frame type.
        frame_type: u64,
        /// The declared payload length.
        length: u64,
        /// The limit for this frame type on this stream.
        limit: u64,
    },
    /// The connection's incomplete non-DATA frames would exceed the budget.
    OverBudget {
        /// The declared payload length of the frame that did not fit.
        length: u64,
        /// The budget.
        limit: u64,
    },
    /// A frame type that may not appear on this stream.
    Unexpected {
        /// The frame type.
        frame_type: u64,
    },
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge {
                frame_type,
                length,
                limit,
            } => write!(
                f,
                "frame type {frame_type:#x} declares {length} bytes, more than {limit}"
            ),
            Self::OverBudget { length, limit } => write!(
                f,
                "a frame of {length} bytes would take the connection's incomplete frames over {limit} bytes"
            ),
            Self::Unexpected { frame_type } => {
                write!(
                    f,
                    "frame type {frame_type:#x} is not allowed on this stream"
                )
            }
        }
    }
}

/// The incomplete non-DATA frames a connection may hold at once, in bytes.
#[derive(Debug)]
pub struct Budget {
    held: AtomicU64,
    limit: u64,
}

impl Budget {
    /// A budget of `limit` bytes.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            held: AtomicU64::new(0),
            limit,
        }
    }

    /// Bytes reserved now.
    #[must_use]
    pub fn held(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }

    fn reserve(&self, n: u64) -> Result<(), Violation> {
        let mut current = self.held.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(n);
            if next > self.limit {
                return Err(Violation::OverBudget {
                    length: n,
                    limit: self.limit,
                });
            }
            match self.held.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    fn release(&self, n: u64) {
        let mut current = self.held.load(Ordering::Relaxed);
        loop {
            match self.held.compare_exchange_weak(
                current,
                current.saturating_sub(n),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

/// Where the parser is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// A unidirectional stream's type.
    StreamType,
    /// A stream whose bytes are not frames rdock reads (QPACK, push, reserved types).
    Opaque,
    /// A frame's type.
    FrameType,
    /// A frame's length, after its type.
    FrameLength { frame_type: u64 },
    /// A frame's payload: `remaining` bytes; `data` for DATA (not limited, not reserved).
    Payload { remaining: u64, data: bool },
    /// The stream failed; nothing more is read.
    Failed,
}

/// A partial QUIC variable-length integer (RFC 9000 §16).
#[derive(Debug, Clone, Copy, Default)]
struct Varint {
    bytes: [u8; 8],
    have: usize,
}

impl Varint {
    /// Feeds bytes from `input`; the value once complete. Consumes only the integer's bytes.
    fn feed(&mut self, input: &mut &[u8]) -> Option<u64> {
        while let Some((&byte, rest)) = input.split_first() {
            if let Some(slot) = self.bytes.get_mut(self.have) {
                *slot = byte;
            }
            self.have += 1;
            *input = rest;
            let len = 1usize << (self.bytes[0] >> 6);
            if self.have == len {
                let mut value = u64::from(self.bytes[0] & 0x3f);
                for b in &self.bytes[1..len] {
                    value = (value << 8) | u64::from(*b);
                }
                *self = Self::default();
                return Some(value);
            }
        }
        None
    }

    fn partial(&self) -> bool {
        self.have > 0
    }
}

/// Reads the frame headers of one stream as its bytes go by.
#[derive(Debug)]
pub struct FrameGuard {
    kind: StreamKind,
    /// Largest HEADERS payload on a request stream.
    headers_limit: u64,
    state: State,
    varint: Varint,
    budget: Option<Arc<Budget>>,
    /// Bytes this stream has reserved in the budget (the incomplete frame's declared length).
    reserved: u64,
}

impl FrameGuard {
    /// A guard for a stream of `kind` on a listener whose `max_header_size` is
    /// `max_header_size`, sharing `budget` with the connection's other streams.
    #[must_use]
    pub fn new(kind: StreamKind, max_header_size: u64, budget: Option<Arc<Budget>>) -> Self {
        Self {
            kind,
            headers_limit: max_header_size.saturating_add(QPACK_PREFIX_SLACK),
            state: match kind {
                StreamKind::Request => State::FrameType,
                StreamKind::Unidirectional => State::StreamType,
            },
            varint: Varint::default(),
            budget,
            reserved: 0,
        }
    }

    /// The limit of a frame of `frame_type` on this stream.
    fn limit(&self, frame_type: u64) -> Option<u64> {
        match (self.kind, frame_type) {
            (StreamKind::Request, DATA) => None,
            (StreamKind::Request, HEADERS) => Some(self.headers_limit),
            _ => Some(SMALL_FRAME),
        }
    }

    /// Reads `chunk`, the next bytes of the stream. An error means the stream (or, for a
    /// unidirectional stream, the connection) must fail; the guard then refuses everything.
    ///
    /// # Errors
    ///
    /// A frame over its limit or the budget, or a frame type the stream may not carry.
    pub fn inspect(&mut self, mut chunk: &[u8]) -> Result<(), Violation> {
        let result = self.run(&mut chunk);
        if result.is_err() {
            self.state = State::Failed;
            self.release();
        }
        result
    }

    fn run(&mut self, input: &mut &[u8]) -> Result<(), Violation> {
        while !input.is_empty() {
            match self.state {
                State::Failed => return Err(Violation::Unexpected { frame_type: 0 }),
                State::Opaque => return Ok(()),
                State::StreamType => {
                    if let Some(stream_type) = self.varint.feed(input) {
                        self.state = if stream_type == CONTROL_STREAM {
                            State::FrameType
                        } else {
                            State::Opaque
                        };
                    }
                }
                State::FrameType => {
                    if let Some(frame_type) = self.varint.feed(input) {
                        if self.kind == StreamKind::Request && frame_type == WEBTRANSPORT_STREAM {
                            return Err(Violation::Unexpected { frame_type });
                        }
                        self.state = State::FrameLength { frame_type };
                    }
                }
                State::FrameLength { frame_type } => {
                    if let Some(length) = self.varint.feed(input) {
                        let limit = self.limit(frame_type);
                        if let Some(limit) = limit {
                            if length > limit {
                                return Err(Violation::TooLarge {
                                    frame_type,
                                    length,
                                    limit,
                                });
                            }
                            if let Some(budget) = &self.budget {
                                budget.reserve(length)?;
                            }
                            self.reserved = length;
                        }
                        self.state = State::Payload {
                            remaining: length,
                            data: limit.is_none(),
                        };
                        self.end_of_payload();
                    }
                }
                State::Payload { remaining, data } => {
                    let n = remaining.min(input.len() as u64);
                    // `n` is at most `input.len()`.
                    *input = input.get(usize::try_from(n).unwrap_or(0)..).unwrap_or(&[]);
                    self.state = State::Payload {
                        remaining: remaining - n,
                        data,
                    };
                    self.end_of_payload();
                }
            }
        }
        Ok(())
    }

    /// After a payload's last byte: the frame is complete, the next one starts.
    fn end_of_payload(&mut self) {
        if let State::Payload { remaining: 0, .. } = self.state {
            self.release();
            self.state = State::FrameType;
        }
    }

    fn release(&mut self) {
        if let Some(budget) = &self.budget {
            budget.release(std::mem::take(&mut self.reserved));
        }
        self.reserved = 0;
    }

    /// Whether a non-DATA frame (or a stream type, or a frame header) is partly received: what
    /// the stream's progress deadline applies to.
    #[must_use]
    pub fn in_progress(&self) -> bool {
        match self.state {
            State::StreamType | State::FrameType => self.varint.partial(),
            State::FrameLength { .. } => true,
            State::Payload { remaining, data } => !data && remaining > 0,
            State::Opaque | State::Failed => false,
        }
    }

    /// The kind of stream this guard reads.
    #[must_use]
    pub fn kind(&self) -> StreamKind {
        self.kind
    }

    /// Bytes this stream holds reserved in the connection's budget.
    #[must_use]
    pub fn reserved(&self) -> u64 {
        self.reserved
    }
}

impl Drop for FrameGuard {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(value: u64) -> Vec<u8> {
        if value < 64 {
            vec![u8::try_from(value).unwrap()]
        } else if value < 16_384 {
            (u16::try_from(value).unwrap() | 0x4000)
                .to_be_bytes()
                .to_vec()
        } else if value < 1 << 30 {
            (u32::try_from(value).unwrap() | 0x8000_0000)
                .to_be_bytes()
                .to_vec()
        } else {
            (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
        }
    }

    fn frame_head(kind: u64, len: u64) -> Vec<u8> {
        [varint(kind), varint(len)].concat()
    }

    fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
        [frame_head(kind, payload.len() as u64), payload.to_vec()].concat()
    }

    /// Feeds `bytes` in one chunk and byte by byte; both must agree.
    fn both(kind: StreamKind, limit: u64, bytes: &[u8]) -> Result<(), Violation> {
        let mut whole = FrameGuard::new(kind, limit, None);
        let a = whole.inspect(bytes);
        let mut split = FrameGuard::new(kind, limit, None);
        let b = bytes.iter().try_for_each(|b| split.inspect(&[*b]));
        assert_eq!(a, b, "{bytes:?}");
        a
    }

    #[test]
    fn request_frames_within_their_limits_pass() {
        let mut bytes = frame(HEADERS, &[0u8; 1000]);
        bytes.extend(frame(DATA, &vec![1u8; 70_000]));
        bytes.extend(frame(0x21, &[0u8; 100])); // GREASE
        bytes.extend(frame(HEADERS, &[0u8; 1016])); // trailers at the limit
        assert_eq!(both(StreamKind::Request, 1000, &bytes), Ok(()));
        // DATA is not limited, whatever it declares.
        let huge_data = frame_head(DATA, 1 << 40);
        assert_eq!(both(StreamKind::Request, 1000, &huge_data), Ok(()));
    }

    #[test]
    fn an_oversized_headers_or_reserved_frame_fails_before_its_payload() {
        assert_eq!(
            both(StreamKind::Request, 1000, &frame_head(HEADERS, 1017)),
            Err(Violation::TooLarge {
                frame_type: HEADERS,
                length: 1017,
                limit: 1016
            })
        );
        // A reserved type declaring 2^62 - 1 bytes, on a request stream.
        assert_eq!(
            both(
                StreamKind::Request,
                65_536,
                &frame_head(0x21, (1 << 62) - 1)
            ),
            Err(Violation::TooLarge {
                frame_type: 0x21,
                length: (1 << 62) - 1,
                limit: SMALL_FRAME
            })
        );
        // After a valid HEADERS frame and some DATA (mid-body).
        let mut bytes = frame(HEADERS, b"abc");
        bytes.extend(frame(DATA, b"body"));
        bytes.extend(frame_head(0x5f, SMALL_FRAME + 1));
        assert!(matches!(
            both(StreamKind::Request, 1000, &bytes),
            Err(Violation::TooLarge {
                frame_type: 0x5f,
                ..
            })
        ));
        assert_eq!(
            both(StreamKind::Request, 1000, &varint(WEBTRANSPORT_STREAM)),
            Err(Violation::Unexpected {
                frame_type: WEBTRANSPORT_STREAM
            })
        );
    }

    #[test]
    fn the_control_stream_limits_every_frame() {
        let mut bytes = varint(CONTROL_STREAM);
        bytes.extend(frame(0x4, &[0u8; 10])); // SETTINGS
        bytes.extend(frame(0x21, &vec![0u8; 16_384]));
        assert_eq!(both(StreamKind::Unidirectional, 1 << 20, &bytes), Ok(()));
        bytes.extend(frame_head(0x21, 1 << 30));
        assert!(matches!(
            both(StreamKind::Unidirectional, 1 << 20, &bytes),
            Err(Violation::TooLarge {
                length: 1_073_741_824,
                ..
            })
        ));
        // Even HEADERS and DATA are small frames there (neither is allowed on it at all).
        let mut headers = varint(CONTROL_STREAM);
        headers.extend(frame_head(HEADERS, SMALL_FRAME + 1));
        assert!(both(StreamKind::Unidirectional, 1 << 20, &headers).is_err());
        let mut data = varint(CONTROL_STREAM);
        data.extend(frame_head(DATA, SMALL_FRAME + 1));
        assert!(both(StreamKind::Unidirectional, 1 << 20, &data).is_err());
    }

    #[test]
    fn other_unidirectional_streams_pass_through() {
        for stream_type in [0x1, 0x2, 0x3, 0x21, 0x1f * 7 + 0x21] {
            let mut bytes = varint(stream_type);
            bytes.extend(frame_head(0x21, 1 << 40));
            bytes.extend([0xffu8; 100]);
            assert_eq!(both(StreamKind::Unidirectional, 100, &bytes), Ok(()));
        }
    }

    #[test]
    fn progress_tracks_incomplete_non_data_frames() {
        let mut guard = FrameGuard::new(StreamKind::Unidirectional, 1000, None);
        assert!(!guard.in_progress());
        guard.inspect(&[0x40]).unwrap(); // half of a two-byte stream type
        assert!(guard.in_progress());
        guard.inspect(&[0x00]).unwrap(); // stream type 0: control
        assert!(!guard.in_progress());
        guard.inspect(&frame_head(0x4, 10)).unwrap();
        assert!(guard.in_progress());
        guard.inspect(&[0u8; 9]).unwrap();
        assert!(guard.in_progress());
        guard.inspect(&[0u8]).unwrap();
        assert!(!guard.in_progress());

        let mut request = FrameGuard::new(StreamKind::Request, 1000, None);
        request.inspect(&frame_head(DATA, 100)).unwrap();
        assert!(!request.in_progress(), "DATA is not held");
        request.inspect(&[0u8; 100]).unwrap();
        request.inspect(&frame_head(HEADERS, 10)).unwrap();
        assert!(request.in_progress());
    }

    #[test]
    fn the_budget_bounds_the_sum_of_incomplete_frames() {
        let budget = Arc::new(Budget::new(3000));
        let mut a = FrameGuard::new(StreamKind::Request, 2000, Some(budget.clone()));
        let mut b = FrameGuard::new(StreamKind::Request, 2000, Some(budget.clone()));
        a.inspect(&frame_head(HEADERS, 2000)).unwrap();
        assert_eq!(budget.held(), 2000);
        assert_eq!(a.reserved(), 2000);
        assert_eq!(
            b.inspect(&frame_head(HEADERS, 1500)),
            Err(Violation::OverBudget {
                length: 1500,
                limit: 3000
            })
        );
        assert_eq!(budget.held(), 2000, "a refused frame reserves nothing");
        // The frame completes: released.
        a.inspect(&[0u8; 2000]).unwrap();
        assert_eq!(budget.held(), 0);
        let mut c = FrameGuard::new(StreamKind::Request, 2000, Some(budget.clone()));
        c.inspect(&frame_head(HEADERS, 1500)).unwrap();
        assert_eq!(budget.held(), 1500);
        // A stream that goes away releases what it held.
        drop(c);
        assert_eq!(budget.held(), 0);
        // DATA reserves nothing.
        a.inspect(&frame_head(DATA, 1 << 30)).unwrap();
        assert_eq!(budget.held(), 0);
    }

    #[test]
    fn a_failed_guard_refuses_everything_after() {
        let mut guard = FrameGuard::new(StreamKind::Request, 10, None);
        assert!(guard.inspect(&frame_head(HEADERS, 1000)).is_err());
        assert!(guard.inspect(&[0]).is_err());
        assert!(!guard.in_progress());
    }

    #[test]
    fn eight_byte_integers_are_read_whole() {
        // Type 0x21 written as an eight-byte integer, then a two-byte length.
        let mut bytes = vec![0xc0, 0, 0, 0, 0, 0, 0, 0x21];
        bytes.extend(varint(20_000));
        assert_eq!(
            both(StreamKind::Request, 1000, &bytes),
            Err(Violation::TooLarge {
                frame_type: 0x21,
                length: 20_000,
                limit: SMALL_FRAME
            })
        );
    }
}
