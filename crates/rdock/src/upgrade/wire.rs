//! The handover protocol between the running process and the new one (ADR-0031): messages as
//! length-prefixed JSON over the Unix socket pair that is the new process's standard input,
//! file descriptors passed with `SCM_RIGHTS` through `rustix` (received ones arrive as
//! `OwnedFd`, close-on-exec).
//!
//! A frame is a 4-byte big-endian length, a 4-byte big-endian descriptor count and the JSON
//! message, sent with at most [`FDS_PER_MESSAGE`] descriptors; further descriptors follow in
//! one-byte messages of [`FDS_PER_MESSAGE`] each. Messages are read with blocking calls and a
//! read timeout, inside `spawn_blocking`.

use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use rdock_model::config::ListenerSocket;
use rdock_model::values::ListenAddress;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use serde::{Deserialize, Serialize};

/// The protocol version in every manifest; a process refuses a newer one.
pub(crate) const PROTOCOL: u32 = 1;
/// Descriptors per `sendmsg` (Linux allows 253, `SCM_MAX_FD`).
pub(crate) const FDS_PER_MESSAGE: usize = 32;
/// Largest message accepted.
const MAX_MESSAGE: u32 = 4 << 20;

/// A message of the protocol. Not `Debug`: the manifest carries TLS ticket keys.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Message {
    /// Old → new: what is handed over; the descriptors follow in the manifest's order.
    Manifest(Box<Manifest>),
    /// New → old: everything is built; nothing is accepted yet.
    Ready,
    /// Old → new: the old process stopped accepting and its writers; start.
    Go,
    /// New → old: accepting.
    Serving {
        /// The new process's pid.
        pid: u32,
    },
    /// New → old: the new process gives up (before `ready`).
    Failed {
        /// Why.
        reason: String,
    },
    /// Old → new, every second while draining: connections still open.
    Draining {
        /// Open client connections in the old process.
        connections: u64,
    },
    /// Old → new, at exit: what the quotas counted while draining.
    Quota {
        /// Increments per quota middleware.
        counters: Vec<QuotaIncrements>,
    },
    /// Old → new: the old process exits now.
    Done,
}

impl Message {
    fn kind(&self) -> &'static str {
        match self {
            Self::Manifest(_) => "manifest",
            Self::Ready => "ready",
            Self::Go => "go",
            Self::Serving { .. } => "serving",
            Self::Failed { .. } => "failed",
            Self::Draining { .. } => "draining",
            Self::Quota { .. } => "quota",
            Self::Done => "done",
        }
    }
}

/// What the running process hands over.
#[derive(Serialize, Deserialize)]
pub(crate) struct Manifest {
    /// [`PROTOCOL`].
    pub(crate) protocol: u32,
    /// The data directory's format version ([`crate::datadir::DATA_FORMAT`]).
    pub(crate) data_format: u32,
    /// Upgrades behind the new process.
    pub(crate) generation: u64,
    /// The old process's pid.
    pub(crate) previous_pid: u32,
    /// Who asked, for the audit record the new process writes.
    pub(crate) triggered_by: String,
    /// How (`socket` or `signal`).
    pub(crate) method: String,
    /// The binary's path and SHA-256 (hex).
    pub(crate) binary: PathBuf,
    pub(crate) binary_sha256: String,
    /// When the old process's drain ends (Unix seconds); 0 for no bound.
    pub(crate) drain_deadline: u64,
    /// One entry per descriptor, in order.
    pub(crate) sockets: Vec<SocketEntry>,
    /// TLS ticket keys by resumption class.
    pub(crate) ticket_keys: Vec<TicketClass>,
}

/// What a passed descriptor is.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum SocketEntry {
    /// The data directory's lock file (`rdock.lock`).
    Lock,
    /// A proxy listener's socket.
    Listener {
        /// Its name in the old process.
        name: String,
        /// Bind address.
        address: ListenAddress,
        /// A UDP socket.
        udp: bool,
        /// The options it has.
        options: ListenerSocket,
    },
    /// The admin API's TCP listener.
    AdminTcp,
    /// The admin API's Unix socket.
    AdminUnix {
        /// Its path.
        path: PathBuf,
    },
}

/// One class's ticket keys, base64 (name ‖ key, 48 bytes each).
#[derive(Serialize, Deserialize)]
pub(crate) struct TicketClass {
    /// Class id, hex.
    pub(crate) class: String,
    pub(crate) current: String,
    pub(crate) previous: Vec<String>,
    pub(crate) rotated_at: u64,
}

/// What one quota middleware counted while the old process drained.
#[derive(Serialize, Deserialize)]
pub(crate) struct QuotaIncrements {
    /// The middleware.
    pub(crate) name: String,
    /// The window's start the increments belong to.
    pub(crate) start: i64,
    /// (key, increment, limit).
    pub(crate) increments: Vec<(String, u64, u64)>,
}

/// One end of the handover socket.
pub(crate) struct Channel {
    stream: UnixStream,
}

impl Channel {
    pub(crate) fn new(stream: UnixStream) -> Self {
        Self { stream }
    }

    /// A second handle on the same socket (for a reader thread).
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            stream: self.stream.try_clone()?,
        })
    }

    /// Sends `message` with `fds`.
    pub(crate) fn send(&self, message: &Message, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        let body = serde_json::to_vec(message).map_err(io::Error::other)?;
        let len = u32::try_from(body.len()).map_err(|_| io::Error::other("message too large"))?;
        let count = u32::try_from(fds.len()).map_err(|_| io::Error::other("too many fds"))?;
        let mut head = [0u8; 8];
        head[..4].copy_from_slice(&len.to_be_bytes());
        head[4..].copy_from_slice(&count.to_be_bytes());
        let mut chunks = fds.chunks(FDS_PER_MESSAGE);
        let first = chunks.next().unwrap_or(&[]);
        let iov = [IoSlice::new(&head), IoSlice::new(&body)];
        let sent = send_with_fds(&self.stream, &iov, first)?;
        let total = head.len() + body.len();
        if sent < total {
            // The descriptors went with the first bytes; the rest is plain data.
            let rest: Vec<u8> = head.iter().chain(body.iter()).copied().skip(sent).collect();
            (&self.stream).write_all(&rest)?;
        }
        for chunk in chunks {
            send_with_fds(&self.stream, &[IoSlice::new(b"F")], chunk)?;
        }
        Ok(())
    }

    /// Receives one message and its descriptors, waiting at most `timeout` for each read
    /// (`None`: no limit). End of file (the other process is gone) is an error.
    pub(crate) fn recv(&self, timeout: Option<Duration>) -> io::Result<(Message, Vec<OwnedFd>)> {
        self.stream.set_read_timeout(timeout)?;
        let mut fds = Vec::new();
        let mut head = [0u8; 8];
        let got = recv_with_fds(&self.stream, &mut head, &mut fds)?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the other process closed the handover socket",
            ));
        }
        (&self.stream).read_exact(&mut head[got..])?;
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let count = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        if len > MAX_MESSAGE {
            return Err(io::Error::other("handover message too large"));
        }
        let mut body = vec![0u8; usize::try_from(len).unwrap_or(0)];
        (&self.stream).read_exact(&mut body)?;
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        while fds.len() < count {
            let mut byte = [0u8; 1];
            if recv_with_fds(&self.stream, &mut byte, &mut fds)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the handover socket closed before every descriptor arrived",
                ));
            }
        }
        if fds.len() != count {
            return Err(io::Error::other(
                "unexpected descriptors on the handover socket",
            ));
        }
        let message: Message = serde_json::from_slice(&body)
            .map_err(|e| io::Error::other(format!("invalid handover message: {e}")))?;
        Ok((message, fds))
    }

    /// Receives a message, which must be of `kind`.
    pub(crate) fn expect(
        &self,
        kind: &str,
        timeout: Option<Duration>,
    ) -> io::Result<(Message, Vec<OwnedFd>)> {
        let (message, fds) = self.recv(timeout)?;
        if let Message::Failed { reason } = &message {
            return Err(io::Error::other(format!(
                "the new process failed: {reason}"
            )));
        }
        if message.kind() != kind {
            return Err(io::Error::other(format!(
                "expected `{kind}` on the handover socket, got `{}`",
                message.kind()
            )));
        }
        Ok((message, fds))
    }
}

fn send_with_fds(
    stream: &UnixStream,
    iov: &[IoSlice<'_>],
    fds: &[BorrowedFd<'_>],
) -> io::Result<usize> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(FDS_PER_MESSAGE))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(io::Error::other("too many descriptors for one message"));
    }
    #[cfg(target_os = "linux")]
    let flags = SendFlags::NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = SendFlags::empty();
    loop {
        match rustix::net::sendmsg(stream.as_fd(), iov, &mut control, flags) {
            Ok(n) => return Ok(n),
            Err(rustix::io::Errno::INTR) => {}
            Err(err) => return Err(err.into()),
        }
    }
}

fn recv_with_fds(stream: &UnixStream, buf: &mut [u8], fds: &mut Vec<OwnedFd>) -> io::Result<usize> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(FDS_PER_MESSAGE))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut iov = [IoSliceMut::new(buf)];
    #[cfg(target_os = "linux")]
    let flags = RecvFlags::CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = RecvFlags::empty();
    let received = loop {
        match rustix::net::recvmsg(stream.as_fd(), &mut iov, &mut control, flags) {
            Ok(r) => break r,
            Err(rustix::io::Errno::INTR) => {}
            Err(err) => return Err(err.into()),
        }
    };
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    if received.flags.contains(ReturnFlags::CTRUNC) {
        return Err(io::Error::other(
            "descriptors were cut off on the handover socket",
        ));
    }
    Ok(received.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_and_many_descriptors_cross_the_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let (a, b) = (Channel::new(a), Channel::new(b));
        let files: Vec<std::fs::File> = (0..70).map(|_| tempfile::tempfile().unwrap()).collect();
        let fds: Vec<BorrowedFd<'_>> = files.iter().map(AsFd::as_fd).collect();
        a.send(&Message::Draining { connections: 7 }, &fds).unwrap();
        a.send(&Message::Go, &[]).unwrap();
        let (message, received) = b.recv(Some(Duration::from_secs(5))).unwrap();
        assert!(matches!(message, Message::Draining { connections: 7 }));
        assert_eq!(received.len(), 70);
        let (message, received) = b.expect("go", Some(Duration::from_secs(5))).unwrap();
        assert!(matches!(message, Message::Go));
        assert!(received.is_empty());
        drop(a);
        let err = b.recv(Some(Duration::from_secs(5))).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_failure_or_another_message_is_an_error_where_one_kind_is_expected() {
        let (a, b) = UnixStream::pair().unwrap();
        let (a, b) = (Channel::new(a), Channel::new(b));
        a.send(
            &Message::Failed {
                reason: "no".into(),
            },
            &[],
        )
        .unwrap();
        a.send(&Message::Done, &[]).unwrap();
        assert!(
            b.expect("ready", None)
                .err()
                .unwrap()
                .to_string()
                .contains("failed: no")
        );
        assert!(
            b.expect("ready", None)
                .err()
                .unwrap()
                .to_string()
                .contains("got `done`")
        );
    }
}
