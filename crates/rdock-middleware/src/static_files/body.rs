//! The body of a file answer, read from the open file as the proxy sends it.

use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use bytes::Bytes;

/// Files up to this size are read in one call.
const WHOLE_READ_MAX: u64 = 1024 * 1024;
/// Larger ones are read and sent in chunks of this size, so HTTP/2 flow control, write
/// timeouts and the `bandwidth` middleware act on them.
const CHUNK: u64 = 256 * 1024;

/// One piece of a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Segment {
    /// Bytes in memory (the part headers of a `multipart/byteranges` answer).
    Bytes(Bytes),
    /// `len` bytes of the file from `offset`.
    File { offset: u64, len: u64 },
}

/// Ranges of an open file, with the part headers of a multipart answer between them. The
/// proxy calls [`FileBody::next_chunk`] until [`FileBody::is_finished`].
#[derive(Debug, Clone)]
pub struct FileBody {
    file: Arc<File>,
    segments: VecDeque<Segment>,
    remaining: u64,
    /// Largest read: everything at once for small files, [`CHUNK`] for large ones.
    read_size: u64,
}

impl PartialEq for FileBody {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.file, &other.file) && self.segments == other.segments
    }
}

impl Eq for FileBody {}

impl FileBody {
    pub(crate) fn new(file: Arc<File>, segments: Vec<Segment>) -> Self {
        let segments: VecDeque<Segment> = segments
            .into_iter()
            .filter(|s| !matches!(s, Segment::File { len: 0, .. }))
            .collect();
        let remaining = segments
            .iter()
            .map(|s| match s {
                Segment::Bytes(b) => b.len() as u64,
                Segment::File { len, .. } => *len,
            })
            .sum();
        let large = segments
            .iter()
            .any(|s| matches!(s, Segment::File { len, .. } if *len > WHOLE_READ_MAX));
        Self {
            file,
            segments,
            remaining,
            read_size: if large { CHUNK } else { WHOLE_READ_MAX },
        }
    }

    /// Bytes not sent yet; the `Content-Length` before the first chunk.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Whether every byte has been read.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.segments.is_empty()
    }

    /// The next chunk; empty once the body is finished.
    ///
    /// # Errors
    /// When the file cannot be read, or has become shorter since the answer started.
    pub async fn next_chunk(&mut self) -> io::Result<Bytes> {
        let Some(segment) = self.segments.pop_front() else {
            return Ok(Bytes::new());
        };
        let chunk = match segment {
            Segment::Bytes(bytes) => bytes,
            Segment::File { offset, len } => {
                let take = len.min(self.read_size);
                if take < len {
                    self.segments.push_front(Segment::File {
                        offset: offset + take,
                        len: len - take,
                    });
                }
                read_at(self.file.clone(), offset, take).await?
            }
        };
        self.remaining = self.remaining.saturating_sub(chunk.len() as u64);
        Ok(chunk)
    }
}

/// Reads exactly `len` bytes at `offset` on the blocking pool.
async fn read_at(file: Arc<File>, offset: u64, len: u64) -> io::Result<Bytes> {
    tokio::task::spawn_blocking(move || {
        let size = usize::try_from(len).map_err(|_| io::Error::other("range too large"))?;
        let mut buf = vec![0; size];
        file.read_exact_at(&mut buf, offset)?;
        Ok(Bytes::from(buf))
    })
    .await
    .map_err(io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::block_on;

    fn body_of(content: &[u8], segments: Vec<Segment>) -> FileBody {
        let mut file = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut file, content).unwrap();
        FileBody::new(Arc::new(file), segments)
    }

    fn drain(mut body: FileBody) -> (Vec<usize>, Vec<u8>) {
        block_on(async {
            let (mut sizes, mut out) = (Vec::new(), Vec::new());
            while !body.is_finished() {
                let chunk = body.next_chunk().await.unwrap();
                sizes.push(chunk.len());
                out.extend_from_slice(&chunk);
            }
            assert_eq!(body.remaining(), 0);
            (sizes, out)
        })
    }

    #[test]
    fn small_ranges_are_read_at_once_and_large_ones_in_chunks() {
        let content: Vec<u8> = (0..3 * 1024 * 1024_u32).map(|i| (i % 251) as u8).collect();
        let whole = body_of(
            &content,
            vec![Segment::File {
                offset: 0,
                len: content.len() as u64,
            }],
        );
        assert_eq!(whole.remaining(), content.len() as u64);
        let (sizes, out) = drain(whole);
        assert_eq!(sizes, vec![256 * 1024; 12]);
        assert_eq!(out, content);

        let small = body_of(
            &content,
            vec![Segment::File {
                offset: 10,
                len: 1024 * 1024,
            }],
        );
        let (sizes, out) = drain(small);
        assert_eq!(sizes, vec![1024 * 1024]);
        assert_eq!(out, &content[10..10 + 1024 * 1024]);
    }

    #[test]
    fn multipart_segments_interleave_bytes_and_ranges() {
        let body = body_of(
            b"0123456789",
            vec![
                Segment::Bytes(Bytes::from_static(b"<a>")),
                Segment::File { offset: 0, len: 2 },
                Segment::Bytes(Bytes::from_static(b"<b>")),
                Segment::File { offset: 8, len: 2 },
                Segment::File { offset: 5, len: 0 },
            ],
        );
        assert_eq!(body.remaining(), 10);
        assert_eq!(drain(body).1, b"<a>01<b>89");
    }

    #[test]
    fn a_file_that_shrank_is_an_error() {
        let mut body = body_of(b"short", vec![Segment::File { offset: 0, len: 50 }]);
        let err = block_on(body.next_chunk()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn an_empty_file_is_finished_at_once() {
        let body = body_of(b"", vec![Segment::File { offset: 0, len: 0 }]);
        assert!(body.is_finished());
        assert_eq!(body.remaining(), 0);
    }
}
