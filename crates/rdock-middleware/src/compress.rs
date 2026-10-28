//! `compress`: zstd, Brotli or gzip for text-like responses, negotiated with `Accept-Encoding`
//! and streamed chunk by chunk.
//!
//! Skipped for HEAD, partial (206) and already encoded responses, bodies known to be smaller
//! than `min_size`, server-sent events and gRPC. `Vary: Accept-Encoding` is added to every
//! response that could be compressed, so caches keep the variants apart.

use std::io::Write;

use async_trait::async_trait;
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use http::{HeaderValue, Method};
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_model::middleware::{CompressAlgorithm, CompressConfig};

use crate::{Context, Flow, Middleware};

/// Content types compressed when `content_types` is empty.
const DEFAULT_TYPES: &[&str] = &[
    "text/*",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/ld+json",
    "application/manifest+json",
    "application/vnd.api+json",
    "application/wasm",
    "image/svg+xml",
    "font/ttf",
    "font/otf",
];

/// Never compressed: streams that must not be buffered or that carry their own framing.
const EXCLUDED_TYPES: &[&str] = &["text/event-stream", "application/grpc"];

/// gzip level: the zlib default, a good balance for dynamic responses.
const GZIP_LEVEL: u32 = 6;
/// Brotli quality for on-the-fly compression; 11 is meant for static files and far slower.
const BROTLI_QUALITY: u32 = 4;
/// Brotli window: 4 MiB (lgwin 22).
const BROTLI_WINDOW: u32 = 22;
/// zstd level 3, its default; the window stays under the 8 MiB browsers accept (RFC 8878).
const ZSTD_LEVEL: i32 = 3;

/// A streaming response encoder. Each chunk is flushed, so streamed responses keep flowing.
pub enum Encoder {
    /// gzip.
    Gzip(GzEncoder<Vec<u8>>),
    /// Brotli.
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    /// Zstandard.
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Encoder {
    fn new(algorithm: CompressAlgorithm) -> std::io::Result<Self> {
        Ok(match algorithm {
            CompressAlgorithm::Gzip => {
                Self::Gzip(GzEncoder::new(Vec::new(), Compression::new(GZIP_LEVEL)))
            }
            CompressAlgorithm::Br => Self::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                BROTLI_QUALITY,
                BROTLI_WINDOW,
            ))),
            CompressAlgorithm::Zstd => {
                Self::Zstd(zstd::stream::write::Encoder::new(Vec::new(), ZSTD_LEVEL)?)
            }
        })
    }

    /// The `Content-Encoding` token.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Gzip(_) => "gzip",
            Self::Brotli(_) => "br",
            Self::Zstd(_) => "zstd",
        }
    }

    /// Compresses `chunk` and returns the bytes to send; `end` finishes the stream.
    pub fn encode(&mut self, chunk: &[u8], end: bool) -> std::io::Result<Bytes> {
        let out = match self {
            Self::Gzip(e) => {
                e.write_all(chunk)?;
                if end {
                    e.try_finish()?;
                } else {
                    e.flush()?;
                }
                std::mem::take(e.get_mut())
            }
            Self::Brotli(e) => {
                e.write_all(chunk)?;
                e.flush()?;
                if end {
                    // Dropping the writer would write the final block into a buffer we no
                    // longer hold; replace it and finish the old one.
                    let done = std::mem::replace(
                        e,
                        Box::new(brotli::CompressorWriter::new(
                            Vec::new(),
                            4096,
                            0,
                            BROTLI_WINDOW,
                        )),
                    );
                    done.into_inner()
                } else {
                    std::mem::take(e.get_mut())
                }
            }
            Self::Zstd(e) => {
                e.write_all(chunk)?;
                if end {
                    e.do_finish()?;
                } else {
                    e.flush()?;
                }
                std::mem::take(e.get_mut())
            }
        };
        Ok(Bytes::from(out))
    }
}

/// The `compress` middleware.
#[derive(Debug)]
pub(crate) struct Compress {
    /// In order of preference.
    algorithms: Vec<CompressAlgorithm>,
    min_size: u64,
    types: Vec<String>,
}

impl Compress {
    pub(crate) fn new(config: &CompressConfig) -> Self {
        let types = if config.content_types.is_empty() {
            DEFAULT_TYPES.iter().map(|t| (*t).to_owned()).collect()
        } else {
            config
                .content_types
                .iter()
                .map(|t| t.to_ascii_lowercase())
                .collect()
        };
        Self {
            algorithms: config.algorithms.clone(),
            min_size: config.min_size.as_u64(),
            types,
        }
    }

    fn type_allowed(&self, content_type: &str) -> bool {
        let media = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if EXCLUDED_TYPES.iter().any(|t| media.starts_with(t)) {
            return false;
        }
        self.types.iter().any(|t| match t.strip_suffix("/*") {
            Some(major) => media.split('/').next() == Some(major),
            None => *t == media,
        })
    }

    fn eligible(&self, resp: &ResponseHeader) -> bool {
        let status = resp.status.as_u16();
        if self.algorithms.is_empty() || status < 200 || matches!(status, 204 | 206 | 304) {
            return false;
        }
        let header = |name| {
            resp.headers
                .get(name)
                .and_then(|v: &HeaderValue| v.to_str().ok())
        };
        if header(http::header::CONTENT_ENCODING)
            .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
            || resp.headers.contains_key(http::header::CONTENT_RANGE)
        {
            return false;
        }
        if header(http::header::CONTENT_LENGTH)
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|len| len < self.min_size)
        {
            return false;
        }
        header(http::header::CONTENT_TYPE).is_some_and(|t| self.type_allowed(t))
    }
}

/// The coding to use: among `offered` (in server preference order), the one the client weighs
/// highest in `Accept-Encoding`; ties go to the server's order. `*` covers codings not named.
/// `None` when the client accepts none of them.
fn negotiate(req: &RequestHeader, offered: &[CompressAlgorithm]) -> Option<CompressAlgorithm> {
    let mut named: Vec<(String, f32)> = Vec::new();
    for value in req.headers.get_all(http::header::ACCEPT_ENCODING) {
        let Ok(text) = value.to_str() else { continue };
        for item in text.split(',') {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let q = parts
                .filter_map(|p| p.trim().strip_prefix("q="))
                .find_map(|q| q.trim().parse::<f32>().ok())
                .unwrap_or(1.0);
            if !coding.is_empty() {
                named.push((coding, q));
            }
        }
    }
    let weight = |algorithm: CompressAlgorithm| {
        let tokens: &[&str] = match algorithm {
            CompressAlgorithm::Gzip => &["gzip", "x-gzip"],
            CompressAlgorithm::Br => &["br"],
            CompressAlgorithm::Zstd => &["zstd"],
        };
        named
            .iter()
            .find(|(c, _)| tokens.contains(&c.as_str()))
            .or_else(|| named.iter().find(|(c, _)| c == "*"))
            .map_or(0.0, |(_, q)| *q)
    };
    let mut best: Option<(CompressAlgorithm, f32)> = None;
    for algorithm in offered {
        let q = weight(*algorithm);
        if q > 0.0 && best.is_none_or(|(_, top)| q > top) {
            best = Some((*algorithm, q));
        }
    }
    best.map(|(algorithm, _)| algorithm)
}

#[async_trait]
impl Middleware for Compress {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        cx.encoding = negotiate(req, &self.algorithms);
        cx.head_request = req.method == Method::HEAD;
        Flow::Next
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        if cx.compression.is_some() || !self.eligible(resp) {
            return;
        }
        let _ = resp.append_header(
            http::header::VARY,
            HeaderValue::from_static("Accept-Encoding"),
        );
        let Some(algorithm) = cx.encoding.filter(|_| !cx.head_request) else {
            return;
        };
        let Ok(encoder) = Encoder::new(algorithm) else {
            return;
        };
        let _ = resp.insert_header(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static(encoder.name()),
        );
        resp.remove_header(&http::header::CONTENT_LENGTH);
        resp.remove_header(&http::header::ACCEPT_RANGES);
        if let Some(etag) = resp
            .headers
            .get(http::header::ETAG)
            .and_then(|v| v.to_str().ok())
            && !etag.starts_with("W/")
            && let Ok(weak) = HeaderValue::from_str(&format!("W/{etag}"))
        {
            let _ = resp.insert_header(http::header::ETAG, weak);
        }
        cx.compression = Some(encoder);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use rdock_model::values::ByteSize;

    use super::*;
    use crate::test_support::{block_on, cx, header, request};

    fn mw() -> Compress {
        Compress::new(&CompressConfig::default())
    }

    fn response(content_type: &str, extra: &[(&'static str, &str)]) -> ResponseHeader {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", content_type).unwrap();
        for (k, v) in extra {
            resp.insert_header(*k, *v).unwrap();
        }
        resp
    }

    fn run(accept: &str, method: &str, mut resp: ResponseHeader) -> (ResponseHeader, bool) {
        let mw = mw();
        let mut req = request(method, "/", &[("accept-encoding", accept)]);
        let mut c = cx();
        block_on(mw.request(&mut req, &mut c));
        block_on(mw.response(&mut resp, &mut c));
        let on = c.compression.is_some();
        (resp, on)
    }

    #[test]
    fn compresses_text_for_gzip_clients() {
        let (resp, on) = run(
            "gzip;q=1, br;q=0.5",
            "GET",
            response(
                "text/html; charset=utf-8",
                &[("content-length", "5000"), ("etag", "\"abc\"")],
            ),
        );
        assert!(on);
        assert_eq!(header(&resp.headers, "content-encoding"), Some("gzip"));
        assert_eq!(header(&resp.headers, "content-length"), None);
        assert_eq!(header(&resp.headers, "etag"), Some("W/\"abc\""));
        assert_eq!(header(&resp.headers, "vary"), Some("Accept-Encoding"));
    }

    #[test]
    fn skips_what_must_not_be_compressed() {
        assert!(!run("gzip;q=0", "GET", response("text/plain", &[])).1);
        assert!(!run("gzip", "HEAD", response("text/plain", &[])).1);
        assert!(!run("gzip", "GET", response("text/event-stream", &[])).1);
        assert!(!run("gzip", "GET", response("application/grpc", &[])).1);
        assert!(!run("gzip", "GET", response("image/png", &[])).1);
        assert!(
            !run(
                "gzip",
                "GET",
                response("text/plain", &[("content-length", "10")])
            )
            .1
        );
        assert!(
            !run(
                "gzip",
                "GET",
                response("text/plain", &[("content-encoding", "br")])
            )
            .1
        );
        let (resp, on) = run("identity", "GET", response("application/json", &[]));
        assert!(!on);
        assert_eq!(
            header(&resp.headers, "vary"),
            Some("Accept-Encoding"),
            "still varies"
        );
        let custom = Compress::new(&CompressConfig {
            content_types: vec!["application/*".into()],
            min_size: ByteSize::kib(0),
            ..CompressConfig::default()
        });
        assert!(custom.type_allowed("application/x-custom"));
        assert!(!custom.type_allowed("text/plain"));
    }

    #[test]
    fn negotiation_follows_q_values_then_server_order() {
        let all = [
            CompressAlgorithm::Zstd,
            CompressAlgorithm::Br,
            CompressAlgorithm::Gzip,
        ];
        let pick = |accept: &str, offered: &[CompressAlgorithm]| {
            negotiate(
                &request("GET", "/", &[("accept-encoding", accept)]),
                offered,
            )
        };
        assert_eq!(
            pick("gzip, deflate, br, zstd", &all),
            Some(CompressAlgorithm::Zstd)
        );
        assert_eq!(
            pick("br;q=1, gzip;q=0.5", &all),
            Some(CompressAlgorithm::Br)
        );
        assert_eq!(
            pick("gzip;q=1, br;q=0.4", &all),
            Some(CompressAlgorithm::Gzip)
        );
        assert_eq!(
            pick("*", &[CompressAlgorithm::Br]),
            Some(CompressAlgorithm::Br)
        );
        assert_eq!(pick("*;q=0.2, zstd;q=0", &all), Some(CompressAlgorithm::Br));
        assert_eq!(pick("identity", &all), None);
        assert_eq!(pick("br", &[CompressAlgorithm::Gzip]), None);
    }

    #[test]
    fn brotli_and_zstd_streams_round_trip() {
        for algorithm in [CompressAlgorithm::Br, CompressAlgorithm::Zstd] {
            let mut encoder = Encoder::new(algorithm).unwrap();
            let mut out = Vec::new();
            let first = encoder.encode(b"hello ", false).unwrap();
            assert!(!first.is_empty(), "{algorithm:?} flushes each chunk");
            out.extend_from_slice(&first);
            out.extend_from_slice(&encoder.encode(b"world", true).unwrap());
            let text = if algorithm == CompressAlgorithm::Zstd {
                zstd::stream::decode_all(&out[..]).unwrap()
            } else {
                let mut text = Vec::new();
                brotli::Decompressor::new(&out[..], 4096)
                    .read_to_end(&mut text)
                    .unwrap();
                text
            };
            assert_eq!(text, b"hello world", "{algorithm:?}");
        }
    }

    #[test]
    fn gzip_stream_round_trips() {
        let mut gz = Encoder::new(CompressAlgorithm::Gzip).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&gz.encode(b"hello ", false).unwrap());
        out.extend_from_slice(&gz.encode(b"world", true).unwrap());
        let mut text = String::new();
        flate2::read::GzDecoder::new(&out[..])
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "hello world");
    }
}
