//! `compress`: gzip for text-like responses, streamed chunk by chunk.
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

/// A streaming gzip encoder.
pub struct Gzip {
    encoder: GzEncoder<Vec<u8>>,
}

impl std::fmt::Debug for Gzip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gzip")
    }
}

impl Gzip {
    fn new() -> Self {
        Self {
            encoder: GzEncoder::new(Vec::new(), Compression::new(6)),
        }
    }

    /// Compresses `chunk` and returns the bytes to send. Each chunk is flushed so streaming
    /// responses keep flowing; `end` writes the gzip trailer.
    pub fn encode(&mut self, chunk: &[u8], end: bool) -> std::io::Result<Bytes> {
        self.encoder.write_all(chunk)?;
        if end {
            self.encoder.try_finish()?;
        } else {
            self.encoder.flush()?;
        }
        Ok(Bytes::from(std::mem::take(self.encoder.get_mut())))
    }
}

/// The `compress` middleware.
#[derive(Debug)]
pub(crate) struct Compress {
    gzip: bool,
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
            gzip: config.algorithms.contains(&CompressAlgorithm::Gzip),
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
        if !self.gzip || status < 200 || matches!(status, 204 | 206 | 304) {
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

/// Whether `Accept-Encoding` allows gzip (an explicit token or `*`, with q above zero).
fn accepts_gzip(req: &RequestHeader) -> bool {
    let mut gzip = None;
    let mut any = None;
    for value in req.headers.get_all(http::header::ACCEPT_ENCODING) {
        let Ok(text) = value.to_str() else { continue };
        for item in text.split(',') {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let q = parts
                .filter_map(|p| p.trim().strip_prefix("q="))
                .find_map(|q| q.trim().parse::<f32>().ok())
                .unwrap_or(1.0);
            match coding.as_str() {
                "gzip" | "x-gzip" => gzip = Some(q > 0.0),
                "*" => any = Some(q > 0.0),
                _ => {}
            }
        }
    }
    gzip.or(any).unwrap_or(false)
}

#[async_trait]
impl Middleware for Compress {
    async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
        cx.accepts_gzip = accepts_gzip(req);
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
        if !cx.accepts_gzip || cx.head_request {
            return;
        }
        let _ = resp.insert_header(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
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
        cx.compression = Some(Gzip::new());
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
            "br;q=1, gzip;q=0.5",
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
    fn gzip_stream_round_trips() {
        let mut gz = Gzip::new();
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
