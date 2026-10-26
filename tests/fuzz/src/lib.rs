//! Checks shared by the fuzz targets and the seed-corpus replay tests.

use std::time::Duration;

use pingora_core::protocols::http::v1::server::HttpSession;
use tokio::io::AsyncWriteExt;

/// Largest body the framing check reads.
const MAX_BODY: usize = 1 << 20;
const STEP: Duration = Duration::from_millis(200);

/// Feeds `data` to Pingora's HTTP/1 server parser. If it accepts a request, rebuilds the request
/// as it would be forwarded (Pingora's own header serialiser, the request target as parsed, the
/// decoded body under a fresh `Content-Length`) and checks with an independent parser that it is
/// exactly one complete request: no header or target bytes may break the framing.
pub fn h1_framing(data: &[u8]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let (mut client, server) = tokio::io::duplex(2 * MAX_BODY);
        if client.write_all(data).await.is_err() || client.shutdown().await.is_err() {
            return;
        }
        let mut session = HttpSession::new(Box::new(server));
        let Ok(Ok(Some(_))) = tokio::time::timeout(STEP, session.read_request()).await else {
            return;
        };
        let mut body = Vec::new();
        loop {
            match tokio::time::timeout(STEP, session.read_body_bytes()).await {
                Ok(Ok(Some(chunk))) => body.extend_from_slice(&chunk),
                Ok(Ok(None)) => break,
                // A body the parser rejects or never finishes is not forwarded.
                _ => return,
            }
            if body.len() > MAX_BODY {
                return;
            }
        }
        check_forwarded(session.req_header(), &body);
    });
}

fn check_forwarded(req: &pingora_http::RequestHeader, body: &[u8]) {
    let mut upstream = req.clone();
    for name in [
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "proxy-connection",
    ] {
        upstream.remove_header(name);
    }
    upstream
        .insert_header("content-length", body.len().to_string())
        .expect("content-length");
    let mut wire = Vec::new();
    wire.extend_from_slice(req.method.as_str().as_bytes());
    wire.push(b' ');
    wire.extend_from_slice(req.raw_path());
    wire.extend_from_slice(b" HTTP/1.1\r\n");
    let mut headers = bytes::BytesMut::new();
    upstream.header_to_h1_wire(&mut headers);
    wire.extend_from_slice(&headers);
    wire.extend_from_slice(b"\r\n");
    let head = wire.len();
    wire.extend_from_slice(body);

    let mut slots = [httparse::EMPTY_HEADER; 512];
    let mut parsed = httparse::Request::new(&mut slots);
    let status = parsed
        .parse(&wire)
        .unwrap_or_else(|e| panic!("the forwarded request does not parse ({e}): {:?}", String::from_utf8_lossy(&wire[..head])));
    let httparse::Status::Complete(parsed_head) = status else {
        panic!("the forwarded header block is incomplete: {:?}", String::from_utf8_lossy(&wire[..head]));
    };
    assert_eq!(parsed_head, head, "the forwarded header block ends where it was written");
    assert_eq!(parsed.method, Some(req.method.as_str()), "method changed in transit");
    assert_eq!(
        parsed.path.map(str::as_bytes),
        Some(req.raw_path()),
        "request target changed in transit"
    );
    let lengths: Vec<&[u8]> = parsed
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| h.value)
        .collect();
    assert_eq!(lengths, vec![body.len().to_string().as_bytes()], "one Content-Length");
    assert!(
        !parsed.headers.iter().any(|h| h.name.eq_ignore_ascii_case("transfer-encoding")),
        "no second framing header"
    );
}

/// Parses a rule; a parsed rule's canonical form must parse back to the same AST.
pub fn rules_parser(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(expr) = rdock_rules::parse(text) {
        let canonical = expr.to_string();
        let again = rdock_rules::parse(&canonical)
            .unwrap_or_else(|e| panic!("canonical form `{canonical}` does not parse: {e:?}"));
        assert_eq!(again, expr, "canonical form changed the rule");
        let _ = expr.validate(rdock_rules::Context::Http);
    }
    let _ = rdock_rules::path::normalize(text);
}

/// Loads arbitrary text as YAML and as JSON; only errors are expected, never panics.
pub fn config_loader(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = rdock_config::load_str(text, rdock_config::Format::Yaml);
    let _ = rdock_config::load_str(text, rdock_config::Format::Json);
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn seeds(target: &str) -> Vec<Vec<u8>> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds").join(target);
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .map(|d| d.filter_map(Result::ok).map(|e| e.path()).collect())
            .unwrap_or_default();
        files.sort();
        files.iter().map(|f| std::fs::read(f).expect("seed")).collect()
    }

    #[test]
    fn h1_framing_seeds() {
        let all = seeds("h1_framing");
        assert!(all.len() >= 20, "seed corpus present");
        for seed in all {
            super::h1_framing(&seed);
        }
    }

    #[test]
    fn rules_and_config_seeds() {
        for rule in [
            "Host(`a.test`) && PathPrefix(`/api`)",
            "!(Header(`X`, `y`) || Query(`q`)) && ClientIP(`10.0.0.0/8`)",
            "host(`A.test.`)",
            "Path(\"/a\\\"b\")",
            "((((Host(`x`)))))",
        ] {
            super::rules_parser(rule.as_bytes());
        }
        super::config_loader(b"routes: { a: { match: \"Host(`x`)\", service: s } }");
        super::config_loader(b"{\"listeners\": {\"web\": {\"address\": \":80\"}}}");
        super::config_loader(b"\xff\xfe");
    }
}
