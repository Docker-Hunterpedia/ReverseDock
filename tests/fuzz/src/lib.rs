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
    let status = parsed.parse(&wire).unwrap_or_else(|e| {
        panic!(
            "the forwarded request does not parse ({e}): {:?}",
            String::from_utf8_lossy(&wire[..head])
        )
    });
    let httparse::Status::Complete(parsed_head) = status else {
        panic!(
            "the forwarded header block is incomplete: {:?}",
            String::from_utf8_lossy(&wire[..head])
        );
    };
    assert_eq!(
        parsed_head, head,
        "the forwarded header block ends where it was written"
    );
    assert_eq!(
        parsed.method,
        Some(req.method.as_str()),
        "method changed in transit"
    );
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
    assert_eq!(
        lengths,
        vec![body.len().to_string().as_bytes()],
        "one Content-Length"
    );
    assert!(
        !parsed
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding")),
        "no second framing header"
    );
}

/// Parses a rule; a parsed rule's canonical form must parse back to the same AST.
pub fn rules_parser(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
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
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = rdock_config::load_str(text, rdock_config::Format::Yaml);
    let _ = rdock_config::load_str(text, rdock_config::Format::Json);
}

/// Parses `data` and each of its prefixes as a PROXY protocol header, as rdock-proxy does with
/// the bytes of a connection: never a panic, never more bytes consumed than given, and a parsed
/// header encodes back to one that parses to the same addresses.
pub fn proxy_header(data: &[u8]) {
    use proxy_header::{Error, ParseConfig, ProxyHeader};
    let config = ParseConfig {
        include_tlvs: false,
        allow_v1: true,
        allow_v2: true,
    };
    for end in 0..=data.len().min(512) {
        let buf = &data[..end];
        match ProxyHeader::parse(buf, config) {
            Ok((header, len)) => {
                assert!(len <= buf.len(), "consumed {len} of {} bytes", buf.len());
                let mut encoded = Vec::new();
                if header.encode_v2(&mut encoded).is_ok() {
                    let (again, again_len) =
                        ProxyHeader::parse(&encoded, config).expect("own encoding parses");
                    assert_eq!(again_len, encoded.len());
                    assert_eq!(again.proxied_address(), header.proxied_address());
                }
            }
            Err(Error::BufferTooShort | Error::Invalid) => {}
            Err(other) => panic!("unexpected parse error {other:?}"),
        }
    }
}

/// Parses arbitrary bytes as the start of a TLS connection. Only results are expected, never
/// panics; a request for more bytes asks for more than were given and stays within the cap; a
/// ClientHello fits in the bytes given and depends on no byte after its records.
pub fn clienthello(data: &[u8]) {
    use rdock_tls::clienthello::{MAX_PEEK, Parsed, parse};
    match parse(data) {
        Ok(Parsed::NeedMore { total }) => {
            assert!(
                total > data.len(),
                "NeedMore {total} for {} bytes",
                data.len()
            );
            assert!(total <= MAX_PEEK, "NeedMore {total} beyond the cap");
        }
        Ok(Parsed::Hello { hello, len }) => {
            assert!(
                len <= data.len(),
                "a hello of {len} bytes in {} bytes",
                data.len()
            );
            let again = parse(&data[..len]);
            assert_eq!(
                again,
                Ok(Parsed::Hello { hello, len }),
                "later bytes changed the hello"
            );
        }
        Ok(Parsed::NotTls) | Err(_) => {}
    }
}

/// Computes the TLS client fingerprints of arbitrary bytes. Never panics; facts exist only for
/// a complete ClientHello that `parse` accepts; JA4 always has its fixed shape (36 characters,
/// three `_`-separated sections) and JA3 is 32 hex digits.
pub fn tls_fingerprint(data: &[u8]) {
    use rdock_tls::clienthello::{MAX_EXTENSIONS, Parsed, facts, parse};
    use rdock_tls::fingerprint::{Transport, ja3, ja4};
    let Some(found) = facts(data) else {
        return;
    };
    assert!(
        matches!(parse(data), Ok(Parsed::Hello { .. })),
        "facts without an accepted hello"
    );
    assert!(found.extensions.len() <= MAX_EXTENSIONS);
    for transport in [Transport::Tcp, Transport::Quic, Transport::Dtls] {
        let fp = ja4(&found, transport);
        assert_eq!(fp.len(), 36, "{fp}");
        assert_eq!(fp.matches('_').count(), 2, "{fp}");
        assert!(fp.is_ascii(), "{fp}");
    }
    let j = ja3(&found);
    assert!(j.len() == 32 && j.bytes().all(|b| b.is_ascii_hexdigit()));
}

/// Treats `data` as a pointer and as `patch \0 document` (both JSON). Pointers that parse
/// round-trip through escaping; a patch that applies gives the same result twice; a check that
/// passes without a document never makes `apply` panic.
pub fn json_patch(data: &[u8]) {
    use rdock_model::json_patch::{PatchOp, apply_within, escape_token, parse_pointer};
    // The cap `transform` applies (its default `max_body`): repeated `copy` operations would
    // otherwise grow the document exponentially.
    const MAX: u64 = 1024 * 1024;
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(tokens) = parse_pointer(text) {
        let rebuilt: String = tokens
            .iter()
            .map(|t| format!("/{}", escape_token(t)))
            .collect();
        assert_eq!(
            parse_pointer(&rebuilt),
            Ok(tokens),
            "pointer `{text}` does not round-trip"
        );
    }
    let (patch, document) = text.split_once('\0').unwrap_or((text, "{}"));
    let (Ok(ops), Ok(doc)) = (
        serde_json::from_str::<Vec<PatchOp>>(patch),
        serde_json::from_str::<serde_json::Value>(document),
    ) else {
        return;
    };
    for op in &ops {
        let _ = op.check();
    }
    let mut first = doc.clone();
    let mut second = doc;
    let a = apply_within(&mut first, &ops, MAX);
    let b = apply_within(&mut second, &ops, MAX);
    assert_eq!(
        a.is_ok(),
        b.is_ok(),
        "the same patch gave different results"
    );
    if a.is_ok() {
        assert_eq!(first, second);
    }
}

/// The HTTP/3 request mapping (ADR-0032) on arbitrary HEADERS payloads: decoding and validation
/// never panic; a section that decodes re-encodes to the same fields; and a request that passes
/// is forwarded as exactly one HTTP/1.1 request head that an independent parser reads back with
/// the same method, target and fields (no smuggling through the HTTP/3 to HTTP/1 translation).
pub fn http3_request(data: &[u8]) {
    use rdock_proxy::http3::request::{FIELD_OVERHEAD, decode, encode, map};
    const LIMIT: u64 = 64 * 1024;
    if let Ok(fields) = decode(data, LIMIT) {
        let pairs: Vec<(&[u8], &[u8])> = fields
            .iter()
            .map(|f| (f.name.as_ref(), f.value.as_ref()))
            .collect();
        let again = decode(&encode::section(&pairs), LIMIT).expect("a decoded section re-encodes");
        assert_eq!(again, fields, "decode . encode . decode is decode");
        let size: u64 = fields
            .iter()
            .map(|f| f.name.len() as u64 + f.value.len() as u64 + FIELD_OVERHEAD)
            .sum();
        assert!(size <= LIMIT, "the limit holds");
    }
    let Ok(mapped) = map(data, LIMIT) else {
        return;
    };
    let req = &mapped.header;
    assert_eq!(req.version, http::Version::HTTP_3);
    assert_ne!(req.method, http::Method::CONNECT);
    let host = req.headers.get("host").expect("a mapped request has a host");
    assert!(!host.as_bytes().contains(&b'@'));
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ] {
        assert!(!req.headers.contains_key(name), "{name} passed");
    }
    assert!(req.headers.get_all("cookie").iter().count() <= 1);
    assert!(req.headers.get_all("content-length").iter().count() <= 1);
    let mut wire = Vec::new();
    wire.extend_from_slice(req.method.as_str().as_bytes());
    wire.push(b' ');
    wire.extend_from_slice(req.raw_path());
    wire.extend_from_slice(b" HTTP/1.1\r\n");
    let mut headers = bytes::BytesMut::new();
    req.header_to_h1_wire(&mut headers);
    wire.extend_from_slice(&headers);
    wire.extend_from_slice(b"\r\n");
    let mut slots = [httparse::EMPTY_HEADER; 4096];
    let mut parsed = httparse::Request::new(&mut slots);
    let status = parsed.parse(&wire).unwrap_or_else(|e| {
        panic!(
            "the forwarded head does not parse ({e}): {:?}",
            String::from_utf8_lossy(&wire)
        )
    });
    assert_eq!(status, httparse::Status::Complete(wire.len()), "one complete head");
    assert_eq!(parsed.method, Some(req.method.as_str()));
    assert_eq!(parsed.path.map(str::as_bytes), Some(req.raw_path()));
    assert_eq!(parsed.headers.len(), req.headers.len(), "no field split or lost");
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn seeds(target: &str) -> Vec<Vec<u8>> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("seeds")
            .join(target);
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .map(|d| d.filter_map(Result::ok).map(|e| e.path()).collect())
            .unwrap_or_default();
        files.sort();
        files
            .iter()
            .map(|f| std::fs::read(f).expect("seed"))
            .collect()
    }

    #[test]
    fn http3_request_seeds() {
        let all = seeds("http3_request");
        assert!(all.len() >= 5, "seed corpus present");
        for seed in all {
            assert!(
                rdock_proxy::http3::request::map(&seed, 64 * 1024).is_ok(),
                "every seed is a valid request head"
            );
            for cut in 0..=seed.len() {
                super::http3_request(&seed[..cut]);
            }
        }
    }

    /// A deterministic mutation smoke run on stable (the real fuzzing needs nightly).
    #[test]
    fn http3_request_mutations() {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for seed in seeds("http3_request") {
            for _ in 0..5_000 {
                let mut data = seed.clone();
                for _ in 0..=(next() % 4) {
                    let at = usize::try_from(next()).unwrap_or(0) % (data.len() + 1);
                    match next() % 3 {
                        0 if at < data.len() => data[at] = u8::try_from(next() & 0xff).unwrap_or(0),
                        1 => data.insert(at, u8::try_from(next() & 0xff).unwrap_or(0)),
                        _ if at < data.len() => {
                            data.remove(at);
                        }
                        _ => {}
                    }
                }
                super::http3_request(&data);
            }
        }
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
    fn clienthello_seeds() {
        let all = seeds("clienthello");
        assert!(all.len() >= 5, "seed corpus present");
        for seed in all {
            let parsed = rdock_tls::clienthello::parse(&seed);
            assert!(
                matches!(parsed, Ok(rdock_tls::clienthello::Parsed::Hello { .. })),
                "every seed is a complete ClientHello: {parsed:?}"
            );
            for cut in 0..=seed.len() {
                super::clienthello(&seed[..cut]);
                super::tls_fingerprint(&seed[..cut]);
            }
            assert!(
                rdock_tls::clienthello::facts(&seed).is_some(),
                "every seed has a fingerprint"
            );
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

    #[test]
    fn oidc_cookie_seeds() {
        for input in [
            &b"v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"[..],
            b"__Host-rdock_oidc_0=v1.AA; __Host-rdock_oidc_1=BB; __Host-rdock_oidc_2=",
            b"__Host-rdock_oidc=v1.; __Host-rdock_oidc=v1.",
            b"=;=;;=\"\"",
            b"\xff\x00v1.",
        ] {
            super::oidc_cookie(input);
        }
    }

    #[test]
    fn json_patch_seeds() {
        for input in [
            "/a~1b/~0c/0",
            "~2",
            "[{\"op\":\"move\",\"from\":\"/a\",\"path\":\"/a/b\"}]\0{\"a\":{}}",
            "[{\"op\":\"add\",\"path\":\"/a/-\",\"value\":1},{\"op\":\"test\",\"path\":\"/a/0\",\"value\":1.0}]\0{\"a\":[]}",
            "[{\"op\":\"remove\",\"path\":\"\"}]\0[]",
            "[{\"op\":\"copy\",\"from\":\"/01\",\"path\":\"/x\"}]\0[1,2]",
        ] {
            super::json_patch(input.as_bytes());
        }
    }

    #[test]
    fn proxy_header_seeds() {
        let signature = b"\r\n\r\n\x00\r\nQUIT\n";
        super::proxy_header(b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nGET /");
        super::proxy_header(b"PROXY TCP6 2001:db8::1 2001:db8::2 1 2\r\n");
        super::proxy_header(b"PROXY UNKNOWN\r\n");
        super::proxy_header(b"PROXY TCP4 1.1.1.1");
        let v4 = [
            &signature[..],
            &[0x21, 0x11, 0x00, 0x0C],
            &[10, 0, 0, 1, 10, 0, 0, 2, 0, 80, 1, 187],
        ]
        .concat();
        super::proxy_header(&v4);
        super::proxy_header(&[&signature[..], &[0x20, 0x00, 0x00, 0x00]].concat());
        super::proxy_header(&[&signature[..], &[0x21, 0x11, 0x00, 0x03, 1, 2, 3]].concat());
        super::proxy_header(&[&signature[..], &[0x21, 0x31, 0x00, 0x10]].concat());
    }
}

/// Verifies arbitrary text as a JWT against fixed keys; only refusals are expected.
pub fn jwt_verify(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        rdock_middleware::fuzz_jwt(text);
    }
}

/// Opens arbitrary bytes as an `oidc` session cookie header and as a sealed value; only
/// refusals are expected (no key is known to the fuzzer).
pub fn oidc_cookie(data: &[u8]) {
    rdock_middleware::fuzz_oidc_cookie(data);
}
