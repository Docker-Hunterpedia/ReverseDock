//! Checks shared by the fuzz targets and the seed-corpus replay tests.

use std::time::Duration;

use pingora_core::protocols::http::v1::server::HttpSession;
use tokio::io::AsyncWriteExt;

/// The NGINX configuration parser of `rdock migrate nginx`, from its source file.
#[allow(dead_code, missing_docs, clippy::all, clippy::pedantic)]
#[path = "../../../crates/rdock-migrate/src/nginx/parser.rs"]
mod nginx;

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

/// Parses arbitrary text as an NGINX configuration: never a panic, never deeper than the parser's
/// limit, and a tree printed back (every argument quoted) parses to the same names and arguments.
pub fn nginx_parser(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(tree) = nginx::parse(text, 0) else {
        return;
    };
    fn depth(tree: &[nginx::Directive]) -> usize {
        tree.iter()
            .map(|d| d.block.as_deref().map_or(0, |b| 1 + depth(b)))
            .max()
            .unwrap_or(0)
    }
    assert!(
        depth(&tree) <= nginx::MAX_DEPTH + 1,
        "nesting beyond the limit"
    );
    if tree.iter().any(|d| d.raw.is_some()) {
        return;
    }
    fn quote(text: &str) -> String {
        format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
    }
    fn print(tree: &[nginx::Directive], out: &mut String) {
        for d in tree {
            out.push_str(&quote(&d.name));
            for a in &d.args {
                out.push(' ');
                out.push_str(&quote(&a.text));
            }
            match &d.block {
                Some(block) => {
                    out.push_str(" {\n");
                    print(block, out);
                    out.push_str("}\n");
                }
                None => out.push_str(";\n"),
            }
        }
    }
    fn shape(tree: &[nginx::Directive]) -> Vec<String> {
        let mut out = Vec::new();
        for d in tree {
            out.push(format!("{:?} {:?}", d.name, d.values()));
            if let Some(block) = &d.block {
                out.push("{".to_owned());
                out.extend(shape(block));
                out.push("}".to_owned());
            }
        }
        out
    }
    let mut printed = String::new();
    print(&tree, &mut printed);
    let again = nginx::parse(&printed, 0)
        .unwrap_or_else(|e| panic!("printed tree does not parse: {e}\n{printed}"));
    assert_eq!(shape(&again), shape(&tree), "printing changed the tree");
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

/// The HTTP/3 frame limits (ADR-0032, review fix H1) on the same bytes read as a stream: the
/// verdict does not depend on how the stream is cut into chunks, the connection's budget never
/// holds more than its limit, and everything a guard reserved is released when it goes.
fn http3_frames(data: &[u8], max_header_size: u64) {
    use rdock_proxy::http3::frames::{Budget, FrameGuard, StreamKind};
    use std::sync::Arc;
    let cut = data
        .first()
        .map_or(0, |b| usize::from(*b) % (data.len() + 1));
    for kind in [StreamKind::Request, StreamKind::Unidirectional] {
        let budget = Arc::new(Budget::new(max_header_size * 2));
        let mut whole = FrameGuard::new(kind, max_header_size, Some(budget.clone()));
        let one = whole.inspect(data);
        assert!(budget.held() <= max_header_size * 2, "the budget holds");
        let mut split = FrameGuard::new(kind, max_header_size, None);
        let two = split
            .inspect(&data[..cut])
            .and_then(|()| split.inspect(&data[cut..]));
        // A budget can only refuse more; without its refusal the verdicts agree.
        if !matches!(
            one,
            Err(rdock_proxy::http3::frames::Violation::OverBudget { .. })
        ) {
            assert_eq!(one, two, "the verdict depends on the chunks");
        }
        drop(whole);
        assert_eq!(budget.held(), 0, "a dropped guard releases its reservation");
    }
}

/// The HTTP/3 request mapping (ADR-0032) on arbitrary HEADERS payloads: decoding and validation
/// never panic; a section that decodes re-encodes to the same fields; and a request that passes
/// is forwarded as exactly one HTTP/1.1 request head that an independent parser reads back with
/// the same method, target and fields (no smuggling through the HTTP/3 to HTTP/1 translation).
pub fn http3_request(data: &[u8]) {
    use rdock_proxy::http3::request::{FIELD_OVERHEAD, decode, encode, map};
    const LIMIT: u64 = 64 * 1024;
    http3_frames(data, LIMIT);
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
    let host = req
        .headers
        .get("host")
        .expect("a mapped request has a host");
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
    assert_eq!(
        status,
        httparse::Status::Complete(wire.len()),
        "one complete head"
    );
    assert_eq!(parsed.method, Some(req.method.as_str()));
    assert_eq!(parsed.path.map(str::as_bytes), Some(req.raw_path()));
    assert_eq!(
        parsed.headers.len(),
        req.headers.len(),
        "no field split or lost"
    );
}

/// The rule grammar's evaluation, not only its parsing: `rule \0 host \0 path \0 method \0
/// headers (one `name: value` per line) \0 query \0 client address`. A rule that compiles
/// gives the same verdict as its explanation, its negation the opposite one, and its canonical
/// form the same one; the path rdock forwards normalises to itself, so the path a backend
/// sees routes like the path that was matched.
pub fn rules_eval(data: &[u8]) {
    use rdock_proxy::router::{Facts, Rule, normalize_host};
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = text.split('\0');
    let mut next = || parts.next().unwrap_or("");
    let (rule, host, raw_path, method, headers, query, ip) =
        (next(), next(), next(), next(), next(), next(), next());
    let path = match rdock_rules::path::normalize(if raw_path.is_empty() { "/" } else { raw_path })
    {
        Ok(path) => {
            let again = rdock_rules::path::normalize(&path.forwarded).unwrap_or_else(|e| {
                panic!(
                    "forwarded path {:?} does not normalise: {e}",
                    path.forwarded
                )
            });
            assert_eq!(again, path, "normalising {raw_path:?} is not idempotent");
            path
        }
        Err(_) => return,
    };
    let Ok(expr) = rdock_rules::parse(rule) else {
        return;
    };
    if !expr.validate(rdock_rules::Context::Http).is_empty() {
        return;
    }
    let Ok(compiled) = Rule::compile(&expr) else {
        return;
    };
    let mut map = http::HeaderMap::new();
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':')
            && let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(name.trim().as_bytes()),
                http::HeaderValue::from_str(value.trim()),
            )
        {
            map.append(name, value);
        }
    }
    let query: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k.to_owned(), v.to_owned())
        })
        .collect();
    let host = normalize_host(host);
    let facts = Facts {
        host: &host,
        path: &path.routing,
        method: if method.is_empty() { "GET" } else { method },
        headers: &map,
        query: &query,
        client_ip: ip.parse().unwrap_or(std::net::IpAddr::from([192, 0, 2, 1])),
        fingerprint: None,
    };
    let verdict = compiled.matches(&facts);
    assert_eq!(
        compiled.explain(&facts).is_none(),
        verdict,
        "`{rule}`: the explanation disagrees with the verdict"
    );
    let negated = Rule::compile(&rdock_rules::Expr::Not(Box::new(expr.clone())))
        .expect("the negation of a rule that compiles compiles");
    assert_eq!(
        negated.matches(&facts),
        !verdict,
        "`{rule}`: `!` does not negate"
    );
    let canonical = rdock_rules::parse(&expr.to_string()).expect("the canonical form parses");
    let again = Rule::compile(&canonical).expect("the canonical form compiles");
    assert_eq!(
        again.matches(&facts),
        verdict,
        "`{rule}`: the canonical form decides otherwise"
    );
}

/// A backend's response head as rdock reads it (`upstream_response_filter`): the head parsed
/// with `httparse`, the connection-specific headers removed (every header the `Connection`
/// field nominates, `Keep-Alive`, `Proxy-Connection`, `Upgrade`; a `101` keeps them), every
/// other header kept, the head written back as exactly one response head, and the pause a
/// `Retry-After` asks for within the cap.
pub fn backend_response(data: &[u8]) {
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut slots);
    let Ok(httparse::Status::Complete(_)) = parsed.parse(data) else {
        return;
    };
    let Some(code) = parsed.code else {
        return;
    };
    let Ok(mut resp) = pingora_http::ResponseHeader::build(code, None) else {
        return;
    };
    for h in parsed.headers.iter() {
        let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(h.name.as_bytes()),
            http::HeaderValue::from_bytes(h.value),
        ) else {
            return;
        };
        if resp.append_header(name, value).is_err() {
            return;
        }
    }
    let nominated: Vec<String> = resp
        .headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty() && t != "close" && t != "keep-alive")
        .collect();
    let before = resp.headers.clone();
    let pause = rdock_proxy::fuzz_backend_response(&mut resp);
    assert!(
        pause.is_none_or(|p| p <= std::time::Duration::from_secs(60)),
        "{pause:?}"
    );
    if code == 101 {
        assert_eq!(
            resp.headers, before,
            "a 101 keeps its headers for the upgrade"
        );
    } else {
        for name in ["keep-alive", "proxy-connection", "upgrade"]
            .into_iter()
            .chain(nominated.iter().map(String::as_str))
        {
            assert!(!resp.headers.contains_key(name), "{name} survived");
        }
        for (name, value) in &before {
            let gone = nominated.iter().any(|n| n == name.as_str())
                || ["keep-alive", "proxy-connection", "upgrade"].contains(&name.as_str());
            if !gone {
                assert!(
                    resp.headers.get_all(name).iter().any(|v| v == value),
                    "{name} was removed though not connection-specific"
                );
            }
        }
    }
    let mut wire = format!("HTTP/1.1 {code} X\r\n").into_bytes();
    let mut head = bytes::BytesMut::new();
    resp.header_to_h1_wire(&mut head);
    wire.extend_from_slice(&head);
    wire.extend_from_slice(b"\r\n");
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut again = httparse::Response::new(&mut slots);
    assert_eq!(
        again.parse(&wire).ok(),
        Some(httparse::Status::Complete(wire.len())),
        "the written head is not one response head: {:?}",
        String::from_utf8_lossy(&wire)
    );
    assert_eq!(
        again.headers.len(),
        resp.headers.len(),
        "a header was split or lost"
    );
}

/// What a CA can send that rdock parses itself: a `Retry-After` value (`text`), an ARI window
/// and its `Retry-After` (the first 33 bytes as numbers), and stored records (`meta.json`,
/// the chain and key, the order journal, which a cluster store or a shared directory holds and
/// another instance wrote) read back through the storage layer. Directory, order,
/// authorisation and problem documents and the ARI document itself are `instant-acme`'s.
pub fn acme_answers(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    rdock_acme::fuzz_retry_after(&text);
    if data.len() >= 33 {
        let num = |at: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[at..at + 8]);
            b
        };
        rdock_acme::fuzz_ari_window(
            i64::from_le_bytes(num(0)),
            i64::from_le_bytes(num(8)),
            std::time::Duration::from_secs(u64::from_le_bytes(num(16))),
            f64::from(data[32]) / 255.0,
            i64::from_le_bytes(num(24)),
        );
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        use rdock_cluster::{ClusterStore, Expect};
        let store = std::sync::Arc::new(rdock_cluster::MemoryStore::new());
        let storage = rdock_acme::Storage::cluster(store.clone());
        // The same bytes as each stored record of one certificate and its order.
        for key in [
            "certs/a.example/meta.json",
            "certs/a.example/cert.pem",
            "certs/a.example/key.pem",
            "orders/a.example.json",
        ] {
            let _ = store.put(key, data.to_vec(), Expect::Any, None).await;
        }
        let _ = storage.read_cert("a.example").await;
        let _ = storage.load_order("a.example").await;
    });
}

/// Arbitrary bytes as what a data plane receives from the control plane: a compressed bundle
/// (zstd, at most 64 MiB of JSON), a bundle as JSON, and the JSON of every other message.
/// A bundle that decodes is refused or accepted by its own rules: another cluster's, an old
/// revision, an empty document or a digest that does not match are refused; the digest does
/// not depend on key order (the canonical JSON parses back to the same document).
pub fn cluster_protocol(data: &[u8]) {
    use rdock_cluster::protocol::{
        Bundle, EnrollResponse, Report, StoreRequest, StoreResponse, canonical_json,
    };
    let bundle = rdock_cluster::agent::decompress(data)
        .ok()
        .or_else(|| serde_json::from_slice::<Bundle>(data).ok());
    let _ = serde_json::from_slice::<StoreRequest>(data);
    let _ = serde_json::from_slice::<StoreResponse>(data);
    let _ = serde_json::from_slice::<EnrollResponse>(data);
    let _ = serde_json::from_slice::<Report>(data);
    let Some(mut bundle) = bundle else {
        return;
    };
    let canonical = canonical_json(&bundle.document);
    let parsed: serde_json::Value =
        serde_json::from_str(&canonical).expect("canonical JSON parses");
    assert_eq!(
        canonical_json(&parsed),
        canonical,
        "canonical JSON is a fixed point"
    );
    let refuse = rdock_cluster::agent::refuse;
    let serving = bundle.revision.saturating_sub(1);
    let verdict = refuse(&bundle, &bundle.cluster_id.clone(), serving);
    let digest_ok = Bundle::digest(&bundle.document) == bundle.sha256;
    let accepted = bundle.revision > 0 && !bundle.is_empty() && digest_ok;
    assert_eq!(verdict.is_none(), accepted, "{verdict:?}");
    assert!(
        refuse(&bundle, "another-cluster\u{0}", serving).is_some()
            || bundle.cluster_id == "another-cluster\u{0}"
    );
    assert!(
        refuse(&bundle, &bundle.cluster_id.clone(), bundle.revision).is_some(),
        "an old revision"
    );
    // A bundle whose digest is set right is accepted unless empty; tampering is refused.
    bundle.sha256 = Bundle::digest(&bundle.document);
    let fixed = refuse(&bundle, &bundle.cluster_id.clone(), serving);
    assert_eq!(
        fixed.is_none(),
        bundle.revision > 0 && !bundle.is_empty(),
        "{fixed:?}"
    );
    bundle.sha256.push('0');
    assert!(
        refuse(&bundle, &bundle.cluster_id.clone(), serving).is_some(),
        "a wrong digest"
    );
}

/// Arbitrary bytes as a Redis server's replies (RESP2) to the cluster-scoped limits: never a
/// panic, a reply never larger than the cap, and a command encoded by rdock reads back as the
/// array of bulk strings it is.
pub fn resp_reader(data: &[u8]) {
    use rdock_cluster::resp::{Reply, encode, read_reply};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut reader = tokio::io::BufReader::new(data);
        for _ in 0..8 {
            let Ok(reply) = read_reply(&mut reader).await else {
                break;
            };
            let _ = reply.time_ms();
        }
        let args: Vec<&[u8]> = data.split(|b| *b == 0).take(16).collect();
        let encoded = encode(&args);
        let mut reader = tokio::io::BufReader::new(encoded.as_slice());
        let reply = read_reply(&mut reader).await;
        if data.len() <= 1 << 16 {
            let expected = Reply::Array(Some(
                args.iter().map(|a| Reply::Bulk(Some(a.to_vec()))).collect(),
            ));
            assert_eq!(reply.ok(), Some(expected), "an encoded command reads back");
        }
    });
}

/// Arbitrary text as the JSON `rdock migrate caddy` reads (what `caddy adapt` writes): never a
/// panic, never an accounting error (every source item has exactly one finding), and the
/// written YAML reads as YAML (a value quoted in a finding stays inside its comment).
pub fn migrate_caddy(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    use rdock_migrate::caddy::{Error, Options, caddy};
    for full in [false, true] {
        let options = Options {
            file: "-".to_owned(),
            full,
        };
        match caddy(text, &options) {
            Ok(migration) if full => {
                // The YAML must read; whether it validates is in the report.
                if let Err(e @ rdock_config::LoadError::Syntax { .. }) =
                    rdock_config::load_str(&migration.yaml, rdock_config::Format::Yaml)
                {
                    panic!("the written YAML does not read: {e:?}\n{}", migration.yaml);
                }
            }
            Ok(_) | Err(Error::Input(_)) => {}
            Err(Error::Accounting(e)) => panic!("accounting error: {e}"),
        }
    }
}

/// Compose interpolation as `rdock migrate traefik` applies it to labels (the Compose
/// Specification's rules): `text \0 env file`. Never a panic; a text without `$` is unchanged;
/// `$$` stands for one `$`; and the whole Compose path (`rdock migrate traefik`) never fails
/// its own accounting.
pub fn compose_interpolation(data: &[u8]) {
    use rdock_migrate::compose::{Vars, env_file, interpolate};
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (body, env) = text.split_once('\0').unwrap_or((text, ""));
    let vars = env_file(env, &Vars::new()).unwrap_or_default();
    let (out, _) = interpolate(body, &vars);
    if !body.contains('$') {
        assert_eq!(out, body, "a text without `$` changed");
    }
    if !body.contains('{') && !body.chars().any(|c| c.is_ascii_alphabetic() || c == '_') {
        assert_eq!(out, body.replace("$$", "$"), "`$$` is one `$`");
    }
    let options = rdock_migrate::Options {
        vars,
        ..rdock_migrate::Options::default()
    };
    if let Err(rdock_migrate::Error::Accounting(e)) = rdock_migrate::traefik(body, &options) {
        panic!("accounting error: {e}");
    }
}

/// Container labels as the Docker provider translates them: `label=value` lines, containers
/// separated by an empty line, the first line of each its name. Never a panic; a container
/// that is not exposed (no `rdock.enable`/`traefik.enable`, the default) contributes no route,
/// whatever else its labels say; and translating twice gives the same result.
pub fn docker_labels(data: &[u8]) {
    use rdock_provider_docker::labels::{Container, Health, translate};
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut containers = Vec::new();
    for block in text.split("\n\n").take(4) {
        let mut lines = block.lines();
        let name = lines.next().unwrap_or("c").trim().to_owned();
        let labels = lines
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        containers.push(Container {
            name: if name.is_empty() {
                "c".to_owned()
            } else {
                name
            },
            labels,
            networks: [(
                "net".to_owned(),
                Some(std::net::IpAddr::from([10, 0, 0, 2])),
            )]
            .into(),
            exposed_ports: [80].into(),
            health: Health::None,
            ..Container::default()
        });
    }
    let settings = rdock_model::providers::DockerProvider::default();
    let first = translate(&containers, &settings);
    assert_eq!(
        first,
        translate(&containers, &settings),
        "translation is not deterministic"
    );
    let hidden: Vec<Container> = containers
        .iter()
        .cloned()
        .map(|mut c| {
            c.labels.retain(|k, _| {
                let k = k.to_ascii_lowercase();
                k != "rdock.enable" && k != "traefik.enable"
            });
            c
        })
        .collect();
    let none = translate(&hidden, &settings);
    assert!(
        none.fragment.routes.is_empty()
            && none.fragment.tcp_routes.is_empty()
            && none.fragment.udp_routes.is_empty(),
        "a container that is not exposed got a route: {:?}",
        none.fragment.routes.keys().collect::<Vec<_>>()
    );
}

/// Arbitrary text through the admin API's own input handling (`rdock_admin::fuzz_admin_input`):
/// request bodies, query strings, user names, token values, TOTP codes, the tenancy table.
pub fn admin_input(data: &[u8]) {
    rdock_admin::fuzz_admin_input(data);
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

    /// The input the fuzzer crashed on in CI: an integer with 88 continuation bytes that add
    /// nothing. It is refused, not a valid head, so it is not in the seed corpus.
    #[test]
    fn http3_request_refuses_an_overlong_integer() {
        let input = [vec![0, 0xff], vec![0x80; 88], vec![0xff]].concat();
        super::http3_request(&input);
        assert!(rdock_proxy::http3::request::map(&input, 64 * 1024).is_err());
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

    /// Deterministic mutations of every seed (byte changes, insertions, removals): `rounds`
    /// per seed, on stable, so plain `cargo test` exercises each target beyond its seeds.
    /// `RDOCK_FUZZ_SMOKE_FACTOR` multiplies the rounds for a longer local run.
    fn mutations(seeds: &[Vec<u8>], rounds: usize, target: fn(&[u8])) {
        let factor = std::env::var("RDOCK_FUZZ_SMOKE_FACTOR")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1);
        let rounds = rounds * factor;
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for seed in seeds {
            target(seed);
            for _ in 0..rounds {
                let mut data = seed.clone();
                for _ in 0..=(next() % 4) {
                    let at = usize::try_from(next()).unwrap_or(0) % (data.len() + 1);
                    let byte = u8::try_from(next() & 0xff).unwrap_or(0);
                    match next() % 4 {
                        0 if at < data.len() => data[at] = byte,
                        1 => data.insert(at, byte),
                        2 if at < data.len() => {
                            data.remove(at);
                        }
                        // Splices a piece of the seed elsewhere (repeats a token or a field).
                        _ if !seed.is_empty() => {
                            let from = usize::try_from(next()).unwrap_or(0) % seed.len();
                            let len =
                                (usize::try_from(next()).unwrap_or(0) % 16).min(seed.len() - from);
                            let piece = seed[from..from + len].to_vec();
                            data.splice(at..at, piece);
                        }
                        _ => {}
                    }
                }
                target(&data);
            }
        }
    }

    fn seeded(target: &str, at_least: usize) -> Vec<Vec<u8>> {
        let all = seeds(target);
        assert!(all.len() >= at_least, "seed corpus of {target} present");
        all
    }

    #[test]
    fn rules_eval_mutations() {
        mutations(&seeded("rules_eval", 5), 2_000, super::rules_eval);
    }

    #[test]
    fn backend_response_mutations() {
        mutations(
            &seeded("backend_response", 5),
            3_000,
            super::backend_response,
        );
    }

    #[test]
    fn acme_answers_mutations() {
        mutations(&seeded("acme_answers", 5), 500, super::acme_answers);
    }

    /// The `Retry-After` the fuzzer would have reached first: a year far beyond RFC 9110's
    /// range overflowed `http_date`'s arithmetic (a panic in debug builds) before the fix.
    #[test]
    fn acme_answers_refuses_an_overflowing_date() {
        super::acme_answers(b"Wed, 21 Oct 99999999999999999 07:28:00 GMT");
        super::acme_answers(&[0xff; 64]);
    }

    #[test]
    fn admin_input_mutations() {
        mutations(&seeded("admin_input", 5), 1_000, super::admin_input);
    }

    #[test]
    fn cluster_protocol_mutations() {
        mutations(
            &seeded("cluster_protocol", 4),
            1_000,
            super::cluster_protocol,
        );
    }

    #[test]
    fn resp_reader_mutations() {
        mutations(&seeded("resp_reader", 5), 2_000, super::resp_reader);
    }

    #[test]
    fn migrate_caddy_mutations() {
        let mut all = seeded("migrate_caddy", 3);
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../conformance/caddy-json");
        for case in std::fs::read_dir(corpus).unwrap().flatten() {
            if let Ok(json) = std::fs::read(case.path().join("caddy.json")) {
                super::migrate_caddy(&json);
                all.push(json);
            }
        }
        assert!(all.len() > 10, "the Caddy corpus seeds the reader");
        mutations(&all, 40, super::migrate_caddy);
    }

    #[test]
    fn compose_interpolation_mutations() {
        let mut all = seeded("compose_interpolation", 3);
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../conformance/traefik-compose");
        for case in std::fs::read_dir(corpus).unwrap().flatten() {
            if let Ok(yaml) = std::fs::read(case.path().join("compose.yaml")) {
                super::compose_interpolation(&yaml);
                all.push(yaml);
            }
        }
        assert!(all.len() > 10, "the Compose corpus seeds the interpolation");
        mutations(&all, 30, super::compose_interpolation);
    }

    #[test]
    fn docker_labels_mutations() {
        mutations(&seeded("docker_labels", 4), 1_000, super::docker_labels);
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
    fn nginx_parser_seeds() {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../conformance/nginx");
        let mut count = 0;
        for case in std::fs::read_dir(corpus).unwrap() {
            let case = case.unwrap().path();
            if !case.is_dir() {
                continue;
            }
            for file in std::fs::read_dir(&case).unwrap() {
                let file = file.unwrap().path();
                if file.extension().is_some_and(|e| e == "conf" || e == "txt") {
                    super::nginx_parser(&std::fs::read(&file).unwrap());
                    count += 1;
                }
            }
        }
        assert!(count > 10, "the NGINX corpus seeds the parser");
        for input in [
            "a { b \"c\\\"d\" '${x}'; }",
            "a;;",
            "}{",
            "content_by_lua_block { x }",
        ] {
            super::nginx_parser(input.as_bytes());
        }
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
