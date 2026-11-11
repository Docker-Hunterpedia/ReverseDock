//! End-to-end: the `static` middleware (F-WEB-01) through the real binary, over a fixture tree
//! made in a temporary directory. Ranges, conditionals, HEAD, precompressed sidecars, the SPA
//! fallback, traversal payloads (OWASP WSTG-ATHZ-01 and `PortSwigger`), symlink policies, streaming
//! over HTTP/1.1 and HTTP/2, concurrency, `compress`, `bandwidth` and `pass_through`; and the
//! directory listings of F-WEB-02 (HTML and JSON, awkward names, policies, precedence).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rdock_testkit::backend::Backend;
use rdock_testkit::certs::TestCa;
use rdock_testkit::client::{self, Reply, get, request};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const SECRET: &str = "TOP-SECRET-OUTSIDE-THE-ROOT";
const BIG: usize = 5 * 1024 * 1024;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Deterministic bytes, so every range has a known value.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + 7) % 251).unwrap())
        .collect()
}

/// File names a listing must escape in text and encode in links.
const NASTY_NAMES: [&str; 12] = [
    "<b>bold<b>.txt",
    "<script>alert(1).txt",
    "a b.txt",
    "100%.txt",
    "%2e%2e.txt",
    "hash#tag.txt",
    "q?x=1.txt",
    "caf\u{e9}.txt",
    "-dash.txt",
    "javascript:alert(1).txt",
    "a&amp;b.txt",
    "quote\"s'.txt",
];

fn app_js() -> Vec<u8> {
    "export const greet = (name) => `hello ${name}`;\n"
        .repeat(64)
        .into_bytes()
}

/// The served tree and a secret next to it, outside the root.
struct Fixture {
    outside: tempfile::TempDir,
    _base: tempfile::TempDir,
    root: PathBuf,
}

fn fixture() -> Fixture {
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), SECRET).unwrap();
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("site");
    let file = |name: &str, content: &[u8]| {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    };
    file("index.html", b"<h1>home</h1>");
    file("about.txt", &pattern(1000));
    file("big.bin", &pattern(BIG));
    file(
        "style.css",
        "body { color: #333; }\n".repeat(100).as_bytes(),
    );
    file("dir/index.html", b"<h1>dir</h1>");
    file("dir-no-index/file.txt", b"file");
    file("assets/app.1f3a.js", b"hashed");
    file(".env", SECRET.as_bytes());
    file(".git/config", SECRET.as_bytes());
    file("caf\u{e9}.txt", b"utf-8 name");
    file("docs/readme.txt", b"readme");
    file("docs/guide/intro.txt", b"intro");
    file("docs/.private", b"private");
    for i in 0..40 {
        file(
            &format!("many/a-reasonably-long-file-name-{i:02}.txt"),
            b"x",
        );
    }
    for name in NASTY_NAMES {
        file(&format!("nasty/{name}"), name.as_bytes());
    }
    let js = app_js();
    file("app.js", &js);
    let mut br = Vec::new();
    brotli::CompressorWriter::new(&mut br, 4096, 11, 22)
        .write_all(&js)
        .unwrap();
    file("app.js.br", &br);
    file("app.js.zst", &zstd::encode_all(&js[..], 19).unwrap());
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&js).unwrap();
    file("app.js.gz", &gz.finish().unwrap());
    std::os::unix::fs::symlink("about.txt", root.join("inside-link.txt")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        root.join("outside-link.txt"),
    )
    .unwrap();
    Fixture {
        outside,
        _base: base,
        root,
    }
}

/// One plain listener with a route per host; every middleware serves `root`.
fn config(port: u16, root: &Path, backend: SocketAddr) -> String {
    let root = root.display();
    format!(
        r#"
listeners:
  web: {{ address: "127.0.0.1:{port}" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  site: {{ match: "Host(`site.test`)", middlewares: [site] }}
  plain: {{ match: "Host(`plain.test`)", middlewares: [plain] }}
  multi: {{ match: "Host(`multi.test`)", middlewares: [multi] }}
  within: {{ match: "Host(`within.test`)", middlewares: [within] }}
  all: {{ match: "Host(`all.test`)", middlewares: [all] }}
  gz: {{ match: "Host(`compress.test`)", middlewares: [gz, plain] }}
  slow: {{ match: "Host(`slow.test`)", middlewares: [slow, plain] }}
  pass: {{ match: "Host(`pass.test`)", middlewares: [pass], service: app }}
  list: {{ match: "Host(`list.test`)", middlewares: [list] }}
  listspa: {{ match: "Host(`listspa.test`)", middlewares: [listspa] }}
  listpass: {{ match: "Host(`listpass.test`)", middlewares: [listpass], service: app }}
  listgz: {{ match: "Host(`listgz.test`)", middlewares: [gz, list] }}
  bare: {{ match: "Host(`bare.test`)", middlewares: [bare] }}
  barewithin: {{ match: "Host(`barewithin.test`)", middlewares: [barewithin] }}
  bareall: {{ match: "Host(`bareall.test`)", middlewares: [bareall] }}
  bareplain: {{ match: "Host(`bareplain.test`)", middlewares: [bareplain] }}
  baredots: {{ match: "Host(`baredots.test`)", middlewares: [baredots] }}
services:
  app: {{ backends: [{{ address: "{backend}" }}] }}
middlewares:
  site:
    type: static
    root: "{root}"
    fallback: /index.html
    fallback_except: [/api/]
    cache_control:
      /assets/: public, max-age=31536000, immutable
  plain: {{ type: static, root: "{root}" }}
  multi: {{ type: static, root: "{root}", max_ranges: 2 }}
  within: {{ type: static, root: "{root}", symlinks: within_root }}
  all: {{ type: static, root: "{root}", symlinks: all }}
  pass: {{ type: static, root: "{root}", pass_through: true }}
  list:
    type: static
    root: "{root}"
    listing: true
    cache_control:
      /many/: public, max-age=30
  listspa: {{ type: static, root: "{root}", listing: true, fallback: /index.html }}
  listpass: {{ type: static, root: "{root}", listing: true, pass_through: true }}
  bare: {{ type: static, root: "{root}", listing: true, index: [absent.html] }}
  barewithin: {{ type: static, root: "{root}", listing: true, index: [absent.html], symlinks: within_root }}
  bareall: {{ type: static, root: "{root}", listing: true, index: [absent.html], symlinks: all, hidden: allow }}
  bareplain: {{ type: static, root: "{root}", listing: true, index: [absent.html], directory_redirect: false }}
  baredots: {{ type: static, root: "{root}", listing: true, index: [absent.html], hidden: allow }}
  gz: {{ type: compress, algorithms: [gzip] }}
  slow: {{ type: bandwidth, rate: 8MiB, burst: 256KiB }}
"#
    )
}

struct Served {
    rdock: Rdock,
    port: u16,
    fixture: Fixture,
    _backend: Backend,
}

async fn serve() -> Served {
    let fixture = fixture();
    let backend = Backend::start("app").await;
    let port = free_port();
    let rdock = Rdock::start(RDOCK, &config(port, &fixture.root, backend.addr));
    Served {
        rdock,
        port,
        fixture,
        _backend: backend,
    }
}

impl Served {
    async fn send(
        &self,
        method: &str,
        host: &str,
        target: &str,
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut req = request(method, host, target, bytes::Bytes::new());
        for (name, value) in headers {
            req.headers_mut().append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        client::http1(addr(self.port), req).await
    }

    async fn get(&self, host: &str, target: &str, headers: &[(&str, &str)]) -> Reply {
        self.send("GET", host, target, headers).await
    }

    /// A request with a target `http::Uri` would refuse or rewrite: status and body.
    async fn raw(&self, host: &str, target: &str) -> (u16, String) {
        let bytes = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let raw = client::raw(addr(self.port), bytes.as_bytes(), Duration::from_secs(2)).await;
        let status = client::statuses(&raw).first().copied().unwrap_or(0);
        (status, String::from_utf8_lossy(&raw).into_owned())
    }
}

/// One row of a table: request and expected answer.
struct Case {
    host: &'static str,
    method: &'static str,
    target: &'static str,
    headers: Vec<(&'static str, String)>,
    status: u16,
    /// Header → expected value; `None` means absent.
    expect: Vec<(&'static str, Option<String>)>,
    body: Option<Vec<u8>>,
}

fn case(host: &'static str, target: &'static str, status: u16) -> Case {
    Case {
        host,
        method: "GET",
        target,
        headers: Vec::new(),
        status,
        expect: Vec::new(),
        body: None,
    }
}

impl Case {
    fn method(mut self, method: &'static str) -> Self {
        self.method = method;
        self
    }

    fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn expect(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.expect.push((name, Some(value.into())));
        self
    }

    fn absent(mut self, name: &'static str) -> Self {
        self.expect.push((name, None));
        self
    }

    fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }
}

async fn run_table(served: &Served, cases: Vec<Case>) {
    let mut failures = Vec::new();
    for case in cases {
        let headers: Vec<(&str, &str)> =
            case.headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let reply = served
            .send(case.method, case.host, case.target, &headers)
            .await;
        let label = format!(
            "{} {}{} {:?}",
            case.method, case.host, case.target, case.headers
        );
        if reply.status != case.status {
            failures.push(format!(
                "{label}: status {} != {}",
                reply.status, case.status
            ));
            continue;
        }
        for (name, value) in &case.expect {
            if reply.header(name) != value.as_deref() {
                failures.push(format!(
                    "{label}: {name} = {:?}, expected {value:?}",
                    reply.header(name)
                ));
            }
        }
        if let Some(body) = &case.body
            && reply.body[..] != body[..]
        {
            failures.push(format!(
                "{label}: body of {} bytes differs (expected {})",
                reply.body.len(),
                body.len()
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[tokio::test]
async fn ranges_head_and_methods() {
    let served = serve().await;
    let about = pattern(1000);
    let first = served.get("site.test", "/about.txt", &[]).await;
    let etag = first.header("etag").unwrap().to_owned();
    let modified = first.header("last-modified").unwrap().to_owned();
    run_table(
        &served,
        vec![
            case("site.test", "/about.txt", 200)
                .expect("content-length", "1000")
                .expect("accept-ranges", "bytes")
                .expect("content-type", "text/plain; charset=utf-8")
                .expect("x-content-type-options", "nosniff")
                .expect("cache-control", "no-cache")
                .body(about.clone()),
            case("site.test", "/about.txt", 206)
                .with("range", "bytes=0-99")
                .expect("content-range", "bytes 0-99/1000")
                .expect("content-length", "100")
                .expect("vary", "Accept-Encoding")
                .body(&about[..100]),
            case("site.test", "/about.txt", 206)
                .with("range", "bytes=100-")
                .expect("content-range", "bytes 100-999/1000")
                .body(&about[100..]),
            case("site.test", "/about.txt", 206)
                .with("range", "bytes=-100")
                .expect("content-range", "bytes 900-999/1000")
                .body(&about[900..]),
            case("site.test", "/about.txt", 206)
                .with("range", "bytes=-5000")
                .expect("content-range", "bytes 0-999/1000")
                .body(about.clone()),
            case("site.test", "/about.txt", 200)
                .with("range", "bytes=0-0,-1")
                .absent("content-range")
                .body(about.clone()),
            case("site.test", "/about.txt", 416)
                .with("range", "bytes=9999999-")
                .expect("content-range", "bytes */1000")
                .expect("vary", "Accept-Encoding"),
            case("site.test", "/about.txt", 200)
                .with("range", "bytes=20-10")
                .body(about.clone()),
            case("site.test", "/about.txt", 200)
                .with("range", "bytes=x-y")
                .body(about.clone()),
            case("site.test", "/about.txt", 200)
                .with("range", "")
                .body(about.clone()),
            case("site.test", "/big.bin", 206)
                .with("range", "bytes=262000-262200")
                .body(&pattern(BIG)[262_000..=262_200]),
            case("site.test", "/about.txt", 206)
                .with("range", "bytes=0-9")
                .with("if-range", etag.clone())
                .body(&about[..10]),
            case("site.test", "/about.txt", 200)
                .with("range", "bytes=0-9")
                .with("if-range", "\"0-1\"")
                .body(about.clone()),
            case("site.test", "/about.txt", 200)
                .with("range", "bytes=0-9")
                .with("if-range", format!("W/{etag}")),
            case("site.test", "/about.txt", 206)
                .with("range", "bytes=0-9")
                .with("if-range", modified.clone()),
            case("site.test", "/about.txt", 200)
                .with("range", "bytes=0-9")
                .with("if-range", "Mon, 01 Jan 2001 00:00:00 GMT"),
            case("site.test", "/about.txt", 200)
                .method("HEAD")
                .with("range", "bytes=0-9")
                .expect("content-length", "1000")
                .absent("content-range")
                .body(Vec::new()),
            case("site.test", "/about.txt", 405)
                .method("POST")
                .with("range", "bytes=0-9")
                .expect("allow", "GET, HEAD"),
            case("site.test", "/about.txt", 405).method("DELETE"),
        ],
    )
    .await;

    // Multipart when more than one range is allowed.
    let multi = served
        .get("multi.test", "/about.txt", &[("range", "bytes=0-0,-1")])
        .await;
    assert_eq!(multi.status, 206);
    let content_type = multi.header("content-type").unwrap().to_owned();
    let boundary = content_type
        .strip_prefix("multipart/byteranges; boundary=")
        .unwrap();
    let mut expected = format!(
        "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Range: bytes 0-0/1000\r\n\r\n"
    )
    .into_bytes();
    expected.push(about[0]);
    expected.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Range: bytes 999-999/1000\r\n\r\n"
        )
        .as_bytes(),
    );
    expected.push(about[999]);
    expected.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    assert_eq!(multi.body[..], expected[..]);
    assert_eq!(
        multi.header("content-length"),
        Some(&*expected.len().to_string())
    );

    // HEAD sends GET's headers without the body.
    let get = served.get("site.test", "/about.txt", &[]).await;
    let head = served.send("HEAD", "site.test", "/about.txt", &[]).await;
    assert!(head.body.is_empty());
    for name in [
        "content-type",
        "content-length",
        "etag",
        "last-modified",
        "cache-control",
        "accept-ranges",
        "vary",
        "x-content-type-options",
    ] {
        assert_eq!(head.header(name), get.header(name), "{name}");
    }
}

#[tokio::test]
async fn conditional_requests_in_rfc_9110_order() {
    let served = serve().await;
    let first = served.get("site.test", "/about.txt", &[]).await;
    let etag = first.header("etag").unwrap().to_owned();
    let modified = first.header("last-modified").unwrap().to_owned();
    let old = "Mon, 01 Jan 2001 00:00:00 GMT";
    let future = "Fri, 01 Jan 2100 00:00:00 GMT";
    run_table(
        &served,
        vec![
            case("site.test", "/about.txt", 304)
                .with("if-none-match", etag.clone())
                .expect("etag", etag.clone())
                .expect("vary", "Accept-Encoding")
                .expect("cache-control", "no-cache")
                .absent("content-type")
                .body(Vec::new()),
            case("site.test", "/about.txt", 304).with("if-none-match", format!("\"x\", {etag}")),
            case("site.test", "/about.txt", 304).with("if-none-match", format!("W/{etag}")),
            case("site.test", "/about.txt", 304).with("if-none-match", "*"),
            case("site.test", "/about.txt", 200).with("if-none-match", "\"x\""),
            case("site.test", "/about.txt", 304)
                .method("HEAD")
                .with("if-none-match", etag.clone()),
            case("site.test", "/about.txt", 304).with("if-modified-since", modified.clone()),
            case("site.test", "/about.txt", 304).with("if-modified-since", future),
            case("site.test", "/about.txt", 200).with("if-modified-since", old),
            case("site.test", "/about.txt", 200).with("if-modified-since", "not a date"),
            case("site.test", "/about.txt", 200)
                .with("if-none-match", "\"x\"")
                .with("if-modified-since", future),
            case("site.test", "/about.txt", 200).with("if-match", etag.clone()),
            case("site.test", "/about.txt", 412).with("if-match", "\"x\""),
            case("site.test", "/about.txt", 412).with("if-match", format!("W/{etag}")),
            case("site.test", "/about.txt", 412).with("if-unmodified-since", old),
            case("site.test", "/about.txt", 200).with("if-unmodified-since", future),
            case("site.test", "/about.txt", 200)
                .with("if-match", etag.clone())
                .with("if-unmodified-since", old),
            case("site.test", "/about.txt", 412)
                .with("if-match", "\"x\"")
                .with("if-none-match", etag.clone()),
            case("site.test", "/about.txt", 304)
                .with("if-none-match", etag.clone())
                .with("range", "bytes=0-9"),
        ],
    )
    .await;
}

#[tokio::test]
async fn precompressed_sidecars_by_accept_encoding() {
    let served = serve().await;
    let root = &served.fixture.root;
    let read = |name: &str| std::fs::read(root.join(name)).unwrap();
    let (js, br, zst, gz) = (
        read("app.js"),
        read("app.js.br"),
        read("app.js.zst"),
        read("app.js.gz"),
    );
    run_table(
        &served,
        vec![
            case("site.test", "/app.js", 200)
                .with("accept-encoding", "br;q=1, gzip;q=0.5")
                .expect("content-encoding", "br")
                .expect("content-type", "text/javascript; charset=utf-8")
                .expect("vary", "Accept-Encoding")
                .body(br.clone()),
            case("site.test", "/app.js", 200)
                .with("accept-encoding", "gzip")
                .expect("content-encoding", "gzip")
                .body(gz.clone()),
            case("site.test", "/app.js", 200)
                .with("accept-encoding", "br, zstd")
                .expect("content-encoding", "zstd")
                .body(zst.clone()),
            case("site.test", "/app.js", 200)
                .with("accept-encoding", "*")
                .expect("content-encoding", "zstd"),
            case("site.test", "/app.js", 200)
                .with("accept-encoding", "zstd;q=0, br;q=0, *;q=0.1")
                .expect("content-encoding", "gzip"),
            case("site.test", "/app.js", 200)
                .with("accept-encoding", "identity")
                .absent("content-encoding")
                .body(js.clone()),
            case("site.test", "/app.js", 200)
                .with("accept-encoding", "deflate")
                .absent("content-encoding")
                .body(js.clone()),
            case("site.test", "/app.js", 206)
                .with("accept-encoding", "br")
                .with("range", "bytes=0-9")
                .expect("content-encoding", "br")
                .expect("content-range", format!("bytes 0-9/{}", br.len()))
                .body(&br[..10]),
            case("site.test", "/style.css", 200)
                .with("accept-encoding", "br")
                .absent("content-encoding")
                .expect("vary", "Accept-Encoding"),
        ],
    )
    .await;
    let plain = served.get("site.test", "/app.js", &[]).await;
    let brotli = served
        .get("site.test", "/app.js", &[("accept-encoding", "br")])
        .await;
    let (plain_tag, br_tag) = (
        plain.header("etag").unwrap(),
        brotli.header("etag").unwrap(),
    );
    assert_ne!(plain_tag, br_tag, "each variant has its own tag");
    let not_modified = served
        .get(
            "site.test",
            "/app.js",
            &[("accept-encoding", "br"), ("if-none-match", br_tag)],
        )
        .await;
    assert_eq!(not_modified.status, 304);
    assert_eq!(not_modified.header("vary"), Some("Accept-Encoding"));

    // `compress` before `static`: text without a sidecar is compressed on the fly, a sidecar
    // is sent as it is, and `Vary` appears once.
    let css = served
        .get(
            "compress.test",
            "/style.css",
            &[("accept-encoding", "gzip")],
        )
        .await;
    assert_eq!(css.header("content-encoding"), Some("gzip"));
    assert_eq!(css.headers.get_all("vary").iter().count(), 1);
    let mut text = Vec::new();
    flate2::read::GzDecoder::new(&css.body[..])
        .read_to_end(&mut text)
        .unwrap();
    assert_eq!(text, read("style.css"));
    let sidecar = served
        .get("compress.test", "/app.js", &[("accept-encoding", "gzip")])
        .await;
    assert_eq!(sidecar.header("content-encoding"), Some("gzip"));
    assert_eq!(sidecar.body[..], gz[..], "not compressed twice");
    let ranged = served
        .get(
            "compress.test",
            "/style.css",
            &[("accept-encoding", "gzip"), ("range", "bytes=0-9")],
        )
        .await;
    assert_eq!(ranged.status, 206);
    assert_eq!(ranged.header("content-encoding"), None);
}

#[tokio::test]
async fn directories_index_and_spa_fallback() {
    let served = serve().await;
    run_table(
        &served,
        vec![
            case("site.test", "/", 200).body("<h1>home</h1>"),
            case("site.test", "/index.html", 200).body("<h1>home</h1>"),
            case("site.test", "/dir", 308).expect("location", "/dir/"),
            case("site.test", "/dir?tab=1", 308).expect("location", "/dir/?tab=1"),
            case("site.test", "/dir/", 200).body("<h1>dir</h1>"),
            case("site.test", "/about", 200)
                .expect("cache-control", "no-cache")
                .body("<h1>home</h1>"),
            case("site.test", "/users/42/profile", 200).body("<h1>home</h1>"),
            case("site.test", "/app.missing.js", 404),
            case("site.test", "/api/x", 404),
            case("site.test", "/caf%C3%A9.txt", 200).body("utf-8 name"),
            case("site.test", "/assets/app.1f3a.js", 200)
                .expect("cache-control", "public, max-age=31536000, immutable"),
            case("plain.test", "/dir-no-index/", 404),
            case("plain.test", "/about", 404),
            case("plain.test", "/about.txt/", 404),
        ],
    )
    .await;
}

/// The names a JSON listing holds, sorted as sent.
fn listed_names(reply: &Reply) -> Vec<String> {
    reply.json()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_owned())
        .collect()
}

const JSON: [(&str, &str); 1] = [("accept", "application/json")];

#[tokio::test]
async fn directory_listings_in_html_and_json() {
    let served = serve().await;
    let page = served.get("list.test", "/dir-no-index/", &[]).await;
    assert_eq!(page.status, 200);
    assert_eq!(
        page.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(page.header("vary"), Some("Accept"));
    assert_eq!(page.header("cache-control"), Some("no-cache"));
    assert_eq!(page.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
    let csp = page.header("content-security-policy").unwrap();
    assert!(csp.starts_with("default-src 'none'"), "{csp}");
    assert_eq!(
        (page.header("etag"), page.header("last-modified")),
        (None, None)
    );
    assert!(
        page.text().contains("href=\"./file.txt\""),
        "{}",
        page.text()
    );
    assert!(page.text().contains("<h1>Index of /dir-no-index/</h1>"));

    let json = served.get("list.test", "/dir-no-index/", &JSON).await;
    assert_eq!(json.status, 200);
    assert_eq!(json.header("content-type"), Some("application/json"));
    assert_eq!(json.header("vary"), Some("Accept"));
    assert_eq!(json.header("content-security-policy"), Some(csp));
    let body = json.json();
    assert_eq!(body["path"], "/dir-no-index/");
    assert_eq!(body["truncated"], false);
    assert_eq!(body["entries"].as_array().unwrap().len(), 1);
    assert_eq!(body["entries"][0]["name"], "file.txt");
    assert_eq!(body["entries"][0]["type"], "file");
    assert_eq!(body["entries"][0]["size"], 4);
    let modified = body["entries"][0]["modified"].as_str().unwrap();
    assert!(
        modified.ends_with('Z') && modified.len() == 20,
        "{modified}"
    );

    // The `Accept` weights decide.
    let browser = served
        .get(
            "list.test",
            "/dir-no-index/",
            &[("accept", "text/html,application/xhtml+xml,*/*;q=0.8")],
        )
        .await;
    assert!(
        browser
            .header("content-type")
            .unwrap()
            .starts_with("text/html")
    );
    let weighted = served
        .get(
            "list.test",
            "/dir-no-index/",
            &[("accept", "text/html;q=0.4, application/json;q=0.9")],
        )
        .await;
    assert_eq!(weighted.header("content-type"), Some("application/json"));

    // HEAD answers GET's headers without the body.
    for headers in [&[][..], &JSON[..]] {
        let get = served.get("list.test", "/dir-no-index/", headers).await;
        let head = served
            .send("HEAD", "list.test", "/dir-no-index/", headers)
            .await;
        assert_eq!(head.status, 200);
        assert!(head.body.is_empty());
        for name in [
            "content-type",
            "content-length",
            "vary",
            "cache-control",
            "content-security-policy",
        ] {
            assert_eq!(head.header(name), get.header(name), "{name}");
        }
        assert_eq!(
            head.header("content-length"),
            Some(get.body.len().to_string().as_str())
        );
    }

    // Conditionals and ranges do not apply to a generated page.
    for headers in [
        [("range", "bytes=0-5")],
        [("if-none-match", "*")],
        [("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT")],
        [("if-match", "\"nope\"")],
    ] {
        let reply = served.get("list.test", "/dir-no-index/", &headers).await;
        assert_eq!(reply.status, 200, "{headers:?}");
        assert_eq!(reply.body, page.body, "{headers:?}");
        assert_eq!(reply.header("content-range"), None);
    }
    assert_eq!(
        served
            .send("POST", "list.test", "/dir-no-index/", &[])
            .await
            .status,
        405
    );

    // A directory with an index, and the root with one, are not listed.
    run_table(
        &served,
        vec![
            case("list.test", "/dir/", 200).body("<h1>dir</h1>"),
            case("list.test", "/", 200).body("<h1>home</h1>"),
            case("list.test", "/dir-no-index", 308).expect("location", "/dir-no-index/"),
            case("list.test", "/dir-no-index?x=1", 308).expect("location", "/dir-no-index/?x=1"),
            case("list.test", "/docs", 308).expect("location", "/docs/"),
            case("list.test", "/missing/", 404),
            case("list.test", "/about.txt/", 404),
            case("list.test", "/many/", 200)
                .expect("cache-control", "public, max-age=30")
                .expect("vary", "Accept"),
        ],
    )
    .await;

    // Nested directories: their own path and a parent link, hidden names left out.
    let docs = served.get("list.test", "/docs/", &JSON).await;
    assert_eq!(docs.json()["path"], "/docs/");
    assert_eq!(listed_names(&docs), ["guide", "readme.txt"]);
    assert_eq!(docs.json()["entries"][0]["type"], "dir");
    assert!(docs.json()["entries"][0].get("size").is_none());
    let docs_html = served.get("list.test", "/docs/", &[]).await.text();
    assert!(docs_html.contains("href=\"../\""), "{docs_html}");
    assert!(
        docs_html.contains("href=\"./guide/\">guide/</a>"),
        "{docs_html}"
    );
    assert!(!docs_html.contains(".private"));
    let guide = served.get("list.test", "/docs/guide/", &JSON).await;
    assert_eq!(guide.json()["path"], "/docs/guide/");
    assert_eq!(listed_names(&guide), ["intro.txt"]);
    assert_eq!(
        served.get("list.test", "/docs/.private", &[]).await.status,
        404
    );
    assert_eq!(
        served
            .get("list.test", "/docs/guide/intro.txt", &[])
            .await
            .body[..],
        b"intro"[..]
    );
}

#[tokio::test]
async fn listed_names_are_escaped_and_every_link_works() {
    let served = serve().await;
    let page = served.get("list.test", "/nasty/", &[]).await.text();
    for raw in [
        "<b>bold",
        "<script>",
        "javascript:alert(1).txt\">",
        "quote\"s'",
        "a&amp;b",
    ] {
        assert!(!page.contains(raw), "{raw} unescaped in {page}");
    }
    assert!(page.contains("&lt;script&gt;alert(1).txt"));
    assert!(page.contains("a&amp;amp;b.txt"));
    assert!(page.contains("quote&quot;s&#39;.txt"));
    // JSON keeps the names exactly.
    let json = served.get("list.test", "/nasty/", &JSON).await;
    let mut expected: Vec<String> = NASTY_NAMES.iter().map(|n| (*n).to_owned()).collect();
    expected.sort();
    assert_eq!(listed_names(&json), expected);
    // Every link, followed relative to the directory, leads to its own file.
    let hrefs: Vec<&str> = page
        .split("href=\"")
        .skip(2) // the parent link is first
        .filter_map(|rest| rest.split('"').next())
        .collect();
    assert_eq!(hrefs.len(), NASTY_NAMES.len(), "{hrefs:?}");
    let mut seen = Vec::new();
    for href in hrefs {
        assert!(href.starts_with("./"), "{href}");
        let reply = served
            .get("list.test", &format!("/nasty/{}", &href[2..]), &[])
            .await;
        assert_eq!(reply.status, 200, "{href}");
        seen.push(reply.text());
    }
    seen.sort();
    assert_eq!(seen, expected, "each link names its own file");
}

#[tokio::test]
async fn listing_policies_for_hidden_files_and_symlinks() {
    let served = serve().await;
    let top = |names: Vec<String>| -> Vec<String> {
        names
            .into_iter()
            .filter(|n| n.contains("link") || n.starts_with('.'))
            .collect()
    };
    // The defaults: no dot-files, no links; the root lists when it has no index.
    let bare = served.get("bare.test", "/", &JSON).await;
    assert_eq!(bare.status, 200);
    assert_eq!(bare.json()["path"], "/");
    let names = listed_names(&bare);
    for name in [
        "about.txt",
        "app.js",
        "assets",
        "big.bin",
        "dir",
        "docs",
        "many",
        "nasty",
        "index.html",
        "caf\u{e9}.txt",
    ] {
        assert!(names.contains(&name.to_owned()), "{name} in {names:?}");
    }
    assert_eq!(top(names.clone()), Vec::<String>::new());
    assert!(
        names.windows(2).all(|w| w[0] < w[1]),
        "sorted by name: {names:?}"
    );
    let html = served.get("bare.test", "/", &[]).await.text();
    assert!(
        !html.contains("href=\"../\""),
        "the root has no parent link"
    );
    assert!(html.contains("href=\"./dir/\">dir/</a>"));
    assert_eq!(served.get("bare.test", "/.env", &[]).await.status, 404);
    assert_eq!(served.get("bare.test", "/.git/", &[]).await.status, 404);
    // within_root: a link that stays inside is listed, typed by its target; one out is not.
    let within = served.get("barewithin.test", "/", &JSON).await;
    let entries = within.json()["entries"].clone();
    let link = entries
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "inside-link.txt")
        .unwrap();
    assert_eq!(link["type"], "file");
    assert_eq!(link["size"], 1000);
    assert_eq!(link["symlink"], true);
    assert!(!listed_names(&within).contains(&"outside-link.txt".to_owned()));
    assert_eq!(
        served
            .get("barewithin.test", "/outside-link.txt", &[])
            .await
            .status,
        404
    );
    // all: every link and, with hidden: allow, dot-files, which are then served too.
    let all = served.get("bareall.test", "/", &JSON).await;
    let names = listed_names(&all);
    for name in ["inside-link.txt", "outside-link.txt", ".env", ".git"] {
        assert!(names.contains(&name.to_owned()), "{name} in {names:?}");
    }
    assert_eq!(
        served
            .get("bareall.test", "/outside-link.txt", &[])
            .await
            .body[..],
        SECRET.as_bytes()[..]
    );
    assert_eq!(
        served.get("bareall.test", "/.git/", &JSON).await.json()["entries"][0]["name"],
        "config"
    );
    // hidden: allow alone does not list links.
    let dots = served.get("baredots.test", "/", &JSON).await;
    let names = listed_names(&dots);
    assert!(names.contains(&".env".to_owned()) && !names.iter().any(|n| n.contains("link")));
    // Without the redirect, a directory lists at its own path and links name it first.
    let plain = served.get("bareplain.test", "/docs", &[]).await;
    assert_eq!(plain.status, 200);
    assert!(plain.text().contains("href=\"docs/readme.txt\""));
    assert_eq!(
        served.get("bareplain.test", "/docs", &JSON).await.json()["path"],
        "/docs/"
    );
}

#[tokio::test]
async fn listing_precedence_fallback_and_pass_through() {
    let served = serve().await;
    // `fallback` is for paths that do not exist; a directory that exists lists.
    let spa_dir = served.get("listspa.test", "/dir-no-index/", &[]).await;
    assert_eq!(spa_dir.status, 200);
    assert!(spa_dir.text().contains("Index of /dir-no-index/"));
    assert_eq!(
        served
            .get("listspa.test", "/dir-no-index", &[])
            .await
            .status,
        308
    );
    let spa_page = served.get("listspa.test", "/users/42", &[]).await;
    assert_eq!(spa_page.body[..], b"<h1>home</h1>"[..]);
    assert_eq!(
        served
            .get("listspa.test", "/app.missing.js", &[])
            .await
            .status,
        404
    );
    // `pass_through` with listing: directories list, the rest goes on.
    assert!(
        served
            .get("listpass.test", "/dir-no-index/", &[])
            .await
            .text()
            .contains("file.txt")
    );
    assert_eq!(
        served.get("listpass.test", "/api/users", &[]).await.json()["target"],
        "/api/users"
    );
    assert_eq!(
        served.get("listpass.test", "/.env", &[]).await.json()["target"],
        "/.env"
    );
    // With listing off nothing changes: 404 without `pass_through`, the service with it.
    assert_eq!(
        served.get("plain.test", "/dir-no-index/", &[]).await.status,
        404
    );
    assert_eq!(
        served.get("plain.test", "/dir-no-index", &[]).await.status,
        404
    );
    assert_eq!(
        served.get("site.test", "/dir-no-index", &[]).await.body[..],
        b"<h1>home</h1>"[..],
        "fallback as before"
    );
    let passed = served.get("pass.test", "/dir-no-index/", &[]).await;
    assert_eq!(passed.json()["target"], "/dir-no-index/");
}

#[tokio::test]
async fn listings_are_compressed_by_compress() {
    let served = serve().await;
    for (accept, kind) in [
        ("text/html", "text/html"),
        ("application/json", "application/json"),
    ] {
        let plain = served
            .get("list.test", "/many/", &[("accept", accept)])
            .await;
        assert!(plain.body.len() > 1024, "large enough to compress");
        let reply = served
            .get(
                "listgz.test",
                "/many/",
                &[("accept", accept), ("accept-encoding", "gzip")],
            )
            .await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("content-encoding"), Some("gzip"), "{kind}");
        assert!(reply.header("content-type").unwrap().starts_with(kind));
        let vary: Vec<String> = reply
            .headers
            .get_all("vary")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        let vary = vary.join(",");
        assert!(
            vary.contains("Accept") && vary.contains("Accept-Encoding"),
            "{vary}"
        );
        let mut text = Vec::new();
        flate2::read::GzDecoder::new(&reply.body[..])
            .read_to_end(&mut text)
            .unwrap();
        assert_eq!(text, plain.body[..]);
    }
    let identity = served.get("listgz.test", "/many/", &[]).await;
    assert_eq!(identity.header("content-encoding"), None);
}

#[tokio::test]
async fn traversal_never_lists() {
    let served = serve().await;
    let payloads = [
        "/..%2f",
        "/docs/..%2f",
        "/docs/..%2f..%2f..%2fetc/",
        "/docs/%2e%2e%2f",
        "/docs%2f..%2f..%2f",
        "/..%5c",
        "/docs/..%5c",
        "/docs/%5c",
        "/%00/",
        "/docs/%00",
        "/%C0%AE%C0%AE/",
        "/docs/%FF/",
        "/docs/%252e%252e/",
        "/nope/",
        "/about.txt/",
        "/etc/",
    ];
    let mut leaks = Vec::new();
    for host in ["list.test", "bare.test", "bareall.test", "listspa.test"] {
        for payload in payloads {
            for accept in ["text/html", "application/json"] {
                let bytes = format!(
                    "GET {payload} HTTP/1.1\r\nHost: {host}\r\nAccept: {accept}\r\nConnection: close\r\n\r\n"
                );
                let raw =
                    client::raw(addr(served.port), bytes.as_bytes(), Duration::from_secs(2)).await;
                let status = client::statuses(&raw).first().copied().unwrap_or(0);
                let text = String::from_utf8_lossy(&raw);
                let listed = text.contains("Index of") || text.contains("\"entries\"");
                let refused = matches!(status, 400 | 404) || host == "listspa.test";
                if listed || !refused || text.contains(SECRET) || text.contains("root:") {
                    leaks.push(format!("{host}{payload} {accept}: {status}"));
                }
            }
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

#[tokio::test]
async fn traversal_payloads_never_leave_the_root() {
    let served = serve().await;
    let payloads = [
        "/../etc/passwd",
        "/../../../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%2e%2e%2f%2e%2e%2fetc/passwd",
        "/..%2f..%2fetc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/%2e%2e%5c%2e%2e%5cetc/passwd",
        "/..%5c..%5cetc/passwd",
        "/a/..%5c..%5cetc/passwd",
        "/%5c..%5cetc/passwd",
        "/..;/..;/etc/passwd",
        "/....//....//etc/passwd",
        "/..\\..\\etc\\passwd",
        "/....\\/....\\/etc/passwd",
        "/%252e%252e%255c%252e%252e%255cetc/passwd",
        "/%252e%252e%252fetc/passwd",
        "/..%c0%af..%c0%afetc/passwd",
        "/..%c1%9c..%c1%9cetc/passwd",
        "/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd",
        "/..%ef%bc%8f..%ef%bc%8fetc/passwd",
        "/%00",
        "/about.txt%00.html",
        "/../../../etc/passwd%00.png",
        "/var/www/images/../../../etc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
        "/./.env",
        "/.env",
        "/.ENV",
        "/%2eenv",
        "/.git/config",
        "/.git/",
        "/outside-link.txt",
    ];
    let mut leaks = Vec::new();
    for payload in payloads {
        for host in ["plain.test", "within.test"] {
            let (status, text) = served.raw(host, payload).await;
            if !matches!(status, 400 | 404) || text.contains(SECRET) || text.contains("root:") {
                leaks.push(format!("{host}{payload}: {status}"));
            }
        }
        // With the SPA fallback a page path may answer index.html, never an outside byte.
        let (_, text) = served.raw("site.test", payload).await;
        if text.contains(SECRET) || text.contains("root:") {
            leaks.push(format!("site.test{payload}: leaked"));
        }
    }
    // The outside secret, by its own path and by traversal relative to the root.
    let outside = served.fixture.outside.path().join("secret.txt");
    let relative = format!("/../../../../../../../..{}", outside.display());
    for target in [outside.display().to_string(), relative] {
        let (status, text) = served.raw("all.test", &target).await;
        if text.contains(SECRET) {
            leaks.push(format!("all.test{target}: {status}"));
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
    // A truncated escape is refused by the path normaliser.
    assert_eq!(served.raw("plain.test", "/%2").await.0, 400);
}

#[tokio::test]
async fn symlink_policies() {
    let served = serve().await;
    run_table(
        &served,
        vec![
            case("plain.test", "/inside-link.txt", 404),
            case("plain.test", "/outside-link.txt", 404),
            case("within.test", "/inside-link.txt", 200).body(pattern(1000)),
            case("within.test", "/outside-link.txt", 404),
            case("all.test", "/inside-link.txt", 200).body(pattern(1000)),
            case("all.test", "/outside-link.txt", 200).body(SECRET),
        ],
    )
    .await;
}

#[tokio::test]
async fn pass_through_sends_misses_to_the_service() {
    let served = serve().await;
    let file = served.get("pass.test", "/about.txt", &[]).await;
    assert_eq!(file.body[..], pattern(1000)[..]);
    let api = served.get("pass.test", "/api/users?page=2", &[]).await;
    assert_eq!(api.json()["target"], "/api/users?page=2");
    let post = served.send("POST", "pass.test", "/about.txt", &[]).await;
    assert_eq!(post.json()["method"], "POST");
    let hidden = served.get("pass.test", "/.env", &[]).await;
    assert_eq!(hidden.json()["target"], "/.env");
}

/// Parallel downloads in the concurrency check; see the comment there for macOS.
const PARALLEL_DOWNLOADS: usize = if cfg!(target_os = "macos") { 16 } else { 100 };

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_files_stream_byte_exact_with_bandwidth_and_concurrency() {
    let served = serve().await;
    let big = pattern(BIG);
    let reply = served.get("site.test", "/big.bin", &[]).await;
    assert_eq!(reply.header("content-length"), Some(&*BIG.to_string()));
    assert_eq!(
        reply.header("content-type"),
        Some("application/octet-stream")
    );
    assert!(reply.body[..] == big[..], "HTTP/1.1 body differs");

    // `bandwidth` before `static` throttles the 256 KiB chunks.
    let started = Instant::now();
    let slow = served.get("slow.test", "/big.bin", &[]).await;
    assert!(slow.body[..] == big[..], "throttled body differs");
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "5 MiB at 8 MiB/s took {:?}",
        started.elapsed()
    );

    // Many downloads at once, and a small request still answers quickly. On macOS, 100 parallel
    // 5 MiB downloads over loopback inside one test process exhaust the kernel's socket buffers:
    // writes fail with ENOBUFS ("No buffer space available", os error 55) on both ends, which is
    // the machine's limit, not rdock's (100 separate curl processes complete every download).
    let port = served.port;
    let downloads: Vec<_> = (0..PARALLEL_DOWNLOADS)
        .map(|_| {
            tokio::spawn(async move {
                client::http1(addr(port), get("site.test", "/big.bin"))
                    .await
                    .body
                    .len()
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let started = Instant::now();
    let tiny = served.get("site.test", "/index.html", &[]).await;
    let tiny_took = started.elapsed();
    assert_eq!(tiny.status, 200);
    let mut failed = 0;
    for download in downloads {
        if download.await.map_or(true, |len| len != BIG) {
            failed += 1;
        }
    }
    assert_eq!(failed, 0, "{}", served.rdock.log());
    assert!(
        tiny_took < Duration::from_secs(2),
        "a small file took {tiny_took:?} during {PARALLEL_DOWNLOADS} downloads"
    );
}

#[tokio::test]
async fn http2_over_tls_streams_byte_exact() {
    let fixture = fixture();
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let cert = ca.issue(dir.path(), "site", &["site.test"]);
    let port = free_port();
    let config = format!(
        r#"
listeners:
  websecure: {{ address: "127.0.0.1:{port}", tls: {{}} }}
certificates:
  site: {{ cert_file: "{}", key_file: "{}" }}
routes:
  site: {{ match: "Host(`site.test`)", middlewares: [files] }}
middlewares:
  files: {{ type: static, root: "{}" }}
"#,
        cert.cert.display(),
        cert.key.display(),
        fixture.root.display()
    );
    let _rdock = Rdock::start(RDOCK, &config);
    let big = pattern(BIG);
    for alpn in [&b"h2"[..], &b"http/1.1"[..]] {
        let reply = client::tls(
            addr(port),
            "site.test",
            ca.client_config(&[alpn]),
            get("site.test", "/big.bin"),
        )
        .await;
        assert_eq!(reply.status, 200);
        assert!(
            reply.body[..] == big[..],
            "{:?} body differs",
            reply.version
        );
    }
    let h2 = client::tls(
        addr(port),
        "site.test",
        ca.client_config(&[b"h2"]),
        request("GET", "site.test", "/big.bin", bytes::Bytes::new()),
    )
    .await;
    assert_eq!(h2.version, http::Version::HTTP_2);
}

#[tokio::test]
async fn a_renamed_root_keeps_serving_and_a_reload_reports_it() {
    let served = serve().await;
    let moved = served.fixture.root.with_extension("moved");
    std::fs::rename(&served.fixture.root, &moved).unwrap();
    let reply = served.get("plain.test", "/about.txt", &[]).await;
    assert_eq!(reply.status, 200, "the directory handle still works");
    let (status, body) = served.rdock.reload();
    assert_eq!(status, 422, "{body}");
    assert!(body.to_string().contains("cannot read"), "{body}");
    std::fs::rename(&moved, &served.fixture.root).unwrap();
}

#[test]
fn validate_reports_roots_and_risky_options() {
    let fixture = fixture();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    let validate = |middleware: &str| {
        let yaml = format!(
            "routes:\n  site: {{ match: \"Host(`site.test`)\", middlewares: [files], tls: off }}\nmiddlewares:\n  files: {middleware}\n"
        );
        std::fs::write(&file, yaml).unwrap();
        let output = std::process::Command::new(RDOCK)
            .args(["validate", file.to_str().unwrap()])
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned()
                + &String::from_utf8_lossy(&output.stderr),
        )
    };
    let root = fixture.root.display();
    let (ok, text) = validate(&format!("{{ type: static, root: \"{root}\" }}"));
    assert!(ok, "{text}");
    let (ok, text) = validate(&format!("{{ type: static, root: \"{root}/nope\" }}"));
    assert!(!ok && text.contains("cannot read"), "{text}");
    let (ok, text) = validate(&format!("{{ type: static, root: \"{root}/about.txt\" }}"));
    assert!(!ok && text.contains("is not a directory"), "{text}");
    let (ok, text) = validate(&format!(
        "{{ type: static, root: \"{root}\", symlinks: all }}"
    ));
    assert!(ok && text.contains("also out of `root`"), "{text}");
    let (ok, text) = validate(&format!(
        "{{ type: static, root: \"{root}\", listing: true }}"
    ));
    assert!(
        ok && !text.contains("planned for") && !text.contains("listing"),
        "{text}"
    );
    let (ok, text) = validate(&format!(
        "{{ type: static, root: \"{root}\", listing: true, hidden: allow }}"
    ));
    assert!(
        ok && text.contains("directory listings show files and directories starting with `.`"),
        "{text}"
    );
    let (ok, text) = validate(&format!(
        "{{ type: static, root: \"{root}\", listing: true, symlinks: all }}"
    ));
    assert!(
        ok && text.contains("directory listings show links that lead out of `root`"),
        "{text}"
    );
    let (ok, text) = validate(&format!(
        "{{ type: static, root: \"{root}\", pass_through: true }}"
    ));
    assert!(!ok && text.contains("the route needs a service"), "{text}");
}
