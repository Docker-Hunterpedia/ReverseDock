//! `static`: answers requests with files from a directory (F-WEB-01, ADR-0026).
//!
//! A terminal middleware: it answers every request itself, unless `pass_through` sends the
//! requests it has no file for on to the route's service. The path it sees is the forwarded
//! path after earlier middlewares (`strip_prefix` included); nothing is stripped implicitly.

use std::sync::Arc;

use async_trait::async_trait;
use http::header::{ALLOW, LOCATION};
use http::{HeaderValue, Method};
use pingora::http::RequestHeader;
use rdock_model::middleware::{CompressAlgorithm, HiddenFiles, StaticConfig};

use crate::compress::preferences;
use crate::{Body, BuildError, Context, Flow, Middleware, Reply};

mod answer;
mod body;
mod listing;
mod path;
mod root;

pub use body::FileBody;

use answer::Answers;
use path::SafePath;
use root::{Directories, Lookup, Resolution, Root};

/// The `static` middleware.
#[derive(Debug)]
pub(crate) struct Static {
    shared: Arc<Shared>,
    precompressed: Vec<CompressAlgorithm>,
    hidden: HiddenFiles,
    /// The fallback file relative to the root.
    fallback: Option<String>,
    fallback_except: Vec<String>,
    pass_through: bool,
    answers: Answers,
}

/// What lookups on the blocking pool need.
#[derive(Debug)]
struct Shared {
    root: Root,
    directories: Directories,
}

impl Static {
    /// Opens the root; a missing root or one that is not a directory fails the build.
    pub(crate) fn new(config: &StaticConfig) -> Result<Self, BuildError> {
        Ok(Self {
            shared: Arc::new(Shared {
                root: Root::open(&config.root, config.symlinks)?,
                directories: Directories {
                    index: config.index.clone(),
                    redirect: config.directory_redirect,
                    listing: config.listing,
                    hidden: config.hidden,
                },
            }),
            precompressed: config.precompressed.clone(),
            hidden: config.hidden,
            fallback: config
                .fallback
                .as_deref()
                .map(|f| f.trim_start_matches('/').to_owned()),
            fallback_except: config.fallback_except.clone(),
            pass_through: config.pass_through,
            answers: Answers::new(config)?,
        })
    }

    /// The fallback for a path that names no file: only page paths (no `.` in the last
    /// segment) outside the `fallback_except` prefixes, so a missing asset stays a 404.
    fn fallback_for(&self, path: &SafePath) -> Option<String> {
        let excepted = self
            .fallback_except
            .iter()
            .any(|prefix| path.decoded.starts_with(prefix.as_str()));
        if path.names_asset() || excepted {
            return None;
        }
        self.fallback.clone()
    }

    /// A refusal, or the next middleware and the service with `pass_through`.
    fn refuse(&self, reply: Reply) -> Flow {
        if self.pass_through {
            Flow::Next
        } else {
            Flow::Reply(reply)
        }
    }

    async fn resolve(&self, lookup: Lookup) -> Option<Resolution> {
        let shared = self.shared.clone();
        match tokio::task::spawn_blocking(move || shared.root.resolve(&lookup, &shared.directories))
            .await
        {
            Ok(resolution) => Some(resolution),
            Err(e) => {
                tracing::warn!(error = %e, "static file lookup failed");
                None
            }
        }
    }
}

/// `308` to the same path with a trailing slash, keeping the query.
fn add_slash(req: &RequestHeader) -> Reply {
    let query = req.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let target = format!("{}/{query}", req.uri.path());
    match HeaderValue::from_str(&target) {
        Ok(location) => {
            let mut reply = Reply::status(308).header(LOCATION, location);
            reply.body = Some(Body::Bytes(bytes::Bytes::new()));
            reply
        }
        Err(_) => Reply::status(404),
    }
}

#[async_trait]
impl Middleware for Static {
    async fn request(&self, req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        if req.method != Method::GET && req.method != Method::HEAD {
            let allow = HeaderValue::from_static("GET, HEAD");
            return self.refuse(Reply::status(405).header(ALLOW, allow));
        }
        let Some(path) = SafePath::parse(req.uri.path(), self.hidden) else {
            return self.refuse(Reply::status(404));
        };
        let lookup = Lookup {
            codings: preferences(req, &self.precompressed),
            fallback: self.fallback_for(&path),
            path,
        };
        match self.resolve(lookup).await {
            Some(Resolution::File(found)) => Flow::Reply(self.answers.reply(req, *found)),
            Some(Resolution::Listing(found)) => Flow::Reply(self.answers.listing(req, &found)),
            Some(Resolution::AddSlash) => Flow::Reply(add_slash(req)),
            Some(Resolution::Missing) => self.refuse(Reply::status(404)),
            None => Flow::Reply(Reply::status(500)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, reply_header, request};

    fn site() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        std::fs::write(r.join("index.html"), "home").unwrap();
        std::fs::create_dir(r.join("dir")).unwrap();
        std::fs::write(r.join("dir/index.html"), "dir").unwrap();
        std::fs::write(r.join(".env"), "SECRET=1").unwrap();
        dir
    }

    fn mw(root: &std::path::Path, extra: serde_json::Value) -> Static {
        let mut config = serde_json::json!({ "root": root });
        if let (Some(base), serde_json::Value::Object(extra)) = (config.as_object_mut(), extra) {
            base.extend(extra);
        }
        Static::new(&serde_json::from_value(config).unwrap()).unwrap()
    }

    fn run(mw: &Static, method: &str, target: &str) -> Flow {
        let mut req = request(method, target, &[]);
        block_on(mw.request(&mut req, &mut cx()))
    }

    fn status(flow: &Flow) -> Option<u16> {
        match flow {
            Flow::Reply(reply) => Some(reply.status),
            Flow::Next => None,
        }
    }

    #[test]
    fn answers_files_redirects_and_refusals() {
        let site = site();
        let mw = mw(site.path(), serde_json::json!({}));
        assert_eq!(status(&run(&mw, "GET", "/")), Some(200));
        assert_eq!(status(&run(&mw, "HEAD", "/dir/")), Some(200));
        let Flow::Reply(redirect) = run(&mw, "GET", "/dir?x=1") else {
            panic!("redirect")
        };
        assert_eq!(redirect.status, 308);
        assert_eq!(reply_header(&redirect, "location"), Some("/dir/?x=1"));
        assert_eq!(status(&run(&mw, "GET", "/.env")), Some(404));
        assert_eq!(status(&run(&mw, "GET", "/missing")), Some(404));
        let Flow::Reply(post) = run(&mw, "POST", "/") else {
            panic!("405")
        };
        assert_eq!(post.status, 405);
        assert_eq!(reply_header(&post, "allow"), Some("GET, HEAD"));
    }

    #[test]
    fn pass_through_sends_misses_on() {
        let site = site();
        let mw = mw(site.path(), serde_json::json!({ "pass_through": true }));
        assert_eq!(status(&run(&mw, "GET", "/")), Some(200));
        assert_eq!(run(&mw, "GET", "/api/users"), Flow::Next);
        assert_eq!(run(&mw, "POST", "/api/users"), Flow::Next);
        assert_eq!(run(&mw, "GET", "/.env"), Flow::Next);
    }

    #[test]
    fn fallback_only_for_pages_outside_the_exceptions() {
        let site = site();
        let mw = mw(
            site.path(),
            serde_json::json!({ "fallback": "/index.html", "fallback_except": ["/api/"] }),
        );
        assert_eq!(status(&run(&mw, "GET", "/about/team")), Some(200));
        assert_eq!(status(&run(&mw, "GET", "/app.3f2a.js")), Some(404));
        assert_eq!(status(&run(&mw, "GET", "/api/users")), Some(404));
    }

    #[test]
    fn directories_without_redirect_answer_their_index() {
        let site = site();
        let mw = mw(
            site.path(),
            serde_json::json!({ "directory_redirect": false }),
        );
        assert_eq!(status(&run(&mw, "GET", "/dir")), Some(200));
    }

    fn listing_site() -> tempfile::TempDir {
        let site = site();
        let r = site.path();
        std::fs::create_dir_all(r.join("pub/sub")).unwrap();
        std::fs::write(r.join("pub/a.txt"), "aaaa").unwrap();
        std::fs::write(r.join("pub/.secret"), "s").unwrap();
        site
    }

    fn reply_of(flow: Flow) -> Reply {
        match flow {
            Flow::Reply(reply) => reply,
            Flow::Next => panic!("not answered"),
        }
    }

    fn get_with(
        mw: &Static,
        method: &str,
        target: &str,
        headers: &[(&'static str, &str)],
    ) -> Reply {
        let mut req = request(method, target, headers);
        reply_of(block_on(mw.request(&mut req, &mut cx())))
    }

    fn json(reply: &Reply) -> serde_json::Value {
        serde_json::from_slice(crate::test_support::reply_bytes(reply).unwrap()).unwrap()
    }

    #[test]
    fn listing_is_off_by_default() {
        let site = listing_site();
        let off = mw(site.path(), serde_json::json!({}));
        assert_eq!(status(&run(&off, "GET", "/pub/")), Some(404));
        assert_eq!(
            status(&run(&off, "GET", "/pub")),
            Some(404),
            "no redirect either"
        );
        let pass = mw(site.path(), serde_json::json!({ "pass_through": true }));
        assert_eq!(run(&pass, "GET", "/pub/"), Flow::Next);
        assert_eq!(run(&pass, "GET", "/pub"), Flow::Next);
    }

    #[test]
    fn a_listing_is_html_by_default_and_json_when_preferred() {
        let site = listing_site();
        let mw = mw(site.path(), serde_json::json!({ "listing": true }));
        let html = get_with(&mw, "GET", "/pub/", &[]);
        assert_eq!(html.status, 200);
        assert_eq!(
            reply_header(&html, "content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(reply_header(&html, "vary"), Some("Accept"));
        assert_eq!(reply_header(&html, "cache-control"), Some("no-cache"));
        assert_eq!(
            reply_header(&html, "x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(reply_header(&html, "referrer-policy"), Some("no-referrer"));
        let csp = reply_header(&html, "content-security-policy").unwrap();
        assert!(csp.starts_with("default-src 'none'"), "{csp}");
        assert!(!csp.contains("unsafe-inline"), "{csp}");
        assert_eq!(reply_header(&html, "etag"), None, "no validator");
        assert_eq!(reply_header(&html, "last-modified"), None);
        let page =
            String::from_utf8(crate::test_support::reply_bytes(&html).unwrap().to_vec()).unwrap();
        assert!(page.contains("href=\"./a.txt\""), "{page}");
        assert!(page.contains("href=\"./sub/\""), "{page}");
        assert!(!page.contains(".secret"), "{page}");
        let json_reply = get_with(&mw, "GET", "/pub/", &[("accept", "application/json")]);
        assert_eq!(
            reply_header(&json_reply, "content-type"),
            Some("application/json")
        );
        assert_eq!(reply_header(&json_reply, "vary"), Some("Accept"));
        let body = json(&json_reply);
        assert_eq!(body["path"], "/pub/");
        assert_eq!(body["truncated"], false);
        assert_eq!(body["entries"][0]["name"], "a.txt");
        assert_eq!(body["entries"][0]["type"], "file");
        assert_eq!(body["entries"][0]["size"], 4);
        assert_eq!(body["entries"][1]["name"], "sub");
        assert_eq!(body["entries"][1]["type"], "dir");
        assert_eq!(body["entries"].as_array().unwrap().len(), 2);
        let browser = get_with(&mw, "GET", "/pub/", &[("accept", "text/html,*/*;q=0.8")]);
        assert_eq!(
            reply_header(&browser, "content-type"),
            Some("text/html; charset=utf-8")
        );
    }

    #[test]
    fn head_conditionals_and_ranges_on_a_listing() {
        let site = listing_site();
        let mw = mw(site.path(), serde_json::json!({ "listing": true }));
        let get = get_with(&mw, "GET", "/pub/", &[]);
        let head = get_with(&mw, "HEAD", "/pub/", &[]);
        assert_eq!(head, get, "HEAD has GET's status, headers and length");
        for headers in [
            [("if-none-match", "*")],
            [("if-modified-since", "Sun, 06 Nov 2094 08:49:37 GMT")],
            [("range", "bytes=0-3")],
            [("if-match", "\"x\"")],
        ] {
            let reply = get_with(&mw, "GET", "/pub/", &headers);
            assert_eq!(
                (reply.status, reply_header(&reply, "content-range")),
                (200, None),
                "{headers:?}"
            );
            assert_eq!(reply, get, "{headers:?}");
        }
        assert_eq!(get_with(&mw, "POST", "/pub/", &[]).status, 405);
    }

    #[test]
    fn listing_redirect_fallback_and_cache_control() {
        let site = listing_site();
        let spa = mw(
            site.path(),
            serde_json::json!({
                "listing": true,
                "fallback": "/index.html",
                "cache_control": { "default": "no-cache", "/pub/": "public, max-age=60" },
            }),
        );
        let redirect = get_with(&spa, "GET", "/pub?x=1", &[]);
        assert_eq!(redirect.status, 308);
        assert_eq!(reply_header(&redirect, "location"), Some("/pub/?x=1"));
        let listed = get_with(&spa, "GET", "/pub/", &[]);
        assert_eq!(listed.status, 200);
        assert_eq!(
            reply_header(&listed, "content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            reply_header(&listed, "cache-control"),
            Some("public, max-age=60")
        );
        let nested = get_with(&spa, "GET", "/pub/sub/", &[]);
        assert_eq!(
            reply_header(&nested, "cache-control"),
            Some("public, max-age=60")
        );
        let root_listing = get_with(&spa, "GET", "/", &[]);
        assert_eq!(
            reply_header(&root_listing, "content-type"),
            Some("text/html; charset=utf-8"),
            "the root has an index, so this is the file"
        );
        assert_eq!(crate::test_support::reply_bytes(&root_listing), None);
        // A path that does not exist still gets the fallback file, a directory that does not.
        let missing = get_with(&spa, "GET", "/nope/deeper", &[]);
        assert_eq!(missing.status, 200);
        assert!(
            missing.body.as_ref().and_then(Body::as_bytes).is_none(),
            "the fallback file"
        );
        assert_eq!(reply_header(&missing, "vary"), Some("Accept-Encoding"));
        // Hidden names and traversal never list.
        for target in [
            "/.git/",
            "/pub/.secret",
            "/pub/../",
            "/%2e%2e/",
            "/pub/%2e%2e/",
            "/pub/..%2f",
        ] {
            assert_ne!(
                reply_header(&get_with(&spa, "GET", target, &[]), "vary"),
                Some("Accept"),
                "{target}"
            );
        }
        let strict = mw(site.path(), serde_json::json!({ "listing": true }));
        for target in [
            "/.git/",
            "/pub/../",
            "/%2e%2e/",
            "/pub/%2e%2e/",
            "/pub/..%2f",
            "/pub/%5c",
        ] {
            assert_eq!(
                get_with(&strict, "GET", target, &[]).status,
                404,
                "{target}"
            );
        }
    }

    #[test]
    fn no_redirect_lists_with_links_that_name_the_directory() {
        let site = listing_site();
        let mw = mw(
            site.path(),
            serde_json::json!({ "listing": true, "directory_redirect": false }),
        );
        let reply = get_with(&mw, "GET", "/pub", &[]);
        assert_eq!(reply.status, 200);
        let page =
            String::from_utf8(crate::test_support::reply_bytes(&reply).unwrap().to_vec()).unwrap();
        assert!(page.contains("href=\"pub/a.txt\""), "{page}");
        let json_reply = get_with(&mw, "GET", "/pub", &[("accept", "application/json")]);
        assert_eq!(json(&json_reply)["path"], "/pub/");
    }
}
