//! Path middlewares: `rewrite` (regular expression), `strip_prefix`, `add_prefix` and
//! `replace_path`, with Traefik's `X-Forwarded-Prefix` and `X-Replaced-Path` headers. A result
//! that normalisation would change (`/api./x` stripped of `/api`) is rejected with 400, so the
//! backend never sees a path that differs from what was routed.

use async_trait::async_trait;
use http::{HeaderName, HeaderValue, Uri};
use pingora::http::RequestHeader;
use rdock_model::middleware::{
    AddPrefixConfig, ReplacePathConfig, RewriteConfig, StripPrefixConfig,
};
use regex::Regex;

use crate::{BuildError, Context, Flow, Middleware, Reply};

const X_FORWARDED_PREFIX: HeaderName = HeaderName::from_static("x-forwarded-prefix");
const X_REPLACED_PATH: HeaderName = HeaderName::from_static("x-replaced-path");

fn current_path(req: &RequestHeader) -> String {
    req.uri.path().to_owned()
}

/// Replaces the path, keeping the query and any authority. Returns 400 when the new path is not
/// in normalised form.
fn set_path(req: &mut RequestHeader, path: &str) -> Flow {
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    match rdock_rules::path::normalize(&path) {
        Ok(normal) if normal.forwarded == path => {}
        _ => return Flow::Reply(Reply::status(400)),
    }
    let path_and_query = match req.uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    let mut parts = req.uri.clone().into_parts();
    let Ok(pq) = path_and_query.parse() else {
        return Flow::Reply(Reply::status(400));
    };
    parts.path_and_query = Some(pq);
    match Uri::from_parts(parts) {
        Ok(uri) => {
            req.set_uri(uri);
            Flow::Next
        }
        Err(_) => Flow::Reply(Reply::status(400)),
    }
}

fn add_header(req: &mut RequestHeader, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        let _ = req.append_header(name, value);
    }
}

/// `rewrite`: replaces every match of the regular expression in the (encoded) path.
#[derive(Debug)]
pub(crate) struct Rewrite {
    regex: Regex,
    replacement: String,
}

impl Rewrite {
    pub(crate) fn new(config: &RewriteConfig) -> Result<Self, BuildError> {
        Ok(Self {
            regex: Regex::new(&config.regex).map_err(|e| BuildError::Invalid(e.to_string()))?,
            replacement: config.replacement.clone(),
        })
    }
}

#[async_trait]
impl Middleware for Rewrite {
    async fn request(&self, req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        let original = current_path(req);
        if !self.regex.is_match(&original) {
            return Flow::Next;
        }
        let rewritten = self
            .regex
            .replace_all(&original, self.replacement.as_str())
            .into_owned();
        add_header(req, X_REPLACED_PATH, &original);
        set_path(req, &rewritten)
    }
}

/// `strip_prefix`: removes the first configured prefix the path starts with.
#[derive(Debug)]
pub(crate) struct StripPrefix {
    prefixes: Vec<String>,
}

impl StripPrefix {
    pub(crate) fn new(config: &StripPrefixConfig) -> Self {
        Self {
            prefixes: config
                .prefixes
                .iter()
                .map(|p| p.trim().to_owned())
                .collect(),
        }
    }
}

#[async_trait]
impl Middleware for StripPrefix {
    async fn request(&self, req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        let path = current_path(req);
        let Some(prefix) = self.prefixes.iter().find(|p| path.starts_with(p.as_str())) else {
            return Flow::Next;
        };
        let rest = path[prefix.len()..].to_owned();
        add_header(req, X_FORWARDED_PREFIX, prefix);
        set_path(req, &rest)
    }
}

/// `add_prefix`: puts a prefix in front of the path.
#[derive(Debug)]
pub(crate) struct AddPrefix {
    prefix: String,
}

impl AddPrefix {
    pub(crate) fn new(config: &AddPrefixConfig) -> Self {
        let prefix = config.prefix.trim_end_matches('/');
        Self {
            prefix: if prefix.starts_with('/') {
                prefix.to_owned()
            } else {
                format!("/{prefix}")
            },
        }
    }
}

#[async_trait]
impl Middleware for AddPrefix {
    async fn request(&self, req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        let path = format!("{}{}", self.prefix, current_path(req));
        set_path(req, &path)
    }
}

/// `replace_path`: replaces the whole path.
#[derive(Debug)]
pub(crate) struct ReplacePath {
    path: String,
}

impl ReplacePath {
    pub(crate) fn new(config: &ReplacePathConfig) -> Self {
        Self {
            path: config.path.clone(),
        }
    }
}

#[async_trait]
impl Middleware for ReplacePath {
    async fn request(&self, req: &mut RequestHeader, _cx: &mut Context) -> Flow {
        let original = current_path(req);
        add_header(req, X_REPLACED_PATH, &original);
        set_path(req, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{block_on, cx, header, request};

    fn run(mw: &dyn Middleware, target: &str) -> (Flow, RequestHeader) {
        let mut req = request("GET", target, &[]);
        let flow = block_on(mw.request(&mut req, &mut cx()));
        (flow, req)
    }

    #[test]
    fn strip_prefix_is_a_string_prefix_and_keeps_the_query() {
        let mw = StripPrefix::new(&StripPrefixConfig {
            prefixes: vec!["/api".into(), "/other".into()],
        });
        let (flow, req) = run(&mw, "/api/users?page=2");
        assert_eq!(flow, Flow::Next);
        assert_eq!(req.uri.path_and_query().unwrap().as_str(), "/users?page=2");
        assert_eq!(header(&req.headers, "x-forwarded-prefix"), Some("/api"));
        let (_, req) = run(&mw, "/apiv2");
        assert_eq!(req.uri.path(), "/v2");
        let (_, req) = run(&mw, "/api");
        assert_eq!(req.uri.path(), "/");
        let (flow, _) = run(&mw, "/api./etc");
        assert_eq!(flow, Flow::Reply(Reply::status(400)));
        let (_, req) = run(&mw, "/elsewhere");
        assert_eq!(req.uri.path(), "/elsewhere");
    }

    #[test]
    fn add_and_replace_path() {
        let add = AddPrefix::new(&AddPrefixConfig {
            prefix: "/v1/".into(),
        });
        let (_, req) = run(&add, "/users?x=1");
        assert_eq!(req.uri.path_and_query().unwrap().as_str(), "/v1/users?x=1");
        let replace = ReplacePath::new(&ReplacePathConfig {
            path: "/fixed".into(),
        });
        let (_, req) = run(&replace, "/old/path?q");
        assert_eq!(req.uri.path_and_query().unwrap().as_str(), "/fixed?q");
        assert_eq!(header(&req.headers, "x-replaced-path"), Some("/old/path"));
    }

    #[test]
    fn rewrite_replaces_every_match() {
        let mw = Rewrite::new(&RewriteConfig {
            regex: "^/foo/(.*)".into(),
            replacement: "/bar/$1".into(),
        })
        .unwrap();
        let (_, req) = run(&mw, "/foo/a/b");
        assert_eq!(req.uri.path(), "/bar/a/b");
        assert_eq!(header(&req.headers, "x-replaced-path"), Some("/foo/a/b"));
        let (_, req) = run(&mw, "/nope");
        assert_eq!(header(&req.headers, "x-replaced-path"), None);
    }
}
