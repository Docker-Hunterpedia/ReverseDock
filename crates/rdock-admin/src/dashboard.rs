//! The dashboard, embedded in the binary from `apps/dashboard/dist` (ADR-0024). Files are
//! served with strong `ETag`s, pre-compressed `.br`/`.gz` siblings when the client accepts them,
//! `immutable` caching for hashed files under `assets/`, and `index.html` for any other page
//! path, so the single-page app handles its own routes. A binary built without the dashboard
//! answers with a short explanation instead.

use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use rust_embed::{EmbeddedFile, RustEmbed};

#[derive(RustEmbed)]
#[folder = "../../apps/dashboard/dist"]
#[allow_missing = true]
struct Assets;

const NOT_BUILT: &str = "<!doctype html><meta charset=utf-8><title>ReverseDock</title>\
<p>This rdock binary was built without the dashboard. Run <code>pnpm --dir apps/dashboard build</code> \
and build rdock again. The admin API under <code>/api/v1</code> works without it.</p>\n";

/// The embedded file for a request path: the file itself, or `index.html` for a page path
/// (no file extension in its last segment).
fn resolve(path: &str) -> Option<(String, EmbeddedFile)> {
    let path = path.trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if let Some(file) = Assets::get(path) {
        return Some((path.to_owned(), file));
    }
    let last = path.rsplit('/').next().unwrap_or_default();
    if last.contains('.') {
        return None;
    }
    Assets::get("index.html").map(|file| ("index.html".to_owned(), file))
}

/// The best variant the client accepts: Brotli, gzip or the file as built.
fn variant(
    path: &str,
    file: EmbeddedFile,
    headers: &HeaderMap,
) -> (EmbeddedFile, Option<&'static str>) {
    let accepts = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let accepts = |coding: &str| {
        accepts
            .split(',')
            .any(|part| part.split(';').next().is_some_and(|c| c.trim() == coding))
    };
    for (coding, suffix) in [("br", ".br"), ("gzip", ".gz")] {
        if accepts(coding)
            && let Some(compressed) = Assets::get(&format!("{path}{suffix}"))
        {
            return (compressed, Some(coding));
        }
    }
    (file, None)
}

/// Answers a `GET` or `HEAD` for a dashboard path.
pub(crate) fn serve(path: &str, headers: &HeaderMap) -> Response {
    let Some((name, file)) = resolve(path) else {
        if Assets::get("index.html").is_none() {
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                NOT_BUILT,
            )
                .into_response();
        }
        return crate::routes::error(StatusCode::NOT_FOUND, "not found");
    };
    let mime = file.metadata.mimetype();
    let mime = if mime.starts_with("text/") || mime.ends_with("javascript") {
        format!("{mime}; charset=utf-8")
    } else {
        mime.to_owned()
    };
    let (body, coding) = variant(&name, file, headers);
    let etag = format!("\"{}\"", crate::hex(&body.metadata.sha256_hash()));
    let cache = if name.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|tag| tag.trim() == etag));
    let mut response = if fresh {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (StatusCode::OK, body.data.into_owned()).into_response()
    };
    let out = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_TYPE, mime.as_str()),
        (header::ETAG, etag.as_str()),
        (header::CACHE_CONTROL, cache),
        (header::VARY, "Accept-Encoding"),
    ] {
        if let Ok(value) = HeaderValue::from_str(value) {
            out.insert(name, value);
        }
    }
    if let Some(coding) = coding {
        out.insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
    }
    response
}
