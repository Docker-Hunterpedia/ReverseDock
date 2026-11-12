//! The one renderer of every answer rdock produces itself (F-GW-04, ADR-0030): small HTML, the
//! pre-v0.8 JSON object, or RFC 9457 problem details, chosen by the route's `errors.format`
//! (or `defaults.errors.format`) and the client's `Accept`. Every page carries the request ID
//! so a user can quote it.
//!
//! Pages of an `errors` middleware and bodies a middleware sets itself (a `maintenance` file,
//! an agent's answer) take precedence; this renderer makes the page when nothing else does.

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use rdock_middleware::ProblemKind;
use rdock_model::config::ErrorFormat;

/// What the page is about.
#[derive(Debug, Clone, Copy)]
pub struct ErrorInfo<'a> {
    /// The status sent.
    pub status: u16,
    /// The request ID.
    pub request_id: &'a str,
    /// The client's `Accept`.
    pub accept: Option<&'a str>,
    /// The route's (or the default) format.
    pub format: ErrorFormat,
    /// The kind, when the status alone does not say it.
    pub kind: Option<ProblemKind>,
    /// Seconds in the answer's `Retry-After`, when it has one.
    pub retry_after: Option<u64>,
    /// Extension members a middleware added (`validate`'s `errors`), rendered in the JSON
    /// formats only. Members named like the standard ones are ignored.
    pub extensions: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

/// Members an extension cannot replace.
const RESERVED: [&str; 8] = [
    "type",
    "title",
    "status",
    "detail",
    "instance",
    "request_id",
    "retry_after",
    "error",
];

fn extend(body: &mut serde_json::Map<String, serde_json::Value>, info: &ErrorInfo<'_>) {
    if let Some(extensions) = info.extensions {
        for (name, value) in extensions {
            if !RESERVED.contains(&name.as_str()) {
                body.insert(name.clone(), value.clone());
            }
        }
    }
}

/// A rendered page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// `Content-Type`.
    pub content_type: HeaderValue,
    /// The body.
    pub body: Bytes,
    /// `Content-Language`, for problem details (whose `title` and `detail` are English).
    pub language: Option<HeaderValue>,
}

/// The page for `info`.
#[must_use]
pub fn render(info: &ErrorInfo<'_>) -> Page {
    // Problem details describe errors; anything else keeps the page it always had.
    let format = if info.status < 400 {
        ErrorFormat::Html
    } else {
        info.format
    };
    let problem = match format {
        // Exactly the behaviour before v0.8.
        ErrorFormat::Html => {
            if legacy_prefers_json(info.accept) {
                return legacy_json(info);
            }
            false
        }
        ErrorFormat::Problem => {
            let accept = Accept::parse(info.accept);
            (!accept.html || accept.json) && accept.any_json
        }
        ErrorFormat::Auto => {
            let accept = Accept::parse(info.accept);
            accept.json && !accept.html
        }
    };
    if problem {
        problem_json(info)
    } else {
        html(info)
    }
}

fn reason(status: u16) -> &'static str {
    StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("Error")
}

fn html(info: &ErrorInfo<'_>) -> Page {
    let status = info.status;
    let reason = reason(status);
    let id = escape(info.request_id);
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{status} {reason}</title><style>\
body{{margin:0;font:16px/1.5 system-ui,sans-serif;background:#fafaf9;color:#1c1917}}\
main{{max-width:32rem;margin:15vh auto;padding:0 1rem}}\
h1{{margin:0;font-size:3rem;color:#c2410c}}p{{margin:.5rem 0}}\
.id{{font:13px ui-monospace,monospace;color:#57534e}}\
@media (prefers-color-scheme:dark){{body{{background:#1c1917;color:#f5f5f4}}.id{{color:#a8a29e}}}}\
</style></head><body><main><h1>{status}</h1><p>{reason}</p>\
<p class=\"id\">Request ID: {id}</p></main></body></html>\n"
    );
    Page {
        content_type: HeaderValue::from_static("text/html; charset=utf-8"),
        body: Bytes::from(body),
        language: None,
    }
}

fn legacy_json(info: &ErrorInfo<'_>) -> Page {
    let mut body = serde_json::Map::new();
    body.insert("status".into(), info.status.into());
    body.insert("error".into(), reason(info.status).into());
    body.insert("request_id".into(), info.request_id.into());
    extend(&mut body, info);
    let body = serde_json::Value::Object(body);
    Page {
        content_type: HeaderValue::from_static("application/json"),
        body: Bytes::from(body.to_string()),
        language: None,
    }
}

fn problem_json(info: &ErrorInfo<'_>) -> Page {
    let kind = info
        .kind
        .filter(|k| k.status() == info.status)
        .or_else(|| ProblemKind::for_status(info.status));
    let mut body = serde_json::Map::new();
    if let Some(kind) = kind {
        body.insert("type".into(), kind.type_uri().into());
        body.insert("title".into(), kind.title().into());
        body.insert("status".into(), info.status.into());
        body.insert("detail".into(), kind.detail().into());
    } else {
        body.insert("type".into(), "about:blank".into());
        body.insert("title".into(), reason(info.status).into());
        body.insert("status".into(), info.status.into());
    }
    // The request ID is a UUID unless a trusted proxy sent its own.
    if uuid::Uuid::try_parse(info.request_id).is_ok() {
        body.insert(
            "instance".into(),
            format!("urn:uuid:{}", info.request_id).into(),
        );
    }
    body.insert("request_id".into(), info.request_id.into());
    if let Some(seconds) = info.retry_after {
        body.insert("retry_after".into(), seconds.into());
    }
    extend(&mut body, info);
    Page {
        content_type: HeaderValue::from_static("application/problem+json"),
        body: Bytes::from(serde_json::Value::Object(body).to_string()),
        language: Some(HeaderValue::from_static("en")),
    }
}

/// The pre-v0.8 rule: JSON when `Accept` names `application/json` and not `text/html`.
fn legacy_prefers_json(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| {
        let a = a.to_ascii_lowercase();
        a.contains("application/json") && !a.contains("text/html")
    })
}

/// What an `Accept` header asks for (media ranges with `q=0` are ignored).
#[derive(Debug, Default)]
struct Accept {
    /// `text/html` is named.
    html: bool,
    /// A JSON type is named: `application/json`, `application/problem+json`, any `+json`.
    json: bool,
    /// JSON is acceptable: a JSON type, `application/*`, `*/*`, or no `Accept` at all.
    any_json: bool,
}

impl Accept {
    fn parse(header: Option<&str>) -> Self {
        let Some(header) = header.filter(|h| !h.trim().is_empty()) else {
            return Self {
                any_json: true,
                ..Self::default()
            };
        };
        let mut out = Self::default();
        for range in header.split(',') {
            let mut parts = range.split(';');
            let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let refused = parts.any(|p| {
                let p = p.trim();
                p.strip_prefix("q=")
                    .or_else(|| p.strip_prefix("Q="))
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            });
            if refused || media.is_empty() {
                continue;
            }
            let json = media == "application/json" || media.ends_with("+json");
            out.html |= media == "text/html";
            out.json |= json;
            out.any_json |= json || media == "*/*" || media == "application/*";
        }
        out
    }
}

fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '&' => "&amp;".to_owned(),
            '"' => "&quot;".to_owned(),
            c => c.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests;
