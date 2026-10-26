//! The built-in error pages: small HTML, or JSON for clients that prefer it, always carrying the
//! request ID so a user can quote it.

use bytes::Bytes;
use http::{HeaderValue, StatusCode};

/// Content type and body of the page for `status`.
#[must_use]
pub fn render(status: u16, request_id: &str, accept: Option<&str>) -> (HeaderValue, Bytes) {
    let reason = StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("Error");
    let id = escape(request_id);
    if prefers_json(accept) {
        let body =
            serde_json::json!({ "status": status, "error": reason, "request_id": request_id });
        return (
            HeaderValue::from_static("application/json"),
            Bytes::from(body.to_string()),
        );
    }
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
    (
        HeaderValue::from_static("text/html; charset=utf-8"),
        Bytes::from(body),
    )
}

fn prefers_json(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| {
        let a = a.to_ascii_lowercase();
        a.contains("application/json") && !a.contains("text/html")
    })
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
mod tests {
    use super::*;

    #[test]
    fn renders_html_or_json() {
        let (content_type, body) = render(502, "abc<1>", Some("text/html,*/*"));
        assert_eq!(content_type, "text/html; charset=utf-8");
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("<h1>502</h1><p>Bad Gateway</p>"), "{text}");
        assert!(text.contains("abc&lt;1&gt;"), "{text}");
        let (content_type, body) = render(429, "id", Some("application/json"));
        assert_eq!(content_type, "application/json");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "Too Many Requests");
        assert_eq!(json["request_id"], "id");
    }
}
