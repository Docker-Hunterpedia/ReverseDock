use std::fmt::Write as _;

use super::*;

const ID: &str = "0190d4c4-8b6e-7a3c-9d2e-1f2a3b4c5d6e";

fn info(status: u16, accept: Option<&'static str>, format: ErrorFormat) -> ErrorInfo<'static> {
    ErrorInfo {
        status,
        request_id: ID,
        accept,
        format,
        kind: None,
        retry_after: None,
    }
}

#[test]
fn the_default_keeps_the_behaviour_before_v0_8() {
    let page = render(&info(502, Some("text/html,*/*"), ErrorFormat::Html));
    assert_eq!(page.content_type, "text/html; charset=utf-8");
    assert_eq!(page.language, None);
    let text = String::from_utf8(page.body.to_vec()).unwrap();
    assert!(text.contains("<h1>502</h1><p>Bad Gateway</p>"), "{text}");
    let mut odd = info(502, None, ErrorFormat::Html);
    odd.request_id = "abc<1>";
    let text = String::from_utf8(render(&odd).body.to_vec()).unwrap();
    assert!(text.contains("abc&lt;1&gt;"), "{text}");
    for accept in [None, Some("*/*"), Some("application/problem+json")] {
        assert_eq!(
            render(&info(429, accept, ErrorFormat::Html)).content_type,
            "text/html; charset=utf-8",
            "{accept:?}"
        );
    }
    let page = render(&info(429, Some("application/json"), ErrorFormat::Html));
    assert_eq!(page.content_type, "application/json");
    let json: serde_json::Value = serde_json::from_slice(&page.body).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "status": 429, "error": "Too Many Requests", "request_id": ID })
    );
}

#[test]
fn accept_parsing_ignores_refused_ranges() {
    let a = Accept::parse(Some("text/html;q=0, application/json"));
    assert!(!a.html && a.json && a.any_json);
    let a = Accept::parse(Some(
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ));
    assert!(a.html && !a.json && a.any_json);
    let a = Accept::parse(Some("text/plain"));
    assert!(!a.html && !a.json && !a.any_json);
    assert!(Accept::parse(None).any_json);
}

#[test]
fn problems_name_their_kind_retry_and_request() {
    let mut quota = info(429, Some("application/json"), ErrorFormat::Problem);
    quota.kind = Some(ProblemKind::QuotaExceeded);
    quota.retry_after = Some(120);
    let page = render(&quota);
    assert_eq!(page.content_type, "application/problem+json");
    assert_eq!(page.language.as_ref().unwrap(), "en");
    let json: serde_json::Value = serde_json::from_slice(&page.body).unwrap();
    assert_eq!(json["type"], ProblemKind::QuotaExceeded.type_uri());
    assert_eq!(json["retry_after"], 120);
    assert_eq!(json["instance"], format!("urn:uuid:{ID}"));
    // A kind whose status differs is ignored, and an unknown status is `about:blank`.
    quota.status = 503;
    let json: serde_json::Value = serde_json::from_slice(&render(&quota).body).unwrap();
    assert_eq!(json["type"], ProblemKind::ServiceUnavailable.type_uri());
    let json: serde_json::Value =
        serde_json::from_slice(&render(&info(418, None, ErrorFormat::Problem)).body).unwrap();
    assert_eq!(json["type"], "about:blank");
    assert_eq!(json["title"], "I'm a teapot");
    assert!(json.get("detail").is_none());
    // A request ID from a trusted proxy that is not a UUID gives no `instance`.
    let mut foreign = info(404, None, ErrorFormat::Problem);
    foreign.request_id = "edge-42";
    let json: serde_json::Value = serde_json::from_slice(&render(&foreign).body).unwrap();
    assert!(json.get("instance").is_none());
    assert_eq!(json["request_id"], "edge-42");
}

/// Every status rdock produces, for each `Accept` and format, against
/// `testdata/error-pages.golden`. Set `RDOCK_UPDATE_GOLDEN=1` to rewrite the file after a
/// deliberate change, and review the diff.
#[test]
fn golden_pages() {
    let statuses = [
        400, 401, 403, 404, 405, 408, 413, 414, 417, 429, 431, 500, 502, 503, 504,
    ];
    let accepts = [
        None,
        Some("*/*"),
        Some("application/json"),
        Some("application/problem+json"),
        Some("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        Some("text/plain"),
    ];
    let mut out = String::new();
    for format in [ErrorFormat::Html, ErrorFormat::Problem, ErrorFormat::Auto] {
        for status in statuses {
            for accept in accepts {
                let mut i = info(status, accept, format);
                if matches!(status, 429 | 503) {
                    i.retry_after = Some(5);
                }
                let page = render(&i);
                let body = if page.content_type == "text/html; charset=utf-8" {
                    // The HTML is checked in full above; here its status line is enough.
                    String::from_utf8_lossy(&page.body)
                        .split("<title>")
                        .nth(1)
                        .and_then(|t| t.split("</title>").next())
                        .unwrap_or_default()
                        .to_owned()
                } else {
                    String::from_utf8_lossy(&page.body).into_owned()
                };
                let _ = writeln!(
                    out,
                    "{format:?} {status} accept={} -> {} {}",
                    accept.unwrap_or("-"),
                    page.content_type.to_str().unwrap(),
                    body
                );
            }
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/error-pages.golden");
    if std::env::var_os("RDOCK_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &out).unwrap();
    }
    let golden = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        golden == out,
        "the rendered pages differ from {}; rerun with RDOCK_UPDATE_GOLDEN=1 and review",
        path.display()
    );
}
