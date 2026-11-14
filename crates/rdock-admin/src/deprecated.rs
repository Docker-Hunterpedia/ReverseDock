//! Deprecated admin API operations (ADR-0033), from the deprecation registry in `rdock-model`:
//! `deprecated: true` in the OpenAPI document, and on every answer of such an operation the
//! `Deprecation` header (RFC 9745: a Structured Field Date, `@<seconds since the epoch>`) and,
//! when a date is promised, the `Sunset` header (RFC 8594: an HTTP-date). Both RFCs were read
//! at rfc-editor.org on 2026-11-14. The headers are hints: the operation behaves as before.

use std::time::{Duration, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use rdock_model::deprecation::{self, Kind};
use serde_json::{Value, json};

/// Adds `Deprecation` and `Sunset` to the answers of deprecated operations.
pub(crate) async fn headers(request: Request, next: Next) -> Response {
    let entry = deprecation::api_operation(request.method().as_str(), request.uri().path());
    let mut response = next.run(request).await;
    if let Some(entry) = entry {
        let headers = response.headers_mut();
        if let Some(value) = entry
            .deprecated_on
            .and_then(seconds)
            .and_then(|s| HeaderValue::from_str(&format!("@{s}")).ok())
        {
            headers.insert("deprecation", value);
        }
        if let Some(value) = entry
            .sunset
            .and_then(seconds)
            .map(|s| httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(s)))
            .and_then(|date| HeaderValue::from_str(&date).ok())
        {
            headers.insert("sunset", value);
        }
    }
    response
}

/// Seconds since the epoch of midnight UTC on `YYYY-MM-DD`.
fn seconds(date: &str) -> Option<u64> {
    let mut parts = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (year, month, day) = (parts.next()??, parts.next()??, parts.next()??);
    let days = rdock_model::gateway::days_from_civil(year, month, day);
    u64::try_from(days).ok()?.checked_mul(86_400)
}

/// Marks the deprecated operations of the OpenAPI document.
pub(crate) fn mark(document: &mut Value) {
    mark_with(document, &deprecation::entries());
}

fn mark_with(document: &mut Value, entries: &[&deprecation::Deprecation]) {
    for entry in entries {
        if entry.kind != Kind::ApiOperation {
            continue;
        }
        let Some((method, path)) = entry.element.split_once(' ') else {
            continue;
        };
        let operation = &mut document["paths"][path][method.to_ascii_lowercase()];
        if !operation.is_object() {
            continue;
        }
        operation["deprecated"] = true.into();
        let note = format!(
            " Deprecated since {}, removed in {}: use {}.",
            entry.since, entry.removal, entry.replacement
        );
        if let Some(text) = operation["description"].as_str() {
            operation["description"] = format!("{text}{note}").into();
        }
        let mut headers = json!({
            "Deprecation": {
                "description": "When the operation was deprecated (RFC 9745)",
                "schema": { "type": "string" },
            }
        });
        if entry.sunset.is_some() {
            headers["Sunset"] = json!({
                "description": "When the operation may stop answering (RFC 8594)",
                "schema": { "type": "string" },
            });
        }
        if let Some(responses) = operation["responses"].as_object_mut() {
            for (status, response) in responses.iter_mut() {
                if status.starts_with('2') && response.get("$ref").is_none() {
                    response["headers"] = headers.clone();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_become_epoch_seconds() {
        // RFC 9745's example: 2023-06-30T23:59:59Z is @1688169599, so midnight is 86399 less.
        assert_eq!(seconds("2023-06-30"), Some(1_688_169_599 - 86_399));
        assert_eq!(seconds("not a date"), None);
        assert_eq!(
            httpdate::fmt_http_date(
                UNIX_EPOCH + Duration::from_secs(seconds("2027-11-14").unwrap())
            ),
            "Sun, 14 Nov 2027 00:00:00 GMT"
        );
    }

    #[test]
    fn operations_are_marked() {
        let mut document = json!({ "paths": { "/api/v1/listeners": { "get": {
            "description": "Listeners.",
            "responses": { "200": { "description": "ok" }, "401": { "$ref": "#/x" } }
        } } } });
        let entries: Vec<&deprecation::Deprecation> = deprecation::TEST_ENTRIES.iter().collect();
        mark_with(&mut document, &entries);
        let get = &document["paths"]["/api/v1/listeners"]["get"];
        assert_eq!(get["deprecated"], true);
        assert!(
            get["description"]
                .as_str()
                .unwrap()
                .contains("Deprecated since 1.0")
        );
        assert!(get["responses"]["200"]["headers"]["Deprecation"].is_object());
        assert!(get["responses"]["200"]["headers"]["Sunset"].is_object());
        assert!(get["responses"]["401"].get("headers").is_none());
        // Without the test entries, nothing is deprecated.
        let mut plain = json!({ "paths": { "/api/v1/listeners": { "get": { "responses": {} } } } });
        mark(&mut plain);
        assert!(
            plain["paths"]["/api/v1/listeners"]["get"]
                .get("deprecated")
                .is_none()
        );
    }
}
