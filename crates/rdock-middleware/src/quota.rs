//! `quota`: requests per consumer per calendar window (F-GW-02, ADR-0030). Counters live in the
//! process-wide [`QuotaRegistry`], so a reload keeps them, and are written to the data
//! directory, so a restart keeps them too (up to the last flush).

use std::sync::Arc;

use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::{RequestHeader, ResponseHeader};
use rdock_limits::quota::{QuotaCounter, QuotaRegistry, Taken, Window};
use rdock_model::gateway::{LimitHeaders, QuotaConfig, QuotaWindow};

use crate::phase::{Capabilities, Phases};
use crate::{Context, Flow, Middleware, ProblemKind, Reply};

/// The `quota` middleware.
#[derive(Debug)]
pub(crate) struct Quota {
    name: String,
    limit: u64,
    overrides: Vec<(String, u64)>,
    headers: LimitHeaders,
    counter: Arc<QuotaCounter>,
}

/// What the response phase adds when `headers: draft`.
struct Remaining {
    limit: u64,
    left: u64,
    reset: u64,
}

impl Quota {
    pub(crate) fn new(name: &str, config: &QuotaConfig, registry: &QuotaRegistry) -> Self {
        let window = match config.window {
            QuotaWindow::Hour => Window::Hour,
            QuotaWindow::Day => Window::Day,
            QuotaWindow::Month => Window::Month,
        };
        let counter = registry.counter(name, window);
        counter.set_flush_interval(config.flush_interval.as_std());
        Self {
            name: name.to_owned(),
            limit: config.limit,
            overrides: config
                .overrides
                .iter()
                .map(|(g, l)| (g.clone(), *l))
                .collect(),
            headers: config.headers,
            counter,
        }
    }

    /// The counter key and the limit for this request: the consumer and the limit of its
    /// first group that has an override, or the client IP and the default limit.
    fn key_and_limit(&self, cx: &Context) -> (String, u64) {
        let Some(consumer) = &cx.consumer else {
            return (format!("ip:{}", cx.client_ip), self.limit);
        };
        let limit = consumer
            .groups
            .iter()
            .find_map(|g| {
                self.overrides
                    .iter()
                    .find(|(group, _)| **group == **g)
                    .map(|(_, l)| *l)
            })
            .unwrap_or(self.limit);
        (consumer.name.to_string(), limit)
    }

    fn window_seconds(&self) -> i64 {
        let (start, end) = self.counter.bounds();
        end - start
    }
}

#[async_trait]
impl Middleware for Quota {
    fn capabilities(&self) -> Capabilities {
        let caps = Capabilities::new(Phases::REQUEST);
        match self.headers {
            LimitHeaders::Off => caps,
            LimitHeaders::Draft => caps.with(Phases::RESPONSE).with_state(),
        }
    }

    async fn request(&self, _req: &mut RequestHeader, cx: &mut Context) -> Flow {
        let (key, limit) = self.key_and_limit(cx);
        match self.counter.take(&key, limit) {
            Taken::Allowed { remaining, reset } => {
                if self.headers == LimitHeaders::Draft {
                    cx.set_state(Remaining {
                        limit,
                        left: remaining,
                        reset,
                    });
                }
                Flow::Next
            }
            Taken::Exceeded { reset } => {
                tracing::debug!(middleware = %self.name, key = %key, "quota used up");
                let mut reply = Reply::problem(ProblemKind::QuotaExceeded)
                    .header(http::header::RETRY_AFTER, HeaderValue::from(reset));
                if self.headers == LimitHeaders::Draft {
                    for (name, value) in
                        draft_headers(&self.name, limit, self.window_seconds(), 0, reset)
                    {
                        reply = reply.header(name, value);
                    }
                }
                Flow::Reply(reply)
            }
        }
    }

    async fn response(&self, resp: &mut ResponseHeader, cx: &mut Context) {
        if let Some(r) = cx.take_state::<Remaining>() {
            for (name, value) in
                draft_headers(&self.name, r.limit, self.window_seconds(), r.left, r.reset)
            {
                let _ = resp.insert_header(name, value);
            }
        }
    }
}

/// `RateLimit-Policy` and `RateLimit` in the syntax of
/// `draft-ietf-httpapi-ratelimit-headers-11` (2026-05-23): structured-field lists whose item
/// is the policy name as a String, with `q` (quota) and `w` (window, seconds) on the policy
/// and `r` (remaining) and `t` (seconds until the quota is restored) on the state.
pub(crate) fn draft_headers(
    policy: &str,
    quota: u64,
    window: i64,
    remaining: u64,
    reset: u64,
) -> Vec<(http::HeaderName, HeaderValue)> {
    let name = sf_string(policy);
    let mut out = Vec::with_capacity(2);
    if let Ok(v) = HeaderValue::from_str(&format!("{name};q={quota};w={window}")) {
        out.push((http::HeaderName::from_static("ratelimit-policy"), v));
    }
    if let Ok(v) = HeaderValue::from_str(&format!("{name};r={remaining};t={reset}")) {
        out.push((http::HeaderName::from_static("ratelimit"), v));
    }
    out
}

/// A structured-field String (RFC 9651 §3.3.3): printable ASCII, `"` and `\` escaped; other
/// characters become `_`.
fn sf_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => out.push('_'),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_headers_follow_the_structured_field_syntax() {
        let headers = draft_headers("daily@file", 1000, 86_400, 250, 3600);
        assert_eq!(headers[0].0, "ratelimit-policy");
        assert_eq!(headers[0].1, "\"daily@file\";q=1000;w=86400");
        assert_eq!(headers[1].0, "ratelimit");
        assert_eq!(headers[1].1, "\"daily@file\";r=250;t=3600");
        assert_eq!(sf_string("a\"b\\c\u{e9}"), "\"a\\\"b\\\\c_\"");
        // Parsed as an RFC 9651 list: one String item with integer parameters.
        let value = headers[1].1.to_str().unwrap();
        let (item, params) = value.split_once(';').unwrap();
        assert!(item.starts_with('"') && item.ends_with('"'));
        for param in params.split(';') {
            let (key, number) = param.split_once('=').unwrap();
            assert!(key.bytes().all(|b| b.is_ascii_lowercase()));
            assert!(number.parse::<u64>().is_ok());
        }
    }
}
