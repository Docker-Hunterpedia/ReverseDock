//! A route's middleware chain and the order of its phases (ADR-0030, "Pipeline and body phase").
//!
//! On the way in, middlewares run in the route's list order (`request`, `upstream_request`,
//! `request_body`); on the way out in reverse order (`response`, `response_body`, `log`). What
//! the chain needs beyond `request` and `response` is computed once, when it is built
//! ([`Flags`]), so the proxy branches once per phase and a chain that uses none of the newer
//! phases does no extra work.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use http::HeaderValue;
use pingora::http::{RequestHeader, ResponseHeader};

use crate::held::HeldBody;
use crate::phase::{BodyHold, BodyVerdict, Capabilities, LogSummary, Phases};
use crate::{Context, Flow, Middleware, Reply};

/// What a chain needs beyond `request` and `response`, computed when it is built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one switch per phase, read once per request"
)]
pub struct Flags {
    /// Some middleware uses `upstream_request`.
    pub upstream_request: bool,
    /// Some middleware holds the request body: the strictest of their holds.
    pub request_body: Option<BodyHold>,
    /// Some middleware uses `response_body`.
    pub response_body: bool,
    /// Some middleware uses `log`.
    pub log: bool,
    /// Some middleware wants a per-request state slot.
    pub state: bool,
}

impl Flags {
    /// Whether the chain uses any phase beyond `request` and `response`, or state.
    #[must_use]
    pub fn any(&self) -> bool {
        self.upstream_request
            || self.request_body.is_some()
            || self.response_body
            || self.log
            || self.state
    }
}

struct Entry {
    name: Arc<str>,
    middleware: Arc<dyn Middleware>,
    caps: Capabilities,
}

/// The middlewares of a route, in list order, with their declared capabilities.
#[derive(Clone)]
pub struct Chain {
    entries: Arc<[Entry]>,
    flags: Flags,
}

impl fmt::Debug for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chain")
            .field("middlewares", &self.names().collect::<Vec<_>>())
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new(std::iter::empty())
    }
}

/// A middleware's answer that ended a phase, with its position in the chain: the response phase
/// then runs for the middlewares before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered {
    /// Position of the middleware that answered.
    pub index: usize,
    /// Its reply.
    pub reply: Reply,
}

/// The held body after every `request_body` middleware has answered.
#[derive(Debug)]
pub struct Released {
    /// The body to forward.
    pub body: HeldBody,
    /// A middleware replaced the client's body.
    pub replaced: bool,
}

impl Chain {
    /// A chain of `(name, middleware)` in list order. Capabilities are read here, once.
    pub fn new(middlewares: impl IntoIterator<Item = (Arc<str>, Arc<dyn Middleware>)>) -> Self {
        let entries: Arc<[Entry]> = middlewares
            .into_iter()
            .map(|(name, middleware)| Entry {
                caps: middleware.capabilities(),
                name,
                middleware,
            })
            .collect();
        let mut flags = Flags::default();
        for entry in entries.iter() {
            let phases = entry.caps.phases();
            flags.upstream_request |= phases.contains(Phases::UPSTREAM_REQUEST);
            flags.response_body |= phases.contains(Phases::RESPONSE_BODY);
            flags.log |= phases.contains(Phases::LOG);
            flags.state |= entry.caps.state();
            if let Some(hold) = entry.caps.body() {
                flags.request_body = Some(flags.request_body.map_or(hold, |h| h.merge(hold)));
            }
        }
        Self { entries, flags }
    }

    /// What the chain needs beyond `request` and `response`.
    #[must_use]
    pub fn flags(&self) -> &Flags {
        &self.flags
    }

    /// Number of middlewares.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Middleware names (references as the route lists them), in list order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| &*e.name)
    }

    /// Each middleware's name and declared capabilities, in list order.
    pub fn capabilities(&self) -> impl Iterator<Item = (&str, Capabilities)> {
        self.entries.iter().map(|e| (&*e.name, e.caps))
    }

    /// The middlewares, in list order.
    pub fn middlewares(&self) -> impl Iterator<Item = &Arc<dyn Middleware>> {
        self.entries.iter().map(|e| &e.middleware)
    }

    /// Whether the proxy translates gRPC-Web for this chain.
    #[must_use]
    pub fn translates_grpc_web(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.middleware.translates_grpc_web())
    }

    /// The body hold for this request: the chain's, unless middlewares waived theirs in the
    /// `request` phase ([`Context::waive_body_hold`]); then the strictest of the remaining
    /// holds, or none.
    #[must_use]
    pub fn hold_for(&self, cx: &Context) -> Option<BodyHold> {
        let hold = self.flags.request_body?;
        if !cx.any_waived() {
            return Some(hold);
        }
        self.entries
            .iter()
            .enumerate()
            .filter(|(index, _)| !cx.waived(*index))
            .filter_map(|(_, entry)| entry.caps.body())
            .reduce(BodyHold::merge)
    }

    /// Prepares a new request's context: state slots, only when some middleware asked for one.
    pub fn start(&self, cx: &mut Context) {
        if self.flags.state {
            cx.prepare_state(self.entries.len());
        }
    }

    /// The `request` phase, in list order. Stops at the first middleware that answers.
    ///
    /// # Errors
    ///
    /// The answer and the position of the middleware that gave it.
    pub async fn request(&self, req: &mut RequestHeader, cx: &mut Context) -> Result<(), Answered> {
        for (index, entry) in self.entries.iter().enumerate() {
            cx.enter(index);
            if let Flow::Reply(reply) = entry.middleware.request(req, cx).await {
                return Err(Answered { index, reply });
            }
        }
        Ok(())
    }

    /// The `upstream_request` phase, in list order, for the middlewares that declared it. Runs
    /// once per attempt; `req` is the head about to be sent to the chosen backend.
    ///
    /// # Errors
    ///
    /// The answer and the position of the middleware that gave it.
    pub async fn upstream_request(
        &self,
        req: &mut RequestHeader,
        cx: &mut Context,
    ) -> Result<(), Answered> {
        if !self.flags.upstream_request {
            return Ok(());
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.caps.phases().contains(Phases::UPSTREAM_REQUEST) {
                cx.enter(index);
                if let Flow::Reply(reply) = entry.middleware.upstream_request(req, cx).await {
                    return Err(Answered { index, reply });
                }
            }
        }
        Ok(())
    }

    /// The `request_body` phase, in list order, for the middlewares that hold the body. Each
    /// sees the body as the previous one left it.
    ///
    /// # Errors
    ///
    /// The answer and the position of the middleware that gave it.
    pub async fn request_body(
        &self,
        mut body: HeldBody,
        cx: &mut Context,
    ) -> Result<Released, Answered> {
        let mut replaced = false;
        for (index, entry) in self.entries.iter().enumerate() {
            if !entry.caps.phases().contains(Phases::REQUEST_BODY) || cx.waived(index) {
                continue;
            }
            cx.enter(index);
            match entry.middleware.request_body(&body, cx).await {
                BodyVerdict::Continue => {}
                BodyVerdict::Replace(bytes) => {
                    if !entry.caps.body().is_some_and(|h| h.replaces) {
                        tracing::error!(
                            middleware = %entry.name,
                            "a middleware replaced the request body without declaring it"
                        );
                        return Err(Answered {
                            index,
                            reply: Reply::status(500),
                        });
                    }
                    body = HeldBody::from_bytes(bytes);
                    replaced = true;
                }
                BodyVerdict::Reply(reply) => return Err(Answered { index, reply }),
            }
        }
        Ok(Released { body, replaced })
    }

    /// The `response` phase in reverse order over the first `upto` middlewares (all of them for
    /// a backend answer; those before the answering one for a middleware's reply).
    pub async fn response(&self, upto: usize, resp: &mut ResponseHeader, cx: &mut Context) {
        let upto = upto.min(self.entries.len());
        for (index, entry) in self.entries[..upto].iter().enumerate().rev() {
            cx.enter(index);
            entry.middleware.response(resp, cx).await;
        }
    }

    /// The `response_body` phase in reverse order over the first `upto` middlewares that
    /// declared it. Synchronous, as Pingora's body filter is.
    pub fn response_body(
        &self,
        upto: usize,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        cx: &mut Context,
    ) {
        if !self.flags.response_body {
            return;
        }
        let upto = upto.min(self.entries.len());
        for (index, entry) in self.entries[..upto].iter().enumerate().rev() {
            if entry.caps.phases().contains(Phases::RESPONSE_BODY) {
                cx.enter(index);
                entry.middleware.response_body(body, end_of_stream, cx);
            }
        }
    }

    /// The `log` phase in reverse order, for the middlewares that declared it. Read-only.
    pub fn log(&self, summary: &LogSummary, cx: &mut Context) {
        if !self.flags.log {
            return;
        }
        for (index, entry) in self.entries.iter().enumerate().rev() {
            if entry.caps.phases().contains(Phases::LOG) {
                cx.enter(index);
                entry.middleware.log(summary, cx);
            }
        }
    }

    /// The first error page a middleware has for `status`, in list order.
    pub async fn error_page(&self, status: u16, cx: &Context) -> Option<(HeaderValue, Bytes)> {
        for entry in self.entries.iter() {
            if let Some(page) = entry.middleware.error_page(status, cx).await {
                return Some(page);
            }
        }
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::test_support::{block_on, cx, request};

    /// Records every hook call as `name:phase` and keeps a counter in its state slot.
    #[derive(Debug)]
    struct Probe {
        name: &'static str,
        caps: Capabilities,
        calls: Arc<Mutex<Vec<String>>>,
        verdict: Option<BodyVerdict>,
    }

    impl Probe {
        fn new(name: &'static str, caps: Capabilities, calls: &Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                name,
                caps,
                calls: calls.clone(),
                verdict: None,
            }
        }

        fn note(&self, phase: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:{phase}", self.name));
        }
    }

    #[async_trait]
    impl Middleware for Probe {
        fn capabilities(&self) -> Capabilities {
            self.caps
        }

        async fn request(&self, _req: &mut RequestHeader, cx: &mut Context) -> Flow {
            self.note("request");
            if self.caps.state() {
                cx.set_state(self.name.to_owned());
            }
            Flow::Next
        }

        async fn upstream_request(&self, req: &mut RequestHeader, cx: &mut Context) -> Flow {
            self.note("upstream_request");
            if let Some(mine) = cx.state::<String>() {
                req.append_header("x-state", mine.as_str()).unwrap();
            }
            Flow::Next
        }

        async fn request_body(&self, body: &HeldBody, _cx: &mut Context) -> BodyVerdict {
            let bytes = body.bytes().await.unwrap();
            self.note(&format!(
                "request_body({})",
                String::from_utf8_lossy(&bytes)
            ));
            self.verdict.clone().unwrap_or(BodyVerdict::Continue)
        }

        async fn response(&self, _resp: &mut ResponseHeader, _cx: &mut Context) {
            self.note("response");
        }

        fn response_body(&self, body: &mut Option<Bytes>, _end: bool, _cx: &mut Context) {
            self.note("response_body");
            if let Some(chunk) = body.as_mut() {
                let mut next = chunk.to_vec();
                next.extend_from_slice(self.name.as_bytes());
                *chunk = Bytes::from(next);
            }
        }

        fn log(&self, summary: &LogSummary, cx: &Context) {
            self.note(&format!(
                "log({} {})",
                summary.status,
                cx.state::<String>().map_or("-", String::as_str)
            ));
        }
    }

    fn chain(probes: Vec<Probe>) -> Chain {
        Chain::new(probes.into_iter().map(|p| {
            let name: Arc<str> = Arc::from(p.name);
            (name, Arc::new(p) as Arc<dyn Middleware>)
        }))
    }

    fn calls(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        std::mem::take(&mut *log.lock().unwrap())
    }

    fn summary() -> LogSummary {
        LogSummary {
            status: 200,
            bytes_in: 0,
            bytes_out: 0,
            duration: Duration::ZERO,
            upstream_duration: None,
            error: None,
        }
    }

    #[test]
    fn a_chain_of_old_middlewares_has_no_flags() {
        let log = Arc::default();
        let chain = chain(vec![
            Probe::new("a", Capabilities::DEFAULT, &log),
            Probe::new("b", Capabilities::DEFAULT, &log),
        ]);
        assert_eq!(*chain.flags(), Flags::default());
        assert!(!chain.flags().any());
        // Built-in middlewares keep the pre-v0.8 capabilities.
        let headers =
            crate::headers::Headers::new(&rdock_model::middleware::HeadersConfig::default())
                .unwrap();
        assert_eq!(headers.capabilities(), Capabilities::DEFAULT);
        // No state is allocated for a chain that did not ask for it.
        let mut cx = cx();
        chain.start(&mut cx);
        assert!(!cx.has_state_slots());
        // New phases are not called for middlewares that did not declare them.
        let mut req = request("GET", "/", &[]);
        block_on(chain.upstream_request(&mut req, &mut cx)).unwrap();
        let mut body = Some(Bytes::from_static(b"x"));
        chain.response_body(2, &mut body, true, &mut cx);
        chain.log(&summary(), &mut cx);
        assert_eq!(body.as_deref(), Some(&b"x"[..]));
        assert_eq!(calls(&log), Vec::<String>::new());
    }

    #[test]
    fn flags_merge_the_declarations() {
        let log = Arc::default();
        let hold = BodyHold::new(1000).timeout(Duration::from_secs(9));
        let chain = chain(vec![
            Probe::new(
                "a",
                Capabilities::DEFAULT.with_body(BodyHold::new(500).replacing()),
                &log,
            ),
            Probe::new("b", Capabilities::DEFAULT.with_body(hold), &log),
            Probe::new(
                "c",
                Capabilities::new(Phases::LOG | Phases::UPSTREAM_REQUEST).with_state(),
                &log,
            ),
        ]);
        let flags = chain.flags();
        assert!(flags.upstream_request && flags.log && flags.state && !flags.response_body);
        assert_eq!(
            flags.request_body,
            Some(BodyHold {
                max: 500,
                timeout: Duration::from_secs(9),
                replaces: true
            })
        );
        let names: Vec<Vec<&str>> = chain
            .capabilities()
            .map(|(_, c)| c.phases().names().collect())
            .collect();
        assert_eq!(
            names,
            vec![
                vec!["request", "request_body", "response"],
                vec!["request", "request_body", "response"],
                vec!["upstream_request", "log"],
            ]
        );
    }

    #[test]
    fn phases_run_in_list_order_in_and_reverse_order_out() {
        let log = Arc::default();
        let all = Capabilities::DEFAULT
            .with(Phases::UPSTREAM_REQUEST | Phases::RESPONSE_BODY | Phases::LOG)
            .with_body(BodyHold::new(100));
        let chain = chain(vec![
            Probe::new("a", all, &log),
            Probe::new("b", Capabilities::DEFAULT, &log),
            Probe::new("c", all, &log),
        ]);
        let mut cx = cx();
        chain.start(&mut cx);
        let mut req = request("POST", "/", &[]);
        block_on(chain.request(&mut req, &mut cx)).unwrap();
        block_on(chain.upstream_request(&mut req, &mut cx)).unwrap();
        let released =
            block_on(chain.request_body(HeldBody::from_bytes(Bytes::from("hi")), &mut cx)).unwrap();
        assert!(!released.replaced);
        let mut resp = ResponseHeader::build(200, None).unwrap();
        block_on(chain.response(chain.len(), &mut resp, &mut cx));
        let mut body = Some(Bytes::from_static(b">"));
        chain.response_body(chain.len(), &mut body, true, &mut cx);
        chain.log(&summary(), &mut cx);
        assert_eq!(
            calls(&log),
            [
                "a:request",
                "b:request",
                "c:request",
                "a:upstream_request",
                "c:upstream_request",
                "a:request_body(hi)",
                "c:request_body(hi)",
                "c:response",
                "b:response",
                "a:response",
                "c:response_body",
                "a:response_body",
                "c:log(200 -)",
                "a:log(200 -)",
            ]
        );
        assert_eq!(body.as_deref(), Some(&b">ca"[..]), "c transforms first");
    }

    #[test]
    fn a_reply_stops_the_phase_and_names_its_position() {
        let log = Arc::default();
        let caps = Capabilities::DEFAULT.with_body(BodyHold::new(100).replacing());
        let mut replacing = Probe::new("a", caps, &log);
        replacing.verdict = Some(BodyVerdict::Replace(Bytes::from("new")));
        let mut refusing = Probe::new("b", caps, &log);
        refusing.verdict = Some(BodyVerdict::Reply(Reply::status(422)));
        let chain = chain(vec![replacing, refusing, Probe::new("c", caps, &log)]);
        let mut cx = cx();
        let answer =
            block_on(chain.request_body(HeldBody::from_bytes(Bytes::from("old")), &mut cx))
                .unwrap_err();
        assert_eq!(answer.index, 1);
        assert_eq!(answer.reply.status, 422);
        assert_eq!(
            calls(&log),
            ["a:request_body(old)", "b:request_body(new)"],
            "b sees a's replacement; c never runs"
        );
        // The response phase of a reply covers the middlewares before the answering one.
        let mut resp = ResponseHeader::build(422, None).unwrap();
        block_on(chain.response(answer.index, &mut resp, &mut cx));
        assert_eq!(calls(&log), ["a:response"]);
    }

    #[test]
    fn replacing_without_declaring_it_is_refused() {
        let log = Arc::default();
        let mut sneaky = Probe::new("a", Capabilities::DEFAULT.with_body(BodyHold::new(9)), &log);
        sneaky.verdict = Some(BodyVerdict::Replace(Bytes::from("x")));
        let chain = chain(vec![sneaky]);
        let answer = block_on(chain.request_body(HeldBody::from_bytes(Bytes::new()), &mut cx()))
            .unwrap_err();
        assert_eq!(answer.reply.status, 500);
    }

    #[test]
    fn state_slots_belong_to_each_position() {
        let log = Arc::default();
        let stateful = Capabilities::DEFAULT
            .with(Phases::UPSTREAM_REQUEST | Phases::LOG)
            .with_state();
        let chain = chain(vec![
            Probe::new("first", stateful, &log),
            Probe::new("plain", Capabilities::DEFAULT, &log),
            Probe::new("second", stateful, &log),
        ]);
        let mut cx = cx();
        chain.start(&mut cx);
        assert!(cx.has_state_slots());
        let mut req = request("GET", "/", &[]);
        block_on(chain.request(&mut req, &mut cx)).unwrap();
        // Each middleware reads back its own value in a later phase.
        let mut upstream = request("GET", "/", &[]);
        block_on(chain.upstream_request(&mut upstream, &mut cx)).unwrap();
        let seen: Vec<&str> = upstream
            .headers
            .get_all("x-state")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            seen,
            ["first", "second"],
            "each reads its own slot, in list order"
        );
        chain.log(&summary(), &mut cx);
        let log = calls(&log);
        assert!(
            log.contains(&"second:log(200 second)".to_owned()),
            "{log:?}"
        );
        assert!(log.contains(&"first:log(200 first)".to_owned()), "{log:?}");
    }

    #[test]
    fn the_state_api_is_typed() {
        let mut cx = cx();
        assert_eq!(cx.state::<u32>(), None);
        cx.set_state(7u32);
        assert_eq!(cx.state::<u32>(), Some(&7));
        assert_eq!(cx.state::<String>(), None, "another type is not visible");
        *cx.state_mut::<u32>().unwrap() += 1;
        assert_eq!(cx.take_state::<u32>(), Some(8));
        assert_eq!(cx.state::<u32>(), None);
        // Another position has its own slot.
        cx.set_state(1u8);
        cx.enter(3);
        assert_eq!(cx.state::<u8>(), None);
        cx.set_state(3u8);
        cx.enter(0);
        assert_eq!(cx.state::<u8>(), Some(&1));
    }
}
