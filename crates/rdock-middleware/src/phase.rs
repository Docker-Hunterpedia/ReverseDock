//! The phases of the middleware pipeline (ADR-0030, "Pipeline and body phase") and what a
//! middleware declares about them.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::Reply;

/// A set of pipeline phases.
///
/// `request` and `response` run for every middleware of a chain, as before v0.8; declaring them
/// documents the middleware (`rdock explain` prints the set). The other phases run only for the
/// middlewares that declare them, and a chain in which none does pays nothing for them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Phases(u8);

impl Phases {
    /// No phase.
    pub const NONE: Self = Self(0);
    /// Before routing to the backend: may change the request or answer it.
    pub const REQUEST: Self = Self(1);
    /// After the backend is chosen, before the request head is sent; once per attempt.
    pub const UPSTREAM_REQUEST: Self = Self(1 << 1);
    /// The complete request body, held by the proxy (see [`BodyHold`]).
    pub const REQUEST_BODY: Self = Self(1 << 2);
    /// The response head, before it is sent to the client.
    pub const RESPONSE: Self = Self(1 << 3);
    /// Each chunk of the response body, synchronously.
    pub const RESPONSE_BODY: Self = Self(1 << 4);
    /// After the response is finished; read-only.
    pub const LOG: Self = Self(1 << 5);

    const NAMES: [(Self, &'static str); 6] = [
        (Self::REQUEST, "request"),
        (Self::UPSTREAM_REQUEST, "upstream_request"),
        (Self::REQUEST_BODY, "request_body"),
        (Self::RESPONSE, "response"),
        (Self::RESPONSE_BODY, "response_body"),
        (Self::LOG, "log"),
    ];

    /// Whether every phase of `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The names of the phases in pipeline order (`request`, `upstream_request`, `request_body`,
    /// `response`, `response_body`, `log`).
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |(phase, _)| self.contains(*phase))
            .map(|(_, name)| name)
    }
}

impl std::ops::BitOr for Phases {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl fmt::Debug for Phases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.names()).finish()
    }
}

/// How a middleware wants the request body: held by the proxy until it is complete, up to `max`
/// bytes (never more than the route's `max_body`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyHold {
    /// Largest body held; a longer one is answered `413`.
    pub max: u64,
    /// Longest time from the first body byte to the last; a slower upload is answered `408`.
    pub timeout: Duration,
    /// The middleware may return [`BodyVerdict::Replace`]. The proxy then sends the body to the
    /// backend without the client's `Content-Length` (chunked on HTTP/1.1, framed by the stream
    /// on HTTP/2), because the request head leaves before the body is known.
    pub replaces: bool,
}

impl BodyHold {
    /// Default for [`Self::timeout`].
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Holds up to `max` bytes, without replacing them.
    #[must_use]
    pub const fn new(max: u64) -> Self {
        Self {
            max,
            timeout: Self::DEFAULT_TIMEOUT,
            replaces: false,
        }
    }

    /// Sets [`Self::timeout`].
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Declares that the middleware may replace the body.
    #[must_use]
    pub const fn replacing(mut self) -> Self {
        self.replaces = true;
        self
    }

    /// The stricter of two holds on one chain: the smaller limit and time, and replacing when
    /// either replaces.
    #[must_use]
    pub fn merge(self, other: Self) -> Self {
        Self {
            max: self.max.min(other.max),
            timeout: self.timeout.min(other.timeout),
            replaces: self.replaces || other.replaces,
        }
    }
}

/// What a middleware declares once, when it is built. The proxy reads it at compile time to
/// decide which phases a chain runs; it never calls a hook of a phase nobody declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    phases: Phases,
    state: bool,
    body: Option<BodyHold>,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Capabilities {
    /// What every pre-v0.8 middleware does: `request` and `response`, no state, no body.
    pub const DEFAULT: Self = Self {
        phases: Phases(Phases::REQUEST.0 | Phases::RESPONSE.0),
        state: false,
        body: None,
    };

    /// Exactly these phases.
    #[must_use]
    pub const fn new(phases: Phases) -> Self {
        Self {
            phases,
            state: false,
            body: None,
        }
    }

    /// Adds phases.
    #[must_use]
    pub const fn with(mut self, phases: Phases) -> Self {
        self.phases = self.phases.union(phases);
        self
    }

    /// Asks for a per-request state slot ([`crate::Context::state`]).
    #[must_use]
    pub const fn with_state(mut self) -> Self {
        self.state = true;
        self
    }

    /// Asks the proxy to hold the request body; adds the `request_body` phase.
    #[must_use]
    pub const fn with_body(mut self, hold: BodyHold) -> Self {
        self.phases = self.phases.union(Phases::REQUEST_BODY);
        self.body = Some(hold);
        self
    }

    /// The declared phases.
    #[must_use]
    pub const fn phases(&self) -> Phases {
        self.phases
    }

    /// Whether a state slot is wanted.
    #[must_use]
    pub const fn state(&self) -> bool {
        self.state
    }

    /// The body hold, if any.
    #[must_use]
    pub const fn body(&self) -> Option<BodyHold> {
        self.body
    }
}

/// The consumer (API client, user) a request is attributed to. Set by authenticating
/// middlewares (`api_key`, `jwt` claims mapping, `oidc` from v0.8 on); visible to later
/// middlewares, the access log and, later, metrics and the cache key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumer {
    /// The consumer's name (`consumers.<name>`, or the name a token asserts), as the access
    /// log, metrics and metering show it.
    pub name: Arc<str>,
    /// Its groups.
    pub groups: Arc<[Arc<str>]>,
    /// How many of `groups`, from the first, come from the configuration (a consumer of
    /// `consumers`, a group a middleware assigns, a token group listed in the middleware's
    /// `trusted_groups`). Only these count for `key: group` and for group `overrides`: a
    /// group taken from a token's claim could otherwise share a configured group's budget, or
    /// create a counter per value an identity provider lets its users choose.
    pub trusted_groups: usize,
    /// Who asserted the name: `None` for a consumer defined in `consumers` (an API key, or a
    /// token middleware with `map_to_consumers`), otherwise the token's issuer. Two consumers
    /// with the same name but different issuers are different identities for the cache,
    /// quotas and rate limits (see [`Consumer::key`]).
    pub issuer: Option<Arc<str>>,
}

impl Consumer {
    /// A consumer of `consumers` without groups.
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self {
            name: Arc::from(name),
            groups: Arc::from([]),
            trusted_groups: 0,
            issuer: None,
        }
    }

    /// A consumer of `consumers` with `groups`, all from the configuration.
    #[must_use]
    pub fn configured(name: &str, groups: &[&str]) -> Self {
        Self {
            name: Arc::from(name),
            groups: groups.iter().map(|g| Arc::from(*g)).collect(),
            trusted_groups: groups.len(),
            issuer: None,
        }
    }

    /// The groups that count for group keys and overrides (see `trusted_groups`).
    #[must_use]
    pub fn counted_groups(&self) -> &[Arc<str>] {
        &self.groups[..self.trusted_groups.min(self.groups.len())]
    }

    /// The primary group for `key: group`: the first counted group.
    #[must_use]
    pub fn primary_group(&self) -> Option<&Arc<str>> {
        self.counted_groups().first()
    }

    /// The identity the cache key, quotas and rate limits count: the name for a consumer of
    /// `consumers`; for a consumer asserted by a token issuer, `~<length of issuer>:<issuer>`
    /// followed by the name. `~` is not allowed in a consumer name, and the length makes the
    /// split unambiguous, so a token can never take a configured consumer's identity, nor one
    /// issuer's user another issuer's.
    #[must_use]
    pub fn key(&self) -> std::borrow::Cow<'_, str> {
        rdock_limits::quota::consumer_key(self.issuer.as_deref(), &self.name)
    }
}

/// The backend chosen for the current attempt, set before the `upstream_request` phase and kept
/// for `log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// Name of the service.
    pub service: Arc<str>,
    /// The backend as configured (`10.0.0.5:8080`, `unix:/run/app.sock`).
    pub backend: String,
    /// Its resolved socket address; `None` for Unix sockets.
    pub addr: Option<SocketAddr>,
    /// Attempt number, from 0 (retries increase it).
    pub attempt: u32,
}

/// What the `log` phase knows about a finished request.
#[derive(Debug, Clone, PartialEq)]
pub struct LogSummary {
    /// Status sent to the client; 0 when nothing could be sent.
    pub status: u16,
    /// Request body bytes read from the client.
    pub bytes_in: u64,
    /// Response body bytes sent to the client.
    pub bytes_out: u64,
    /// Time from the request head to the end of the response.
    pub duration: Duration,
    /// Time from the start of the last backend attempt to the end, if a backend was tried.
    pub upstream_duration: Option<Duration>,
    /// The error that ended the request, if any.
    pub error: Option<String>,
}

/// The answer of a `request_body` phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyVerdict {
    /// Forward the body as it is (or as an earlier middleware replaced it).
    Continue,
    /// Forward these bytes instead. Needs [`BodyHold::replaces`].
    Replace(Bytes),
    /// Answer the client with this reply; the upstream request is aborted.
    Reply(Reply),
}
