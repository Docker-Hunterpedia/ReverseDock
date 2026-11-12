//! What a plugin declares once, when it is built: its phases, whether it keeps per-request
//! state, and whether the proxy should hold the request body for it.

use std::fmt;
use std::time::Duration;

/// A set of pipeline phases.
///
/// The proxy calls a plugin's hook only for the phases its [`Capabilities`] declare. Phases
/// run in the route's list order on the way in (`request`, `upstream_request`,
/// `request_body`) and in reverse order on the way out (`response`, `response_body`, `log`).
///
/// ```
/// use rdock_plugin_api::Phases;
///
/// let phases = Phases::REQUEST | Phases::RESPONSE;
/// assert!(phases.contains(Phases::REQUEST));
/// assert!(!phases.contains(Phases::LOG));
/// assert_eq!(phases.names().collect::<Vec<_>>(), ["request", "response"]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Phases(u8);

impl Phases {
    /// No phase.
    pub const NONE: Self = Self(0);
    /// Before the backend is chosen: may change the request head or answer the request.
    pub const REQUEST: Self = Self(1);
    /// After the backend is chosen, before the request head is sent; once per attempt.
    pub const UPSTREAM_REQUEST: Self = Self(1 << 1);
    /// The complete request body, held by the proxy (declare it with
    /// [`Capabilities::with_body`]).
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

    /// The names of the phases, in pipeline order.
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

/// How a plugin wants the request body: held by the proxy until it is complete, up to
/// [`Self::max`] bytes, before any of it is forwarded.
///
/// A longer body is refused with `413` before the plugin sees it; a body that does not arrive
/// within [`Self::timeout`] is refused with `408`. The route's own `max_body` applies when it
/// is smaller.
///
/// ```
/// use std::time::Duration;
/// use rdock_plugin_api::BodyLimit;
///
/// let limit = BodyLimit::new(64 * 1024).timeout(Duration::from_secs(5));
/// assert_eq!(limit.max, 65_536);
/// assert!(!limit.replaces);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BodyLimit {
    /// Largest body held, at most [`Self::MAX`].
    pub max: u64,
    /// Longest time from the first body byte to the last.
    pub timeout: Duration,
    /// The plugin may answer [`crate::BodyDecision::Replace`]. The proxy then forwards the
    /// body without the client's `Content-Length`.
    pub replaces: bool,
}

impl BodyLimit {
    /// The largest [`Self::max`] the proxy accepts: a held body is read into memory in full
    /// when it is given to the plugin.
    pub const MAX: u64 = 64 * 1024 * 1024;
    /// Default [`Self::timeout`].
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Holds up to `max` bytes (capped at [`Self::MAX`]), without replacing them.
    #[must_use]
    pub const fn new(max: u64) -> Self {
        Self {
            max: if max > Self::MAX { Self::MAX } else { max },
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

    /// Declares that the plugin may replace the body.
    #[must_use]
    pub const fn replacing(mut self) -> Self {
        self.replaces = true;
        self
    }
}

/// What a plugin declares, read once when the route's chain is built.
///
/// ```
/// use rdock_plugin_api::{BodyLimit, Capabilities, Phases};
///
/// let caps = Capabilities::new(Phases::REQUEST | Phases::LOG)
///     .with_state()
///     .with_body(BodyLimit::new(1024));
/// assert!(caps.phases().contains(Phases::REQUEST_BODY), "a body hold adds its phase");
/// assert!(caps.state());
/// assert_eq!(caps.body().map(|b| b.max), Some(1024));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    phases: Phases,
    state: bool,
    body: Option<BodyLimit>,
}

impl Capabilities {
    /// Exactly these phases, no state, no body.
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

    /// Asks for per-request state that survives from one phase to a later one
    /// ([`crate::Ctx::set_state`]). Without it, state set in one hook is gone in the next.
    #[must_use]
    pub const fn with_state(mut self) -> Self {
        self.state = true;
        self
    }

    /// Asks the proxy to hold the request body; adds the `request_body` phase.
    #[must_use]
    pub const fn with_body(mut self, limit: BodyLimit) -> Self {
        self.phases = self.phases.union(Phases::REQUEST_BODY);
        self.body = Some(limit);
        self
    }

    /// The declared phases.
    #[must_use]
    pub const fn phases(&self) -> Phases {
        self.phases
    }

    /// Whether per-request state is wanted.
    #[must_use]
    pub const fn state(&self) -> bool {
        self.state
    }

    /// The body hold, if any.
    #[must_use]
    pub const fn body(&self) -> Option<BodyLimit> {
        self.body
    }
}
