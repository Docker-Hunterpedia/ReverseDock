//! `hold_body`: holds the request body until it is complete before any of it reaches the
//! backend (ADR-0030). It needs nothing from the body itself; asking for it is the point: the
//! proxy refuses an oversize body with `413` before the backend has seen a byte of it, and
//! later body middlewares on the route get the whole body.

use async_trait::async_trait;
use rdock_model::middleware::HoldBodyConfig;

use crate::Middleware;
use crate::phase::{BodyHold, Capabilities};

/// The `hold_body` middleware.
#[derive(Debug)]
pub(crate) struct HoldBody {
    hold: BodyHold,
}

impl HoldBody {
    pub(crate) fn new(config: &HoldBodyConfig) -> Self {
        Self {
            hold: BodyHold::new(config.max.as_u64()).timeout(config.timeout.as_std()),
        }
    }
}

#[async_trait]
impl Middleware for HoldBody {
    fn capabilities(&self) -> Capabilities {
        Capabilities::DEFAULT.with_body(self.hold)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::phase::Phases;

    #[test]
    fn declares_a_hold_and_nothing_else() {
        let config: HoldBodyConfig =
            serde_json::from_str(r#"{"max":"2KiB","timeout":"5s"}"#).unwrap();
        let caps = HoldBody::new(&config).capabilities();
        assert_eq!(
            caps.body(),
            Some(BodyHold {
                max: 2048,
                timeout: Duration::from_secs(5),
                replaces: false
            })
        );
        assert!(caps.phases().contains(Phases::REQUEST_BODY));
        assert!(!caps.phases().contains(Phases::LOG) && !caps.state());
        let defaults = HoldBody::new(&HoldBodyConfig::default()).capabilities();
        assert_eq!(defaults.body().map(|h| h.max), Some(1 << 20));
    }
}
