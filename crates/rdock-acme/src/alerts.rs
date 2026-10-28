//! Certificate alerts (B-TLS-12): a warning in the log, and the same event as JSON to
//! `observability.alerts.webhook`.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::state::CertState;

/// Consecutive failures after which a renewal is reported as failing.
const FAILURES_BEFORE_ALERT: u32 = 3;
/// A certificate with less than this left is reported as expiring.
const EXPIRY_WARNING_SECS: i64 = 7 * 24 * 3600;
/// The same certificate is reported at most this often.
const REPEAT_AFTER: Duration = Duration::from_secs(24 * 3600);

/// The alert `state` calls for now, if any.
pub(crate) fn due(state: &CertState, names: &[String], now: i64) -> Option<Value> {
    if state
        .alerted_at
        .is_some_and(|at| at.elapsed() < REPEAT_AFTER)
    {
        return None;
    }
    let not_after = state.cert.as_ref().map(|c| c.not_after);
    let event = if state.failures >= FAILURES_BEFORE_ALERT {
        "certificate_renewal_failing"
    } else if not_after.is_some_and(|t| t - now < EXPIRY_WARNING_SECS) {
        "certificate_expiring"
    } else {
        return None;
    };
    Some(json!({
        "event": event,
        "names": names,
        "not_after": not_after,
        "failures": state.failures,
        "error": state.last_error,
    }))
}

/// Records that an alert was sent.
pub(crate) fn sent(state: &mut CertState) {
    state.alerted_at = Some(Instant::now());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_after_three_failures_once_a_day() {
        let names = vec!["a.example.com".to_owned()];
        let mut state = CertState::default();
        state.fail("x".into());
        state.fail("y".into());
        assert_eq!(due(&state, &names, 0), None);
        state.fail("z".into());
        let alert = due(&state, &names, 0).unwrap();
        assert_eq!(alert["event"], "certificate_renewal_failing");
        assert_eq!(alert["error"], "z");
        sent(&mut state);
        assert_eq!(due(&state, &names, 0), None, "not repeated within a day");
    }
}
