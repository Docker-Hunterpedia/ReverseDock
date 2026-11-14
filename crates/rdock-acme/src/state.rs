//! What the manager knows about one certificate, and when it renews it: inside the CA's ARI
//! window when the CA offers one (RFC 9773), otherwise with a third of the lifetime left.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use instant_acme::CertificateIdentifier;
use rdock_tls::LoadedCert;
use serde::Serialize;

/// Backoff after the first failure, doubled after each further one.
const FIRST_RETRY: Duration = Duration::from_secs(60);
/// Longest backoff between attempts.
const MAX_RETRY: Duration = Duration::from_secs(24 * 3600);
/// RFC 9773 §4.3: clamp the server's Retry-After to one minute … one day.
const ARI_MIN_RECHECK: Duration = Duration::from_secs(60);
const ARI_MAX_RECHECK: Duration = Duration::from_secs(24 * 3600);
/// When fetching renewal information fails, try again after this long.
const ARI_RETRY_AFTER_ERROR: Duration = Duration::from_secs(3600);

/// The failure back-off of certificates no longer asked for, kept per name, so a name that
/// leaves the plan and comes back (a crash-looping container's route), alone or with other
/// names than before, does not start over at once with a new order: each return would
/// otherwise place one, and the CA's limits on failed validations and new orders would soon
/// refuse every certificate of the account. A certificate that comes back gets the longest
/// back-off any of its names had. Bounded by [`Backoffs::MAX`] names and [`Backoffs::KEEP`]
/// each.
#[derive(Debug, Default)]
pub(crate) struct Backoffs {
    entries: std::collections::BTreeMap<String, Kept>,
}

/// A kept back-off: failures, when to try again, the last error, and when it was kept.
type Kept = (u32, Option<Instant>, Option<String>, Instant);

impl Backoffs {
    /// Names kept at most.
    pub const MAX: usize = 4096;
    /// How long an entry is kept.
    pub const KEEP: Duration = Duration::from_secs(24 * 3600);

    /// Remembers the back-off of `state`, under each of `names`, when it has failures.
    pub fn keep(&mut self, names: Vec<String>, state: &CertState) {
        if state.failures == 0 {
            return;
        }
        let now = Instant::now();
        self.entries
            .retain(|_, (_, _, _, at)| now.duration_since(*at) < Self::KEEP);
        for name in names {
            if self.entries.len() >= Self::MAX
                && !self.entries.contains_key(&name)
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, _, _, at))| *at)
                    .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
            let kept = (
                state.failures,
                state.retry_at,
                state.last_error.clone(),
                now,
            );
            // A name kept twice keeps the longer back-off.
            match self.entries.get(&name) {
                Some(old) if old.0 > kept.0 => {}
                _ => {
                    self.entries.insert(name, kept);
                }
            }
        }
    }

    /// A new state for `names`, with the longest back-off any of them had when it left the
    /// plan: the most failures, and the latest time to try again.
    pub fn restore(&mut self, names: &[String]) -> CertState {
        let mut state = CertState::default();
        for name in names {
            let Some((failures, retry_at, last_error, at)) = self.entries.remove(name) else {
                continue;
            };
            if at.elapsed() >= Self::KEEP {
                continue;
            }
            if failures > state.failures {
                state.failures = failures;
                state.last_error = last_error;
            }
            state.retry_at = state.retry_at.max(retry_at);
        }
        state
    }
}

/// One certificate the configuration asks for.
#[derive(Debug, Default)]
pub(crate) struct CertState {
    pub cert: Option<LoadedCert>,
    /// ARI identifier of `cert`, used for renewal information and `replaces`.
    pub cert_id: Option<CertificateIdentifier<'static>>,
    pub loaded_from_disk: bool,
    pub failures: u32,
    pub retry_at: Option<Instant>,
    pub last_error: Option<String>,
    /// Renewal time chosen inside the CA's suggested window (Unix seconds).
    pub ari_renew_at: Option<i64>,
    /// When to fetch renewal information next; `None` means now.
    pub ari_check_at: Option<Instant>,
    /// The CA has no renewal information endpoint.
    pub ari_unsupported: bool,
    /// Whether the window came from ARI at least once, so renewals carry `replaces`.
    pub ari_known: bool,
    /// When an alert was last sent for this certificate.
    pub alerted_at: Option<Instant>,
    /// When an operator asked for renewal now (`POST /api/v1/certificates/{name}/renew`).
    pub renewal_requested: Option<Instant>,
    /// The version of the stored metadata last loaded (`0`: none), to notice certificates
    /// other instances store.
    pub meta_version: u64,
    /// Another instance holds the lease on this certificate: who, and when to look again.
    pub waiting_on: Option<(String, Instant)>,
}

/// The renewal state of one certificate, as `rdock status` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertStatus {
    /// Names on the certificate.
    pub names: Vec<String>,
    /// Expiry of the certificate in use (Unix seconds), if one is in use.
    pub not_after: Option<i64>,
    /// When renewal is planned (Unix seconds).
    pub renew_at: Option<i64>,
    /// `ari` when the CA chose the renewal window, else `lifetime`.
    pub renewal: &'static str,
    /// Failed attempts since the last success.
    pub failures: u32,
    /// The last failure, if the last attempt failed.
    pub last_error: Option<String>,
}

impl CertState {
    /// Uses a newly issued or loaded certificate; renewal information is fetched again.
    pub fn set_cert(&mut self, cert: LoadedCert) {
        self.cert_id = cert
            .key
            .cert
            .first()
            .and_then(|der| CertificateIdentifier::try_from(der).ok())
            .map(CertificateIdentifier::into_owned);
        self.cert = Some(cert);
        self.failures = 0;
        self.retry_at = None;
        self.last_error = None;
        self.ari_renew_at = None;
        self.ari_check_at = None;
        self.renewal_requested = None;
    }

    /// Takes the shared renewal time from stored metadata (ADR-0031).
    pub fn adopt_meta(&mut self, meta: &crate::storage::CertMeta) {
        if let Some(window) = meta.ari {
            self.ari_renew_at = Some(window.renew_at);
            self.ari_known = true;
        }
        self.waiting_on = None;
    }

    /// Another instance works on this certificate: look again after `recheck`.
    pub fn wait_for(&mut self, holder: &str, recheck: Duration) {
        self.waiting_on = Some((holder.to_owned(), Instant::now() + recheck));
    }

    /// Counts a failed attempt and schedules the next one.
    pub fn fail(&mut self, error: String) {
        self.failures += 1;
        self.retry_at = Some(Instant::now() + backoff(self.failures));
        self.last_error = Some(error);
    }

    /// Waits at least until `at` before the next attempt (the CA's `Retry-After`).
    pub fn not_before(&mut self, at: SystemTime) {
        let wait = at.duration_since(SystemTime::now()).unwrap_or_default();
        let at = Instant::now() + wait;
        if self.retry_at.is_none_or(|current| current < at) {
            self.retry_at = Some(at);
        }
    }

    /// When the certificate should be renewed (Unix seconds).
    pub fn renew_at(&self) -> Option<i64> {
        let cert = self.cert.as_ref()?;
        self.ari_renew_at.or_else(|| {
            let lifetime = cert.not_after.saturating_sub(cert.not_before);
            Some(cert.not_after.saturating_sub(lifetime / 3))
        })
    }

    pub fn due(&self, now: i64) -> bool {
        let now_instant = Instant::now();
        let waiting = self.retry_at.is_some_and(|at| at > now_instant)
            || self
                .waiting_on
                .as_ref()
                .is_some_and(|(_, at)| *at > now_instant);
        !waiting && (self.renewal_requested.is_some() || self.renew_at().is_none_or(|at| now >= at))
    }

    /// Whether renewal information should be fetched now.
    pub fn wants_ari(&self) -> bool {
        self.cert_id.is_some()
            && !self.ari_unsupported
            && self.ari_check_at.is_none_or(|at| at <= Instant::now())
    }

    /// Applies a suggested window `[start, end]` (Unix seconds) and the server's Retry-After.
    /// The renewal time is spread over the window, so many servers do not renew at once.
    pub fn apply_window(&mut self, start: i64, end: i64, retry_after: Duration, spread: f64) {
        let recheck = retry_after.clamp(ARI_MIN_RECHECK, ARI_MAX_RECHECK);
        self.ari_check_at = Some(Instant::now() + recheck);
        if end <= start {
            return;
        }
        // A window from a CA's answer or a stored record: saturating, so extreme values (the
        // `acme_answers` fuzz target) cannot overflow.
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        let offset = (end.saturating_sub(start) as f64 * spread.clamp(0.0, 1.0)) as i64;
        self.ari_renew_at = Some(start.saturating_add(offset).min(end));
        self.ari_known = true;
    }

    /// Records that renewal information could not be fetched.
    pub fn ari_failed(&mut self, unsupported: bool) {
        self.ari_unsupported = unsupported;
        self.ari_check_at = Some(Instant::now() + ARI_RETRY_AFTER_ERROR);
    }

    /// When this certificate next needs attention.
    pub fn wake_at(&self, now: i64) -> Instant {
        if let Some((_, at)) = &self.waiting_on
            && *at > Instant::now()
        {
            return *at;
        }
        let renewal = self.retry_at.unwrap_or_else(|| {
            let secs = self.renew_at().map_or(0, |at| at.saturating_sub(now));
            // At most a day ahead: the manager looks again then, and an instant far in the
            // future (a stored renewal time from a corrupt record) cannot overflow.
            let secs = u64::try_from(secs).unwrap_or(0).min(MAX_RETRY.as_secs());
            Instant::now() + Duration::from_secs(secs)
        });
        match self.ari_check_at {
            Some(check) if !self.ari_unsupported && self.cert.is_some() => renewal.min(check),
            _ => renewal,
        }
    }

    pub fn status(&self, names: &[String]) -> CertStatus {
        CertStatus {
            names: names.to_vec(),
            not_after: self.cert.as_ref().map(|c| c.not_after),
            renew_at: self.renew_at(),
            renewal: if self.ari_renew_at.is_some() {
                "ari"
            } else {
                "lifetime"
            },
            failures: self.failures,
            last_error: self.last_error.clone(),
        }
    }
}

/// Fuzzing entry point (`tests/fuzz`, target `acme_answers`): an ARI window and the server's
/// `Retry-After` from a CA's answer applied to a certificate's renewal state, then the
/// questions the manager asks it. Never a panic; the renewal time stays inside the window.
#[doc(hidden)]
pub fn fuzz_ari_window(start: i64, end: i64, retry_after: Duration, spread: f64, now: i64) {
    let mut state = CertState::default();
    state.apply_window(start, end, retry_after, spread);
    if let Some(at) = state.ari_renew_at {
        assert!(
            start < end && (start..=end).contains(&at),
            "{at} outside [{start}, {end}]"
        );
    }
    let _ = state.due(now);
    let _ = state.wake_at(now);
    let _ = state.status(&[]);
}

/// The first backoff. For tests only, never in a release build: `RDOCK_TEST_ACME_RETRY`
/// (seconds, at least 1) replaces the minute, so the chaos suite (ADR-0033) can watch several
/// retries in seconds; the doubling and the cap stay.
fn first_retry() -> Duration {
    if cfg!(debug_assertions)
        && let Some(seconds) = std::env::var("RDOCK_TEST_ACME_RETRY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_secs(seconds.max(1));
    }
    FIRST_RETRY
}

/// Exponential backoff with up to 10 % jitter: 1 minute, 2, 4, … at most 24 hours.
pub(crate) fn backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(16);
    let base = first_retry().saturating_mul(1 << exponent).min(MAX_RETRY);
    base + base / 1000 * u32::from(spread_percent())
}

/// A number in `0..100` that differs between calls and processes; spreads retries and renewal
/// times. Not for anything secret.
fn spread_percent() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    u16::try_from(nanos.wrapping_mul(2_654_435_761) % 100).unwrap_or(0)
}

/// A fraction in `[0, 1)` for spreading renewal times over a window.
pub(crate) fn spread() -> f64 {
    f64::from(spread_percent()) / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_a_day() {
        assert!(backoff(1) >= FIRST_RETRY && backoff(1) < FIRST_RETRY * 11 / 10);
        assert!(backoff(2) >= FIRST_RETRY * 2);
        assert!(backoff(30) >= MAX_RETRY && backoff(30) <= MAX_RETRY * 11 / 10);
    }

    #[test]
    fn a_missing_certificate_is_due_at_once() {
        let state = CertState::default();
        assert!(state.due(0));
        assert_eq!(state.renew_at(), None);
    }

    #[test]
    fn ari_windows_set_the_renewal_time_and_clamp_rechecks() {
        let mut state = CertState::default();
        state.apply_window(1_000, 2_000, Duration::from_secs(1), 0.5);
        assert_eq!(state.ari_renew_at, Some(1_500));
        assert!(state.ari_known);
        let check = state.ari_check_at.unwrap();
        assert!(check >= Instant::now() + Duration::from_secs(59));
        let mut empty = CertState::default();
        empty.apply_window(2_000, 1_000, Duration::from_secs(48 * 3600), 0.5);
        assert_eq!(empty.ari_renew_at, None, "an inverted window is ignored");
        assert!(empty.ari_check_at.unwrap() <= Instant::now() + ARI_MAX_RECHECK);
    }

    /// Extreme windows and renewal times (from a CA's answer or a stored record) never
    /// overflow; the renewal time stays inside the window.
    #[test]
    fn extreme_windows_do_not_overflow() {
        let mut state = CertState::default();
        state.apply_window(i64::MIN, i64::MAX, Duration::MAX, 1.0);
        assert!(state.ari_renew_at.is_some());
        let _ = state.wake_at(i64::MIN);
        let _ = state.wake_at(i64::MAX);
        state.apply_window(i64::MIN, i64::MIN + 1, Duration::ZERO, f64::NAN);
        assert!(state.ari_renew_at.is_some_and(|at| at <= i64::MIN + 1));
        let _ = state.due(i64::MAX);
    }

    #[test]
    fn a_name_that_leaves_and_returns_keeps_its_back_off() {
        let names = vec!["flaky.example".to_owned()];
        let mut state = CertState::default();
        state.fail("validation failed".into());
        state.fail("validation failed".into());
        let retry_at = state.retry_at.unwrap();
        assert!(retry_at > Instant::now());
        let mut backoffs = Backoffs::default();
        backoffs.keep(names.clone(), &state);
        let back = backoffs.restore(&names);
        assert_eq!(back.failures, 2);
        assert_eq!(back.retry_at, Some(retry_at));
        assert!(!back.due(0), "not ordered again at once");
        // A name that never failed, or was restored already, starts fresh.
        assert_eq!(backoffs.restore(&names).failures, 0);
        backoffs.keep(names.clone(), &CertState::default());
        assert_eq!(backoffs.restore(&names).failures, 0);
    }

    #[test]
    fn a_name_that_returns_with_other_names_keeps_its_back_off() {
        let mut state = CertState::default();
        for _ in 0..3 {
            state.fail("validation failed".into());
        }
        let retry_at = state.retry_at.unwrap();
        let mut backoffs = Backoffs::default();
        backoffs.keep(vec!["app.example".into(), "x1.example".into()], &state);
        // Back with a new name next to it, and in another order: the back-off holds.
        let back = backoffs.restore(&["x2.example".to_owned(), "app.example".to_owned()]);
        assert_eq!(back.failures, 3);
        assert_eq!(back.retry_at, Some(retry_at));
        assert!(!back.due(0));
        // The other name of the old set is still remembered on its own.
        assert_eq!(backoffs.restore(&["x1.example".to_owned()]).failures, 3);
    }

    #[test]
    fn failures_back_off_and_are_reported() {
        let mut state = CertState::default();
        state.fail("rejected".into());
        assert_eq!(state.failures, 1);
        assert!(!state.due(0));
        let status = state.status(&["a.example.com".into()]);
        assert_eq!(status.last_error.as_deref(), Some("rejected"));
        assert_eq!(status.renewal, "lifetime");
    }
}
