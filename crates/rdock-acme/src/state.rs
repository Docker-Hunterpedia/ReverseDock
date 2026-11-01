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

    /// Counts a failed attempt and schedules the next one.
    pub fn fail(&mut self, error: String) {
        self.failures += 1;
        self.retry_at = Some(Instant::now() + backoff(self.failures));
        self.last_error = Some(error);
    }

    /// When the certificate should be renewed (Unix seconds).
    pub fn renew_at(&self) -> Option<i64> {
        let cert = self.cert.as_ref()?;
        self.ari_renew_at.or_else(|| {
            let lifetime = cert.not_after - cert.not_before;
            Some(cert.not_after - lifetime / 3)
        })
    }

    pub fn due(&self, now: i64) -> bool {
        let waiting = self.retry_at.is_some_and(|at| at > Instant::now());
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
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        let offset = ((end - start) as f64 * spread.clamp(0.0, 1.0)) as i64;
        self.ari_renew_at = Some(start + offset);
        self.ari_known = true;
    }

    /// Records that renewal information could not be fetched.
    pub fn ari_failed(&mut self, unsupported: bool) {
        self.ari_unsupported = unsupported;
        self.ari_check_at = Some(Instant::now() + ARI_RETRY_AFTER_ERROR);
    }

    /// When this certificate next needs attention.
    pub fn wake_at(&self, now: i64) -> Instant {
        let renewal = self.retry_at.unwrap_or_else(|| {
            let secs = self.renew_at().map_or(0, |at| at - now);
            Instant::now() + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
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

/// Exponential backoff with up to 10 % jitter: 1 minute, 2, 4, … at most 24 hours.
pub(crate) fn backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(16);
    let base = FIRST_RETRY.saturating_mul(1 << exponent).min(MAX_RETRY);
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
