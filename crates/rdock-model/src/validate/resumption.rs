//! TLS session resumption: tickets and the session cache (H-PERF-02, ADR-0031).

use super::Validator;
use crate::diagnostics::{Diagnostic, path_key};

/// Shortest ticket-key rotation accepted.
const MIN_ROTATE_SECS: u64 = 1;
/// Longest ticket-key rotation: tickets live for two intervals, which must stay within the
/// 7 days TLS 1.3 allows (RFC 8446 §4.6.1).
const MAX_ROTATE_SECS: u64 = 302_400;
/// Largest session cache accepted (sessions; each holds a few hundred bytes).
const MAX_CACHE: u32 = 1_048_576;

impl Validator<'_> {
    pub(super) fn check_resumption(&mut self) {
        for (name, listener) in &self.config.listeners {
            let Some(tls) = &listener.tls else { continue };
            let base = format!("{}.tls", path_key("listeners", name));
            if let Some(tickets) = &tls.tickets {
                let rotate = tickets.rotate.as_std().as_secs();
                if !(MIN_ROTATE_SECS..=MAX_ROTATE_SECS).contains(&rotate) {
                    self.push(
                        Diagnostic::error(
                            format!("{base}.tickets.rotate"),
                            "must be between 1s and 84h",
                        )
                        .with_hint(
                            "tickets stay valid for two rotations, and TLS 1.3 allows at most 7 days (RFC 8446 §4.6.1)",
                        ),
                    );
                }
                if !tickets.enabled && tickets.key_file.is_some() {
                    self.warning(
                        format!("{base}.tickets.key_file"),
                        "tickets are off (`enabled: false`); the key file is not read",
                    );
                }
            }
            if let Some(cache) = &tls.session_cache
                && cache.size > MAX_CACHE
            {
                self.error(
                    format!("{base}.session_cache.size"),
                    format!("at most {MAX_CACHE} sessions"),
                );
            }
        }
    }
}
