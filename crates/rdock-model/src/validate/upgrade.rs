//! In-place binary upgrades (H-PERF-04, ADR-0031).

use super::Validator;
use crate::diagnostics::Diagnostic;
use crate::settings::DrainLimit;

impl Validator<'_> {
    pub(super) fn check_upgrade(&mut self) {
        let Some(upgrade) = &self.config.upgrade else {
            return;
        };
        if !upgrade.binary.is_absolute() {
            self.error("upgrade.binary", "must be an absolute path");
        }
        let start = upgrade.start_timeout.as_std().as_secs();
        if !(1..=600).contains(&start) {
            self.error("upgrade.start_timeout", "must be between 1s and 10m");
        }
        if upgrade.drain == DrainLimit::Unlimited {
            self.push(
                Diagnostic::warning(
                    "upgrade.drain",
                    "`unlimited` keeps the old binary serving for as long as a client holds a connection",
                )
                .with_hint("a bound such as the default 10m closes what is left after it"),
            );
        }
        for (i, key) in upgrade.trusted_keys.iter().enumerate() {
            // A minisign public key: base64 of "Ed", an 8-byte key ID and a 32-byte key.
            let plausible = key.len() == 56
                && key.starts_with("RW")
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
            if !plausible {
                self.error(
                    format!("upgrade.trusted_keys[{i}]"),
                    "not a minisign public key (the `RW…` line of a `.pub` file)",
                );
            }
        }
        if !cfg!(target_os = "linux") {
            self.warning(
                "upgrade",
                "in-place binary upgrades are only supported on Linux; `rdock upgrade` is refused here",
            );
        }
    }
}
