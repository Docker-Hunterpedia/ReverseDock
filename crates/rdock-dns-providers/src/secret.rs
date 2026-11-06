//! Secrets stay `${file:…}`/`${env:…}` references in the configuration and are resolved for
//! every call, so a rotated file is picked up without a reload.

use rdock_acme::dns::DnsError;

/// The secret behind `reference` (or the text itself when it is not a reference), without
/// surrounding whitespace. `field` names the setting in errors; the secret never appears there.
pub(crate) fn resolve(reference: &str, field: &str) -> Result<String, DnsError> {
    rdock_config::interpolate::expand(reference, &rdock_config::System)
        .map(|secret| secret.trim().to_owned())
        .map_err(|e| DnsError(format!("{field}: {e}")))
}
