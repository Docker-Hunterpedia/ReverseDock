//! Where `${…}` references in string values are resolved.
//!
//! The loader replaces `${NAME}`, `${env:NAME}` and `${file:/path}` in ordinary string values.
//! Secret fields keep the reference, so the secret never appears in the loaded configuration,
//! its history or the admin API; the component that needs it resolves it at use. Regular
//! expression replacements keep their text unchanged because `$1` and `${name}` there refer to
//! capture groups.

/// How a string value at some location is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// References are resolved when the configuration is loaded.
    Interpolated,
    /// A secret: the reference is kept and resolved by the component that uses it.
    Secret,
    /// Taken literally (regular-expression replacements).
    Verbatim,
}

/// Locations of secret fields; `*` matches any map key.
const SECRETS: &[&[&str]] = &[
    &["acme", "dns_providers", "*", "api_token"],
    &["acme", "eab", "hmac_key"],
    &["acme", "dns_providers", "*", "token"],
    &["acme", "dns_providers", "*", "tsig_secret"],
    &["acme", "dns_providers", "*", "access_key_id"],
    &["acme", "dns_providers", "*", "secret_access_key"],
    &["acme", "dns_providers", "*", "session_token"],
    &["acme", "dns_providers", "*", "client_secret"],
    &["acme", "dns_providers", "*", "client_certificate"],
    &["observability", "alerts", "webhook", "token"],
    &["observability", "alerts", "channels", "*", "url"],
    &["observability", "alerts", "channels", "*", "secret"],
    &["observability", "alerts", "channels", "*", "token"],
    &["observability", "alerts", "channels", "*", "password"],
    &["certificates", "*", "key_password"],
    &["services", "*", "sticky", "cookie", "secret"],
    &["middlewares", "*", "hmac_secret"],
    &["services", "*", "sticky", "cookie", "previous_secrets", "*"],
    &["observability", "metering", "webhook", "secret"],
    &["observability", "metering", "webhook", "token"],
    &["observability", "metering", "otlp", "token"],
    &["secrets", "vault", "auth", "token"],
    &["middlewares", "*", "client_secret"],
    &["middlewares", "*", "session", "key"],
    &["middlewares", "*", "session", "keys", "*"],
    &["cluster", "control", "join_token"],
    &["cluster", "limits", "redis", "password"],
];

/// Locations taken literally.
const VERBATIM: &[&[&str]] = &[&["middlewares", "*", "replacement"]];

/// The kind of the string value at `path`, given as map keys from the root.
#[must_use]
pub fn field_kind(path: &[&str]) -> FieldKind {
    let matches = |pattern: &&[&str]| {
        pattern.len() == path.len()
            && pattern
                .iter()
                .zip(path)
                .all(|(want, have)| *want == "*" || want == have)
    };
    if SECRETS.iter().any(matches) {
        FieldKind::Secret
    } else if VERBATIM.iter().any(matches) {
        FieldKind::Verbatim
    } else {
        FieldKind::Interpolated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_fields_by_location() {
        assert_eq!(
            field_kind(&["acme", "dns_providers", "cf", "api_token"]),
            FieldKind::Secret
        );
        assert_eq!(
            field_kind(&["acme", "dns_providers", "ns", "tsig_secret"]),
            FieldKind::Secret
        );
        for field in [
            "secret_access_key",
            "session_token",
            "client_secret",
            "client_certificate",
        ] {
            assert_eq!(
                field_kind(&["acme", "dns_providers", "cloud", field]),
                FieldKind::Secret
            );
        }
        assert_eq!(
            field_kind(&["certificates", "main", "key_password"]),
            FieldKind::Secret
        );
        assert_eq!(
            field_kind(&["middlewares", "to-www", "replacement"]),
            FieldKind::Verbatim
        );
        assert_eq!(
            field_kind(&["services", "app", "backends"]),
            FieldKind::Interpolated
        );
        assert_eq!(field_kind(&["acme", "email"]), FieldKind::Interpolated);
        assert_eq!(
            field_kind(&["cluster", "limits", "redis", "password"]),
            FieldKind::Secret
        );
    }
}
