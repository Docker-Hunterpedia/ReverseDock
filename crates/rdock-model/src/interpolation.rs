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
    &["certificates", "*", "key_password"],
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
    }
}
