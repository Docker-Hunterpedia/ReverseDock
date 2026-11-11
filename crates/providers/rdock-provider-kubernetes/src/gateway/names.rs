//! Names of the objects the translator puts into the fragment.
//!
//! A fragment name must be a valid configuration object name (at most 63 characters, starting
//! with a letter or digit, then letters, digits, `-`, `_` and `.`; the merge adds
//! `@kubernetes`). Kubernetes names are up to 253 characters, so a name is built from a short
//! kind prefix, the readable parts (namespace, name, …) and a hash of the exact identity:
//!
//! `<prefix>-<readable parts joined by '-', cut to fit>-<10 hex digits>`
//!
//! The hash is FNV-1a (64 bits, the first 40 bits written), stable across platforms and
//! versions, of the identity string, so two objects with the same readable parts (`a-b`/`c`
//! and `a`/`b-c`) still get different names, and the same object always gets the same name.

/// Longest object name the configuration accepts.
pub const MAX_NAME: usize = 63;

/// FNV-1a, 64 bits.
#[must_use]
pub fn fnv64(data: &str) -> u64 {
    data.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// A fragment object name: `prefix`, the readable `parts` (sanitised and cut so the whole
/// fits [`MAX_NAME`]) and a hash of `identity`.
#[must_use]
pub fn object_name(prefix: &str, parts: &[&str], identity: &str) -> String {
    let hash = format!("{:010x}", fnv64(identity) >> 24);
    let mut readable = sanitize(prefix);
    for part in parts {
        let part = sanitize(part);
        if !part.is_empty() {
            if !readable.is_empty() {
                readable.push('-');
            }
            readable.push_str(&part);
        }
    }
    // Room for `-` and the hash.
    let room = MAX_NAME - hash.len() - 1;
    let mut cut: String = readable.chars().take(room).collect();
    while cut.ends_with(['-', '.', '_']) {
        cut.pop();
    }
    while cut.starts_with(['-', '.', '_']) {
        cut.remove(0);
    }
    if cut.is_empty() {
        return format!("k{hash}");
    }
    format!("{cut}-{hash}")
}

/// Keeps letters, digits, `-`, `_` and `.`; anything else becomes `-`.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= MAX_NAME
            && name.starts_with(|c: char| c.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    }

    #[test]
    fn names_are_valid_short_and_stable() {
        let short = object_name("gw", &["infra", "web", "80"], "infra/web/80");
        assert!(short.starts_with("gw-infra-web-80-"), "{short}");
        assert!(valid(&short));
        assert_eq!(
            short,
            object_name("gw", &["infra", "web", "80"], "infra/web/80")
        );
        let long_name = "a".repeat(253);
        let long = object_name(
            "gw",
            &["gateway-conformance-infra", &long_name, "80"],
            &long_name,
        );
        assert_eq!(long.len(), MAX_NAME);
        assert!(valid(&long), "{long}");
        // Same readable parts, different identity: different names.
        assert_ne!(
            object_name("hr", &["a-b", "c"], "a-b/c"),
            object_name("hr", &["a", "b-c"], "a/b-c")
        );
        // Characters that are not allowed are replaced.
        assert!(valid(&object_name("hr", &["ns", "a b/c@d"], "x")));
        assert!(valid(&object_name("", &[""], "x")));
    }
}
