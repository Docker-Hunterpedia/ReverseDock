//! The request path, made safe to look up under the root.
//!
//! The proxy has already normalised the path (`rdock_rules::path::normalize`): dot segments are
//! gone and only unreserved escapes are decoded, so `%2F`, `%5C` and `%00` are still encoded.
//! Here it is decoded exactly once more (RFC 3986 §2.4) and every component is checked again
//! on the decoded text, before the file system is touched.

use percent_encoding::percent_decode_str;
use rdock_model::middleware::HiddenFiles;

/// A decoded request path whose components are safe to open under the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafePath {
    /// The decoded path as the client sees it, starting with `/`.
    pub(crate) decoded: String,
    /// Components joined by `/`, without a leading slash; empty for the root itself.
    pub(crate) relative: String,
    /// The path ends with `/`.
    pub(crate) trailing_slash: bool,
}

impl SafePath {
    /// `None` (answered as a missing file) when the path is not valid UTF-8 once decoded, or a
    /// component is `.` or `..`, contains `\` or NUL, or starts with `.` while hidden files are
    /// refused.
    pub(crate) fn parse(raw: &str, hidden: HiddenFiles) -> Option<Self> {
        if !raw.starts_with('/') {
            return None;
        }
        let decoded = percent_decode_str(raw).decode_utf8().ok()?.into_owned();
        let mut components = Vec::new();
        for component in decoded.split('/').filter(|c| !c.is_empty()) {
            let refused = component == "."
                || component == ".."
                || component.contains(['\\', '\0'])
                || (hidden == HiddenFiles::Refuse && component.starts_with('.'));
            if refused {
                return None;
            }
            components.push(component);
        }
        Some(Self {
            trailing_slash: decoded.ends_with('/'),
            relative: components.join("/"),
            decoded,
        })
    }

    /// The last component has an extension (a `.` in it): a request for an asset, never
    /// answered with the SPA fallback.
    pub(crate) fn names_asset(&self) -> bool {
        self.relative
            .rsplit('/')
            .next()
            .is_some_and(|last| last.contains('.'))
    }

    /// `relative` joined with `name`.
    pub(crate) fn child(&self, name: &str) -> String {
        if self.relative.is_empty() {
            name.to_owned()
        } else {
            format!("{}/{name}", self.relative)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Option<SafePath> {
        SafePath::parse(raw, HiddenFiles::Refuse)
    }

    #[test]
    fn plain_paths_keep_their_components() {
        let path = parse("/docs/a%20b/index.html").unwrap();
        assert_eq!(path.relative, "docs/a b/index.html");
        assert_eq!(path.decoded, "/docs/a b/index.html");
        assert!(!path.trailing_slash);
        assert!(path.names_asset());
        let root = parse("/").unwrap();
        assert_eq!((root.relative.as_str(), root.trailing_slash), ("", true));
        assert_eq!(root.child("index.html"), "index.html");
        let dir = parse("/dir/").unwrap();
        assert_eq!((dir.relative.as_str(), dir.trailing_slash), ("dir", true));
        assert_eq!(dir.child("index.html"), "dir/index.html");
        assert!(!dir.names_asset());
        assert_eq!(parse("/caf%C3%A9.txt").unwrap().relative, "café.txt");
    }

    #[test]
    fn traversal_and_odd_bytes_are_refused_after_one_decoding() {
        for raw in [
            "/..%2Fetc/passwd",
            "/%2e%2e/etc/passwd",
            "/a/..%5C..%5Cetc",
            "/%5C..%5Cetc",
            "/a%5Cb",
            "/%00",
            "/file.txt%00.html",
            "/%C0%AE%C0%AE/etc/passwd",
            "/..%c0%af",
            "/%FF",
            "/a/%2E/b",
            "relative",
        ] {
            assert_eq!(parse(raw), None, "{raw}");
        }
        // Decoded once only: a double-encoded `..` stays a literal name.
        assert_eq!(parse("/%252e%252e/x").unwrap().relative, "%2e%2e/x");
    }

    #[test]
    fn hidden_components_follow_the_setting() {
        for raw in ["/.env", "/.ENV", "/.git/config", "/a/.hidden/b", "/%2Eenv"] {
            assert_eq!(parse(raw), None, "{raw}");
            assert!(SafePath::parse(raw, HiddenFiles::Allow).is_some(), "{raw}");
        }
        assert!(SafePath::parse("/.well-known/x", HiddenFiles::Allow).is_some());
        assert_eq!(SafePath::parse("/..", HiddenFiles::Allow), None);
    }
}
