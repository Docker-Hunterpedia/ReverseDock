//! Checks of the `static` middleware (F-WEB-01). Whether `root` exists is checked when the
//! configuration compiles, where the directory is opened.

use super::Validator;
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::middleware::{HiddenFiles, StaticCacheControl, StaticConfig, SymlinkPolicy};

/// Most ranges a `static` middleware may answer in one request (RFC 9110 §17.15 asks servers
/// to limit them).
const MAX_RANGES: u32 = 16;

/// Whether `value` can be sent as a header value: visible ASCII, spaces and tabs.
fn is_header_value(value: &str) -> bool {
    !value.trim().is_empty()
        && value
            .bytes()
            .all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
}

/// Whether `path` is an absolute URL path without `.` or `..` segments.
fn is_clean_url_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['\\', '\0', '?', '#'])
        && path
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

impl Validator<'_> {
    pub(super) fn check_static(&mut self, path: &str, config: &StaticConfig) {
        if config.root.as_os_str().is_empty() {
            self.error(format!("{path}.root"), "name the directory to serve");
        }
        self.check_static_index(path, &config.index);
        self.check_static_fallback(path, config);
        if !(1..=MAX_RANGES).contains(&config.max_ranges) {
            self.error(
                format!("{path}.max_ranges"),
                format!("must be between 1 and {MAX_RANGES}"),
            );
        }
        self.check_static_cache_control(&format!("{path}.cache_control"), &config.cache_control);
        self.check_static_types(path, config);
        if config.symlinks == SymlinkPolicy::All {
            self.push(
                Diagnostic::warning(
                    format!("{path}.symlinks"),
                    "every symbolic link is followed, also out of `root`",
                )
                .with_hint("`within_root` follows only links that stay inside the directory"),
            );
        }
        if config.hidden == HiddenFiles::Allow {
            self.warning(
                format!("{path}.hidden"),
                "files and directories starting with `.` (such as `.env` and `.git/`) are served",
            );
        }
    }

    fn check_static_index(&mut self, path: &str, index: &[String]) {
        for (i, name) in index.iter().enumerate() {
            let plain = !name.is_empty()
                && name != "."
                && name != ".."
                && !name.contains(['/', '\\', '\0']);
            if !plain {
                self.error(
                    path_index(&format!("{path}.index"), i),
                    format!("`{name}` must be a file name, without `/`"),
                );
            }
        }
    }

    fn check_static_fallback(&mut self, path: &str, config: &StaticConfig) {
        if let Some(fallback) = &config.fallback
            && (!is_clean_url_path(fallback) || fallback.ends_with('/'))
        {
            self.push(
                Diagnostic::error(
                    format!("{path}.fallback"),
                    format!("`{fallback}` must be the path of a file in `root`"),
                )
                .with_hint("for a single-page app, usually `/index.html`"),
            );
        }
        for (i, prefix) in config.fallback_except.iter().enumerate() {
            self.check_starts_with_slash(
                &path_index(&format!("{path}.fallback_except"), i),
                prefix,
            );
        }
        if config.fallback.is_none() && !config.fallback_except.is_empty() {
            self.warning(
                format!("{path}.fallback_except"),
                "has no effect without `fallback`",
            );
        }
    }

    fn check_static_cache_control(&mut self, path: &str, cache: &StaticCacheControl) {
        if !is_header_value(&cache.default) {
            self.error(
                format!("{path}.default"),
                "must be a valid `Cache-Control` value",
            );
        }
        for (prefix, value) in &cache.paths {
            let key = path_key(path, prefix);
            if !prefix.starts_with('/') {
                self.push(
                    Diagnostic::error(
                        key.clone(),
                        format!("`{prefix}` must be `default` or a path prefix starting with `/`"),
                    )
                    .with_hint(
                        "prefixes are compared literally, e.g. `/assets/`; globs are not supported",
                    ),
                );
            }
            if !is_header_value(value) {
                self.error(key, "must be a valid `Cache-Control` value");
            }
        }
    }

    fn check_static_types(&mut self, path: &str, config: &StaticConfig) {
        for (extension, media_type) in &config.types {
            let key = path_key(&format!("{path}.types"), extension);
            if extension.is_empty() || extension.contains(['.', '/', '\\']) {
                self.error(
                    key.clone(),
                    format!("`{extension}` must be a file extension without the dot"),
                );
            }
            let (kind, subtype) = media_type
                .split(';')
                .next()
                .unwrap_or_default()
                .split_once('/')
                .unwrap_or_default();
            if kind.trim().is_empty() || subtype.trim().is_empty() || !is_header_value(media_type) {
                self.error(
                    key,
                    format!("`{media_type}` is not a media type like `text/plain`"),
                );
            }
        }
    }
}
