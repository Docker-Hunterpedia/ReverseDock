//! The HTTP cache: stores under `caches`, `cache` middlewares, and the rule for routes that
//! authenticate (F-WEB-03, ADR-0030).

use std::path::{Component, Path};

use super::{Validator, reference_key};
use crate::cache::{CacheConfig, CacheStore, QueryKey};
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::middleware::{Identity, Middleware};
use crate::route::Route;
use crate::values::is_token;

/// Longest coalescing wait accepted.
const MAX_LOCK_TIMEOUT_SECS: u64 = 60;

impl Validator<'_> {
    pub(super) fn check_caches(&mut self) {
        let mut disk_paths: Vec<(String, &Path)> = Vec::new();
        for (name, store) in &self.config.caches {
            let path = path_key("caches", name);
            self.check_name("caches", name);
            self.check_not_zero(&format!("{path}.max_size"), store.max_size().as_u64() == 0);
            let CacheStore::Disk(disk) = store else {
                continue;
            };
            self.check_not_zero(&format!("{path}.max_objects"), disk.max_objects == 0);
            let Some(dir) = &disk.path else {
                continue;
            };
            let p = format!("{path}.path");
            if !dir.is_absolute() {
                self.error(&p, format!("`{}` must be an absolute path", dir.display()));
                continue;
            }
            if dir.components().any(|c| matches!(c, Component::ParentDir)) {
                self.error(&p, "the path must not contain `..`");
                continue;
            }
            if dir.parent().is_none() {
                self.error(&p, "the store cannot be the root directory");
                continue;
            }
            if let Some((other, _)) = disk_paths
                .iter()
                .find(|(_, o)| dir.starts_with(o) || o.starts_with(dir))
            {
                self.push(
                    Diagnostic::error(&p, format!("the directory overlaps store `{other}`"))
                        .with_hint("each disk store needs a directory of its own"),
                );
                continue;
            }
            disk_paths.push((name.clone(), dir));
        }
    }

    pub(super) fn check_cache(&mut self, path: &str, cache: &CacheConfig) {
        self.check_reference(
            &format!("{path}.store"),
            "cache store",
            &cache.store,
            &self.config.caches,
        );
        self.check_not_zero(
            &format!("{path}.max_object_size"),
            cache.max_object_size.as_u64() == 0,
        );
        if let Some(store) = self.config.caches.get(&cache.store)
            && store.max_size() < cache.max_object_size
        {
            self.warning(
                format!("{path}.max_object_size"),
                format!(
                    "larger than the store's `max_size`; objects above {} bytes are never stored",
                    store.max_size().as_u64()
                ),
            );
        }
        let statuses = cache
            .statuses
            .clone()
            .unwrap_or_else(|| vec![200, 203, 204, 300, 301, 308, 404, 410]);
        if let Some(list) = &cache.statuses {
            if list.is_empty() {
                self.error(format!("{path}.statuses"), "list at least one status");
            }
            for (i, status) in list.iter().enumerate() {
                let p = path_index(&format!("{path}.statuses"), i);
                if !(200..=599).contains(status) {
                    self.error(p, format!("`{status}` is not a final status code"));
                } else if matches!(status, 206 | 304) {
                    self.push(
                        Diagnostic::error(p, format!("`{status}` responses are never stored as such"))
                            .with_hint("the cache asks the origin for whole objects and answers ranges and conditional requests from them"),
                    );
                }
            }
        }
        for (code, ttl) in &cache.default_ttl {
            let p = format!("{path}.default_ttl.{code}");
            match code.parse::<u16>() {
                Ok(status) if statuses.contains(&status) => {
                    self.check_not_zero(&p, ttl.is_zero());
                }
                Ok(_) => self.error(
                    p,
                    format!("status `{code}` is not one the route stores (`statuses`)"),
                ),
                Err(_) => self.error(p, format!("`{code}` is not a status code")),
            }
        }
        self.check_token_list(
            &format!("{path}.key.headers"),
            &cache.key.headers,
            "header name",
        );
        self.check_token_list(
            &format!("{path}.bypass.headers"),
            &cache.bypass.headers,
            "header name",
        );
        self.check_token_list(
            &format!("{path}.bypass.cookies"),
            &cache.bypass.cookies,
            "cookie name",
        );
        self.check_token_list(
            &format!("{path}.tags.headers"),
            &cache.tags.headers,
            "header name",
        );
        self.check_targeted(path, &cache.targeted);
        match &cache.key.query {
            QueryKey::Only(list) | QueryKey::Ignore(list) => {
                let p = format!("{path}.key.query");
                if list.is_empty() {
                    self.error(&p, "list at least one parameter");
                }
                for (i, pattern) in list.iter().enumerate() {
                    let name = pattern.strip_suffix('*').unwrap_or(pattern);
                    if pattern.is_empty() || name.contains('*') || name.contains(['&', '=']) {
                        self.error(
                            path_index(&p, i),
                            format!("`{pattern}` is not a parameter name or `prefix*`"),
                        );
                    }
                }
            }
            QueryKey::AsSent | QueryKey::Sorted => {}
        }
        let timeout = cache.lock.timeout.as_std();
        if cache.lock.enabled && (timeout.is_zero() || timeout.as_secs() > MAX_LOCK_TIMEOUT_SECS) {
            self.error(
                format!("{path}.lock.timeout"),
                format!("must be above zero and at most {MAX_LOCK_TIMEOUT_SECS}s"),
            );
        }
    }

    /// `targeted` lists header names, each once, and never the fields a targeted field
    /// replaces (RFC 9213 §2.1).
    fn check_targeted(&mut self, path: &str, targeted: &[String]) {
        self.check_token_list(&format!("{path}.targeted"), targeted, "header name");
        for (i, name) in targeted.iter().enumerate() {
            let lower = name.to_ascii_lowercase();
            let p = path_index(&format!("{path}.targeted"), i);
            if matches!(lower.as_str(), "cache-control" | "expires" | "pragma") {
                self.push(
                    Diagnostic::error(p, format!("`{name}` is not a targeted field"))
                        .with_hint("`Cache-Control` is always read when no targeted field applies (RFC 9213 §2.1); list fields such as `CDN-Cache-Control`"),
                );
            } else if targeted[..i]
                .iter()
                .any(|other| other.eq_ignore_ascii_case(name))
            {
                self.error(p, format!("`{name}` is listed twice"));
            }
        }
    }

    fn check_token_list(&mut self, path: &str, values: &[String], what: &str) {
        for (i, value) in values.iter().enumerate() {
            if !is_token(value) {
                self.error(
                    path_index(path, i),
                    format!("`{value}` is not a valid {what}"),
                );
            }
        }
    }

    /// A route caches with at most one `cache` middleware, and a route that authenticates
    /// requests caches only with `shared_across_users: true` or a key that holds the
    /// identity. The position of `cache` in the list does not matter: Pingora looks the
    /// cache up after every `request` phase has run, so an authenticating middleware placed
    /// after `cache` still sees the request before the cache does, and its user's response
    /// would still be stored for everyone.
    pub(super) fn check_route_cache(&mut self, path: &str, route: &Route) {
        let defined = |reference: &String| self.config.middlewares.get(reference_key(reference));
        let caches: Vec<(usize, &String, &CacheConfig)> = route
            .middlewares
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match defined(r) {
                Some(Middleware::Cache(c)) => Some((i, r, c)),
                _ => None,
            })
            .collect();
        let Some(&(index, cache_name, cache)) = caches.first() else {
            return;
        };
        if let Some(&(second, name, _)) = caches.get(1) {
            self.error(
                path_index(&format!("{path}.middlewares"), second),
                format!("`{name}` is a second `cache` middleware; a route caches in one store"),
            );
        }
        if route.mirror.as_ref().is_some_and(|m| m.percent == 100) {
            self.warning(
                format!("{path}.mirror.percent"),
                "every request is mirrored and mirrored requests skip the cache, so the cache is never used",
            );
        }
        if cache.shared_across_users {
            return;
        }
        let key_headers: Vec<String> = cache
            .key
            .headers
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        for reference in &route.middlewares {
            let Some(identity) = defined(reference).and_then(Middleware::authenticates) else {
                continue;
            };
            let covered = match &identity {
                Identity::External { headers } => headers
                    .iter()
                    .any(|h| key_headers.contains(&h.to_ascii_lowercase())),
                _ => cache.key.consumer,
            };
            if covered {
                continue;
            }
            let hint = if identity.keyable() {
                format!(
                    "set `shared_across_users: true` on `{cache_name}` when the responses are the same for every user, or `key.consumer: true` to keep one copy per user (keyed on {})",
                    identity.describe()
                )
            } else {
                format!(
                    "`{reference}` asks an external service, so rdock does not learn who it let in and `key.consumer` cannot keep users apart; set `shared_across_users: true` on `{cache_name}` when the responses are the same for every user, or add to `key.headers` a header `{reference}` copies from the service (`copy_headers`)"
                )
            };
            self.push(
                Diagnostic::error(
                    path_index(&format!("{path}.middlewares"), index),
                    format!(
                        "`{cache_name}` caches the responses of a route that authenticates with `{reference}`: one user's response could be served to another"
                    ),
                )
                .with_hint(hint),
            );
        }
    }
}
