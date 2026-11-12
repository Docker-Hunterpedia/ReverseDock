//! Consumers, API keys, per-consumer limits and quotas, and metering (F-GW-01, F-GW-02,
//! F-GW-05, ADR-0030).

use std::collections::BTreeMap;

use super::{Validator, reference_key};
use crate::diagnostics::{Diagnostic, path_index, path_key};
use crate::gateway::{ApiKeyConfig, QuotaConfig, parse_rfc3339};
use crate::middleware::{Identity, Middleware, RateLimitConfig};
use crate::route::Route;
use crate::values::{RateLimitKey, is_token};

/// Most events in one metering batch.
const MAX_BATCH: u32 = 10_000;

impl Validator<'_> {
    pub(super) fn check_consumers(&mut self) {
        let mut ids: BTreeMap<&str, &str> = BTreeMap::new();
        for (name, consumer) in &self.config.consumers {
            let path = path_key("consumers", name);
            self.check_name("consumers", name);
            if name.contains(',') {
                self.error(&path, "a consumer name cannot contain `,`");
            }
            for (i, group) in consumer.groups().iter().enumerate() {
                if !is_token(group) || group.contains(',') {
                    self.error(
                        path_index(&format!("{path}.groups"), i),
                        format!("`{group}` is not a group name (letters, digits, `-`, `_`, `.`)"),
                    );
                }
            }
            for (i, key) in consumer.keys.iter().enumerate() {
                let at = path_index(&format!("{path}.keys"), i);
                if key.hash.starts_with(rdock_credentials::API_KEY.prefix)
                    || key.id.starts_with(rdock_credentials::API_KEY.prefix)
                {
                    // Never echo the value: it may be a working key.
                    self.push(
                        Diagnostic::error(&at, "this looks like an API key itself; store only its ID and hash")
                            .with_hint("`rdock keys hash` prints the `id` and `hash` of a key read from standard input"),
                    );
                    continue;
                }
                if !rdock_credentials::API_KEY.is_id(&key.id) {
                    self.error(
                        format!("{at}.id"),
                        "an API key ID is the 12 letters and digits after `rdk_`",
                    );
                }
                if !rdock_credentials::is_sha256_hex(&key.hash) {
                    self.error(
                        format!("{at}.hash"),
                        "the hash is the SHA-256 of the key's secret as 64 lower-case hex digits",
                    );
                }
                if let Some(expires) = &key.expires
                    && parse_rfc3339(expires).is_none()
                {
                    self.error(
                        format!("{at}.expires"),
                        format!(
                            "`{expires}` is not an RFC 3339 time such as `2027-01-01T00:00:00Z`"
                        ),
                    );
                }
                if let Some(other) = ids.insert(&key.id, name) {
                    self.error(
                        format!("{at}.id"),
                        format!("key `{}` is also a key of consumer `{other}`", key.id),
                    );
                }
            }
        }
    }

    pub(super) fn check_api_key(&mut self, path: &str, config: &ApiKeyConfig) {
        if config.headers.is_empty() && config.query.is_none() {
            self.error(
                format!("{path}.headers"),
                "name at least one header (or a `query` parameter) to read the key from",
            );
        }
        for (i, header) in config.headers.iter().enumerate() {
            if !is_token(header) {
                self.error(
                    path_index(&format!("{path}.headers"), i),
                    format!("`{header}` is not a header name"),
                );
            }
        }
        if let Some(query) = &config.query {
            if query.is_empty() {
                self.error(format!("{path}.query"), "the parameter name is empty");
            } else {
                self.warning(
                    format!("{path}.query"),
                    "keys in URLs end up in browser histories and other systems' logs; prefer a header",
                );
            }
        }
        if self
            .config
            .consumers
            .values()
            .all(|c| c.keys.is_empty() && c.keys_file.is_none())
            && self.merged
        {
            self.warning(path, "no consumer has a key yet, so every key is refused");
        }
        for (i, group) in config.groups.iter().enumerate() {
            if !self
                .config
                .consumers
                .values()
                .any(|c| c.groups().contains(group))
                && self.merged
            {
                self.warning(
                    path_index(&format!("{path}.groups"), i),
                    format!("no consumer is in group `{group}`"),
                );
            }
        }
    }

    pub(super) fn check_rate_limit_overrides(&mut self, path: &str, limit: &RateLimitConfig) {
        if limit.overrides.is_empty() {
            return;
        }
        if limit.key != RateLimitKey::Consumer {
            self.error(
                format!("{path}.overrides"),
                "per-group overrides need `key: consumer`",
            );
        }
        for (group, o) in &limit.overrides {
            let at = format!("{path}.overrides.{group}");
            self.check_not_zero(&format!("{at}.average"), o.average == 0);
            self.check_not_zero(&format!("{at}.burst"), o.burst == Some(0));
            self.check_not_zero(
                &format!("{at}.period"),
                o.period.is_some_and(crate::values::Duration::is_zero),
            );
        }
    }

    pub(super) fn check_quota(&mut self, path: &str, quota: &QuotaConfig) {
        self.check_not_zero(&format!("{path}.limit"), quota.limit == 0);
        if quota.key != RateLimitKey::Consumer {
            self.error(
                format!("{path}.key"),
                "a quota counts per consumer: use `key: consumer` (the default)",
            );
        }
        for (group, limit) in &quota.overrides {
            self.check_not_zero(&format!("{path}.overrides.{group}"), *limit == 0);
        }
        if quota.flush_interval.as_std() < std::time::Duration::from_secs(1) {
            self.error(format!("{path}.flush_interval"), "use at least 1s");
        }
    }

    /// A limit or quota keyed by consumer needs a middleware that sets one, earlier in the
    /// route's chain: without it every request would be counted by client IP.
    pub(super) fn check_route_consumer_keys(&mut self, path: &str, route: &Route) {
        let defined = |reference: &String| self.config.middlewares.get(reference_key(reference));
        let mut identified = false;
        let mut problems = Vec::new();
        for (i, reference) in route.middlewares.iter().enumerate() {
            let Some(middleware) = defined(reference) else {
                continue;
            };
            let by_consumer = match middleware {
                Middleware::RateLimit(r) => r.key == RateLimitKey::Consumer,
                Middleware::InFlight(f) => f.key == RateLimitKey::Consumer,
                Middleware::Bandwidth(b) => b.key == RateLimitKey::Consumer,
                Middleware::Quota(_) => true,
                _ => false,
            };
            if by_consumer && !identified {
                problems.push((i, reference.clone()));
            }
            if middleware.authenticates() == Some(Identity::Consumer) {
                identified = true;
            }
        }
        for (i, reference) in problems {
            self.push(
                Diagnostic::error(
                    path_index(&format!("{path}.middlewares"), i),
                    format!(
                        "`{reference}` counts per consumer, but no middleware before it sets one"
                    ),
                )
                .with_hint(
                    "put an `api_key`, `oidc`, `cloudflare_access` or `jwt` (with `consumer_claim`) middleware earlier in the list",
                ),
            );
        }
    }

    pub(super) fn check_metering(&mut self) {
        let Some(metering) = &self.config.observability.metering else {
            return;
        };
        let path = "observability.metering";
        if metering.webhook.is_none() && metering.otlp.is_none() {
            self.warning(
                path,
                "no sink: add `webhook` or `otlp`, or events go nowhere",
            );
        }
        if metering.max_batch == 0 || metering.max_batch > MAX_BATCH {
            self.error(format!("{path}.max_batch"), format!("use 1 to {MAX_BATCH}"));
        }
        self.check_not_zero(&format!("{path}.queue"), metering.queue == 0);
        self.check_not_zero(
            &format!("{path}.flush_interval"),
            metering.flush_interval.is_zero(),
        );
        if let Some(webhook) = &metering.webhook {
            let at = format!("{path}.webhook");
            if let Some(secret) = &webhook.secret {
                self.check_secret_reference(&format!("{at}.secret"), secret, "metering_secret");
            }
            if let Some(token) = &webhook.token {
                self.check_secret_reference(&format!("{at}.token"), token, "metering_token");
            }
            if !webhook.url.is_https_or_loopback() {
                self.warning(
                    format!("{at}.url"),
                    "events (consumer names, routes) are sent unencrypted; use https",
                );
            }
            if webhook.r#type.trim().is_empty() {
                self.error(format!("{at}.type"), "the event type is empty");
            }
        }
        if let Some(otlp) = &metering.otlp
            && let Some(token) = &otlp.token
        {
            self.check_secret_reference(&format!("{path}.otlp.token"), token, "metering_token");
        }
    }
}
