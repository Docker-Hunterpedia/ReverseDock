//! `cluster` and `control` (H-HA-01…03, ADR-0031).

use std::net::IpAddr;
use std::time::Duration as StdDuration;

use super::Validator;
use crate::acme::Challenge;
use crate::cluster::{
    Cluster, ClusterLimits, ClusterStoreType, ControlPlane, LimitStoreType, RedisAddress,
    RedisStore, Rollout, RolloutMode, is_ca_pin, is_instance_name,
};
use crate::diagnostics::{Diagnostic, path_index};
use crate::route::{RouteTls, TlsMode};

/// Whether `value` lies within `min..=max` milliseconds.
fn within_ms(value: StdDuration, min: u64, max: u64) -> bool {
    let ms = value.as_millis();
    ms >= u128::from(min) && ms <= u128::from(max)
}

/// Whether `value` lies within `min..=max` seconds.
fn within(value: StdDuration, min: u64, max: u64) -> bool {
    let ms = value.as_millis();
    ms >= u128::from(min) * 1000 && ms <= u128::from(max) * 1000
}

impl Validator<'_> {
    pub(super) fn check_cluster(&mut self) {
        if self.config.cluster.is_some() && self.config.control.is_some() {
            self.push(
                Diagnostic::error(
                    "control",
                    "a process is either a data plane (`cluster`) or the control plane (`control`), not both",
                )
                .with_hint("give `rdock control run` a file of its own"),
            );
        }
        if let Some(cluster) = self.config.cluster.as_deref() {
            self.check_cluster_member(cluster);
        }
        if let Some(control) = self.config.control.as_deref() {
            self.check_control_plane(control);
        }
    }

    fn check_cluster_member(&mut self, cluster: &Cluster) {
        if let Some(instance) = &cluster.instance
            && !is_instance_name(instance)
        {
            self.error(
                "cluster.instance",
                "letters, digits, `.`, `-` and `_`, at most 63 characters",
            );
        }
        if let Some(control) = &cluster.control {
            let url = control.url.as_url();
            if url.scheme() != "https" {
                self.push(
                    Diagnostic::error(
                        "cluster.control.url",
                        "the control plane is reached over `https://` only",
                    )
                    .with_hint("the cluster listener always uses TLS; there is no plain-HTTP mode"),
                );
            }
            if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
                self.error(
                    "cluster.control.url",
                    "the address is the control plane's root, without a path, query or fragment",
                );
            }
            match (&control.ca_file, &control.ca_pin) {
                (None, None) => self.push(
                    Diagnostic::error(
                        "cluster.control",
                        "`ca_file` or `ca_pin` is required to authenticate the control plane",
                    )
                    .with_hint("`rdock control token create` prints the `ca_pin` line"),
                ),
                (Some(path), _) if !path.is_absolute() => {
                    self.error("cluster.control.ca_file", "must be an absolute path");
                }
                _ => {}
            }
            if let Some(pin) = &control.ca_pin
                && !is_ca_pin(pin)
            {
                self.error(
                    "cluster.control.ca_pin",
                    "`sha256:` followed by 64 lower-case hex digits",
                );
            }
            if let Some(dir) = &control.identity_dir
                && !dir.is_absolute()
            {
                self.error("cluster.control.identity_dir", "must be an absolute path");
            }
            if let Some(token) = &control.join_token {
                self.check_secret("cluster.control.join_token", token, "rdock-join");
            }
            if !within(control.poll_timeout.as_std(), 5, 300) {
                self.error("cluster.control.poll_timeout", "must be between 5s and 5m");
            }
        }
        self.check_cluster_store(cluster);
        self.check_cluster_challenges(cluster);
        if let Some(limits) = &cluster.limits {
            self.check_cluster_limits(cluster, limits);
        }
    }

    fn check_cluster_limits(&mut self, cluster: &Cluster, limits: &ClusterLimits) {
        if !(100..=10_000).contains(&limits.sync_interval.as_std().as_millis()) {
            self.error(
                "cluster.limits.sync_interval",
                "must be between 100ms and 10s",
            );
        }
        if limits.headroom_percent > 100 {
            self.error(
                "cluster.limits.headroom_percent",
                "must be between 0 and 100",
            );
        }
        match (limits.store, &limits.redis) {
            (LimitStoreType::Cluster, Some(_)) => self.warning(
                "cluster.limits.redis",
                "ignored with `store: cluster`; set `store: redis` to use it",
            ),
            (LimitStoreType::Cluster, None) if cluster.effective_store().is_none() => self.error(
                "cluster.limits.store",
                "`cluster` needs a cluster store (`cluster.control` or `cluster.store`)",
            ),
            (LimitStoreType::Redis, None) => {
                self.error("cluster.limits.redis", "required with `store: redis`");
            }
            (LimitStoreType::Redis, Some(redis)) => self.check_redis(redis),
            (LimitStoreType::Cluster, None) => {}
        }
    }

    fn check_redis(&mut self, redis: &RedisStore) {
        match RedisAddress::parse(&redis.url) {
            Err(message) => self.error("cluster.limits.redis.url", message),
            Ok(address) if !address.tls && !address.is_loopback() && !redis.allow_plaintext => {
                self.push(
                    Diagnostic::error(
                        "cluster.limits.redis.url",
                        "`redis://` sends the password and the counters in clear to another machine",
                    )
                    .with_hint("use `rediss://` (TLS); `allow_plaintext: true` accepts the risk on a private network"),
                );
            }
            Ok(address) if address.tls && redis.allow_plaintext => self.warning(
                "cluster.limits.redis.allow_plaintext",
                "has no effect with `rediss://`",
            ),
            Ok(_) => {}
        }
        if let Some(password) = &redis.password {
            self.check_secret_reference("cluster.limits.redis.password", password, "redis");
        } else if redis.username.is_some() {
            self.error(
                "cluster.limits.redis.username",
                "a user name needs a `password`",
            );
        }
        if let Some(path) = &redis.ca_file
            && !path.is_absolute()
        {
            self.error("cluster.limits.redis.ca_file", "must be an absolute path");
        }
        if !within_ms(redis.timeout.as_std(), 100, 10_000) {
            self.error(
                "cluster.limits.redis.timeout",
                "must be between 100ms and 10s",
            );
        }
        if redis.key_prefix.is_empty()
            || redis.key_prefix.len() > 64
            || !redis
                .key_prefix
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'*' && b != b'?')
        {
            self.error(
                "cluster.limits.redis.key_prefix",
                "1 to 64 visible characters, without `*` or `?`",
            );
        }
    }

    fn check_cluster_store(&mut self, cluster: &Cluster) {
        let redis_only = cluster
            .limits
            .as_ref()
            .is_some_and(|l| l.store == LimitStoreType::Redis);
        match (&cluster.store, &cluster.control) {
            (None, None) if redis_only => {}
            (None, None) => self.push(Diagnostic::error(
                "cluster",
                "a cluster needs `control` (a control plane), a `store` of type `directory`, or `limits` on Redis",
            )),
            (Some(store), control) => {
                match store.kind {
                    ClusterStoreType::Control if control.is_none() => self.error(
                        "cluster.store.type",
                        "`control` needs `cluster.control`; without a control plane use `type: directory`",
                    ),
                    ClusterStoreType::Directory => match &store.path {
                        None => self.error(
                            "cluster.store.path",
                            "the shared directory is required for `type: directory`",
                        ),
                        Some(path) if !path.is_absolute() => {
                            self.error("cluster.store.path", "must be an absolute path");
                        }
                        Some(_) => self.push(
                            Diagnostic::warning(
                                "cluster.store",
                                "a shared directory is best effort: leases are lock files whose expiry depends on every instance's clock, and a writer paused past its lease is not stopped",
                            )
                            .with_hint("keep the clocks synchronised (NTP); the control plane's store enforces fencing"),
                        ),
                    },
                    ClusterStoreType::Control => {
                        if store.path.is_some() {
                            self.error("cluster.store.path", "only for `type: directory`");
                        }
                    }
                }
                if !within(store.lease_ttl.as_std(), 10, 600) {
                    self.error("cluster.store.lease_ttl", "must be between 10s and 10m");
                }
                if !within(store.barrier_timeout.as_std(), 1, 120) {
                    self.error("cluster.store.barrier_timeout", "must be between 1s and 2m");
                }
            }
            (None, Some(_)) => {}
        }
    }

    fn check_cluster_challenges(&mut self, cluster: &Cluster) {
        if cluster.effective_store().is_some()
            && let Some(acme) = self.config.effective_acme()
        {
            let shared_answers = acme
                .challenges
                .iter()
                .any(|c| matches!(c, Challenge::Http01 | Challenge::TlsAlpn01));
            let answered_here = self.config.routes.values().any(|r| match &r.tls {
                Some(RouteTls::Mode(TlsMode::Off)) => false,
                Some(RouteTls::Options(o)) => {
                    o.auto && o.dns_provider.is_none() && o.certificate.is_none()
                }
                _ => true,
            });
            if shared_answers && answered_here {
                self.push(
                    Diagnostic::warning(
                        "acme.challenges",
                        "in a cluster, HTTP-01 and TLS-ALPN-01 answers are copied to the members the store knows before validation; an instance cut off from the store that still receives public traffic cannot answer",
                    )
                    .with_hint("DNS-01 (`acme.dns_providers` and `tls.dns_provider`) works from any instance and is the recommendation for clusters"),
                );
            }
        }
    }

    fn check_control_plane(&mut self, control: &ControlPlane) {
        for (i, name) in control.names.iter().enumerate() {
            let ok = name.parse::<IpAddr>().is_ok()
                || (!name.is_empty()
                    && name.len() <= 253
                    && name.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    }));
            if !ok {
                self.error(
                    path_index("control.names", i),
                    "a DNS name or an IP address",
                );
            }
        }
        if let Some(name) = &control.name
            && !is_instance_name(name)
        {
            self.error(
                "control.name",
                "letters, digits, `.`, `-` and `_`, at most 63 characters",
            );
        }
        if !within(control.identity_lifetime.as_std(), 3600, 90 * 24 * 3600) {
            self.error("control.identity_lifetime", "must be between 1h and 90d");
        }
        if !within(control.join_token_ttl.as_std(), 60, 30 * 24 * 3600) {
            self.error("control.join_token_ttl", "must be between 1m and 30d");
        }
        if !(1..=1000).contains(&control.history) {
            self.error("control.history", "must be between 1 and 1000");
        }
        if !within(control.offline_after.as_std(), 10, 3600) {
            self.error("control.offline_after", "must be between 10s and 1h");
        }
        self.check_rollout(&control.rollout);
        if control.listener.ip().is_none_or(|ip| !ip.is_loopback()) && control.names.is_empty() {
            self.push(
                Diagnostic::warning(
                    "control.names",
                    "data planes on other machines must name the control plane as its certificate does",
                )
                .with_hint("list the DNS names or addresses data planes use in `cluster.control.url`"),
            );
        }
    }
}

impl Validator<'_> {
    fn check_rollout(&mut self, rollout: &Rollout) {
        if let Some(canary) = &rollout.canary
            && !is_instance_name(canary)
        {
            self.error(
                "control.rollout.canary",
                "an instance name: letters, digits, `.`, `-` and `_`, at most 63 characters",
            );
        }
        if !within(rollout.soak.as_std(), 0, 24 * 3600) {
            self.error("control.rollout.soak", "must be between 0s and 24h");
        }
        if !within(rollout.canary_timeout.as_std(), 10, 3600) {
            self.error(
                "control.rollout.canary_timeout",
                "must be between 10s and 1h",
            );
        }
        if rollout.mode == RolloutMode::All && rollout.canary.is_some() {
            self.warning(
                "control.rollout.canary",
                "ignored with `mode: all`: every instance takes a revision at once",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cluster::{is_ca_pin, is_instance_name};

    #[test]
    fn names_and_pins() {
        assert!(is_instance_name("edge-1.eu_a"));
        assert!(!is_instance_name(""));
        assert!(!is_instance_name("a/b"));
        assert!(!is_instance_name(&"a".repeat(64)));
        assert!(is_ca_pin(&format!("sha256:{}", "ab".repeat(32))));
        assert!(!is_ca_pin(&format!("sha256:{}", "AB".repeat(32))));
        assert!(!is_ca_pin("sha256:abc"));
        assert!(!is_ca_pin(&"ab".repeat(32)));
    }

    #[test]
    fn redis_addresses() {
        use crate::cluster::RedisAddress;
        let a = RedisAddress::parse("rediss://cache.example.com:6380/2").unwrap();
        assert!(a.tls);
        assert_eq!(
            (a.host.as_str(), a.port, a.database),
            ("cache.example.com", 6380, 2)
        );
        let b = RedisAddress::parse("redis://[::1]").unwrap();
        assert!(!b.tls && b.is_loopback() && b.port == 6379 && b.database == 0);
        assert!(RedisAddress::parse("redis://user:pw@localhost").is_err());
        assert!(RedisAddress::parse("http://localhost").is_err());
        assert!(RedisAddress::parse("redis://localhost/x").is_err());
    }
}
