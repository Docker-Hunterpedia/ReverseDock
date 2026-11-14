//! Edge security (H-SEC-03, H-SEC-04, ADR-0031): TLS client fingerprints and GeoIP.

use rdock_rules::Expr;

use super::Validator;
use crate::config::ListenerProtocol;
use crate::diagnostics::Diagnostic;
use crate::diagnostics::path_key;
use crate::route::Route;

impl Validator<'_> {
    /// `listeners.<l>.tls.fingerprint` and `geoip`.
    pub(super) fn check_edge(&mut self) {
        let listeners = self.listeners.clone();
        for (name, listener) in &listeners {
            let Some(fp) = listener.tls.as_ref().and_then(|t| t.fingerprint.as_ref()) else {
                continue;
            };
            let path = format!("{}.tls.fingerprint", path_key("listeners", name));
            if listener.effective_protocol() != ListenerProtocol::Https {
                self.error(
                    &path,
                    "TLS fingerprints are computed by `https` listeners only; TCP routes compute JA4 by themselves when a rule uses `ClientFingerprint`",
                );
            }
            if !fp.ja4 && !fp.ja3 {
                self.warning(&path, "neither `ja4` nor `ja3` is on: nothing is computed");
            }
            if fp.ja3_header.is_some() && !fp.ja3 {
                self.error(format!("{path}.ja3_header"), "needs `ja3: true`");
            }
            if fp.header.is_some() && !fp.ja4 {
                self.error(format!("{path}.header"), "needs `ja4: true`");
            }
            for (field, header) in [("header", &fp.header), ("ja3_header", &fp.ja3_header)] {
                if let Some(header) = header
                    && !crate::values::is_token(header)
                {
                    self.error(
                        format!("{path}.{field}"),
                        format!("`{header}` is not a valid header name"),
                    );
                }
            }
            if fp.header.is_some()
                && fp
                    .header
                    .as_deref()
                    .zip(fp.ja3_header.as_deref())
                    .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            {
                self.error(format!("{path}.ja3_header"), "must differ from `header`");
            }
        }
        if let Some(geoip) = &self.config.geoip {
            if geoip.max_age.is_zero() {
                self.error("geoip.max_age", "must be more than zero");
            }
            if geoip.database.is_none() && geoip.asn_database.is_none() {
                self.warning(
                    "geoip",
                    "neither `database` nor `asn_database` is set: GeoIP matchers cannot be used",
                );
            }
            if (geoip.log.country && geoip.database.is_none())
                || (geoip.log.asn && geoip.database.is_none() && geoip.asn_database.is_none())
            {
                self.warning("geoip.log", "the database for this field is not configured");
            }
        }
        for (name, route) in &self.config.tcp_routes {
            if let Ok(expr) = rdock_rules::parse(&route.matcher) {
                self.check_geo_rule(&format!("{}.match", path_key("tcp_routes", name)), &expr);
            }
        }
        for (name, route) in &self.config.udp_routes {
            if let Some(Ok(expr)) = route.matcher.as_deref().map(rdock_rules::parse) {
                self.check_geo_rule(&format!("{}.match", path_key("udp_routes", name)), &expr);
            }
        }
    }

    /// An HTTP route's `ClientFingerprint` and GeoIP matchers.
    pub(super) fn check_route_edge(&mut self, path: &str, route: &Route, expr: Option<&Expr>) {
        let Some(expr) = expr else {
            return;
        };
        let match_path = format!("{path}.match");
        self.check_geo_rule(&match_path, expr);
        if !expr.uses_fingerprint() {
            return;
        }
        let attached = self.config.route_listeners(route);
        let computes = attached.iter().any(|l| {
            self.listeners
                .get(l)
                .and_then(|l| l.tls.as_ref())
                .is_some_and(|t| t.fingerprint.as_ref().is_some_and(|f| f.ja4 || f.ja3))
        });
        if !computes {
            self.push(
                Diagnostic::error(
                    match_path,
                    "`ClientFingerprint` needs a listener of this route that computes fingerprints; it would never match",
                )
                .with_hint("set `tls.fingerprint: {}` on the route's https listener"),
            );
        }
    }

    /// `type: abuse`.
    pub(super) fn check_abuse(&mut self, path: &str, abuse: &crate::middleware::AbuseConfig) {
        use crate::middleware::{AbuseAction, AbuseKey};
        if abuse.events.is_empty() {
            self.error(format!("{path}.events"), "list at least one event");
        }
        if abuse.threshold == 0 {
            self.error(format!("{path}.threshold"), "must be at least 1");
        }
        for (field, value) in [("window", abuse.window), ("ban", abuse.ban)] {
            if value.as_std().as_secs() == 0 {
                self.error(format!("{path}.{field}"), "must be at least 1s");
            }
        }
        if abuse.ban.as_std().as_secs() > 30 * 86_400 {
            self.error(format!("{path}.ban"), "must be at most 30d");
        }
        if !(100..=10_000_000).contains(&abuse.max_keys) {
            self.error(
                format!("{path}.max_keys"),
                "must be between 100 and 10000000",
            );
        }
        if !(1..=1_000_000).contains(&abuse.max_bans) {
            self.error(format!("{path}.max_bans"), "must be between 1 and 1000000");
        }
        if abuse.action == AbuseAction::Tarpit {
            let delay = abuse.tarpit.delay.as_std();
            if delay.is_zero() || delay.as_secs() > 60 {
                self.error(
                    format!("{path}.tarpit.delay"),
                    "must be between 1ms and 60s",
                );
            }
            if abuse.tarpit.max_held == 0 {
                self.error(format!("{path}.tarpit.max_held"), "must be at least 1");
            }
        }
        if let AbuseKey::Header(name) = &abuse.key
            && abuse.action != AbuseAction::Tag
        {
            self.push(
                Diagnostic::warning(
                    format!("{path}.key"),
                    format!("the client chooses `{name}`: a ban by it is evaded by changing the header, and every new value takes a counter"),
                )
                .with_hint("count by `client_ip` or `consumer`, or use `action: tag`"),
            );
        }
        if abuse.key == AbuseKey::Ja4 && abuse.action != AbuseAction::Tag {
            self.push(fingerprint_warning(&format!("{path}.key"), "ban"));
        }
    }

    /// `client_cert` typed lists and `spiffe` (H-SEC-05).
    pub(super) fn check_client_cert_identity(
        &mut self,
        path: &str,
        c: &crate::middleware::ClientCertConfig,
    ) {
        for (field, list) in [
            ("subjects", &c.subjects),
            ("organizations", &c.organizations),
            ("dns", &c.dns),
            ("uris", &c.uris),
            ("emails", &c.emails),
        ] {
            if list.iter().any(|p| p.trim().is_empty()) {
                self.error(format!("{path}.{field}"), "a pattern is empty");
            }
        }
        for (field, list, len) in [
            ("serials", &c.serials, None),
            ("sha256", &c.sha256, Some(64)),
        ] {
            for value in list {
                let hex = value.replace(':', "");
                if hex.is_empty()
                    || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                    || len.is_some_and(|n| hex.len() != n)
                {
                    self.error(
                        format!("{path}.{field}"),
                        format!(
                            "`{value}` is not a hexadecimal {}",
                            if len.is_some() {
                                "SHA-256 (64 digits)"
                            } else {
                                "serial number"
                            }
                        ),
                    );
                }
            }
        }
        let Some(spiffe) = &c.spiffe else {
            return;
        };
        let spath = format!("{path}.spiffe");
        if spiffe.trust_domains.is_empty() {
            self.error(
                format!("{spath}.trust_domains"),
                "list at least one trust domain",
            );
        }
        for domain in &spiffe.trust_domains {
            let valid = !domain.is_empty()
                && domain.len() <= 255
                && domain
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
            if !valid {
                self.error(
                    format!("{spath}.trust_domains"),
                    format!("`{domain}` is not a trust domain name (lower case [a-z0-9._-], no scheme or port)"),
                );
            }
        }
        for (field, list) in [("ids", &spiffe.ids), ("id_prefixes", &spiffe.id_prefixes)] {
            for id in list {
                let domain = id
                    .strip_prefix("spiffe://")
                    .map(|rest| rest.split('/').next().unwrap_or_default());
                match domain {
                    Some(d) if spiffe.trust_domains.iter().any(|t| t == d) => {}
                    Some(_) => self.error(
                        format!("{spath}.{field}"),
                        format!("`{id}` is not in one of `trust_domains`"),
                    ),
                    None => self.error(
                        format!("{spath}.{field}"),
                        format!("`{id}` is not a SPIFFE ID (`spiffe://<trust domain>/<path>`)"),
                    ),
                }
            }
        }
        if !c.required {
            self.warning(
                &spath,
                "`spiffe` is checked only when a certificate is sent, because `required` is false",
            );
        }
    }

    /// GeoIP matchers need a database.
    fn check_geo_rule(&mut self, path: &str, expr: &Expr) {
        let geoip = self.config.geoip.as_ref();
        for m in expr.matchers() {
            let configured = match m {
                rdock_rules::Matcher::ClientCountry(_)
                | rdock_rules::Matcher::ClientContinent(_) => {
                    geoip.is_some_and(|g| g.database.is_some())
                }
                rdock_rules::Matcher::ClientAsn(_) => {
                    geoip.is_some_and(|g| g.database.is_some() || g.asn_database.is_some())
                }
                _ => continue,
            };
            if !configured {
                self.push(
                    Diagnostic::error(
                        path,
                        format!(
                            "`{}` needs a GeoIP database, and none is configured",
                            m.name()
                        ),
                    )
                    .with_hint(
                        if matches!(m, rdock_rules::Matcher::ClientAsn(_)) {
                            "set `geoip.asn_database` (or a `geoip.database` that carries ASNs)"
                        } else {
                            "set `geoip.database` to a country database in the MaxMind DB format"
                        },
                    ),
                );
            }
        }
    }
}

/// A ban or limit by a TLS fingerprint alone: one JA4 is shared by every user of a client
/// build, and anyone can send it (`curl-impersonate`, uTLS).
pub(super) fn fingerprint_warning(path: &str, what: &str) -> Diagnostic {
    Diagnostic::warning(
        path,
        format!("a {what} by `ja4` alone hits every client with the same TLS stack (all users of one browser version share a JA4), and an attacker can copy a fingerprint to get it applied to them"),
    )
    .with_hint("count by `client_ip` or `consumer`, and use the fingerprint to tag (`action: tag`) or in a route rule together with the address")
}
