//! The `tls` app, connection policies and automatic HTTPS.
//!
//! Shapes: <https://caddyserver.com/docs/json/apps/tls/> (certificates, `automation.policies`,
//! issuers `acme`, `internal`, `zerossl`), `…/apps/http/servers/tls_connection_policies/` and
//! `…/apps/http/servers/automatic_https/` (Caddy v2.11.9, read 2026-11-14); how the Caddyfile's
//! `tls cert key` and `tls internal` adapt is from `tls_automation_policies_10`,
//! `tls_conn_policy_consolidate` and `global_options_acme` in `caddytest/integration/caddyfile_adapt/`
//! at v2.11.9. DNS provider fields are the plugin pages under
//! `…/issuers/acme/challenges/dns/provider/` (cloudflare `api_token`, digitalocean `auth_token`,
//! hetzner `auth_api_token`, desec `token`, googleclouddns `gcp_project`,
//! `gcp_application_default`); the route53 page lists no credential fields, so its credentials
//! are always referenced from the standard AWS variables.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::{Notes, Run};
use crate::output::slug;

/// Per-host TLS choices that routes pick up.
#[derive(Debug, Default)]
pub(crate) struct HostTls {
    /// (server or none for every server, SNI names or empty for any, certificate name).
    certs: Vec<(Option<String>, Vec<String>, String)>,
    /// Certificate tags → certificate names.
    tags: BTreeMap<String, String>,
    /// (subjects, DNS provider).
    dns: Vec<(Vec<String>, String)>,
    /// Servers without automatic certificates.
    no_auto: Vec<String>,
    /// Hosts without automatic certificates.
    skip: Vec<String>,
}

fn covers(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|p| {
        p == host
            || p.strip_prefix("*.")
                .is_some_and(|rest| host.split_once('.').is_some_and(|(_, h)| h == rest))
    })
}

impl HostTls {
    /// The route's `tls` for a server and the route's hosts; `None` keeps the default (automatic).
    pub(crate) fn route_tls(
        &self,
        server: &str,
        hosts: &std::collections::BTreeSet<String>,
    ) -> Option<Value> {
        for (scope, names, cert) in &self.certs {
            if scope.as_deref().is_some_and(|s| s != server) {
                continue;
            }
            if names.is_empty() || (!hosts.is_empty() && hosts.iter().all(|h| covers(names, h))) {
                return Some(json!({ "certificate": cert }));
            }
        }
        if self.no_auto.iter().any(|s| s == server)
            || (!hosts.is_empty() && hosts.iter().all(|h| covers(&self.skip, h)))
        {
            return Some(json!({ "auto": false }));
        }
        for (subjects, provider) in &self.dns {
            if !hosts.is_empty() && hosts.iter().all(|h| covers(subjects, h)) {
                return Some(json!({ "dns_provider": provider }));
            }
        }
        None
    }
}

/// Suffixes ReverseDock's local CA certifies (`rdock_tls::PRIVATE_SUFFIXES`, RFC 2606, 6761,
/// 6762, 8375 and `.internal`); kept in step with `crates/rdock-tls/src/request.rs`.
const PRIVATE_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "home.arpa",
    "test",
    "example",
    "invalid",
];

fn local_ca_name(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if let Ok(ip) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
    {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        };
    }
    let name = host.strip_prefix("*.").unwrap_or(host).to_ascii_lowercase();
    PRIVATE_SUFFIXES
        .iter()
        .any(|s| name == *s || name.ends_with(&format!(".{s}")))
}

/// The `tls` app.
#[allow(clippy::too_many_lines)] // one pass, in reading order
pub(crate) fn app(run: &mut Run<'_>, app: &Value) {
    let Value::Object(fields) = app else {
        run.account(
            Some("tls"),
            "/apps/tls",
            Notes::manual_finding("caddy.tls", "the TLS app is not an object"),
        );
        return;
    };
    if let Some(Value::Object(certificates)) = fields.get("certificates") {
        for (loader, value) in certificates {
            let pointer = format!("/apps/tls/certificates/{loader}");
            match loader.as_str() {
                "load_files" => {
                    for (i, pair) in value
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .iter()
                        .enumerate()
                    {
                        let mut notes = Notes::default();
                        let cert = pair
                            .get("certificate")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let key = pair.get("key").and_then(Value::as_str).unwrap_or("");
                        let tags: Vec<String> = pair
                            .get("tags")
                            .and_then(Value::as_array)
                            .map(|a| {
                                a.iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default();
                        let mut target = None;
                        if cert.is_empty()
                            || key.is_empty()
                            || pair
                                .get("format")
                                .and_then(Value::as_str)
                                .is_some_and(|f| f != "pem")
                        {
                            notes.manual("a certificate pair without both PEM files");
                        } else {
                            let stem = cert
                                .rsplit('/')
                                .next()
                                .unwrap_or(cert)
                                .split('.')
                                .next()
                                .unwrap_or("cert");
                            let base = tags.first().cloned().unwrap_or_else(|| slug(stem));
                            let mut name = if base.is_empty() {
                                "certificate".to_owned()
                            } else {
                                base
                            };
                            let mut n = 2;
                            while run.certificates.contains_key(&name) {
                                name = format!(
                                    "{}-{n}",
                                    tags.first().cloned().unwrap_or_else(|| slug(stem))
                                );
                                n += 1;
                            }
                            run.certificates.insert(
                                name.clone(),
                                json!({ "cert_file": cert, "key_file": key }),
                            );
                            for tag in &tags {
                                run.tls.tags.insert(tag.clone(), name.clone());
                            }
                            notes.exact(format!("certificate files → `certificates.{name}` (the files are named, never read)"));
                            if tags.is_empty() {
                                notes.approx("served wherever its names match the requested name; routes still get automatic certificates unless they name it (`tls.certificate`)");
                            }
                            target = Some(format!("certificates.{name}"));
                        }
                        run.account(
                            Some("tls"),
                            &format!("{pointer}/{i}"),
                            notes.finding("caddy.tls", target.as_deref()),
                        );
                    }
                }
                "load_pem" => {
                    let mut notes = Notes::default();
                    notes.manual("certificates and private keys written inline in the configuration are never copied");
                    notes.hint("store them as files and list them under `certificates` (`cert_file`, `key_file`)");
                    notes.security();
                    let id = run.item(Some("tls"), &pointer);
                    run.b.account(id, crate::report::Finding::new("caddy.tls.credentials", "certificates and private keys written inline in the configuration (`load_pem`) are never copied").hint("store them as files and list them under `certificates` (`cert_file`, `key_file`)").security());
                    let _ = notes;
                }
                "automate" => {
                    let mut notes = Notes::default();
                    notes.exact("names with automatic certificates: ReverseDock obtains certificates for the hosts of its routes");
                    run.account(Some("tls"), &pointer, notes.finding("caddy.tls", None));
                }
                other => {
                    let mut notes = Notes::default();
                    notes.manual(format!("certificate loader `{other}` has no equivalent"));
                    notes.hint("list the certificate and key files under `certificates`");
                    run.account(Some("tls"), &pointer, notes.finding("caddy.tls", None));
                }
            }
        }
    }
    for (key, value) in fields {
        let pointer = format!("/apps/tls/{key}");
        match key.as_str() {
            "certificates" => {}
            "automation" => automation(run, value),
            "session_tickets" => {
                let mut notes = Notes::default();
                if value.get("disabled") == Some(&json!(true)) {
                    notes.approx(
                        "session tickets are on in ReverseDock (`listeners.<name>.tls.tickets`)",
                    );
                } else {
                    notes.approx("ReverseDock rotates its own ticket keys (`listeners.<name>.tls.tickets`); Caddy's key source and rotation settings are not carried over");
                }
                run.account(Some("tls"), &pointer, notes.finding("caddy.tls", None));
            }
            other => {
                let mut notes = Notes::default();
                notes.dropped(format!("`{other}` of the TLS app has no equivalent"));
                run.account(Some("tls"), &pointer, notes.finding("caddy.tls", None));
            }
        }
    }
}

fn automation(run: &mut Run<'_>, value: &Value) {
    for (key, item) in value.as_object().cloned().unwrap_or_default() {
        let pointer = format!("/apps/tls/automation/{key}");
        if key == "policies" {
            for (i, policy) in item
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                self::policy(run, policy, &format!("{pointer}/{i}"));
            }
            continue;
        }
        let mut notes = Notes::default();
        match key.as_str() {
            "on_demand" => {
                notes.manual("on-demand TLS has no equivalent: ReverseDock obtains certificates for the hosts its routes name");
                notes.hint("list the hosts in routes (wildcards need DNS-01)");
            }
            "ocsp_interval" | "renew_interval" | "storage_clean_interval" => {
                notes.dropped(format!(
                    "`{key}`: ReverseDock's renewal and OCSP schedule is fixed"
                ));
            }
            other => notes.dropped(format!("automation setting `{other}` has no equivalent")),
        }
        run.account(Some("tls"), &pointer, notes.finding("caddy.tls", None));
    }
}

/// Let's Encrypt's, ZeroSSL's and Google's ACME directories, by the name ReverseDock uses.
fn known_ca(url: &str) -> Option<(&'static str, bool)> {
    match url.trim_end_matches('/') {
        "https://acme-v02.api.letsencrypt.org/directory" => Some(("letsencrypt", false)),
        "https://acme-staging-v02.api.letsencrypt.org/directory" => Some(("letsencrypt", true)),
        "https://acme.zerossl.com/v2/DV90" => Some(("zerossl", false)),
        "https://dv.acme-v02.api.pki.goog/directory" => Some(("google", false)),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)] // one block per policy field and issuer field
fn policy(run: &mut Run<'_>, policy: &Value, pointer: &str) {
    let subjects: Vec<String> = policy
        .get("subjects")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    let mut notes = Notes::default();
    for (key, value) in policy.as_object().cloned().unwrap_or_default() {
        match key.as_str() {
            "subjects" => notes.exact(if subjects.is_empty() {
                "applies to every name".to_owned()
            } else {
                format!("applies to {}", subjects.join(", "))
            }),
            "issuers" => {
                for (j, issuer) in value
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .enumerate()
                {
                    self::issuer(run, issuer, &subjects, &format!("{pointer}/issuers/{j}"));
                }
            }
            "on_demand" if value == json!(true) => {
                notes.manual("on-demand certificates have no equivalent");
                notes.hint("list the hosts in routes (wildcards need DNS-01)");
            }
            "key_type" => notes.approx(format!(
                "key type `{}`: ReverseDock chooses the key type itself (ECDSA P-256)",
                value.as_str().unwrap_or("?")
            )),
            "storage" => notes.manual("a storage module per policy has no equivalent"),
            "get_certificate" => {
                notes.manual(
                    "getting certificates from another service at handshake time has no equivalent",
                );
            }
            "must_staple"
            | "renewal_window_ratio"
            | "reuse_private_keys"
            | "disable_ocsp_stapling"
            | "ocsp_overrides"
            | "on_demand" => {
                notes.dropped(format!("`{key}`: ReverseDock's choice is fixed"));
            }
            other => notes.dropped(format!("policy setting `{other}` has no equivalent")),
        }
    }
    run.account(
        Some("tls"),
        pointer,
        notes.finding("caddy.tls", Some("acme")),
    );
}

fn issuer(run: &mut Run<'_>, issuer: &Value, subjects: &[String], pointer: &str) {
    let module = issuer.get("module").and_then(Value::as_str).unwrap_or("");
    let mut notes = Notes::default();
    let mut credentials = false;
    match module {
        "acme" => credentials = acme(run, issuer, subjects, &mut notes),
        "internal" => {
            if !subjects.is_empty() && subjects.iter().all(|s| local_ca_name(s)) {
                notes.exact("Caddy's internal CA for private names → ReverseDock's local CA, which signs these names automatically (`rdock trust` installs its root)");
            } else {
                notes.manual(format!(
                    "Caddy's internal CA for {}: ReverseDock's local CA signs only private names (`.localhost`, `.internal`, `.test`, private addresses …)",
                    if subjects.is_empty() { "every name".to_owned() } else { subjects.join(", ") }
                ));
                notes.hint("use public certificates (the default), or certificate files under `certificates`");
            }
            if issuer.get("lifetime").is_some()
                || issuer.get("ca").is_some()
                || issuer.get("sign_with_root").is_some()
            {
                notes.approx("the internal CA's settings (`ca`, `lifetime`, `sign_with_root`) are not carried over");
            }
        }
        "zerossl" => {
            notes.manual("the ZeroSSL API issuer needs an API key, which is never copied; ReverseDock speaks ACME to ZeroSSL with external account binding");
            notes.hint("set `acme.ca: zerossl` and `acme.eab` with the key ID and HMAC key from ZeroSSL as `${env:…}` references");
            notes.security();
        }
        other => notes.manual(format!("issuer `{other}` has no equivalent")),
    }
    let target = (module == "acme").then_some("acme");
    let finding = if notes.is_manual() && (module == "zerossl" || credentials) {
        notes.finding_as("caddy.tls.credentials", target)
    } else {
        notes.finding("caddy.tls", target)
    };
    run.account(Some("tls"), pointer, finding);
}

/// A credential value: `{env.NAME}` becomes `${env:NAME}`; anything else is replaced by a
/// reference to `fallback` (the value is never copied). Returns (value, copied reference?).
fn credential(value: &Value, fallback: &str) -> (String, bool) {
    if let Some(name) = value
        .as_str()
        .and_then(|v| v.strip_prefix("{env."))
        .and_then(|v| v.strip_suffix('}'))
    {
        return (format!("${{env:{name}}}"), true);
    }
    (format!("${{env:{fallback}}}"), false)
}

#[allow(clippy::too_many_lines)] // one block per issuer field
/// An ACME issuer → `acme`; returns whether a credential was replaced by a reference.
fn acme(run: &mut Run<'_>, issuer: &Value, subjects: &[String], notes: &mut Notes) -> bool {
    let mut account_key = false;
    let mut acme = Map::new();
    let mut credentials = Vec::new();
    for (key, value) in issuer.as_object().cloned().unwrap_or_default() {
        match key.as_str() {
            "module" => {}
            "ca" => match value.as_str().and_then(known_ca) {
                Some((name, staging)) => {
                    if name != "letsencrypt" {
                        acme.insert("ca".to_owned(), json!(name));
                    }
                    if staging {
                        acme.insert("staging".to_owned(), json!(true));
                    }
                }
                None => {
                    acme.insert("ca".to_owned(), value.clone());
                }
            },
            "test_ca" => notes.approx("the fallback test CA (`test_ca`) has no equivalent"),
            "email" => {
                acme.insert("email".to_owned(), value.clone());
            }
            "external_account" => {
                let key_id = value.get("key_id").cloned().unwrap_or(Value::Null);
                let (hmac, referenced) = credential(value.get("mac_key").unwrap_or(&Value::Null), "ACME_EAB_HMAC_KEY");
                acme.insert("eab".to_owned(), json!({ "key_id": key_id, "hmac_key": hmac }));
                if !referenced {
                    credentials.push("ACME_EAB_HMAC_KEY".to_owned());
                }
            }
            "account_key" => {
                notes.manual("the ACME account key is never copied: ReverseDock creates its own account");
                notes.security();
                account_key = true;
            }
            "challenges" => challenges(run, &value, subjects, &mut acme, &mut credentials, notes),
            "trusted_roots_pem_files" => match value.as_array().map(Vec::as_slice) {
                Some([file]) => {
                    acme.insert("ca_root".to_owned(), file.clone());
                }
                _ => notes.manual("several trusted roots for the ACME CA: `acme.ca_root` names one file (concatenate them)"),
            },
            "preferred_chains" | "acme_timeout" => notes.approx(format!("`{key}` has no equivalent")),
            "certificate_lifetime" => notes.approx("the certificate lifetime is chosen by the CA profile (`acme.profile`) here"),
            other => notes.approx(format!("ACME setting `{other}` has no equivalent")),
        }
    }
    let mut conflicts = Vec::new();
    for (k, v) in acme {
        if k == "dns_providers" {
            let providers = run
                .acme
                .entry("dns_providers".to_owned())
                .or_insert_with(|| json!({}));
            if let (Value::Object(target), Value::Object(new)) = (providers, v) {
                target.extend(new);
            }
        } else if k == "challenges" {
            // The union of the challenge types every issuer allows.
            let mut list: Vec<Value> = run
                .acme
                .get("challenges")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for c in v.as_array().cloned().unwrap_or_default() {
                if !list.contains(&c) {
                    list.push(c);
                }
            }
            run.acme.insert(k, Value::Array(list));
        } else {
            match run.acme.get(&k) {
                None => {
                    run.acme.insert(k, v);
                }
                Some(existing) if *existing == v => {}
                Some(_) => conflicts.push(k),
            }
        }
    }
    if !conflicts.is_empty() {
        notes.manual(format!("an ACME issuer whose {} differ from an earlier issuer's: ReverseDock has one ACME account (`acme`), and the earlier settings are written", conflicts.iter().map(|c| format!("`{c}`")).collect::<Vec<_>>().join(", ")));
    }
    if credentials.is_empty() {
        notes.exact("ACME issuer → `acme` (with `--full`)");
        account_key
    } else {
        credentials.sort();
        credentials.dedup();
        notes.manual(format!(
            "credentials are never copied: the output reads them from {}",
            credentials
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        notes.hint(format!(
            "set {} in ReverseDock's environment (or use `${{file:…}}` references)",
            credentials.join(", ")
        ));
        notes.security();
        true
    }
}

/// A Caddy DNS plugin and the adapter it maps to: (plugin, our type, [(our field, plugin field,
/// default variable, secret)]).
type DnsAdapter = (
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str, &'static str, bool)],
);

#[allow(clippy::too_many_lines)] // one pass, in reading order
fn challenges(
    run: &mut Run<'_>,
    value: &Value,
    subjects: &[String],
    acme: &mut Map<String, Value>,
    credentials: &mut Vec<String>,
    notes: &mut Notes,
) {
    let mut list = Vec::new();
    if value.pointer("/http/disabled") != Some(&json!(true)) {
        list.push("http-01");
    }
    if value.pointer("/tls-alpn/disabled") != Some(&json!(true)) {
        list.push("tls-alpn-01");
    }
    for key in ["/http/alternate_port", "/tls-alpn/alternate_port"] {
        if value.pointer(key).is_some() {
            notes.approx("challenge ports follow the listeners here (`web`, `websecure`)");
        }
    }
    if let Some(dns) = value.get("dns") {
        let name = dns
            .pointer("/provider/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let provider = dns.get("provider").cloned().unwrap_or(Value::Null);
        // (Caddy plugin name, our type, [(our field, Caddy field, default variable, secret)]).
        let table: [DnsAdapter; 6] = [
            (
                "cloudflare",
                "cloudflare",
                &[("api_token", "api_token", "CF_API_TOKEN", true)],
            ),
            (
                "digitalocean",
                "digitalocean",
                &[("api_token", "auth_token", "DO_AUTH_TOKEN", true)],
            ),
            (
                "hetzner",
                "hetzner",
                &[("api_token", "auth_api_token", "HETZNER_API_TOKEN", true)],
            ),
            ("desec", "desec", &[("token", "token", "DESEC_TOKEN", true)]),
            (
                "route53",
                "route53",
                &[
                    ("access_key_id", "", "AWS_ACCESS_KEY_ID", true),
                    ("secret_access_key", "", "AWS_SECRET_ACCESS_KEY", true),
                    ("region", "", "AWS_REGION", false),
                ],
            ),
            (
                "googleclouddns",
                "google_cloud_dns",
                &[
                    ("project", "gcp_project", "GCE_PROJECT", false),
                    (
                        "credentials_file",
                        "gcp_application_default",
                        "GCE_SERVICE_ACCOUNT_FILE",
                        false,
                    ),
                ],
            ),
        ];
        if let Some((_, kind, fields)) = table.iter().find(|(caddy, ..)| *caddy == name) {
            let mut settings = Map::new();
            settings.insert("type".to_owned(), json!(kind));
            for (ours, theirs, var, secret) in *fields {
                let given = if theirs.is_empty() {
                    None
                } else {
                    provider.get(*theirs)
                };
                match given {
                    Some(v) if !*secret && v.as_str().is_some_and(|s| !s.contains('{')) => {
                        settings.insert((*ours).to_owned(), v.clone());
                    }
                    Some(v) => {
                        let (reference, copied) = credential(v, var);
                        if !copied {
                            credentials.push((*var).to_owned());
                        }
                        settings.insert((*ours).to_owned(), json!(reference));
                    }
                    None => {
                        settings.insert((*ours).to_owned(), json!(format!("${{env:{var}}}")));
                        credentials.push((*var).to_owned());
                    }
                }
            }
            acme.insert("dns_providers".to_owned(), json!({ name: settings }));
            list.push("dns-01");
            if subjects.is_empty() {
                acme.insert("dns_provider".to_owned(), json!(name));
            } else {
                run.tls.dns.push((subjects.to_vec(), name.to_owned()));
            }
            notes.exact(format!(
                "DNS-01 with `{name}` → `acme.dns_providers.{name}` (type `{kind}`)"
            ));
        } else {
            notes.manual(format!("DNS provider `{name}` has no adapter here (Cloudflare, deSEC, Route 53, Google Cloud DNS, Azure DNS, DigitalOcean, Hetzner, RFC 2136, exec, webhook)"));
            notes.hint("configure `acme.dns_providers` by hand");
        }
        if let Some(r) = dns.get("resolvers") {
            acme.insert("dns_resolvers".to_owned(), r.clone());
        }
        if let Some(t) = dns
            .get("propagation_timeout")
            .and_then(super::handlers::duration)
        {
            acme.insert("dns_propagation_timeout".to_owned(), json!(t));
        }
        for key in ["ttl", "propagation_delay", "override_domain"] {
            if dns.get(key).is_some() {
                notes.approx(format!("DNS challenge `{key}` has no equivalent"));
            }
        }
    }
    if value.get("bind_host").is_some() {
        notes.approx("`bind_host` for challenges has no equivalent: challenges use the listeners");
    }
    if list.len() < 3 || value.get("dns").is_none() {
        acme.insert("challenges".to_owned(), json!(list));
    }
}

/// `automatic_https` of a server.
pub(crate) fn automatic_https(run: &mut Run<'_>, server: &str, pointer: &str, value: &Value) {
    let mut notes = Notes::default();
    let mut target = None;
    for (key, item) in value.as_object().cloned().unwrap_or_default() {
        match key.as_str() {
            "disable" if item == json!(true) => {
                run.tls.no_auto.push(server.to_owned());
                run.defaults
                    .insert("redirect_http_to_https".to_owned(), json!(false));
                target = Some("defaults.redirect_http_to_https");
                notes.approx("automatic HTTPS off: the server's routes get no automatic certificates (`tls.auto: false`), and the HTTP-to-HTTPS redirect is off (`defaults.redirect_http_to_https: false`, global, with `--full`)");
            }
            "disable_redirects" if item == json!(true) => {
                run.defaults
                    .insert("redirect_http_to_https".to_owned(), json!(false));
                target = Some("defaults.redirect_http_to_https");
                notes.approx("the HTTP-to-HTTPS redirect is off: `defaults.redirect_http_to_https: false` (global, with `--full`)");
            }
            "disable_certificates" if item == json!(true) => {
                run.tls.no_auto.push(server.to_owned());
                notes.exact("no automatic certificates: the server's routes get `tls.auto: false`");
            }
            "skip" | "skip_certificates" => {
                let hosts: Vec<String> = item
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_ascii_lowercase)
                            .collect()
                    })
                    .unwrap_or_default();
                run.tls.skip.extend(hosts.iter().cloned());
                notes.approx(format!(
                    "{} get no automatic certificate (`tls.auto: false`){}",
                    hosts.join(", "),
                    if key == "skip" {
                        "; their HTTP-to-HTTPS redirect still applies"
                    } else {
                        ""
                    }
                ));
            }
            "ignore_loaded_certificates" | "prefer_wildcard" => {
                notes.approx(format!("`{key}` has no equivalent"));
            }
            other => notes.exact(format!("`{other}` is off, as by default")),
        }
    }
    run.account(Some(server), pointer, notes.finding("caddy.server", target));
}

/// `tls_connection_policies` of a server → listener TLS settings and per-host certificates.
pub(crate) fn connection_policies(
    run: &mut Run<'_>,
    server: &str,
    pointer: &str,
    value: &Value,
    listeners: &[String],
) {
    for (i, policy) in value
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let mut notes = Notes::default();
        let sni: Vec<String> = policy
            .pointer("/match/sni")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_ascii_lowercase)
                    .collect()
            })
            .unwrap_or_default();
        for (key, item) in policy.as_object().cloned().unwrap_or_default() {
            match key.as_str() {
                "match" => {
                    let others: Vec<&String> = item.as_object().map(|m| m.keys().filter(|k| *k != "sni").collect()).unwrap_or_default();
                    if others.is_empty() {
                        notes.exact("matched by server name");
                    } else {
                        notes.manual("a connection policy matched by something other than the server name has no equivalent");
                    }
                }
                "certificate_selection" => {
                    let tags: Vec<String> = item.get("any_tag").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
                    match tags.iter().find_map(|t| run.tls.tags.get(t).cloned()) {
                        Some(cert) => {
                            run.tls.certs.push((Some(server.to_owned()), sni.clone(), cert.clone()));
                            notes.exact(format!("routes for {} use `certificates.{cert}` (`tls.certificate`)", if sni.is_empty() { "every name".to_owned() } else { sni.join(", ") }));
                        }
                        None => notes.manual("a certificate selection other than a tag of loaded certificate files has no equivalent"),
                    }
                }
                "protocol_min" => match item.as_str() {
                    Some("tls1.3") => {
                        set_policy(run, listeners, "modern");
                        if sni.is_empty() {
                            notes.exact("TLS 1.3 only → `tls.policy: modern` on the listener");
                        } else {
                            notes.approx("TLS 1.3 only → `tls.policy: modern` on the whole listener, also for the names of other connection policies");
                        }
                    }
                    Some("tls1.2") => notes.exact("TLS 1.2 and 1.3, ReverseDock's default (`intermediate`)"),
                    Some(other) => {
                        notes.manual(format!("minimum `{other}` is weaker than ReverseDock's floor (TLS 1.2) and is not written"));
                        notes.security();
                    }
                    None => notes.manual("not a protocol version"),
                },
                "protocol_max" => notes.approx("the maximum TLS version is always 1.3 here"),
                "cipher_suites" | "curves" => notes.approx(format!("`{key}`: TLS settings are two presets here (`intermediate`, `modern`); the listener keeps `intermediate`")),
                "alpn" => notes.approx("ALPN protocols follow the listener's HTTP versions"),
                "client_authentication" => client_auth(run, &item, listeners, &mut notes),
                "default_sni" | "fallback_sni" => notes.approx(format!("`{key}`: `defaults.certificate` names the certificate served when no other matches")),
                "insecure_secrets_log" => {
                    notes.dropped("the TLS key log is not written (it would let anyone decrypt the traffic)");
                    notes.security();
                }
                "drop" => notes.manual("dropping TLS connections by policy has no equivalent"),
                other => notes.manual(format!("connection policy setting `{other}` has no equivalent")),
            }
        }
        if policy.as_object().is_some_and(Map::is_empty) {
            notes.exact("TLS with the defaults");
        }
        run.account(
            Some(server),
            &format!("{pointer}/{i}"),
            notes.finding("caddy.server", Some("listeners")),
        );
    }
}

fn set_policy(run: &mut Run<'_>, listeners: &[String], policy: &str) {
    for l in listeners {
        if let Some(listener) = run.listeners.get_mut(l)
            && listener.get("tls").is_some()
        {
            listener["tls"]["policy"] = json!(policy);
        }
    }
}

fn client_auth(run: &mut Run<'_>, item: &Value, listeners: &[String], notes: &mut Notes) {
    let mode = item
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("require_and_verify");
    let mut files: Vec<Value> = item
        .get("trusted_ca_certs_pem_files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(ca) = item.get("ca") {
        if ca.get("provider").and_then(Value::as_str) == Some("file") {
            files.extend(
                ca.get("pem_files")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
            );
        } else {
            notes.manual("a client CA pool other than PEM files has no equivalent");
            return;
        }
    }
    let ours = match mode {
        "require_and_verify" => "required",
        "verify_if_given" => "optional",
        other => {
            notes.manual(format!(
                "client authentication mode `{other}` (no verification) has no equivalent"
            ));
            notes.security();
            return;
        }
    };
    if files.is_empty() {
        notes.manual("client authentication without CA files (inline certificates are not copied)");
        return;
    }
    for l in listeners {
        if let Some(listener) = run.listeners.get_mut(l)
            && listener.get("tls").is_some()
        {
            listener["tls"]["client_auth"] = json!({ "mode": ours, "ca_files": files });
        }
    }
    notes.approx(format!("client certificates `{ours}` → `listeners.<name>.tls.client_auth` (per listener here, per connection policy in Caddy)"));
}
