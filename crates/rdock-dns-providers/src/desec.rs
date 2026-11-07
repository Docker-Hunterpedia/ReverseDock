//! DNS-01 through the deSEC API (W-DNS-03). A TXT RRset holds all its values, so present and
//! cleanup read the RRset, change its `records` and write it back, under the zone's lock;
//! `records: []` deletes it. deSEC limits RRset writes per domain (2/s, 15/min, 100/h, 300/day),
//! so a value already present costs no write, and `429` answers are retried after their
//! `Retry-After`.
//!
//! API: <https://desec.readthedocs.io/en/latest/dns/rrsets.html>,
//! <https://desec.readthedocs.io/en/latest/dns/domains.html> and
//! <https://desec.readthedocs.io/en/latest/rate-limits.html> (checked 2026-11-07).

use std::sync::Arc;

use async_trait::async_trait;
use rdock_acme::dns::{DnsError, DnsSolver};
use rdock_model::acme::DesecProvider;
use serde_json::{Value, json};

use crate::lock::ZoneLocks;
use crate::rest::{ErrorFormat, RestClient, RestError, StaticToken, form, segment};
use crate::zone::{ZoneFinder, normalize, relative_name};

/// The deSEC API.
pub const API: &str = "https://desec.io/api/v1";
/// TTL of a new RRset when the domain does not state its `minimum_ttl`; lego's default.
const FALLBACK_TTL: u64 = 3600;

/// deSEC for one token.
#[derive(Debug)]
pub struct DesecDns {
    api: RestClient,
    zones: ZoneFinder,
    locks: ZoneLocks,
}

impl DesecDns {
    /// The provider for `config`, calling `api_url` when set (tests) and [`API`] otherwise.
    pub fn new(config: &DesecProvider) -> Result<Self, DnsError> {
        let base = config
            .api_url
            .as_ref()
            .map_or(API, |url| url.as_url().as_str());
        Ok(Self {
            api: RestClient::with(
                "deSEC API",
                base,
                Arc::new(StaticToken::new("Token", &config.token, "token")),
                ErrorFormat::Json(error_message),
            )?,
            zones: ZoneFinder::new(config.zone.as_deref()),
            locks: ZoneLocks::default(),
        })
    }

    /// The domain responsible for `fqdn`, asked with `owns_qname`.
    async fn zone(&self, fqdn: &str) -> Result<String, DnsError> {
        self.zones
            .zone_of("deSEC", fqdn, |name| async move {
                let path = format!("/domains/?{}", form(&[("owns_qname", &name)]));
                let domains = self.api.get(&path).await?;
                Ok(domains
                    .as_array()
                    .and_then(|domains| domains.first())
                    .and_then(|domain| domain["name"].as_str())
                    .map(str::to_owned))
            })
            .await
    }

    /// The records of the TXT RRset at `fqdn`, as stored (quoted), or `None` without one.
    async fn records(&self, zone: &str, fqdn: &str) -> Result<Option<Vec<String>>, RestError> {
        match self.api.get(&rrset_path(zone, fqdn)).await {
            Ok(rrset) => Ok(Some(
                rrset["records"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            )),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Creates the RRset at `fqdn` with one record and the domain's smallest allowed TTL.
    async fn create(&self, zone: &str, fqdn: &str, record: String) -> Result<(), RestError> {
        let domain = self
            .api
            .get(&format!("/domains/{}/", segment(zone)))
            .await?;
        let ttl = domain["minimum_ttl"].as_u64().unwrap_or(FALLBACK_TTL);
        let subname = match relative_name(fqdn, zone).as_str() {
            "@" => String::new(),
            relative => relative.to_owned(),
        };
        let body = json!({ "subname": subname, "type": "TXT", "ttl": ttl, "records": [record] });
        self.api
            .post(&format!("/domains/{}/rrsets/", segment(zone)), &body)
            .await?;
        Ok(())
    }

    /// Replaces the records of the RRset at `fqdn`; none deletes it.
    async fn replace(&self, zone: &str, fqdn: &str, records: &[String]) -> Result<(), RestError> {
        self.api
            .patch(&rrset_path(zone, fqdn), &json!({ "records": records }))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl DnsSolver for DesecDns {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = self.zone(&fqdn).await?;
        let _held = self.locks.lock(&zone).await;
        let record = quoted(value);
        match self.records(&zone, &fqdn).await? {
            Some(records) if records.contains(&record) => {}
            Some(mut records) => {
                records.push(record);
                self.replace(&zone, &fqdn, &records).await?;
            }
            None => self.create(&zone, &fqdn, record).await?,
        }
        Ok(())
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = self.zone(&fqdn).await?;
        let _held = self.locks.lock(&zone).await;
        let record = quoted(value);
        let Some(records) = self.records(&zone, &fqdn).await? else {
            return Ok(());
        };
        if records.contains(&record) {
            let rest: Vec<String> = records.into_iter().filter(|r| *r != record).collect();
            self.replace(&zone, &fqdn, &rest).await?;
        }
        Ok(())
    }
}

/// `/domains/{zone}/rrsets/{subname}/TXT/`, with `@` for the apex.
fn rrset_path(zone: &str, fqdn: &str) -> String {
    format!(
        "/domains/{}/rrsets/{}/TXT/",
        segment(zone),
        segment(&relative_name(fqdn, zone))
    )
}

/// TXT contents must be enclosed in double quotes. Challenge values are base64url, so no
/// escaping is needed.
fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

/// `{"detail": "Invalid token."}`, or field errors such as `{"ttl": ["…"]}`.
fn error_message(answer: &Value) -> Option<String> {
    match answer["detail"].as_str() {
        Some(detail) => Some(detail.to_owned()),
        None => answer
            .as_object()
            .filter(|fields| !fields.is_empty())
            .map(|_| answer.to_string()),
    }
}

#[cfg(test)]
mod tests;
