//! DNS-01 through the DigitalOcean API (W-DNS-03). Records are individual, so each value is
//! its own TXT record: present creates one, cleanup deletes the records with that value.
//!
//! API: <https://docs.digitalocean.com/reference/api/digitalocean/#tag/Domain-Records>
//! (checked 2026-11-07).

use async_trait::async_trait;
use rdock_acme::dns::{DnsError, DnsSolver};
use rdock_model::acme::DigitalOceanProvider;
use serde_json::{Value, json};

use crate::rest::{RestClient, RestError, segment};
use crate::zone::{ZoneFinder, normalize, relative_name};

/// The DigitalOcean API.
pub const API: &str = "https://api.digitalocean.com";
/// TTL of challenge records; the API's minimum.
const TTL: u32 = 30;
/// Records per page when listing; the API's maximum.
const PAGE: u32 = 200;

/// DigitalOcean DNS for one API token.
#[derive(Debug)]
pub struct DigitalOceanDns {
    api: RestClient,
    zones: ZoneFinder,
}

impl DigitalOceanDns {
    /// The provider for `config`, calling `api_url` when set (tests) and [`API`] otherwise.
    pub fn new(config: &DigitalOceanProvider) -> Result<Self, DnsError> {
        let base = config
            .api_url
            .as_ref()
            .map_or(API, |url| url.as_url().as_str());
        Ok(Self {
            api: RestClient::new("DigitalOcean API", base, &config.api_token, error_message)?,
            zones: ZoneFinder::new(config.zone.as_deref()),
        })
    }

    async fn zone(&self, fqdn: &str) -> Result<String, DnsError> {
        self.zones
            .zone("DigitalOcean", fqdn, |name| async move {
                match self
                    .api
                    .get(&format!("/v2/domains/{}", segment(&name)))
                    .await
                {
                    Ok(_) => Ok(Some(name)),
                    Err(e) if e.is_not_found() => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    /// The ids of the TXT records at `fqdn` holding `value`.
    async fn record_ids(&self, zone: &str, fqdn: &str, value: &str) -> Result<Vec<u64>, RestError> {
        let records = self
            .api
            .get(&format!(
                "/v2/domains/{}/records?type=TXT&name={}&per_page={PAGE}",
                segment(zone),
                segment(fqdn)
            ))
            .await?;
        Ok(records["domain_records"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|record| record["data"].as_str() == Some(value))
            .filter_map(|record| record["id"].as_u64())
            .collect())
    }
}

#[async_trait]
impl DnsSolver for DigitalOceanDns {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = self.zone(&fqdn).await?;
        let record = json!({
            "type": "TXT",
            "name": relative_name(&fqdn, &zone),
            "data": value,
            "ttl": TTL,
        });
        self.api
            .post(&format!("/v2/domains/{}/records", segment(&zone)), &record)
            .await?;
        Ok(())
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = self.zone(&fqdn).await?;
        for id in self.record_ids(&zone, &fqdn, value).await? {
            match self
                .api
                .delete(&format!("/v2/domains/{}/records/{id}", segment(&zone)))
                .await
            {
                Err(e) if !e.is_not_found() => return Err(e.into()),
                _ => {}
            }
        }
        Ok(())
    }
}

/// `{"id": "unauthorized", "message": "Unable to authenticate you"}`.
fn error_message(answer: &Value) -> Option<String> {
    let message = answer["message"].as_str()?;
    Some(match answer["id"].as_str() {
        Some(id) => format!("{message} ({id})"),
        None => message.to_owned(),
    })
}

#[cfg(test)]
mod tests;
