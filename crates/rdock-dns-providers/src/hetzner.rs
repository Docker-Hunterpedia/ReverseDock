//! DNS-01 through the Hetzner Cloud API (W-DNS-03), where Hetzner DNS lives since the move to
//! the Hetzner Console; the old `dns.hetzner.com` API is not supported. Values are added to and
//! removed from the TXT RRset with the `add_records` and `remove_records` actions, so other
//! values stay, and each action is followed until it succeeds.
//!
//! API: <https://docs.hetzner.cloud/reference/cloud#zone-rrset-actions> and the OpenAPI document
//! <https://docs.hetzner.cloud/cloud.spec.json> (checked 2026-11-07).

use std::time::{Duration, Instant};

use async_trait::async_trait;
use rdock_acme::dns::{DnsError, DnsSolver};
use rdock_model::acme::HetznerProvider;
use serde_json::{Value, json};

use crate::rest::{RestClient, RestError, segment};
use crate::zone::{ZoneFinder, normalize, relative_name};

/// The Hetzner Cloud API.
pub const API: &str = "https://api.hetzner.cloud/v1";
/// TTL of challenge records; the API's minimum.
const TTL: u32 = 60;
/// How often a running action is checked.
const ACTION_POLL: Duration = Duration::from_millis(500);
/// How long an action may run.
const ACTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Hetzner DNS for one Cloud API token.
#[derive(Debug)]
pub struct HetznerDns {
    api: RestClient,
    zones: ZoneFinder,
}

impl HetznerDns {
    /// The provider for `config`, calling `api_url` when set (tests) and [`API`] otherwise.
    pub fn new(config: &HetznerProvider) -> Result<Self, DnsError> {
        let base = config
            .api_url
            .as_ref()
            .map_or(API, |url| url.as_url().as_str());
        Ok(Self {
            api: RestClient::new("Hetzner Cloud API", base, &config.api_token, error_message)?,
            zones: ZoneFinder::new(config.zone.as_deref()),
        })
    }

    async fn zone(&self, fqdn: &str) -> Result<String, DnsError> {
        self.zones
            .zone("Hetzner", fqdn, |name| async move {
                match self.api.get(&format!("/zones/{}", segment(&name))).await {
                    Ok(_) => Ok(Some(name)),
                    Err(e) if e.is_not_found() => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    /// `POST /zones/{zone}/rrsets/{name}/TXT/actions/{action}` for the RRset at `fqdn`.
    async fn rrset_action(
        &self,
        zone: &str,
        fqdn: &str,
        action: &str,
        body: &Value,
    ) -> Result<Value, RestError> {
        let path = format!(
            "/zones/{}/rrsets/{}/TXT/actions/{action}",
            segment(zone),
            segment(&relative_name(fqdn, zone))
        );
        self.api.post(&path, body).await
    }

    /// Follows the action in `answer` until it succeeds.
    async fn finish(&self, answer: &Value) -> Result<(), DnsError> {
        let started = Instant::now();
        let mut action = answer["action"].clone();
        loop {
            match action["status"].as_str() {
                Some("success") => return Ok(()),
                Some("error") => {
                    return Err(DnsError(format!(
                        "Hetzner Cloud API action {} failed: {}",
                        action["id"],
                        error_message(&action).unwrap_or_else(|| "no reason given".into())
                    )));
                }
                Some("running") if started.elapsed() < ACTION_TIMEOUT => {}
                Some("running") => {
                    return Err(DnsError(format!(
                        "Hetzner Cloud API action {} did not finish within {} s",
                        action["id"],
                        ACTION_TIMEOUT.as_secs()
                    )));
                }
                _ => {
                    return Err(DnsError(format!(
                        "Hetzner Cloud API answered without an action status: {action}"
                    )));
                }
            }
            let Some(id) = action["id"].as_u64() else {
                return Err(DnsError("Hetzner Cloud API action without an id".into()));
            };
            tokio::time::sleep(ACTION_POLL).await;
            action = self.api.get(&format!("/actions/{id}")).await?["action"].take();
        }
    }
}

#[async_trait]
impl DnsSolver for HetznerDns {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = self.zone(&fqdn).await?;
        let body = json!({ "ttl": TTL, "records": [{ "value": quoted(value) }] });
        let answer = self
            .rrset_action(&zone, &fqdn, "add_records", &body)
            .await?;
        self.finish(&answer).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = self.zone(&fqdn).await?;
        let body = json!({ "records": [{ "value": quoted(value) }] });
        match self
            .rrset_action(&zone, &fqdn, "remove_records", &body)
            .await
        {
            Ok(answer) => self.finish(&answer).await,
            // The RRset is gone already: nothing left to remove.
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// TXT values are written as quoted character strings. Challenge values are base64url, so no
/// escaping is needed.
fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

/// `{"error": {"code": "unauthorized", "message": "…"}}`, or an action's `error`.
fn error_message(answer: &Value) -> Option<String> {
    let error = &answer["error"];
    let message = error["message"].as_str()?;
    Some(match error["code"].as_str() {
        Some(code) => format!("{message} ({code})"),
        None => message.to_owned(),
    })
}

#[cfg(test)]
mod tests;
