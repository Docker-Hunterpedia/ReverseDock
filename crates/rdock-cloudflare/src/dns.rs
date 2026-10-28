//! DNS-01 through the Cloudflare API (W-CF-03): TXT records are created and deleted with a
//! token allowed to edit the zone's DNS records.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Request, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rdock_acme::dns::{BuiltinProviders, DnsError, DnsProviders, DnsSolver};
use rdock_model::acme::DnsProvider;
use serde_json::{Value, json};

/// The Cloudflare API.
pub const API: &str = "https://api.cloudflare.com/client/v4";
/// TTL of challenge records; Cloudflare's minimum for TXT records.
const TTL: u32 = 60;
/// Time allowed for each API call.
const TIMEOUT: Duration = Duration::from_secs(30);

/// DNS providers including Cloudflare; the others come from [`BuiltinProviders`].
#[derive(Debug, Default)]
pub struct Providers;

impl DnsProviders for Providers {
    fn build(&self, config: &DnsProvider) -> Result<Arc<dyn DnsSolver>, DnsError> {
        match config {
            DnsProvider::Cloudflare { api_token, zone_id } => Ok(Arc::new(CloudflareDns::new(
                API,
                api_token,
                zone_id.clone(),
            )?)),
            other => BuiltinProviders.build(other),
        }
    }
}

/// Cloudflare DNS for one API token.
#[derive(Debug)]
pub struct CloudflareDns {
    api: String,
    /// The token reference (`${file:…}`), resolved for each call so rotated files are picked up.
    token: String,
    zone_id: Option<String>,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl CloudflareDns {
    /// A provider calling `api` with the token `token` (a reference or the literal token). With
    /// `zone_id`, no zone lookup is made.
    pub fn new(api: &str, token: &str, zone_id: Option<String>) -> Result<Self, DnsError> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|e| DnsError(format!("TLS setup: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            api: api.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
            zone_id,
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    /// Calls the API and returns `result` of a successful answer.
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, DnsError> {
        let token = rdock_config::interpolate::expand(&self.token, &rdock_config::System)
            .map_err(|e| DnsError(format!("api_token: {e}")))?;
        let request = Request::builder()
            .method(method.clone())
            .uri(format!("{}{path}", self.api))
            .header(header::AUTHORIZATION, format!("Bearer {}", token.trim()))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(
                body.map(|b| b.to_string()).unwrap_or_default(),
            )))
            .map_err(|e| DnsError(e.to_string()))?;
        let response = tokio::time::timeout(TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| DnsError(format!("Cloudflare API {method} timed out")))?
            .map_err(|e| DnsError(format!("Cloudflare API {method}: {e}")))?;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| DnsError(format!("Cloudflare API {method}: {e}")))?
            .to_bytes();
        let answer: Value = serde_json::from_slice(&bytes).map_err(|_| {
            DnsError(format!(
                "Cloudflare API {method} answered {status} without JSON"
            ))
        })?;
        if answer["success"].as_bool() == Some(true) {
            return Ok(answer["result"].clone());
        }
        let errors: Vec<String> = answer["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| format!("{} ({})", e["message"].as_str().unwrap_or("?"), e["code"]))
            .collect();
        Err(DnsError(format!(
            "Cloudflare API {method} answered {status}: {}",
            errors.join("; ")
        )))
    }

    /// The zone holding `fqdn`: the configured one, or the closest parent Cloudflare knows.
    async fn zone(&self, fqdn: &str) -> Result<String, DnsError> {
        if let Some(id) = &self.zone_id {
            return Ok(id.clone());
        }
        let mut candidate = fqdn.trim_end_matches('.');
        while let Some((_, parent)) = candidate.split_once('.') {
            candidate = parent;
            if !candidate.contains('.') {
                break;
            }
            let found = self
                .call(Method::GET, &format!("/zones?name={candidate}"), None)
                .await?;
            if let Some(id) = found[0]["id"].as_str() {
                return Ok(id.to_owned());
            }
        }
        Err(DnsError(format!(
            "no Cloudflare zone for `{fqdn}` is visible to this token (set `zone_id`, or allow Zone → Zone → Read)"
        )))
    }
}

#[async_trait]
impl DnsSolver for CloudflareDns {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let zone = self.zone(fqdn).await?;
        let record = json!({ "type": "TXT", "name": fqdn, "content": value, "ttl": TTL });
        self.call(
            Method::POST,
            &format!("/zones/{zone}/dns_records"),
            Some(record),
        )
        .await
        .map(|_| ())
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let zone = self.zone(fqdn).await?;
        let query: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("type", "TXT")
            .append_pair("name", fqdn)
            .append_pair("content", value)
            .finish();
        let records = self
            .call(
                Method::GET,
                &format!("/zones/{zone}/dns_records?{query}"),
                None,
            )
            .await?;
        for id in records
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r["id"].as_str())
        {
            self.call(
                Method::DELETE,
                &format!("/zones/{zone}/dns_records/{id}"),
                None,
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
