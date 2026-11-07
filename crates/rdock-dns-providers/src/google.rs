//! DNS-01 through the Google Cloud DNS API (W-DNS-03). A service account key signs an RS256
//! JWT that is exchanged for an access token (RFC 7523); the key file is read for every call
//! and the token cached until shortly before it expires. A record set holds all values and a
//! deletion must match it exactly, so present and cleanup replace the whole TXT set in one
//! atomic change (deletion of the old set, addition of the new one) under the zone's lock, then
//! follow the change until it is `done`. Private zones are skipped when the zone is looked up.
//!
//! API: <https://developers.google.com/identity/protocols/oauth2/service-account>,
//! <https://cloud.google.com/dns/docs/reference/rest/v1/managedZones/list>,
//! <https://cloud.google.com/dns/docs/reference/rest/v1/resourceRecordSets/list> and
//! <https://cloud.google.com/dns/docs/reference/rest/v1/changes> (checked 2026-11-07).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rdock_acme::dns::{DnsError, DnsSolver};
use rdock_model::acme::GoogleCloudDnsProvider;
use serde_json::{Value, json};
use tracing::debug;

use crate::jwt::{Algorithm, RsaKey};
use crate::lock::ZoneLocks;
use crate::oauth::{self, AccessToken, OAuthBearer, TokenSource};
use crate::rest::{Anonymous, ErrorFormat, RestClient, form, segment};
use crate::zone::{ZoneFinder, normalize};

/// The Cloud DNS API.
pub const API: &str = "https://dns.googleapis.com/dns/v1";
/// Google's OAuth 2.0 token endpoint, which is also the JWT's audience.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// The token endpoint's origin and path.
const TOKEN_BASE: &str = "https://oauth2.googleapis.com";
const TOKEN_PATH: &str = "/token";
/// The scope that allows reading and changing Cloud DNS records.
const SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";
/// Lifetime asked for the JWT: Google's maximum, one hour.
const ASSERTION_LIFETIME: u64 = 3600;
/// TTL of challenge records.
const TTL: u64 = 60;
/// How often a pending change is checked.
const CHANGE_POLL: Duration = Duration::from_secs(1);
/// How long a change may stay pending.
const CHANGE_TIMEOUT: Duration = Duration::from_secs(120);

/// Google Cloud DNS for one service account key.
#[derive(Debug)]
pub struct GoogleCloudDns {
    api: RestClient,
    credentials_file: PathBuf,
    project: Option<String>,
    zone: Option<String>,
    zones: ZoneFinder,
    locks: ZoneLocks,
}

/// A TXT record set as Cloud DNS holds it: name with the trailing dot, TTL, quoted values.
struct RecordSet {
    ttl: u64,
    rrdatas: Vec<String>,
}

impl GoogleCloudDns {
    /// The provider for `config`. With `api_url` (tests) the token endpoint is
    /// `{api_url}/token` and the DNS API `{api_url}/dns/v1`.
    pub fn new(config: &GoogleCloudDnsProvider) -> Result<Self, DnsError> {
        let (token_base, api) = match &config.api_url {
            Some(url) => {
                let base = url.as_url().as_str().trim_end_matches('/');
                (base.to_owned(), format!("{base}/dns/v1"))
            }
            None => (TOKEN_BASE.to_owned(), API.to_owned()),
        };
        let account = ServiceAccount {
            file: config.credentials_file.clone(),
            token_api: RestClient::with(
                "Google OAuth",
                &token_base,
                Arc::new(Anonymous),
                ErrorFormat::Json(oauth::error_message),
            )?,
        };
        Ok(Self {
            api: RestClient::with(
                "Cloud DNS API",
                &api,
                Arc::new(OAuthBearer::new(account)),
                ErrorFormat::Json(error_message),
            )?,
            credentials_file: config.credentials_file.clone(),
            project: config.project.clone(),
            zone: config.zone.clone(),
            zones: ZoneFinder::new(None),
            locks: ZoneLocks::default(),
        })
    }

    /// The configured project, or the key file's `project_id`.
    async fn project(&self) -> Result<String, DnsError> {
        if let Some(project) = &self.project {
            return Ok(project.clone());
        }
        let key = read_key_file(&self.credentials_file).await?;
        key["project_id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| DnsError("credentials_file has no project_id; set `project`".to_owned()))
    }

    /// The managed zone holding `fqdn`: the configured one, or the public zone found by name.
    async fn zone(&self, project: &str, fqdn: &str) -> Result<String, DnsError> {
        if let Some(zone) = &self.zone {
            return Ok(zone.clone());
        }
        self.zones
            .zone("Cloud DNS", fqdn, |name| async move {
                self.public_zone(project, &name).await
            })
            .await
    }

    /// The name of the public managed zone for the DNS name `name`, if there is one.
    async fn public_zone(&self, project: &str, name: &str) -> Result<Option<String>, DnsError> {
        let path = format!(
            "/projects/{}/managedZones?{}",
            segment(project),
            form(&[("dnsName", &format!("{name}."))])
        );
        let answer = self.api.get(&path).await?;
        for zone in answer["managedZones"].as_array().into_iter().flatten() {
            if zone["dnsName"].as_str().map(normalize).as_deref() != Some(name) {
                continue;
            }
            if zone["visibility"].as_str() == Some("private") {
                debug!(zone = name, "skipping a private managed zone");
                continue;
            }
            if let Some(id) = zone["name"].as_str() {
                return Ok(Some(id.to_owned()));
            }
        }
        Ok(None)
    }

    fn zone_path(project: &str, zone: &str) -> String {
        format!(
            "/projects/{}/managedZones/{}",
            segment(project),
            segment(zone)
        )
    }

    /// The TXT record set at `fqdn`, if there is one.
    async fn record_set(&self, zone_path: &str, fqdn: &str) -> Result<Option<RecordSet>, DnsError> {
        let path = format!(
            "{zone_path}/rrsets?{}",
            form(&[("name", &format!("{fqdn}.")), ("type", "TXT")])
        );
        let answer = self.api.get(&path).await?;
        let Some(set) = answer["rrsets"].as_array().and_then(|sets| sets.first()) else {
            return Ok(None);
        };
        Ok(Some(RecordSet {
            ttl: set["ttl"].as_u64().unwrap_or(TTL),
            rrdatas: set["rrdatas"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        }))
    }

    /// Replaces the set at `fqdn` (`old`, if any) with `new` values (none deletes it) in one
    /// change, and follows the change until it is done.
    async fn replace(
        &self,
        zone_path: &str,
        fqdn: &str,
        old: Option<&RecordSet>,
        new: &[String],
    ) -> Result<(), DnsError> {
        let name = format!("{fqdn}.");
        let set = |ttl: u64, rrdatas: &[String]| json!({ "name": name, "type": "TXT", "ttl": ttl, "rrdatas": rrdatas });
        let deletions: Vec<Value> = old.iter().map(|o| set(o.ttl, &o.rrdatas)).collect();
        let additions: Vec<Value> = if new.is_empty() {
            Vec::new()
        } else {
            vec![set(old.map_or(TTL, |o| o.ttl), new)]
        };
        let change = self
            .api
            .post(
                &format!("{zone_path}/changes"),
                &json!({ "additions": additions, "deletions": deletions }),
            )
            .await?;
        self.wait_done(zone_path, change).await
    }

    /// Follows the change until its status is `done`.
    async fn wait_done(&self, zone_path: &str, mut change: Value) -> Result<(), DnsError> {
        let started = Instant::now();
        loop {
            let id = change["id"].as_str().map(str::to_owned).ok_or_else(|| {
                DnsError("Cloud DNS API answered a change without its id".to_owned())
            })?;
            match change["status"].as_str() {
                Some("done") => return Ok(()),
                Some("pending") if started.elapsed() < CHANGE_TIMEOUT => {}
                Some("pending") => {
                    return Err(DnsError(format!(
                        "Cloud DNS change {id} was not done within {} s",
                        CHANGE_TIMEOUT.as_secs()
                    )));
                }
                other => {
                    return Err(DnsError(format!(
                        "Cloud DNS API answered change {id} with the status {other:?}"
                    )));
                }
            }
            tokio::time::sleep(CHANGE_POLL).await;
            change = self
                .api
                .get(&format!("{zone_path}/changes/{}", segment(&id)))
                .await?;
        }
    }
}

#[async_trait]
impl DnsSolver for GoogleCloudDns {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let project = self.project().await?;
        let zone = self.zone(&project, &fqdn).await?;
        let zone_path = Self::zone_path(&project, &zone);
        let _held = self.locks.lock(&zone_path).await;
        let value = quoted(value);
        let old = self.record_set(&zone_path, &fqdn).await?;
        let mut values = old.as_ref().map(|o| o.rrdatas.clone()).unwrap_or_default();
        if values.contains(&value) {
            return Ok(());
        }
        values.push(value);
        self.replace(&zone_path, &fqdn, old.as_ref(), &values).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let project = self.project().await?;
        let zone = self.zone(&project, &fqdn).await?;
        let zone_path = Self::zone_path(&project, &zone);
        let _held = self.locks.lock(&zone_path).await;
        let value = quoted(value);
        let Some(old) = self.record_set(&zone_path, &fqdn).await? else {
            return Ok(());
        };
        if !old.rrdatas.contains(&value) {
            return Ok(());
        }
        let rest: Vec<String> = old
            .rrdatas
            .iter()
            .filter(|v| **v != value)
            .cloned()
            .collect();
        self.replace(&zone_path, &fqdn, Some(&old), &rest).await
    }
}

/// The service account key file, exchanged for access tokens.
#[derive(Debug)]
struct ServiceAccount {
    file: PathBuf,
    token_api: RestClient,
}

#[async_trait]
impl TokenSource for ServiceAccount {
    async fn credential(&self) -> Result<Vec<u8>, DnsError> {
        tokio::fs::read(&self.file).await.map_err(|e| {
            DnsError(format!(
                "credentials_file {} cannot be read: {e}",
                self.file.display()
            ))
        })
    }

    async fn exchange(&self, credential: &[u8]) -> Result<AccessToken, DnsError> {
        let assertion = assertion(credential, unix_now())?;
        let answer = self
            .token_api
            .post_form(
                TOKEN_PATH,
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    ("assertion", &assertion),
                ],
            )
            .await?;
        AccessToken::from_answer(&answer, "Google OAuth")
    }
}

/// The signed JWT for the key file `key_file` at `now` (Unix seconds): issued by the service
/// account, for the Cloud DNS scope, with the token endpoint as audience, valid for one hour.
fn assertion(key_file: &[u8], now: u64) -> Result<String, DnsError> {
    let key: Value = serde_json::from_slice(key_file)
        .map_err(|_| DnsError("credentials_file is not a JSON service account key".to_owned()))?;
    let field = |name: &str| {
        key[name]
            .as_str()
            .ok_or_else(|| DnsError(format!("credentials_file has no `{name}`")))
    };
    let signer = RsaKey::from_pem(field("private_key")?.as_bytes(), "credentials_file")?;
    let mut header = json!({});
    if let Ok(id) = field("private_key_id") {
        header["kid"] = id.into();
    }
    let claims = json!({
        "iss": field("client_email")?,
        "scope": SCOPE,
        "aud": TOKEN_URL,
        "iat": now,
        "exp": now + ASSERTION_LIFETIME,
    });
    signer.sign(Algorithm::Rs256, &header, &claims)
}

async fn read_key_file(path: &Path) -> Result<Value, DnsError> {
    let bytes = tokio::fs::read(path).await.map_err(|e| {
        DnsError(format!(
            "credentials_file {} cannot be read: {e}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|_| DnsError("credentials_file is not a JSON service account key".to_owned()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// TXT data are quoted character strings. Challenge values are base64url, so no escaping is
/// needed inside the quotes.
fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

/// `{"error": {"code": 403, "message": "…", "status": "PERMISSION_DENIED"}}`.
fn error_message(answer: &Value) -> Option<String> {
    let error = &answer["error"];
    let message = error["message"].as_str()?;
    Some(match error["status"].as_str() {
        Some(status) => format!("{message} ({status})"),
        None => message.to_owned(),
    })
}

#[cfg(test)]
mod tests;
