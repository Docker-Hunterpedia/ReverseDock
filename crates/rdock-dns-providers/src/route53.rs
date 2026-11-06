//! DNS-01 through the Amazon Route 53 API (W-DNS-03), signed with AWS Signature Version 4 on
//! ring: no AWS SDK, whose MSRV and default aws-lc-rs we cannot take (ADR-0026). A record set
//! holds all values, so present and cleanup list the TXT set, change its values and write it
//! back with `UPSERT` (or `DELETE` for the last value) under the zone's lock; present then waits
//! for `GetChange` to report `INSYNC`. `PriorRequestNotComplete` and `Throttling` are retried
//! with backoff. Only the standard AWS partition is supported: `route53.amazonaws.com`, signed
//! as `us-east-1`.
//!
//! API: <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListHostedZonesByName.html>,
//! <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html>,
//! <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html>,
//! <https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetChange.html> and the
//! endpoints <https://docs.aws.amazon.com/general/latest/gr/r53.html> (checked 2026-11-07).

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Request};
use rdock_acme::dns::{DnsError, DnsSolver};
use rdock_model::acme::Route53Provider;
use time::OffsetDateTime;
use tracing::debug;

use crate::lock::ZoneLocks;
use crate::rest::{Body, Credentials, ErrorFormat, ProviderError, RestClient, form, segment};
use crate::secret;
use crate::sigv4::{self, AwsKey, Scope};
use crate::xml;
use crate::zone::{ZoneFinder, normalize};

/// The Route 53 API in the standard partition.
pub const API: &str = "https://route53.amazonaws.com";
/// Route 53 is global; requests in the standard partition are signed for this region.
const SIGNING_REGION: &str = "us-east-1";
/// The API version every path starts with.
const VERSION: &str = "/2013-04-01";
/// TTL of challenge records.
const TTL: u64 = 60;
/// How often a pending change is checked.
const CHANGE_POLL: Duration = Duration::from_secs(2);
/// How long a change may stay pending; AWS says changes are "generally" in sync within 60 s.
const CHANGE_TIMEOUT: Duration = Duration::from_secs(120);
/// Hosted zones asked for per lookup: enough for a public and private zones of one name.
const ZONES_PER_LOOKUP: &str = "10";

/// Route 53 for one access key.
#[derive(Debug)]
pub struct Route53Dns {
    api: RestClient,
    hosted_zone_id: Option<String>,
    zones: ZoneFinder,
    locks: ZoneLocks,
}

/// A TXT record set as Route 53 holds it.
struct RecordSet {
    ttl: u64,
    /// The values, quoted as stored.
    values: Vec<String>,
}

impl Route53Dns {
    /// The provider for `config`, calling `api_url` when set (tests) and [`API`] otherwise.
    pub fn new(config: &Route53Provider) -> Result<Self, DnsError> {
        let base = config
            .api_url
            .as_ref()
            .map_or(API, |url| url.as_url().as_str());
        let signer = SigV4 {
            access_key_id: config.access_key_id.clone(),
            secret_access_key: config.secret_access_key.clone(),
            session_token: config.session_token.clone(),
        };
        Ok(Self {
            api: RestClient::with(
                "Route 53 API",
                base,
                Arc::new(signer),
                ErrorFormat::Raw(read_error),
            )?,
            hosted_zone_id: config.hosted_zone_id.as_deref().map(bare_zone_id),
            zones: ZoneFinder::new(None),
            locks: ZoneLocks::default(),
        })
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Body>,
    ) -> Result<String, DnsError> {
        let bytes = self.api.send(method, path, &[], body).await?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| DnsError(format!("Route 53 API {path} answered with invalid UTF-8")))
    }

    /// The hosted zone ID holding `fqdn`: the configured one, or the public zone found by name.
    async fn zone(&self, fqdn: &str) -> Result<String, DnsError> {
        if let Some(id) = &self.hosted_zone_id {
            return Ok(id.clone());
        }
        self.zones
            .zone("Route 53", fqdn, |name| async move {
                self.public_zone(&name).await
            })
            .await
    }

    /// The ID of the public hosted zone named `name`, if there is one.
    async fn public_zone(&self, name: &str) -> Result<Option<String>, DnsError> {
        let query = form(&[("dnsname", name), ("maxitems", ZONES_PER_LOOKUP)]);
        let answer = self
            .call(
                Method::GET,
                &format!("{VERSION}/hostedzonesbyname?{query}"),
                None,
            )
            .await?;
        for zone in xml::elements(&answer, "HostedZone") {
            if xml::text(zone, "Name").map(|n| normalize(&n)).as_deref() != Some(name) {
                continue;
            }
            let Some(id) = xml::text(zone, "Id") else {
                continue;
            };
            if xml::text(zone, "PrivateZone").as_deref() == Some("true") {
                debug!(zone = name, id, "skipping a private hosted zone");
                continue;
            }
            return Ok(Some(bare_zone_id(&id)));
        }
        Ok(None)
    }

    /// The TXT record set at `fqdn`, if there is one.
    async fn record_set(&self, zone: &str, fqdn: &str) -> Result<Option<RecordSet>, DnsError> {
        let query = form(&[("name", fqdn), ("type", "TXT"), ("maxitems", "1")]);
        let path = format!("{VERSION}/hostedzone/{}/rrset?{query}", segment(zone));
        let answer = self.call(Method::GET, &path, None).await?;
        // The list starts at `name`/`type`; the first set is another one when ours is missing.
        let Some(set) = xml::elements(&answer, "ResourceRecordSet")
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let ours = xml::text(set, "Name").map(|n| normalize(&n)).as_deref() == Some(fqdn)
            && xml::text(set, "Type").as_deref() == Some("TXT");
        if !ours {
            return Ok(None);
        }
        let ttl = xml::text(set, "TTL")
            .and_then(|ttl| ttl.parse().ok())
            .ok_or_else(|| DnsError(format!("Route 53 API listed `{fqdn}` without a TTL")))?;
        let values = xml::elements(set, "Value")
            .into_iter()
            .map(|value| {
                xml::unescape(value).ok_or_else(|| {
                    DnsError(format!("Route 53 API listed a malformed value at `{fqdn}`"))
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Some(RecordSet { ttl, values }))
    }

    /// Submits one change to the set at `fqdn` and answers its change ID.
    async fn change(
        &self,
        zone: &str,
        action: &str,
        fqdn: &str,
        set: &RecordSet,
    ) -> Result<String, DnsError> {
        let path = format!("{VERSION}/hostedzone/{}/rrset/", segment(zone));
        let body = Body::new("application/xml", change_batch(action, fqdn, set));
        let answer = self.call(Method::POST, &path, Some(body)).await?;
        xml::text(&answer, "Id")
            .map(|id| id.trim_start_matches("/change/").to_owned())
            .ok_or_else(|| DnsError("Route 53 API answered a change without its ID".to_owned()))
    }

    /// Waits until the change is served by every Route 53 nameserver.
    async fn wait_in_sync(&self, change: &str) -> Result<(), DnsError> {
        let started = Instant::now();
        loop {
            let answer = self
                .call(
                    Method::GET,
                    &format!("{VERSION}/change/{}", segment(change)),
                    None,
                )
                .await?;
            match xml::text(&answer, "Status").as_deref() {
                Some("INSYNC") => return Ok(()),
                Some("PENDING") if started.elapsed() < CHANGE_TIMEOUT => {}
                Some("PENDING") => {
                    return Err(DnsError(format!(
                        "Route 53 change {change} was not in sync within {} s",
                        CHANGE_TIMEOUT.as_secs()
                    )));
                }
                other => {
                    return Err(DnsError(format!(
                        "Route 53 API answered change {change} with the status {other:?}"
                    )));
                }
            }
            tokio::time::sleep(CHANGE_POLL).await;
        }
    }
}

#[async_trait]
impl DnsSolver for Route53Dns {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = self.zone(&fqdn).await?;
        // Held until the change is in sync: Route 53 refuses a second change to the zone while
        // one is pending (`PriorRequestNotComplete`).
        let _held = self.locks.lock(&zone).await;
        let value = quoted(value);
        let mut set = self.record_set(&zone, &fqdn).await?.unwrap_or(RecordSet {
            ttl: TTL,
            values: Vec::new(),
        });
        if set.values.contains(&value) {
            return Ok(());
        }
        set.values.push(value);
        let change = self.change(&zone, "UPSERT", &fqdn, &set).await?;
        self.wait_in_sync(&change).await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        let zone = self.zone(&fqdn).await?;
        let _held = self.locks.lock(&zone).await;
        let value = quoted(value);
        let Some(set) = self.record_set(&zone, &fqdn).await? else {
            return Ok(());
        };
        if !set.values.contains(&value) {
            return Ok(());
        }
        let rest = RecordSet {
            ttl: set.ttl,
            values: set
                .values
                .iter()
                .filter(|v| **v != value)
                .cloned()
                .collect(),
        };
        if rest.values.is_empty() {
            // A deletion names the set exactly as it is.
            self.change(&zone, "DELETE", &fqdn, &set).await?;
        } else {
            self.change(&zone, "UPSERT", &fqdn, &rest).await?;
        }
        Ok(())
    }
}

/// Signs every attempt with the key pair, read afresh from its references.
#[derive(Debug)]
struct SigV4 {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

#[async_trait]
impl Credentials for SigV4 {
    async fn apply(&self, request: &mut Request<Bytes>) -> Result<(), DnsError> {
        let key = AwsKey {
            access_key_id: secret::resolve(&self.access_key_id, "access_key_id")?,
            secret_access_key: secret::resolve(&self.secret_access_key, "secret_access_key")?,
            session_token: self
                .session_token
                .as_deref()
                .map(|token| secret::resolve(token, "session_token"))
                .transpose()?,
        };
        let scope = Scope {
            region: SIGNING_REGION,
            service: "route53",
        };
        sigv4::sign(request, &key, &scope, OffsetDateTime::now_utc())
    }
}

/// `Z123` from `/hostedzone/Z123` or `Z123`.
fn bare_zone_id(id: &str) -> String {
    id.trim_start_matches("/hostedzone/").to_owned()
}

/// TXT values are quoted character strings. Challenge values are base64url, so no escaping is
/// needed inside the quotes.
fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}

/// `<ResourceRecord><Value>…</Value></ResourceRecord>` for each value.
fn resource_records(values: &[String]) -> String {
    values
        .iter()
        .map(|value| {
            format!(
                "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                xml::escape(value)
            )
        })
        .collect::<Vec<_>>()
        .concat()
}

/// The `ChangeResourceRecordSetsRequest` document for one change.
fn change_batch(action: &str, fqdn: &str, set: &RecordSet) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">"#,
            "<ChangeBatch><Changes><Change><Action>{action}</Action><ResourceRecordSet>",
            "<Name>{name}.</Name><Type>TXT</Type><TTL>{ttl}</TTL>",
            "<ResourceRecords>{records}</ResourceRecords>",
            "</ResourceRecordSet></Change></Changes></ChangeBatch>",
            "</ChangeResourceRecordSetsRequest>"
        ),
        action = action,
        name = xml::escape(fqdn),
        ttl = set.ttl,
        records = resource_records(&set.values)
    )
}

/// `<ErrorResponse><Error><Code>Throttling</Code><Message>Rate exceeded</Message></Error>…`;
/// throttling and a concurrent change to the zone are answered `400` but are transient.
fn read_error(body: &[u8]) -> ProviderError {
    let text = String::from_utf8_lossy(body);
    let code = xml::text(&text, "Code");
    let message = xml::text(&text, "Message");
    ProviderError {
        transient: matches!(
            code.as_deref(),
            Some("PriorRequestNotComplete" | "Throttling" | "ThrottlingException")
        ),
        message: match (message, code) {
            (Some(message), Some(code)) => Some(format!("{message} ({code})")),
            (message, code) => message.or(code),
        },
    }
}

#[cfg(test)]
mod tests;
