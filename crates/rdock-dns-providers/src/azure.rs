//! DNS-01 through Azure DNS on Azure Resource Manager (W-DNS-03). The access token comes from
//! Microsoft Entra ID with a client secret or a certificate assertion (a PS256 JWT with the
//! certificate's SHA-256 thumbprint), or from the instance metadata service for a managed
//! identity; it is cached until shortly before it expires and replaced when the secret
//! changes. A record set holds all values, so present and cleanup read it, change its values
//! and write it back with `If-Match` on its etag (`If-None-Match: *` to create) under the
//! zone's lock; a `412` means someone else changed it, and the set is read again. Endpoints are
//! fixed per `environment`; the metadata service is the only plain-HTTP endpoint and is fixed.
//!
//! API: <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow>,
//! <https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials>,
//! <https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token>,
//! <https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update?view=rest-dns-2018-05-01>
//! and the national clouds
//! <https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud>,
//! <https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure>,
//! <https://learn.microsoft.com/en-us/azure/china/concepts-service-availability> (checked
//! 2026-11-07).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{Method, StatusCode};
use rdock_acme::dns::{DnsError, DnsSolver};
use rdock_model::acme::{AzureDnsProvider, AzureEnvironment};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde_json::{Value, json};

use crate::backoff::ATTEMPTS;
use crate::jwt::{Algorithm, RsaKey};
use crate::lock::ZoneLocks;
use crate::oauth::{self, AccessToken, OAuthBearer, TokenSource};
use crate::rest::{Anonymous, ErrorFormat, RestClient, RestError, form, segment};
use crate::secret;
use crate::sigv4::hex;
use crate::zone::{ZoneFinder, normalize, relative_name};

/// The instance metadata service, reachable only from inside the Azure VM or service.
const IMDS: &str = "http://169.254.169.254";
/// The DNS record set API version.
const API_VERSION: &str = "2018-05-01";
/// TTL of challenge records.
const TTL: u64 = 60;
/// Lifetime of a certificate assertion; Microsoft advises 5 to 10 minutes.
const ASSERTION_LIFETIME: u64 = 600;

/// The sign-in and Resource Manager endpoints of an Azure cloud.
#[derive(Debug, Clone, Copy)]
struct Cloud {
    login: &'static str,
    management: &'static str,
}

fn cloud(environment: AzureEnvironment) -> Cloud {
    match environment {
        AzureEnvironment::Public => Cloud {
            login: "https://login.microsoftonline.com",
            management: "https://management.azure.com",
        },
        AzureEnvironment::UsGovernment => Cloud {
            login: "https://login.microsoftonline.us",
            management: "https://management.usgovcloudapi.net",
        },
        AzureEnvironment::China => Cloud {
            login: "https://login.partner.microsoftonline.cn",
            management: "https://management.chinacloudapi.cn",
        },
    }
}

/// Azure DNS for one zone and identity.
#[derive(Debug)]
pub struct AzureDns {
    api: RestClient,
    /// `/subscriptions/{s}/resourceGroups/{rg}/providers/Microsoft.Network/dnsZones/{zone}`.
    zone_path: String,
    zones: ZoneFinder,
    locks: ZoneLocks,
}

/// A TXT record set: its etag and values.
struct RecordSet {
    etag: String,
    ttl: u64,
    values: Vec<String>,
}

impl AzureDns {
    /// The provider for `config`. With `api_url` (tests), sign-in, the metadata service and
    /// Resource Manager are all called there; the token scope and assertion audience stay
    /// those of `environment`.
    pub fn new(config: &AzureDnsProvider) -> Result<Self, DnsError> {
        let cloud = cloud(config.environment);
        let test_base = config
            .api_url
            .as_ref()
            .map(|url| url.as_url().as_str().trim_end_matches('/').to_owned());
        let identity = Identity::new(config, cloud, test_base.as_deref())?;
        let management = test_base.as_deref().unwrap_or(cloud.management);
        Ok(Self {
            api: RestClient::with(
                "Azure Resource Manager",
                management,
                Arc::new(OAuthBearer::new(identity)),
                ErrorFormat::Json(error_message),
            )?,
            zone_path: format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}",
                segment(&config.subscription_id),
                segment(&config.resource_group),
                segment(&normalize(&config.zone))
            ),
            zones: ZoneFinder::new(Some(&config.zone)),
            locks: ZoneLocks::default(),
        })
    }

    fn record_path(&self, relative: &str) -> String {
        format!(
            "{}/TXT/{}?api-version={API_VERSION}",
            self.zone_path,
            segment(relative)
        )
    }

    /// The TXT record set at `path`, if there is one.
    async fn record_set(&self, path: &str) -> Result<Option<RecordSet>, RestError> {
        let set = match self.api.get(path).await {
            Ok(set) => set,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(e),
        };
        let properties = &set["properties"];
        Ok(Some(RecordSet {
            etag: set["etag"].as_str().unwrap_or_default().to_owned(),
            ttl: properties["TTL"].as_u64().unwrap_or(TTL),
            values: properties["TXTRecords"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|record| {
                    record["value"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect::<String>()
                })
                .collect(),
        }))
    }

    /// Writes `values` to the set at `path`: created when `current` is `None`, replaced on its
    /// etag otherwise; no values deletes it.
    async fn write(
        &self,
        path: &str,
        current: Option<&RecordSet>,
        values: &[String],
    ) -> Result<(), RestError> {
        let condition = match current {
            Some(set) => ("if-match", set.etag.as_str()),
            None => ("if-none-match", "*"),
        };
        if values.is_empty() {
            self.api
                .json(Method::DELETE, path, &[condition], None)
                .await?;
            return Ok(());
        }
        let records: Vec<Value> = values.iter().map(|v| json!({ "value": [v] })).collect();
        let body = json!({ "properties": {
            "TTL": current.map_or(TTL, |set| set.ttl),
            "TXTRecords": records,
        } });
        self.api
            .json(Method::PUT, path, &[condition], Some(&body))
            .await?;
        Ok(())
    }

    /// Reads the set at `fqdn`, lets `change` decide its new values (`None`: nothing to do) and
    /// writes them, reading again when the set changed in between (`412`).
    async fn update(
        &self,
        fqdn: &str,
        change: impl Fn(Vec<String>) -> Option<Vec<String>>,
    ) -> Result<(), DnsError> {
        let fqdn = normalize(fqdn);
        // The zone is always configured, so the finder only checks that it holds the name.
        let zone = self
            .zones
            .zone("Azure DNS", &fqdn, |_| async { Ok(None) })
            .await?;
        let path = self.record_path(&relative_name(&fqdn, &zone));
        let _held = self.locks.lock(&zone).await;
        for _ in 0..ATTEMPTS {
            let current = self.record_set(&path).await?;
            let values = current
                .as_ref()
                .map(|s| s.values.clone())
                .unwrap_or_default();
            let Some(new) = change(values) else {
                return Ok(());
            };
            match self.write(&path, current.as_ref(), &new).await {
                Err(e) if e.status() == Some(StatusCode::PRECONDITION_FAILED) => {}
                other => return other.map_err(Into::into),
            }
        }
        Err(DnsError(format!(
            "Azure DNS: the record set at `{fqdn}` kept changing during {ATTEMPTS} attempts"
        )))
    }
}

#[async_trait]
impl DnsSolver for AzureDns {
    async fn present(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        self.update(fqdn, |mut values| {
            (!values.iter().any(|v| v == value)).then(|| {
                values.push(value.to_owned());
                values
            })
        })
        .await
    }

    async fn cleanup(&self, fqdn: &str, value: &str) -> Result<(), DnsError> {
        self.update(fqdn, |values| {
            values
                .iter()
                .any(|v| v == value)
                .then(|| values.iter().filter(|v| *v != value).cloned().collect())
        })
        .await
    }
}

/// How the access token is obtained.
#[derive(Debug)]
struct Identity {
    auth: Auth,
    /// Where tokens are asked for: the Entra ID token endpoint or the metadata service.
    token_api: RestClient,
    /// The token's audience: the cloud's Resource Manager.
    management: &'static str,
}

/// The configured authentication method.
#[derive(Debug)]
enum Auth {
    /// A client secret, read from its reference.
    Secret {
        tenant: String,
        client_id: String,
        reference: String,
    },
    /// A certificate and its private key in one PEM, read from its reference.
    Certificate {
        tenant: String,
        client_id: String,
        reference: String,
        /// The assertion's audience: the cloud's token endpoint for the tenant.
        audience: String,
    },
    /// The managed identity, optionally a user-assigned one by client ID.
    Managed { client_id: Option<String> },
}

impl Identity {
    fn new(
        config: &AzureDnsProvider,
        cloud: Cloud,
        test_base: Option<&str>,
    ) -> Result<Self, DnsError> {
        let required = |value: &Option<String>, field: &str| {
            value
                .clone()
                .ok_or_else(|| DnsError(format!("azure_dns needs `{field}`")))
        };
        let (auth, base, api) = if config.managed_identity {
            (
                Auth::Managed {
                    client_id: config.client_id.clone(),
                },
                test_base.unwrap_or(IMDS),
                "Azure instance metadata service",
            )
        } else {
            let tenant = required(&config.tenant_id, "tenant_id")?;
            let client_id = required(&config.client_id, "client_id")?;
            let auth = match (&config.client_secret, &config.client_certificate) {
                (Some(reference), None) => Auth::Secret {
                    tenant,
                    client_id,
                    reference: reference.clone(),
                },
                (None, Some(reference)) => Auth::Certificate {
                    audience: format!("{}/{}/oauth2/v2.0/token", cloud.login, tenant),
                    tenant,
                    client_id,
                    reference: reference.clone(),
                },
                _ => {
                    return Err(DnsError(
                        "azure_dns needs exactly one of `client_secret`, `client_certificate` and `managed_identity`"
                            .to_owned(),
                    ));
                }
            };
            (auth, test_base.unwrap_or(cloud.login), "Microsoft Entra ID")
        };
        Ok(Self {
            auth,
            token_api: RestClient::with(
                api,
                base,
                Arc::new(Anonymous),
                ErrorFormat::Json(oauth::error_message),
            )?,
            management: cloud.management,
        })
    }

    fn scope(&self) -> String {
        format!("{}/.default", self.management)
    }

    /// The client credentials grant at `/{tenant}/oauth2/v2.0/token` with `credential`
    /// (`client_secret` or `client_assertion`) form fields.
    async fn client_credentials(
        &self,
        tenant: &str,
        client_id: &str,
        credential: &[(&str, &str)],
    ) -> Result<AccessToken, DnsError> {
        let scope = self.scope();
        let mut fields = vec![
            ("client_id", client_id),
            ("scope", scope.as_str()),
            ("grant_type", "client_credentials"),
        ];
        fields.extend_from_slice(credential);
        let answer = self
            .token_api
            .post_form(&format!("/{}/oauth2/v2.0/token", segment(tenant)), &fields)
            .await?;
        AccessToken::from_answer(&answer, "Microsoft Entra ID")
    }

    async fn managed(&self, client_id: Option<&str>) -> Result<AccessToken, DnsError> {
        let resource = format!("{}/", self.management);
        let mut query = vec![
            ("api-version", "2018-02-01"),
            ("resource", resource.as_str()),
        ];
        if let Some(id) = client_id {
            query.push(("client_id", id));
        }
        let answer = self
            .token_api
            .json(
                Method::GET,
                &format!("/metadata/identity/oauth2/token?{}", form(&query)),
                &[("metadata", "true")],
                None,
            )
            .await?;
        AccessToken::from_answer(&answer, "Azure instance metadata service")
    }
}

#[async_trait]
impl TokenSource for Identity {
    async fn credential(&self) -> Result<Vec<u8>, DnsError> {
        Ok(match &self.auth {
            Auth::Secret { reference, .. } => {
                secret::resolve(reference, "client_secret")?.into_bytes()
            }
            Auth::Certificate { reference, .. } => {
                secret::resolve(reference, "client_certificate")?.into_bytes()
            }
            Auth::Managed { .. } => Vec::new(),
        })
    }

    async fn exchange(&self, credential: &[u8]) -> Result<AccessToken, DnsError> {
        match &self.auth {
            Auth::Secret {
                tenant, client_id, ..
            } => {
                let secret = String::from_utf8_lossy(credential);
                self.client_credentials(tenant, client_id, &[("client_secret", &secret)])
                    .await
            }
            Auth::Certificate {
                tenant,
                client_id,
                audience,
                ..
            } => {
                let assertion = certificate_assertion(credential, client_id, audience, unix_now())?;
                self.client_credentials(
                    tenant,
                    client_id,
                    &[
                        (
                            "client_assertion_type",
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        ),
                        ("client_assertion", &assertion),
                    ],
                )
                .await
            }
            Auth::Managed { client_id } => self.managed(client_id.as_deref()).await,
        }
    }
}

/// The client assertion for the certificate and key in `pem` at `now` (Unix seconds), as
/// Microsoft documents it: PS256, `x5t#S256` the base64url SHA-256 thumbprint of the
/// certificate, `iss` and `sub` the client ID, `aud` the token endpoint, a random `jti`, valid
/// for ten minutes.
fn certificate_assertion(
    pem: &[u8],
    client_id: &str,
    audience: &str,
    now: u64,
) -> Result<String, DnsError> {
    let certificate = CertificateDer::from_pem_slice(pem)
        .map_err(|_| DnsError("client_certificate: no certificate in PEM form".to_owned()))?;
    let key = RsaKey::from_pem(pem, "client_certificate")?;
    let mut id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| DnsError("no randomness for the assertion ID".to_owned()))?;
    let header = json!({ "x5t#S256": URL_SAFE_NO_PAD.encode(digest(&SHA256, &certificate)) });
    let claims = json!({
        "aud": audience,
        "iss": client_id,
        "sub": client_id,
        "jti": hex(&id),
        "nbf": now,
        "iat": now,
        "exp": now + ASSERTION_LIFETIME,
    });
    key.sign(Algorithm::Ps256, &header, &claims)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `{"error": {"code": "AuthorizationFailed", "message": "…"}}`.
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
