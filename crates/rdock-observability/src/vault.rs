//! A client for the KV version 2 secrets engine of `HashiCorp` Vault and `OpenBao` (W-OBS-02,
//! ADR-0030): raw REST on the hyper-rustls client the alerts and metering use, no SDK.
//!
//! - `GET /v1/<mount>/data/<path>` reads a secret; `data.data.<field>` is the value.
//! - `POST /v1/auth/<mount>/login` with `{ role, jwt }` logs in with a Kubernetes
//!   service-account token; the client token is used until two thirds of its lease have passed
//!   and then replaced by logging in again (also after a `403`).
//! - A `token` setting is a `${file:…}`/`${env:…}` reference read again for every request, so a
//!   token file an agent rotates is picked up.
//!
//! Values and tokens never appear in errors, logs or `Debug` output: errors name the secret's
//! path and the field, which are configuration, never what Vault returned.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rdock_model::secrets::{VaultAuth, VaultReference, VaultSettings};
use serde_json::{Value, json};

use crate::alerts::deliver::{Guarded, private_literal};

/// Largest answer read from Vault.
const MAX_ANSWER: usize = 1 << 20;

/// Why a value could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The settings cannot be used (CA file, address).
    #[error("{0}")]
    Settings(String),
    /// The token cannot be read, or the login failed.
    #[error("cannot log in to Vault: {0}")]
    Login(String),
    /// No answer.
    #[error("cannot reach Vault: {0}")]
    Transport(String),
    /// An answer other than 200.
    #[error("Vault answered {status} for `{path}`")]
    Status {
        /// The HTTP status.
        status: u16,
        /// The secret's location (`<mount>/<path>`).
        path: String,
    },
    /// The answer is not a KV version 2 secret.
    #[error("the answer for `{0}` is not a KV version 2 secret; is the mount KV version 2?")]
    Shape(String),
    /// The secret has no such field.
    #[error("`{path}` has no field `{field}`")]
    NoField {
        /// The secret's location.
        path: String,
        /// The field.
        field: String,
    },
    /// The field holds an object, an array or null.
    #[error("field `{field}` of `{path}` is not a string, number or boolean")]
    FieldType {
        /// The secret's location.
        path: String,
        /// The field.
        field: String,
    },
}

type Http = Client<HttpsConnector<HttpConnector<Guarded>>, Full<Bytes>>;

/// A token from a Kubernetes login and when to replace it.
struct Login {
    token: String,
    renew_at: Option<Instant>,
}

/// A Vault or `OpenBao` server.
pub struct Vault {
    settings: VaultSettings,
    base: String,
    http: Http,
    login: tokio::sync::Mutex<Option<Login>>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("address", &self.base)
            .finish_non_exhaustive()
    }
}

fn tls_config(ca_file: &std::path::Path) -> Result<rustls::ClientConfig, VaultError> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let settings = |e: &dyn std::fmt::Display| {
        VaultError::Settings(format!(
            "`secrets.vault.ca_file` ({}): {e}",
            ca_file.display()
        ))
    };
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(ca_file).map_err(|e| settings(&e))? {
        roots
            .add(certificate.map_err(|e| settings(&e))?)
            .map_err(|e| settings(&e))?;
    }
    if roots.is_empty() {
        return Err(settings(&"no certificate in the file"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| settings(&e))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Reads one field from the `data.data` object of a KV v2 answer.
fn field(
    data: &serde_json::Map<String, Value>,
    path: &str,
    name: &str,
) -> Result<String, VaultError> {
    match data.get(name) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(Value::Bool(b)) => Ok(b.to_string()),
        Some(_) => Err(VaultError::FieldType {
            path: path.to_owned(),
            field: name.to_owned(),
        }),
        None => Err(VaultError::NoField {
            path: path.to_owned(),
            field: name.to_owned(),
        }),
    }
}

impl Vault {
    /// A client for `settings`. Connects to nothing yet.
    ///
    /// # Errors
    ///
    /// The CA file cannot be read, or the system's roots cannot be loaded.
    pub fn new(settings: &VaultSettings) -> Result<Self, VaultError> {
        let timeout = settings.timeout.as_std();
        let mut http = HttpConnector::new_with_resolver(Guarded {
            allow_private: settings.allow_private_targets,
        });
        http.enforce_http(false);
        http.set_connect_timeout(Some(timeout));
        let builder = match &settings.ca_file {
            Some(path) => HttpsConnectorBuilder::new().with_tls_config(tls_config(path)?),
            None => HttpsConnectorBuilder::new()
                .try_with_platform_verifier()
                .map_err(|e| VaultError::Settings(e.to_string()))?,
        };
        let connector = builder.https_or_http().enable_http1().wrap_connector(http);
        let base = settings
            .address
            .as_url()
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            settings: settings.clone(),
            base,
            http: Client::builder(TokioExecutor::new()).build(connector),
            login: tokio::sync::Mutex::new(None),
        })
    }

    /// The settings this client was made for.
    #[must_use]
    pub fn settings(&self) -> &VaultSettings {
        &self.settings
    }

    /// Sends one request; returns the status and the JSON answer (`Null` when not JSON).
    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value), VaultError> {
        let url = format!("{}{path}", self.base);
        if !self.settings.allow_private_targets && private_literal(&url) {
            return Err(VaultError::Transport(
                "the address is private; set `allow_private_targets: true`".to_owned(),
            ));
        }
        let mut request = Request::builder()
            .method(method)
            .uri(&url)
            .header(
                header::USER_AGENT,
                concat!("rdock/", env!("CARGO_PKG_VERSION")),
            )
            .header(header::ACCEPT, "application/json");
        if let Some(token) = token {
            request = request.header("x-vault-token", token);
        }
        if let Some(namespace) = &self.settings.namespace {
            request = request.header("x-vault-namespace", namespace);
        }
        let payload = match body {
            Some(body) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Bytes::from(body.to_string())
            }
            None => Bytes::new(),
        };
        let request = request.body(Full::new(payload)).map_err(|_| {
            VaultError::Settings(
                "the request cannot be built (token or namespace has invalid characters)"
                    .to_owned(),
            )
        })?;
        let timeout = self.settings.timeout.as_std();
        let exchange = async {
            let response = self.http.request(request).await.map_err(|e| {
                VaultError::Transport(match std::error::Error::source(&e) {
                    Some(source) => format!("{e}: {source}"),
                    None => e.to_string(),
                })
            })?;
            let status = response.status();
            let bytes = Limited::new(response.into_body(), MAX_ANSWER)
                .collect()
                .await
                .map_err(|_| {
                    VaultError::Transport("the answer is too large or broken off".to_owned())
                })?
                .to_bytes();
            Ok::<_, VaultError>((
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            ))
        };
        tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| VaultError::Transport(format!("no answer within {timeout:?}")))?
    }

    /// The token to send, logging in when needed (or when `fresh`).
    async fn token(&self, fresh: bool) -> Result<String, VaultError> {
        match &self.settings.auth {
            VaultAuth::Token(reference) => {
                rdock_config::interpolate::expand(reference, &rdock_config::System)
                    .map(|t| t.trim().to_owned())
                    .map_err(|e| VaultError::Login(e.to_string()))
            }
            VaultAuth::Kubernetes(k) => {
                let mut login = self.login.lock().await;
                if !fresh
                    && let Some(current) = login.as_ref()
                    && current.renew_at.is_none_or(|at| Instant::now() < at)
                {
                    return Ok(current.token.clone());
                }
                let jwt = std::fs::read_to_string(&k.token_file).map_err(|e| {
                    VaultError::Login(format!(
                        "cannot read the service-account token `{}`: {}",
                        k.token_file.display(),
                        e.kind()
                    ))
                })?;
                let path = format!("/v1/auth/{}/login", k.mount);
                let (status, answer) = self
                    .send(
                        Method::POST,
                        &path,
                        None,
                        Some(json!({ "role": k.role, "jwt": jwt.trim() })),
                    )
                    .await?;
                if status != StatusCode::OK {
                    return Err(VaultError::Login(format!(
                        "`auth/{}/login` as role `{}` answered {}",
                        k.mount,
                        k.role,
                        status.as_u16()
                    )));
                }
                let token = answer
                    .pointer("/auth/client_token")
                    .and_then(Value::as_str)
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| {
                        VaultError::Login("the login answer has no `auth.client_token`".to_owned())
                    })?
                    .to_owned();
                let lease = answer
                    .pointer("/auth/lease_duration")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                // Log in again after two thirds of the lease, well before it runs out.
                let renew_at = (lease > 0)
                    .then(|| Instant::now() + Duration::from_secs(lease.saturating_mul(2) / 3));
                tracing::debug!(mount = %k.mount, role = %k.role, lease, "logged in to Vault");
                *login = Some(Login {
                    token: token.clone(),
                    renew_at,
                });
                Ok(token)
            }
        }
    }

    /// Reads one secret's `data.data` object.
    async fn secret(
        &self,
        mount: &str,
        path: &str,
    ) -> Result<serde_json::Map<String, Value>, VaultError> {
        let location = format!("{mount}/{path}");
        let url = format!("/v1/{mount}/data/{path}");
        let mut fresh = false;
        loop {
            let token = self.token(fresh).await?;
            let (status, answer) = self.send(Method::GET, &url, Some(&token), None).await?;
            if status == StatusCode::FORBIDDEN
                && !fresh
                && matches!(self.settings.auth, VaultAuth::Kubernetes(_))
            {
                // The token may have been revoked or expired early: log in once more.
                fresh = true;
                continue;
            }
            if status != StatusCode::OK {
                return Err(VaultError::Status {
                    status: status.as_u16(),
                    path: location,
                });
            }
            return match answer.pointer("/data/data") {
                Some(Value::Object(data)) => Ok(data.clone()),
                _ => Err(VaultError::Shape(location)),
            };
        }
    }

    /// Reads every reference, one request per secret. Returns the values read, keyed by the
    /// reference's body (`<mount>/<path>#<field>`), and the references that failed with why.
    pub async fn read(
        &self,
        references: &[VaultReference],
    ) -> (BTreeMap<String, String>, Vec<(String, VaultError)>) {
        let mut by_secret: BTreeMap<(&str, &str), Vec<&VaultReference>> = BTreeMap::new();
        for reference in references {
            by_secret
                .entry((reference.mount.as_str(), reference.path.as_str()))
                .or_default()
                .push(reference);
        }
        let mut values = BTreeMap::new();
        let mut failed = Vec::new();
        for ((mount, path), wanted) in by_secret {
            match self.secret(mount, path).await {
                Ok(data) => {
                    for reference in wanted {
                        match field(&data, &format!("{mount}/{path}"), &reference.field) {
                            Ok(value) => {
                                values.insert(reference.body(), value);
                            }
                            Err(e) => failed.push((reference.body(), e)),
                        }
                    }
                }
                Err(e) => {
                    for reference in wanted {
                        failed.push((reference.body(), e.clone()));
                    }
                }
            }
        }
        (values, failed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_text_numbers_or_booleans() {
        let data = json!({ "s": "x", "n": 7, "b": true, "o": {}, "z": null });
        let data = data.as_object().unwrap();
        assert_eq!(field(data, "kv/a", "s").unwrap(), "x");
        assert_eq!(field(data, "kv/a", "n").unwrap(), "7");
        assert_eq!(field(data, "kv/a", "b").unwrap(), "true");
        assert!(matches!(
            field(data, "kv/a", "o"),
            Err(VaultError::FieldType { .. })
        ));
        assert!(matches!(
            field(data, "kv/a", "z"),
            Err(VaultError::FieldType { .. })
        ));
        let missing = field(data, "kv/a", "q").unwrap_err().to_string();
        assert_eq!(missing, "`kv/a` has no field `q`");
    }
}
