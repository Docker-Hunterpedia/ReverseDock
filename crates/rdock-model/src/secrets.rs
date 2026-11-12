//! External secret stores (W-OBS-02, ADR-0030): `secrets.vault` and the `${vault:…}`
//! reference.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::values::{Duration, HttpUrl};

/// External secret stores.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Secrets {
    /// A `HashiCorp` Vault or `OpenBao` server whose KV version 2 secrets secret fields may
    /// reference as `${vault:<mount>/<path>#<field>}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultSettings>,
}

impl Secrets {
    /// Whether nothing is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vault.is_none()
    }
}

/// A Vault or `OpenBao` server (`secrets.vault`).
///
/// Values are read when a configuration is loaded and every `refresh`; a changed value reloads
/// the configuration. They stay in memory only: the configuration, its history, snapshots, the
/// admin API, logs and diagnostics keep the `${vault:…}` reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VaultSettings {
    /// The server, e.g. `https://vault.internal:8200`. `https://` only, or `http://` to a
    /// loopback address (a dev server or a local agent), unless `insecure_http` is set.
    pub address: HttpUrl,
    /// CA certificates (PEM) that sign the server's certificate, instead of the system's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    /// A Vault Enterprise or `OpenBao` namespace, sent as `X-Vault-Namespace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// How rdock logs in.
    pub auth: VaultAuth,
    /// How often referenced values are read again.
    #[serde(default = "five_minutes")]
    pub refresh: Duration,
    /// Time allowed for one request to the server.
    #[serde(default = "five_seconds")]
    pub timeout: Duration,
    /// Allow a server on a private address (`10.0.0.0/8`, …). On by default: Vault usually
    /// runs inside the network.
    #[serde(default = "crate::defaults::yes")]
    pub allow_private_targets: bool,
    /// Allow `http://` to a server that is not on a loopback address. **Unsafe**: the token
    /// and every secret cross the network unencrypted. Validation warns.
    #[serde(default)]
    pub insecure_http: bool,
}

const fn five_minutes() -> Duration {
    Duration::from_secs(300)
}

const fn five_seconds() -> Duration {
    Duration::from_secs(5)
}

/// How rdock logs in to Vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultAuth {
    /// A token, as a `${file:…}` or `${env:…}` reference (read again on every request, so a
    /// token file rotated by an agent is picked up).
    Token(String),
    /// Kubernetes service-account login (`POST /v1/auth/<mount>/login`); the token is renewed
    /// by logging in again before its lease runs out.
    Kubernetes(KubernetesAuth),
}

/// Kubernetes login settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAuth {
    /// The Vault role to log in as.
    pub role: String,
    /// Where the Kubernetes auth method is mounted.
    #[serde(default = "kubernetes")]
    pub mount: String,
    /// The service-account token, read at every login.
    #[serde(default = "service_account_token")]
    pub token_file: PathBuf,
}

fn kubernetes() -> String {
    "kubernetes".to_owned()
}

fn service_account_token() -> PathBuf {
    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
}

/// A parsed `${vault:<mount>/<path>#<field>}` reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultReference {
    /// The KV version 2 mount (the first path segment).
    pub mount: String,
    /// The secret's path below the mount.
    pub path: String,
    /// The field of the secret's data.
    pub field: String,
}

impl VaultReference {
    /// Parses the body of a reference, `<mount>/<path>#<field>` (without `vault:`).
    ///
    /// # Errors
    ///
    /// What is wrong with the reference.
    pub fn parse(body: &str) -> Result<Self, String> {
        let (location, field) = body.split_once('#').ok_or_else(|| {
            "a Vault reference needs `#<field>`: `${vault:<mount>/<path>#<field>}`".to_owned()
        })?;
        let (mount, path) = location.split_once('/').ok_or_else(|| {
            "a Vault reference needs a mount and a path: `${vault:<mount>/<path>#<field>}`"
                .to_owned()
        })?;
        let segment_ok = |s: &str| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
        };
        if !segment_ok(mount) || !path.split('/').all(segment_ok) {
            return Err("a Vault mount and path are `/`-separated names of letters, digits, `-`, `_`, `.` and `@`".to_owned());
        }
        if field.is_empty() || field.contains(['}', '#']) {
            return Err("the field after `#` is empty or has `#` or `}`".to_owned());
        }
        Ok(Self {
            mount: mount.to_owned(),
            path: path.to_owned(),
            field: field.to_owned(),
        })
    }

    /// The body of the reference, `<mount>/<path>#<field>`: the key its value is stored under.
    #[must_use]
    pub fn body(&self) -> String {
        format!("{}/{}#{}", self.mount, self.path, self.field)
    }

    /// The reference as written, `${vault:<mount>/<path>#<field>}`.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("${{vault:{}/{}#{}}}", self.mount, self.path, self.field)
    }
}

/// The bodies of every `${vault:…}` reference in `text` (between `${vault:` and `}`); `$${`
/// escapes are skipped.
#[must_use]
pub fn vault_references(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let escaped = rest[..start].ends_with('$');
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else { break };
        if !escaped && let Some(body) = after[..end].strip_prefix("vault:") {
            out.push(body);
        }
        rest = &after[end + 1..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_parse() {
        let r = VaultReference::parse("secret/rdock/jwt#key").unwrap();
        assert_eq!(
            (r.mount.as_str(), r.path.as_str(), r.field.as_str()),
            ("secret", "rdock/jwt", "key")
        );
        assert_eq!(r.reference(), "${vault:secret/rdock/jwt#key}");
        for bad in [
            "secret/rdock",
            "secret#key",
            "/x#k",
            "secret/../x#k",
            "secret/a b#k",
            "secret/x#",
            "secret//x#k",
        ] {
            assert!(VaultReference::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn references_are_found() {
        assert_eq!(
            vault_references("a${vault:kv/x#y}b$${vault:kv/z#w}${env:E}${vault:kv/q#r}"),
            vec!["kv/x#y", "kv/q#r"]
        );
        assert_eq!(vault_references("${file:/x}"), Vec::<&str>::new());
    }

    #[test]
    fn settings_parse_with_defaults() {
        let s: VaultSettings = serde_json::from_value(serde_json::json!({
            "address": "https://vault.internal:8200",
            "auth": { "kubernetes": { "role": "rdock" } }
        }))
        .unwrap();
        assert_eq!(s.refresh, Duration::from_secs(300));
        assert_eq!(s.timeout, Duration::from_secs(5));
        assert!(s.allow_private_targets && !s.insecure_http);
        let VaultAuth::Kubernetes(k) = s.auth else {
            unreachable!()
        };
        assert_eq!(k.mount, "kubernetes");
        let token: VaultSettings = serde_json::from_value(serde_json::json!({
            "address": "http://127.0.0.1:8200",
            "auth": { "token": "${file:/run/secrets/vault-token}" }
        }))
        .unwrap();
        assert!(matches!(token.auth, VaultAuth::Token(_)));
    }
}
