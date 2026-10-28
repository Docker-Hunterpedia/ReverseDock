//! Automatic certificates.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::values::{Duration, HttpUrl};

/// The `acme` section: `false` turns automatic certificates off, `true` or settings keep them on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum AcmeSetting {
    /// `true` uses the defaults; `false` turns automatic certificates off.
    Enabled(bool),
    /// Settings.
    Settings(Box<Acme>),
}

impl<'de> Deserialize<'de> for AcmeSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SettingVisitor;
        impl<'de> Visitor<'de> for SettingVisitor {
            type Value = AcmeSetting;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("`true`, `false` or ACME settings")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<AcmeSetting, E> {
                Ok(AcmeSetting::Enabled(value))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<AcmeSetting, A::Error> {
                Acme::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(|acme| AcmeSetting::Settings(Box::new(acme)))
            }
        }
        deserializer.deserialize_any(SettingVisitor)
    }
}

/// ACME (automatic certificates) settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Acme {
    /// Contact address for the CA account (optional for Let's Encrypt).
    pub email: Option<String>,
    /// Certificate authority: a known name or an `https://` ACME directory URL.
    pub ca: CaRef,
    /// Certificate profile (Let's Encrypt): `classic` (90 days), `tlsserver` (45 days) or
    /// `shortlived` (about 6 days, needed for IP addresses).
    pub profile: Option<AcmeProfile>,
    /// Challenge types to use, in order of preference.
    pub challenges: Vec<Challenge>,
    /// DNS providers for DNS-01, referenced by routes.
    pub dns_providers: BTreeMap<String, DnsProvider>,
    /// DNS provider (a key of `dns_providers`) used for every route that does not name one:
    /// all certificates are then validated with DNS-01.
    pub dns_provider: Option<String>,
    /// Use the CA's staging environment (untrusted certificates, high rate limits).
    pub staging: bool,
    /// External account binding, required by some CAs.
    pub eab: Option<ExternalAccountBinding>,
    /// Where accounts and certificates are stored. Defaults to `$RDOCK_DATA_DIR/acme`.
    pub storage: Option<PathBuf>,
    /// PEM file with the root certificate of a CA whose ACME endpoint is not publicly trusted,
    /// such as an internal step-ca. Only this root is then trusted for the CA's endpoint.
    pub ca_root: Option<PathBuf>,
}

impl Default for Acme {
    fn default() -> Self {
        Self {
            email: None,
            ca: CaRef::Known(KnownCa::Letsencrypt),
            profile: None,
            challenges: vec![Challenge::Http01, Challenge::TlsAlpn01],
            dns_providers: BTreeMap::new(),
            dns_provider: None,
            staging: false,
            eab: None,
            storage: None,
            ca_root: None,
        }
    }
}

/// A certificate authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum CaRef {
    /// A CA known by name.
    Known(KnownCa),
    /// Any RFC 8555 ACME directory.
    Directory(HttpUrl),
}

impl Default for CaRef {
    fn default() -> Self {
        Self::Known(KnownCa::Letsencrypt)
    }
}

impl<'de> Deserialize<'de> for CaRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CaVisitor;
        impl Visitor<'_> for CaVisitor {
            type Value = CaRef;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("`letsencrypt`, `zerossl`, `google` or an https:// ACME directory URL")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<CaRef, E> {
                if let Ok(known) = KnownCa::deserialize(de::value::StrDeserializer::<E>::new(value))
                {
                    return Ok(CaRef::Known(known));
                }
                match value.parse::<HttpUrl>() {
                    Ok(url) if url.as_url().scheme() == "https" => Ok(CaRef::Directory(url)),
                    _ => Err(E::invalid_value(de::Unexpected::Str(value), &self)),
                }
            }
        }
        deserializer.deserialize_str(CaVisitor)
    }
}

/// Certificate authorities known by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KnownCa {
    /// Let's Encrypt.
    Letsencrypt,
    /// ZeroSSL (needs `eab`).
    Zerossl,
    /// Buypass Go SSL: discontinued on 2025-10-16 and refused by validation.
    Buypass,
    /// Google Trust Services (needs `eab`).
    Google,
}

/// Let's Encrypt certificate profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AcmeProfile {
    /// 90-day certificates (the default).
    Classic,
    /// 45-day certificates without legacy fields.
    Tlsserver,
    /// About 6-day certificates; the only profile that allows IP addresses.
    Shortlived,
}

/// ACME challenge types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Challenge {
    /// HTTP-01 on port 80.
    #[serde(rename = "http-01")]
    Http01,
    /// TLS-ALPN-01 on port 443.
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// DNS-01 through a DNS provider; needed for wildcard certificates.
    #[serde(rename = "dns-01")]
    Dns01,
}

/// A DNS provider for DNS-01 challenges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DnsProvider {
    /// Cloudflare DNS, with an API token allowed to edit the zone's DNS records.
    Cloudflare {
        /// API token with Zone → DNS → Edit. Write it as a `${file:…}` or `${env:…}` reference.
        api_token: String,
        /// Zone ID. Looked up from the name when omitted, which also needs Zone → Zone → Read.
        #[serde(default)]
        zone_id: Option<String>,
    },
    /// A program run as `<command> <args…> present|cleanup <name> <value>`, without a shell.
    Exec {
        /// Absolute path of the program.
        command: PathBuf,
        /// Arguments placed before the action.
        #[serde(default)]
        args: Vec<String>,
        /// Time allowed for each run.
        #[serde(default = "thirty_seconds")]
        timeout: Duration,
    },
    /// A JSON `POST` of `{"action", "name", "value"}` to an HTTPS endpoint.
    Webhook(Webhook),
}

/// An HTTPS endpoint that receives JSON events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Webhook {
    /// `https://` URL (`http://` only for loopback addresses).
    pub url: HttpUrl,
    /// Bearer token sent in `Authorization`. Write it as a `${file:…}` or `${env:…}` reference.
    #[serde(default)]
    pub token: Option<String>,
    /// Time allowed for each request.
    #[serde(default = "ten_seconds")]
    pub timeout: Duration,
}

const fn thirty_seconds() -> Duration {
    Duration::from_secs(30)
}

const fn ten_seconds() -> Duration {
    Duration::from_secs(10)
}

/// External account binding credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExternalAccountBinding {
    /// Key identifier from the CA.
    pub key_id: String,
    /// Base64url HMAC key from the CA. Reference a secret instead of writing it here.
    pub hmac_key: String,
}
