//! The cluster protocol between data planes and the control plane (ADR-0031), version 1.
//!
//! Every call is HTTP/2 (or HTTP/1.1) over TLS to the control plane's cluster listener, with
//! JSON bodies, under `/cluster/v1/`. Enrolment is the only call without a client certificate:
//! the data plane authenticates the control plane by the cluster CA it was given (file or pin)
//! and presents a single-use join token. Every later call presents the client certificate the
//! control plane issued; its subject names the instance.
//!
//! | Call | Method and path | Body → answer |
//! |---|---|---|
//! | Enrol | `POST /cluster/v1/enroll` | [`EnrollRequest`] → [`EnrollResponse`] |
//! | Renew the certificate | `POST /cluster/v1/renew` | [`RenewRequest`] → [`EnrollResponse`] |
//! | Next bundle | `GET /cluster/v1/bundle?after=N&wait=S` | → `200` zstd-compressed [`Bundle`], or `204` when none is newer within `S` seconds |
//! | Report | `POST /cluster/v1/report` | [`Report`] → `204` |
//! | Store | `POST /cluster/v1/store` | [`StoreRequest`] → [`StoreResponse`] |
//!
//! A revoked or unknown instance gets `403` on every call but enrolment.

use serde::{Deserialize, Serialize};

use crate::store::{Expect, Lease};

/// The protocol version in paths and documents.
pub const VERSION: u32 = 1;

/// The media type of a compressed bundle.
pub const BUNDLE_MEDIA_TYPE: &str = "application/vnd.rdock.bundle+zstd";

/// The URI SAN prefix of an instance's client certificate: `urn:rdock:instance:<cluster id>:<instance>`.
pub const INSTANCE_URI_PREFIX: &str = "urn:rdock:instance:";

/// `POST /cluster/v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// The join token, `rdk_join_…`.
    pub token: String,
    /// A PKCS#10 signing request for the instance's key (PEM); the key never leaves the data
    /// plane.
    pub csr_pem: String,
    /// The name the instance asks for (`cluster.instance`), if any.
    #[serde(default)]
    pub name: Option<String>,
    /// The data plane's version.
    pub version: String,
}

impl Drop for EnrollRequest {
    fn drop(&mut self) {
        // Not a real wipe (the allocator may have copies); keeps the token out of later dumps
        // of this value at least.
        self.token.clear();
    }
}

/// The answer to enrolment and renewal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// The cluster's id.
    pub cluster_id: String,
    /// The instance's name, as the control plane knows it.
    pub instance: String,
    /// The client certificate (PEM).
    pub certificate_pem: String,
    /// The cluster CA (PEM).
    pub ca_pem: String,
    /// When the certificate expires (Unix seconds).
    pub not_after: i64,
}

/// `POST /cluster/v1/renew`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewRequest {
    /// A PKCS#10 signing request for a new key (PEM).
    pub csr_pem: String,
}

/// A configuration bundle: what the control plane publishes (ADR-0031).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    /// The bundle format, [`VERSION`].
    pub format: u32,
    /// The cluster it belongs to; a data plane refuses another cluster's bundle.
    pub cluster_id: String,
    /// Assigned by the control plane, growing with every publication (rollbacks included).
    pub revision: u64,
    /// SHA-256 of the canonical JSON of `document`, lower-case hex.
    pub sha256: String,
    /// When it was published (RFC 3339).
    pub published_at: String,
    /// Who published it.
    #[serde(default)]
    pub published_by: Option<String>,
    /// The revision whose document this one republishes, for a rollback.
    #[serde(default)]
    pub rollback_of: Option<u64>,
    /// The configuration as written (references such as `${file:…}` unresolved: each data
    /// plane resolves them itself).
    pub document: serde_json::Value,
}

impl Bundle {
    /// The SHA-256 of `document`'s canonical JSON (keys sorted, no spaces), lower-case hex.
    #[must_use]
    pub fn digest(document: &serde_json::Value) -> String {
        let canonical = canonical_json(document);
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        digest.as_ref().iter().fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    /// Whether `document` has no configuration at all (an empty object).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.document
            .as_object()
            .is_none_or(serde_json::Map::is_empty)
    }
}

/// JSON with object keys sorted, whatever order the maps keep (`serde_json` keeps insertion
/// order with its `preserve_order` feature).
#[must_use]
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::Value::String(k.clone()),
                        canonical_json(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        serde_json::Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        other => other.to_string(),
    }
}

/// How a data plane took a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Validated, compiled, stored and applied.
    Ack,
    /// Not applied; the previous revision stays in use. `diagnostics` say why.
    Nack,
}

/// `POST /cluster/v1/report`: the outcome of a bundle, and the data plane's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// The revision this report is about.
    pub revision: u64,
    /// ACK or NACK.
    pub verdict: Verdict,
    /// The revision the data plane serves now.
    pub serving: u64,
    /// Why it was refused, and warnings.
    #[serde(default)]
    pub diagnostics: Vec<serde_json::Value>,
    /// The data plane's version.
    pub version: String,
}

/// `POST /cluster/v1/store`: one store operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StoreRequest {
    /// [`crate::ClusterStore::get`].
    Get {
        /// The key.
        key: String,
    },
    /// [`crate::ClusterStore::put`]; the value in standard base64.
    Put {
        /// The key.
        key: String,
        /// The value, base64.
        value: String,
        /// The condition.
        expect: Expect,
        /// The lease a fenced write carries.
        #[serde(default)]
        fence: Option<Lease>,
    },
    /// [`crate::ClusterStore::delete`].
    Delete {
        /// The key.
        key: String,
        /// The condition.
        expect: Expect,
        /// The lease a fenced write carries.
        #[serde(default)]
        fence: Option<Lease>,
    },
    /// [`crate::ClusterStore::list`].
    List {
        /// The prefix.
        prefix: String,
    },
    /// [`crate::ClusterStore::acquire`]; the holder is always the calling instance.
    Acquire {
        /// The lease name.
        name: String,
        /// Milliseconds.
        ttl_ms: u64,
    },
    /// [`crate::ClusterStore::renew`].
    Renew {
        /// The lease.
        lease: Lease,
        /// Milliseconds.
        ttl_ms: u64,
    },
    /// [`crate::ClusterStore::release`].
    Release {
        /// The lease.
        lease: Lease,
    },
    /// [`crate::ClusterStore::lease`].
    Lease {
        /// The lease name.
        name: String,
    },
}

/// The answer to a [`StoreRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum StoreResponse {
    /// A value (base64) and its version, or none.
    Entry {
        /// The value, base64, if any.
        value: Option<String>,
        /// Its version (`0` without a value).
        version: u64,
    },
    /// The version written.
    Version {
        /// The new version.
        version: u64,
    },
    /// Keys.
    Keys {
        /// Sorted keys.
        keys: Vec<String>,
    },
    /// A lease, or none.
    Lease {
        /// The lease.
        lease: Option<Lease>,
    },
    /// Done.
    Done,
    /// Failed: `kind` is `conflict`, `fenced`, `lost`, `invalid_key` or `backend`.
    Error {
        /// What went wrong.
        kind: String,
        /// Details.
        message: String,
        /// The current version, for `conflict`.
        #[serde(default)]
        current: u64,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn digests_do_not_depend_on_key_order() {
        let a = json!({ "routes": { "b": 1, "a": [1, { "y": 2, "x": 1 }] }, "acme": false });
        let b = json!({ "acme": false, "routes": { "a": [1, { "x": 1, "y": 2 }], "b": 1 } });
        assert_eq!(Bundle::digest(&a), Bundle::digest(&b));
        assert_ne!(Bundle::digest(&a), Bundle::digest(&json!({})));
        assert_eq!(
            canonical_json(&json!({ "b": "x", "a": null })),
            r#"{"a":null,"b":"x"}"#
        );
    }
}
