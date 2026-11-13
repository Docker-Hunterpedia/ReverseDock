//! Enrolled data planes (`<data>/control/instances.json`): identity, certificate, the revision
//! each serves and the outcome of the last bundle it was given.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::Error;

/// The last bundle outcome a data plane reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LastReport {
    /// The revision reported on.
    pub revision: u64,
    /// `ack` or `nack`.
    pub verdict: rdock_cluster::protocol::Verdict,
    /// Why, for a NACK (the data plane's diagnostics).
    #[serde(default)]
    pub diagnostics: Vec<serde_json::Value>,
    /// When (Unix seconds).
    pub at: i64,
}

/// One enrolled data plane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Instance {
    /// Its name in the cluster.
    pub name: String,
    /// When it enrolled (Unix seconds).
    pub enrolled_at: i64,
    /// The join token it used.
    pub token_id: String,
    /// Serial (hex) and expiry (Unix seconds) of its newest client certificate.
    pub certificate_serial: String,
    /// Expiry of its newest client certificate (Unix seconds).
    pub certificate_not_after: i64,
    /// Revoked instances can no longer fetch bundles or use the store.
    #[serde(default)]
    pub revoked: bool,
    /// When it last called the control plane (Unix seconds).
    #[serde(default)]
    pub last_seen: Option<i64>,
    /// The version it last reported.
    #[serde(default)]
    pub version: Option<String>,
    /// The revision it serves, as it last reported.
    #[serde(default)]
    pub serving: u64,
    /// The outcome of the last bundle.
    #[serde(default)]
    pub last_report: Option<LastReport>,
}

/// The registry file.
#[derive(Debug)]
pub struct Registry {
    path: PathBuf,
    instances: BTreeMap<String, Instance>,
}

impl Registry {
    /// Loads `<dir>/instances.json`.
    pub fn load(dir: &std::path::Path) -> Result<Self, Error> {
        let path = dir.join("instances.json");
        let instances = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::State(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(Error::State(format!("{}: {e}", path.display()))),
        };
        Ok(Self { path, instances })
    }

    /// Writes the registry.
    pub fn save(&self) -> Result<(), Error> {
        let json =
            serde_json::to_vec_pretty(&self.instances).map_err(|e| Error::State(e.to_string()))?;
        rdock_cluster::dir::write_private(&self.path, &json)
            .map_err(|e| Error::State(format!("{}: {e}", self.path.display())))
    }

    /// The instance named `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Instance> {
        self.instances.get(name)
    }

    /// The instance named `name`, to change.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Instance> {
        self.instances.get_mut(name)
    }

    /// Adds or replaces an instance.
    pub fn insert(&mut self, instance: Instance) {
        self.instances.insert(instance.name.clone(), instance);
    }

    /// Every instance, by name.
    pub fn all(&self) -> impl Iterator<Item = &Instance> {
        self.instances.values()
    }

    /// Whether `name` may call the control plane: enrolled and not revoked.
    #[must_use]
    pub fn allowed(&self, name: &str) -> bool {
        self.instances.get(name).is_some_and(|i| !i.revoked)
    }
}
