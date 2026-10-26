//! Certificate selection by server name (SNI), swappable at runtime.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::cert::LoadedCert;

/// Certificates indexed by the names they cover.
#[derive(Debug, Default)]
pub struct CertIndex {
    exact: HashMap<String, Entry>,
    /// `*.example.com` is stored under `example.com`.
    wildcard: HashMap<String, Entry>,
    default: Option<Arc<CertifiedKey>>,
}

#[derive(Debug, Clone)]
struct Entry {
    key: Arc<CertifiedKey>,
    not_after: i64,
}

impl CertIndex {
    /// Indexes `certs` by their subject alternative names. When several certificates cover a
    /// name, the one that expires last wins. `default` names the certificate served when nothing
    /// else matches.
    #[must_use]
    pub fn build(certs: &[LoadedCert], default: Option<&str>) -> Self {
        let mut index = Self::default();
        for cert in certs {
            let entry = Entry {
                key: cert.key.clone(),
                not_after: cert.not_after,
            };
            for name in &cert.names {
                let (map, key) = match name.strip_prefix("*.") {
                    Some(parent) => (&mut index.wildcard, parent),
                    None => (&mut index.exact, name.as_str()),
                };
                match map.get(key) {
                    Some(existing) if existing.not_after >= entry.not_after => {}
                    _ => {
                        map.insert(key.to_owned(), entry.clone());
                    }
                }
            }
        }
        index.default =
            default.and_then(|name| certs.iter().find(|c| c.name == name).map(|c| c.key.clone()));
        index
    }

    /// The certificate for a requested name: exact match, then a one-label wildcard, then the
    /// default certificate.
    #[must_use]
    pub fn lookup(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        server_name
            .and_then(|name| self.find(name))
            .or_else(|| self.default.clone())
    }

    /// Whether a certificate other than the default covers `host`.
    #[must_use]
    pub fn covers(&self, host: &str) -> bool {
        self.find(host).is_some()
    }

    fn find(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(entry) = self.exact.get(&name) {
            return Some(entry.key.clone());
        }
        let (_, parent) = name.split_once('.')?;
        self.wildcard.get(parent).map(|e| e.key.clone())
    }
}

/// A rustls certificate resolver backed by a [`CertIndex`] that can be replaced while
/// listeners keep running.
#[derive(Debug, Default)]
pub struct SniResolver {
    index: ArcSwap<CertIndex>,
}

impl SniResolver {
    /// A resolver serving `index`.
    #[must_use]
    pub fn new(index: CertIndex) -> Self {
        Self {
            index: ArcSwap::from_pointee(index),
        }
    }

    /// Replaces the certificates; new handshakes use them immediately.
    pub fn swap(&self, index: impl Into<Arc<CertIndex>>) {
        self.index.store(index.into());
    }

    /// The current index.
    #[must_use]
    pub fn index(&self) -> Arc<CertIndex> {
        self.index.load_full()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.index.load().lookup(client_hello.server_name())
    }
}
