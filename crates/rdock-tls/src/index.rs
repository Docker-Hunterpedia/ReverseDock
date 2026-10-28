//! Certificate selection by server name (SNI), swappable at runtime.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::cert::LoadedCert;
use crate::challenge::{ACME_TLS_ALPN, Challenges};

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

    /// The certificate covering `name` (exact, then one-label wildcard), ignoring the default.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.find(name)
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

/// A rustls certificate resolver that can be updated while listeners keep running. It serves
/// the configured certificates first, then automatically issued ones, then the configured
/// default.
///
/// A handshake that offers only the `acme-tls/1` protocol is a TLS-ALPN-01 validation: it gets
/// the validation certificate for its name, or none.
#[derive(Debug, Default)]
pub struct SniResolver {
    index: ArcSwap<CertIndex>,
    managed: ArcSwap<CertIndex>,
    challenges: Arc<Challenges>,
}

impl SniResolver {
    /// A resolver serving `index`.
    #[must_use]
    pub fn new(index: CertIndex) -> Self {
        Self {
            index: ArcSwap::from_pointee(index),
            managed: ArcSwap::default(),
            challenges: Arc::default(),
        }
    }

    /// The challenge answers this resolver serves, shared with the HTTP listeners.
    #[must_use]
    pub fn challenges(&self) -> Arc<Challenges> {
        self.challenges.clone()
    }

    /// Replaces the automatically issued certificates; new handshakes use them immediately.
    pub fn swap_managed(&self, index: impl Into<Arc<CertIndex>>) {
        self.managed.store(index.into());
    }

    /// Whether a configured or automatically issued certificate covers `name`.
    #[must_use]
    pub fn covers(&self, name: &str) -> bool {
        self.index.load().covers(name) || self.managed.load().covers(name)
    }

    /// Replaces the configured certificates; new handshakes use them immediately.
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
        if client_hello.alpn().is_some_and(|mut offered| {
            offered.next() == Some(ACME_TLS_ALPN) && offered.next().is_none()
        }) {
            return client_hello
                .server_name()
                .and_then(|name| self.challenges.tls_alpn01(name));
        }
        let index = self.index.load();
        let Some(name) = client_hello.server_name() else {
            return index.lookup(None);
        };
        index
            .get(name)
            .or_else(|| self.managed.load().get(name))
            .or_else(|| index.lookup(None))
    }
}
