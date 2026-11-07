#![doc = include_str!("../README.md")]

use std::sync::Arc;

use rdock_acme::dns::{BuiltinProviders, DnsError, DnsProviders, DnsSolver};
use rdock_model::acme::DnsProvider;

pub mod azure;
mod backoff;
pub mod desec;
pub mod digitalocean;
pub mod google;
pub mod hetzner;
mod jwt;
mod lock;
mod oauth;
mod rest;
pub mod rfc2136;
pub mod route53;
mod secret;
mod sigv4;
#[cfg(test)]
mod testdata;
mod xml;
mod zone;

pub use azure::AzureDns;
pub use desec::DesecDns;
pub use digitalocean::DigitalOceanDns;
pub use google::GoogleCloudDns;
pub use hetzner::HetznerDns;
pub use rfc2136::Rfc2136Dns;
pub use route53::Route53Dns;

/// The DNS providers of this crate; every other `type` goes to the providers it wraps.
#[derive(Debug)]
pub struct Providers {
    others: Arc<dyn DnsProviders>,
}

impl Providers {
    /// These providers, falling back to `others` (for example the Cloudflare adapter).
    pub fn new(others: Arc<dyn DnsProviders>) -> Self {
        Self { others }
    }
}

impl Default for Providers {
    /// These providers and the built-in `exec` and `webhook`.
    fn default() -> Self {
        Self::new(Arc::new(BuiltinProviders))
    }
}

impl DnsProviders for Providers {
    fn build(&self, config: &DnsProvider) -> Result<Arc<dyn DnsSolver>, DnsError> {
        match config {
            DnsProvider::DigitalOcean(provider) => Ok(Arc::new(DigitalOceanDns::new(provider)?)),
            DnsProvider::Hetzner(provider) => Ok(Arc::new(HetznerDns::new(provider)?)),
            DnsProvider::Rfc2136(provider) => Ok(Arc::new(Rfc2136Dns::new(provider)?)),
            DnsProvider::Desec(provider) => Ok(Arc::new(DesecDns::new(provider)?)),
            DnsProvider::Route53(provider) => Ok(Arc::new(Route53Dns::new(provider)?)),
            DnsProvider::GoogleCloudDns(provider) => Ok(Arc::new(GoogleCloudDns::new(provider)?)),
            DnsProvider::AzureDns(provider) => Ok(Arc::new(AzureDns::new(provider)?)),
            other => self.others.build(other),
        }
    }
}
