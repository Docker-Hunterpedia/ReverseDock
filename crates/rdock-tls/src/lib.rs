#![doc = include_str!("../README.md")]

pub mod cert;
pub mod challenge;
pub mod client_auth;
pub mod clienthello;
pub mod index;
pub mod policy;
pub mod request;
pub mod tickets;

pub use cert::{CertError, LoadedCert, load_certificate};
pub use challenge::Challenges;
pub use client_auth::{CLOUDFLARE_ORIGIN_PULL_CA, ClientAuth, ClientAuthError};
pub use index::{CertIndex, ListenerResolver, SniResolver};
pub use policy::{ALPN, PolicyError, server_config};
pub use request::{CertRequest, PRIVATE_SUFFIXES, is_local_ca_name, is_private_name};
pub use tickets::{ClassKey, ClassKeys, Resumption, ResumptionSettings, TicketRegistry};

#[cfg(test)]
mod tests;
