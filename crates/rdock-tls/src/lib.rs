#![doc = include_str!("../README.md")]

pub mod cert;
pub mod challenge;
pub mod index;
pub mod policy;
pub mod request;

pub use cert::{CertError, LoadedCert, load_certificate};
pub use challenge::Challenges;
pub use index::{CertIndex, SniResolver};
pub use policy::{ALPN, PolicyError, server_config};
pub use request::{CertRequest, PRIVATE_SUFFIXES, is_local_ca_name, is_private_name};

#[cfg(test)]
mod tests;
