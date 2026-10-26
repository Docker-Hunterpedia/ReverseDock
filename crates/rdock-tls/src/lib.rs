#![doc = include_str!("../README.md")]

pub mod cert;
pub mod index;
pub mod policy;

pub use cert::{CertError, LoadedCert, load_certificate};
pub use index::{CertIndex, SniResolver};
pub use policy::{ALPN, PolicyError, server_config};

#[cfg(test)]
mod tests;
