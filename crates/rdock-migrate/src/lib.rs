#![doc = include_str!("../README.md")]

pub mod compose;
pub mod config;
pub mod report;
pub mod traefik;

pub use traefik::{Error, Input, Migration, Options, StaticFile, traefik};

#[cfg(test)]
mod tests;
