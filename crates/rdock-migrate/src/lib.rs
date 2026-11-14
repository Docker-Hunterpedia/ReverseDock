#![doc = include_str!("../README.md")]

pub mod caddy;
pub mod compose;
pub mod config;
pub mod nginx;
mod output;
pub mod report;
pub mod traefik;

pub use traefik::{Error, Input, Migration, Options, StaticFile, traefik};

#[cfg(test)]
mod tests;
