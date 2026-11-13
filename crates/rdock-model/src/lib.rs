#![doc = include_str!("../README.md")]

pub mod acme;
pub mod cache;
pub mod cluster;
pub mod config;
pub mod diagnostics;
pub mod gateway;
pub mod interpolation;
pub mod json_patch;
pub mod middleware;
pub mod oidc;
pub mod providers;
pub mod route;
mod schema;
pub mod secrets;
pub mod service;
pub mod settings;
pub mod transform;
mod validate;
pub mod validation;
pub mod values;

pub use config::Config;
pub use diagnostics::{Diagnostic, Severity, path_index, path_key};
pub use rdock_rules::closest_match;
pub use schema::{SCHEMA_ID, json_schema, json_schema_string};
pub use validate::status_range;

/// Serde default helpers shared by the configuration types.
pub(crate) mod defaults {
    pub(crate) const fn yes() -> bool {
        true
    }
}
