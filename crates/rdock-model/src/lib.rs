#![doc = include_str!("../README.md")]

pub mod acme;
pub mod config;
pub mod diagnostics;
pub mod middleware;
pub mod providers;
pub mod route;
mod schema;
pub mod service;
pub mod settings;
mod validate;
pub mod values;

pub use config::Config;
pub use diagnostics::{Diagnostic, Severity, path_index, path_key};
pub use rdock_rules::closest_match;
pub use schema::{SCHEMA_ID, json_schema, json_schema_string};

/// Serde default helpers shared by the configuration types.
pub(crate) mod defaults {
    pub(crate) const fn yes() -> bool {
        true
    }
}
