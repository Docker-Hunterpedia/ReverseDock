#![doc = include_str!("../README.md")]

pub mod bundles;
pub mod ca;
mod plane;
pub mod registry;
pub mod server;
mod store;
pub mod tokens;

pub use plane::{ControlPlane, InstanceState, rfc3339};

/// Why a control-plane operation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request is refused (a bad token, a revoked name, an empty bundle…); the message is
    /// safe to show to the caller.
    #[error("{0}")]
    Refused(String),
    /// The caller is not an enrolled, unrevoked instance.
    #[error("not enrolled or revoked")]
    Forbidden,
    /// A certificate could not be made or read.
    #[error("certificate: {0}")]
    Certificate(String),
    /// The control plane's state could not be read or written.
    #[error("control plane state: {0}")]
    State(String),
}

/// Now, in Unix seconds.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
