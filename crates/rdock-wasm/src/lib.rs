//! Sandboxed WebAssembly plugins for ReverseDock (F-EXT-03, ADR-0030). **Experimental.**
//!
//! A plugin is a WebAssembly component targeting the world `rdock:plugin/filter@0.1.0`
//! ([`WIT`]). Before a module is compiled, [`artifact::load`] checks that the file matches its
//! pinned SHA-256 and carries a minisign signature by a trusted key ([`minisign`]); an
//! unsigned module is accepted only with `allow_unsigned`.
//!
//! The wasmtime host is behind the cargo feature **`wasm`** (off by default): one engine with
//! fuel metering and epoch interruption, components checked against the world and the granted
//! capabilities when they are loaded, a fresh instance per request with a memory limit, and no
//! WASI. Without the feature this crate holds only the digest and signature checks.

pub mod artifact;
/// The minisign verifier, shared with binary upgrades (`upgrade.trusted_keys`); it lives in
/// `rdock-credentials`.
pub use rdock_credentials::minisign;

#[cfg(feature = "testing")]
pub mod testing;
#[cfg(all(test, not(feature = "testing")))]
mod testing;

#[cfg(feature = "wasm")]
mod host;

#[cfg(feature = "wasm")]
pub use host::{CallError, CompileError, Facts, Grants, Instance, Limits, Plugin, Settings};

/// The version of the host ABI (the WIT package `rdock:plugin`).
pub const ABI_VERSION: &str = "0.1.0";

/// The WIT text of the host ABI.
pub const WIT: &str = include_str!("../wit/filter.wit");

/// Whether this build includes the wasmtime host.
pub const ENABLED: bool = cfg!(feature = "wasm");

#[cfg(test)]
mod tests {
    #[test]
    fn the_guide_carries_the_wit_verbatim() {
        let guide =
            include_str!("../../../apps/website/src/content/docs/docs/guides/wasm-plugins.mdx");
        assert!(
            guide.contains(&format!("```wit\n{}```", super::WIT)),
            "copy crates/rdock-wasm/wit/filter.wit into the guide's ABI reference"
        );
        assert!(super::WIT.contains(&format!("package rdock:plugin@{};", super::ABI_VERSION)));
    }
}
