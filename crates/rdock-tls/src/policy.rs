//! TLS server configurations for the named policies.

use std::sync::Arc;

use rdock_model::config::TlsPolicy;
use rustls::server::ResolvesServerCert;
use rustls::{ServerConfig, SupportedProtocolVersion};

/// ALPN protocols offered on TLS listeners, in order of preference.
pub const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Why a server configuration could not be built.
#[derive(Debug, thiserror::Error)]
#[error("cannot build the TLS configuration: {0}")]
pub struct PolicyError(#[from] rustls::Error);

/// A server configuration for `policy`: `modern` is TLS 1.3 only; `intermediate` adds TLS 1.2
/// with the forward-secret AEAD suites of the ring provider. Session tickets with rotating keys
/// are enabled, 0-RTT is not.
pub fn server_config(
    policy: TlsPolicy,
    resolver: Arc<dyn ResolvesServerCert>,
) -> Result<Arc<ServerConfig>, PolicyError> {
    let versions: &[&SupportedProtocolVersion] = match policy {
        TlsPolicy::Modern => &[&rustls::version::TLS13],
        TlsPolicy::Intermediate => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
    config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    config.ticketer = rustls::crypto::ring::Ticketer::new()?;
    Ok(Arc::new(config))
}
