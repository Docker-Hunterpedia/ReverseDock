//! TLS server configurations for the named policies.

use std::sync::Arc;

use rdock_model::config::TlsPolicy;
use rustls::server::ResolvesServerCert;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ServerConfig, SupportedProtocolVersion};

use crate::tickets::Resumption;

/// ALPN protocols offered on TLS listeners, in order of preference. `acme-tls/1` is only
/// chosen by TLS-ALPN-01 validation handshakes, which offer nothing else.
pub const ALPN: [&[u8]; 3] = [b"h2", b"http/1.1", crate::challenge::ACME_TLS_ALPN];

/// Why a server configuration could not be built.
#[derive(Debug, thiserror::Error)]
#[error("cannot build the TLS configuration: {0}")]
pub struct PolicyError(#[from] rustls::Error);

/// A server configuration for `policy`: `modern` is TLS 1.3 only; `intermediate` adds TLS 1.2
/// with the forward-secret AEAD suites of the ring provider. Resumption uses `resumption`
/// (shared by the listeners of one security class, [`crate::tickets`]). 0-RTT is never
/// accepted: early data is not forward secret and can be replayed (RFC 8446 §2.3, §8), and a
/// proxy cannot know which upstream requests are safe to replay.
pub fn server_config(
    policy: TlsPolicy,
    resolver: Arc<dyn ResolvesServerCert>,
    client_auth: Option<Arc<dyn ClientCertVerifier>>,
    resumption: &Resumption,
) -> Result<Arc<ServerConfig>, PolicyError> {
    let versions: &[&SupportedProtocolVersion] = match policy {
        TlsPolicy::Modern => &[&rustls::version::TLS13],
        TlsPolicy::Intermediate => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };
    let builder =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)?;
    let builder = match client_auth {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_cert_resolver(resolver);
    config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    config.ticketer = resumption.ticketer.clone();
    config.session_storage = resumption.cache.clone();
    config.send_tls13_tickets = resumption.tls13_tickets;
    // rustls's default, stated so that no later change turns 0-RTT on by accident.
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}
