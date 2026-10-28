# rdock-tls

TLS termination: the rustls SNI certificate resolver, certificate store, TLS policies, mTLS and the local development CA.

**v0.1:** PEM certificates with plain or encrypted PKCS#8 keys, an SNI index (exact name, then one-label wildcard, then `defaults.certificate`) behind a lock-free resolver that is swapped on reload, and the `modern`/`intermediate` policies on rustls with the ring provider ([ADR-0013](../../docs/decisions/0013-tls-crypto-provider-ring.md)), ALPN `h2`/`http/1.1` and session tickets. **v0.3:** the resolver serves configured, then ACME-issued, then local-CA certificates, each swapped on its own; `is_private_name` and `is_local_ca_name` decide which names go to the local CA. mTLS lands in v0.4. Design: [architecture §10](../../docs/05-architecture.md).
