# rdock-acme

Automatic certificates ([ADR-0020](../../docs/decisions/0020-automatic-https.md)): the certificate manager, a background task that keeps one certificate per requested set of names, orders them with [instant-acme](https://crates.io/crates/instant-acme) (ring), answers HTTP-01 and TLS-ALPN-01 challenges through `rdock_tls::Challenges`, stores accounts and certificates under `$RDOCK_DATA_DIR/acme` (0600, atomic writes, a lock against a second process) and publishes issued certificates to the data plane's resolver. The data plane only reads; ACME or CA outages never stop traffic that already has certificates.

**Status:** HTTP-01 and TLS-ALPN-01 issuance, renewal at a third of the remaining lifetime (v0.3). ARI renewal, alerts and DNS-01 follow in the v0.3 milestone. End-to-end test against Pebble: `crates/rdock/tests/e2e_acme.rs` (`RDOCK_ACME_TESTS=1`, needs Docker).
