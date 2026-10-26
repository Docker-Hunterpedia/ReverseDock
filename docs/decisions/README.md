# Architecture Decision Records

Format: Context → Decision → Consequences. Status is `accepted` unless noted. New ADRs: copy `0000-template.md`, next number, one decision per file.

| # | Decision |
|---|---|
| [0001](0001-build-fresh-on-pingora.md) | Build fresh on Pingora 0.9 instead of forking Pingap |
| [0002](0002-tls-backend-rustls.md) | rustls (aws-lc-rs) is the default TLS backend; OpenSSL/BoringSSL are opt-in features |
| [0003](0003-config-model-superset-of-traefik.md) | Internal model is a superset of Traefik's dynamic config; YAML/JSON canonical with JSON Schema |
| [0004](0004-embedded-spa-dashboard.md) | Dashboard is a static SPA embedded in the binary (no Node runtime) |
| [0005](0005-license-apache2-dco.md) | Apache-2.0 with DCO, no CLA, no open-core |
| [0006](0006-http3-separate-track.md) | HTTP/3 is a separate, feature-gated track on tokio-quiche |
| [0007](0007-admin-api-separate-listener.md) | Admin API is an axum server on its own localhost listener |
| [0008](0008-listener-changes-via-self-upgrade.md) | Listener set changes need a (supervised) restart until the v0.9 supervisor model; everything else hot-swaps |
| [0009](0009-provider-ownership-and-merge.md) | Provider-namespaced ownership and deterministic merge rules |
| [0010](0010-retry-semantics.md) | Retries live in `fail_to_connect`/`error_while_proxy`; status-code retries wait for upstream Pingora support |
