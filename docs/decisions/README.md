# Architecture Decision Records

Format: Context → Decision → Consequences. Status is `accepted` unless noted. New ADRs: copy `0000-template.md`, next number, one decision per file.

| # | Decision |
|---|---|
| [0001](0001-build-fresh-on-pingora.md) | Build fresh on Pingora 0.9 instead of forking Pingap |
| [0002](0002-tls-backend-rustls.md) | ~~rustls (aws-lc-rs) is the default TLS backend~~ superseded by 0013 |
| [0003](0003-config-model-superset-of-traefik.md) | Internal model is a superset of Traefik's dynamic config; YAML/JSON canonical with JSON Schema |
| [0004](0004-embedded-spa-dashboard.md) | Dashboard is a static SPA embedded in the binary (no Node runtime) |
| [0005](0005-license-apache2-dco.md) | Apache-2.0 with DCO, no CLA, no open-core |
| [0006](0006-http3-separate-track.md) | HTTP/3 is a separate, feature-gated track on tokio-quiche |
| [0007](0007-admin-api-separate-listener.md) | Admin API is an axum server on its own localhost listener |
| [0008](0008-listener-changes-via-self-upgrade.md) | ~~Listener set changes need a (supervised) restart~~ superseded by 0012 |
| [0009](0009-provider-ownership-and-merge.md) | Provider-namespaced ownership and deterministic merge rules |
| [0010](0010-retry-semantics.md) | ~~Status-code retries wait for upstream Pingora support~~ superseded by 0015 |
| [0011](0011-yaml-parser-and-msrv.md) | YAML is parsed with serde-saphyr (YAML 1.2 booleans); MSRV is 1.89 |
| [0012](0012-own-listeners-pingora-http-engine.md) | rdock owns listeners and the runtime; Pingora's HTTP stack is a library; listener changes apply without a restart |
| [0013](0013-tls-crypto-provider-ring.md) | rustls with the ring provider (what Pingora 0.9 supports) is the TLS backend |
| [0014](0014-http-semantics-v0-1.md) | HTTP semantics of v0.1 (Traefik parity and deliberate differences); unimplemented settings are refused, not ignored |
| [0015](0015-status-code-retries.md) | Status-code retries work through `upstream_response_filter`, no fork needed |
| [0016](0016-config-references-and-secrets.md) | `${…}` references; secrets stay references; unknown keys are errors |
