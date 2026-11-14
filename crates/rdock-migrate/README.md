# rdock-migrate

Migration assistants (F-MGMT-03, ADR-0033).

- `rdock migrate config` moves an `rdock.yaml` off deprecated settings with the deprecation registry's rewrite rules, editing the text in place where it can so comments stay (`src/config.rs`).
- `rdock migrate traefik` (`src/traefik.rs`) turns a Docker Compose file with Traefik labels, a Traefik dynamic configuration file (`src/traefik/dynamic.rs`) or Traefik's static configuration (`src/traefik/statics.rs`: `traefik.yml`, and the `command:` flags and `TRAEFIK_*` variables of a Compose service that runs Traefik) into `rdock.yaml`.
- `rdock migrate caddy` (`src/caddy.rs`, `src/caddy/`) reads Caddy's JSON configuration (the output of `caddy adapt`) and flattens its ordered route lists into routes with priorities (`caddy/routes.rs`), handlers and matchers one module at a time (`caddy/handlers.rs`, `caddy/proxy.rs`), and the `tls` app (`caddy/tls.rs`).
- `rdock migrate nginx` (`src/nginx.rs`; beta) has its own parser (`nginx/parser.rs`), resolves `include` and `nginx -T` dumps (`nginx/files.rs`), and translates servers, locations and directives (`nginx/translate.rs`).
- Every migration builds one report (`src/report.rs`): each source item is accounted for exactly once at one of four levels (exact, approximate, manual, dropped) with a stable code, the source location, the generated object, a message and a hint. The JSON form is `schema/migrate-report.v1.json`.

Labels go through the Docker provider's own translator (`rdock-provider-docker::labels`), and each label's level comes from its coverage table (`labels/coverage.rs`), so the migration says what the provider would do with the same labels. Compose `${VAR}` references are interpolated as Compose does (`src/compose.rs`), with values passed by the caller: the library never reads the process environment, and credentials it finds are referenced, never copied.

Tests: unit tests in `src/tests.rs` and next to the code; the corpora with golden output in `tests/corpus.rs` (`tests/conformance/traefik-compose`), `tests/corpus_caddy.rs` (`tests/conformance/caddy-json`) and `tests/corpus_nginx.rs` (`tests/conformance/nginx`; `just migrate-golden` rewrites the goldens); NGINX location precedence and `proxy_pass` paths against an independent implementation of the documented algorithm in `tests/nginx_locations.rs`; parser properties in `tests/nginx_parser.rs`.
