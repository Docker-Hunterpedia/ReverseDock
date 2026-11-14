# NGINX corpus

Golden cases for `rdock migrate nginx` ([ADR-0033](../../../docs/decisions/0033-v1-0-stable.md); beta). The test is `crates/rdock-migrate/tests/corpus_nginx.rs`; it runs in `cargo test` and needs no NGINX.

Each directory holds the input (`nginx.conf`, or as `case.json` names it: `site.conf` for a `conf.d` file, `dump.txt` for `nginx -T` output), any files it includes, `case.json` (`input`, `exercises`, `source`, `full`, `include_outside`, `expect_invalid`), the exact output `expected.yaml` and the exact report `report.json` (`rdock_version` replaced by `<version>`). The input's first comment says what the case exercises. `outside.conf` next to the cases is what case 14's `include ../outside.conf` must not read.

The test fails when an output or report differs, when a directive is not accounted for exactly once, when a finding's level is not its code's, or when the output does not read as rdock.yaml or does not validate (other than as `expect_invalid` says). A separate test checks that files named by `auth_basic_user_file` and `ssl_certificate_key` are never read. After a deliberate change, `just migrate-golden` rewrites the goldens; review the diff before committing.

Every file was written by hand for ReverseDock; the semantics each case relies on are those of the official NGINX 1.30 reference at [nginx.org/en/docs](https://nginx.org/en/docs/), read on 2026-11-14 (each case's `source` names the modules). Host names use `example.com`, `.example` and `.internal`, and addresses use private and documentation ranges.

## Behaviour, not only structure

The goldens pin the translation; two more tests prove that it behaves like NGINX:

- `crates/rdock-migrate/tests/nginx_locations.rs` evaluates the migrated routes with ReverseDock's rule semantics and compares the chosen location and the upstream path with an independent implementation of NGINX's documented algorithm (`crates/rdock-migrate/tests/support/nginx_reference.rs`), for the reference's own example, the `proxy_pass` URI cases and 256 random location sets.
- `crates/rdock/tests/e2e_migrate_nginx.rs` runs rdock with a migrated configuration and checks the answering backend and the path it receives for a matrix of requests.

A differential job against a real NGINX container (like `traefik-diff`) is later work.

## Coverage and what is left

22 cases. Not yet covered as their own cases: `limit_req` with `nodelay`, the certbot-style `if ($host = …) { return 301 … }` server, `error_page` with a named location, `split_clients`, `stream` with `ssl_preread`, HTTP/3 `listen … quic`, large real-world configurations. Add a case for each bug found in the migration.
