# Traefik Compose corpus

Layer 2 of "conformance-tested" ([ADR-0033](../../../docs/decisions/0033-v1-0-stable.md)): realistic Compose files with Traefik labels, each with the output and report `rdock migrate traefik` must produce. The test is `crates/rdock-migrate/tests/corpus.rs`; it runs in `cargo test` and needs no Docker.

Each directory holds:

| File | What it is |
|---|---|
| `compose.yaml` (or `dynamic.yml`, `dynamic.toml`) | The input. Its header comment says what the case exercises. |
| `case.json` | `input`, `exercises`, `diff` (whether the differential test runs it), `args` (`full`, `expose_by_default`, `env_file`, `static`) and `expect_invalid` (validation errors the output is meant to have, as parts of their messages). |
| `vars.env`, `traefik.yml` | The `--env-file` and `--static` inputs, when `args` names them. |
| `expected.yaml` | The exact output. |
| `report.json` | The exact report (`--report`), with `rdock_version` replaced by `<version>`. |

The test fails when an output or report differs, when a source item is not accounted for exactly once, when the output does not validate (other than as `expect_invalid` says: a fragment that names a middleware that was not migrated, a listener defined elsewhere), when a credential from an input reaches the output, or when a case marked `diff` has a manual finding. After a deliberate change, `just migrate-golden` rewrites the goldens; review the diff before committing.

## Sources

Every file was written by hand for ReverseDock in the shapes Traefik's documentation shows (one site, path routing, auth, headers, TCP and UDP, the static configuration in flags, environment variables or `traefik.yml`) and the shapes of common self-hosted setups (an SSO portal in front of an app, blue/green replicas, a wildcard certificate). Nothing is copied from Traefik's documentation or from other projects, so no attribution is needed; the password hash is `openssl passwd -apr1 -salt rdocksal example-password`. Host names use `example.com` and addresses use documentation ranges.

## Coverage and what is left

46 cases today. The research note suggested at least 100 files. Not yet covered as their own cases: platform patterns (Dokploy, Coolify, Portainer stacks), several Compose files merged (`-f a -f b`), `extends` and YAML anchors in labels, profiles, Swarm stacks with several services per network, the `ipStrategy` and Redis rate-limit variants beyond one example each, every lego DNS provider without an adapter, Traefik static options in TOML, a Kubernetes-style dynamic file with `mirroring` and `failover` services, and larger real-world files with dozens of services. Add a case for each bug found in the migration.
