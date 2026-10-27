# ADR-0019: Zero-config mode keeps the default admin address

- Status: accepted
- Date: 2026-10-28
- Supersedes: the admin address in the zero-config paragraph of [ADR-0018](0018-docker-provider-and-merge.md); the rest of ADR-0018 stands

## Context
ADR-0018 lists the zero-config defaults with the admin listener on `127.0.0.1:9900`. Everywhere else the admin listener defaults to `127.0.0.1:2080` (ADR-0007, architecture §3 and §13), and v0.2.0-alpha.1 shipped zero-config with `2080`: the built-in configuration leaves `admin` unset, so it takes the normal default. `9900` was an error in the ADR, not a decision.

## Decision
Zero-config mode uses the same admin default as a configuration file: `127.0.0.1:2080`. It does not set an admin address of its own. The other zero-config defaults of ADR-0018 are unchanged.

## Consequences
- `rdock status`, `rdock reload` and the docs work the same with and without a configuration file; there is one admin port to remember.
- Changing the admin default later changes zero-config mode with it.
