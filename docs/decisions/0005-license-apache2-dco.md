# ADR-0005: Apache-2.0 with DCO, no CLA, no open-core

- Status: accepted · Date: 2026-10-26

## Context
The project is meant to be 100 % free to help people secure their infrastructure. Pingora, Pingap and Zentinel are Apache-2.0. A CLA would allow future relicensing; an open-core split would recreate the Traefik Hub / NGINX Plus problem we are solving.

## Decision
Apache-2.0 for all code and docs (CC-BY-4.0 for docs if separated later). Contributions via Developer Certificate of Origin sign-off. No enterprise edition; features are never gated by licence, account or telemetry.

## Consequences
- Compatible with reusing Apache-2.0 code (with NOTICE attribution) from Pingora-ecosystem projects.
- Sustainability must come from sponsorship/services, not from withholding features.
