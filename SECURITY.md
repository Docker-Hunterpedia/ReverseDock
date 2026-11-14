# Security policy

ReverseDock sits in front of other people's infrastructure, so we treat security reports as our highest priority.

## Supported versions

| Version | Supported |
|---|---|
| `0.x` (alpha pre-releases, currently `0.9.0-alpha.1`) and `-rc` pre-releases | Latest release only |
| `1.x` and later | The two most recent minor releases of the current major |
| The previous major, after a new major | Its last minor release, for six months |

Fixes land on `main` first and are cherry-picked to the release branches; fixes to experimental features are not backported. The full policy, including what is backported, is in [Stability, deprecation and support](docs/10-stability.md) §6. ReverseDock has one maintainer and no SLA: the response times below are targets.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for security problems.**

1. Use GitHub's private vulnerability reporting: **[Report a vulnerability](https://github.com/Docker-Hunterpedia/ReverseDock/security/advisories/new)**.
2. If you cannot use GitHub, email **contact@oday-bakkour.com** with the subject `[SECURITY] ReverseDock`.

Please include:

- the affected version or commit, and how you run it (binary, Docker, Swarm, Kubernetes);
- a description of the issue and its impact;
- a minimal reproduction (config, labels, requests) with secrets removed;
- any proof-of-concept, logs or packet captures that help us confirm it.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment and severity (CVSS v4) | within 7 days |
| Fix, advisory and coordinated disclosure | within 90 days, sooner for actively exploited issues |

We keep you informed during the process, agree on a disclosure date with you, request a CVE through GitHub when appropriate, and credit you in the advisory unless you prefer to stay anonymous.

## Scope

In scope:

- the `rdock` binary: HTTP/TCP/UDP proxying, request parsing, TLS and ACME, providers, middlewares;
- the admin API and the embedded dashboard;
- official container images, Helm chart, manifests and systemd units;
- documented examples whose defaults would lead to an insecure deployment.

Out of scope:

- vulnerabilities in third-party dependencies that are already public (report them upstream, and tell us if ReverseDock is affected so we can ship an update);
- volumetric denial of service (we provide application-layer limits, not network-level DDoS protection);
- issues that require an already compromised host, a malicious administrator, or social engineering;
- missing hardening that is documented as a deliberate, configurable default.

Experimental features (HTTP/3, WASM plugins) are in scope for reports, but they are off in release builds and need an explicit `experimental:` opt-in; fixes to them are not backported.

## How the project tests itself

- **Threat model**: [docs/11-threat-model.md](docs/11-threat-model.md) lists the assets, actors and trust boundaries, and for each entry point the threats considered, the mitigation with the code and the test that proves it, and the residual risks. Start there if you are reviewing ReverseDock.
- **Fuzzing**: 21 cargo-fuzz targets in `tests/fuzz` cover our side of every parser that reads bytes from outside (HTTP/1 framing, ClientHello, PROXY protocol, rules, backend response heads, ACME answers, admin request bodies, cluster bundles, Redis replies, labels, migration inputs); weekly for 30 minutes each, with seeds and mutation smoke tests in every `cargo test`.
- **End-to-end security tests**: the request-smuggling catalogue, size and slow-client limits, admin authentication, CSRF, roles and tenants, secrets masking, TLS resumption classes, PROXY-protocol trust.
- **Static analysis and supply chain**: `clippy` with panics denied in library crates and `unsafe` forbidden, Semgrep and CodeQL, `cargo deny` (RustSec advisories, licences, sources), dependency review, an image scan, OpenSSF Scorecard, actions pinned by commit SHA.
- **Reviews**: internal reviews of the admin surface (ASVS 5.0 Level 2, [docs/security/](docs/security/asvs-5.0-l2-admin.md)) and of each milestone's security surfaces, recorded in the ADRs. **No independent third-party audit has been done yet**; 1.0 is not released as final without one ([ADR-0033](docs/decisions/0033-v1-0-stable.md)).

## Safe harbour

We will not pursue or support legal action against anyone who researches and reports security issues in good faith under this policy: avoid privacy violations, data destruction and service degradation, only test against systems you own or have permission to test, and give us reasonable time to fix the issue before disclosure.

## Verifying releases

Every release publishes `SHA256SUMS`, a keyless cosign signature of it, an SPDX SBOM, and GitHub build-provenance attestations for each archive.

```bash
# 1. The checksums file was signed by this repository's release workflow
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/Docker-Hunterpedia/ReverseDock/\.github/workflows/release\.yml@refs/tags/v'

# 2. Your archive matches the signed checksums
sha256sum --ignore-missing -c SHA256SUMS

# 3. The archive was built by GitHub Actions from this repository
gh attestation verify rdock-<version>-<target>.tar.gz --repo Docker-Hunterpedia/ReverseDock
```

## Hardening references

The threat model is [docs/11-threat-model.md](docs/11-threat-model.md); the control table is [docs/05-architecture.md §15](docs/05-architecture.md#15-security-model).
