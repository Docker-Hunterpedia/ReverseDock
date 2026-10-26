# Security policy

ReverseDock sits in front of other people's infrastructure, so we treat security reports as our highest priority.

## Supported versions

| Version | Supported |
|---|---|
| No release yet (design phase) | Report design-level issues in the plan the same way as code issues |
| `0.x` (once released) | Latest minor release only |
| `1.x` and later | The two most recent minor releases |

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

The threat model and controls are documented in [docs/05-architecture.md §15](docs/05-architecture.md#15-security-model).
