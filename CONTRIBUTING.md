# Contributing to ReverseDock

Thank you for helping build a free reverse proxy that anyone can use to secure their infrastructure. This guide explains how to propose changes and what a pull request needs before it can be merged.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Project status

ReverseDock is in the **design phase**: the plan lives in [`docs/`](docs/README.md) and code starts with milestone **M0**. The most useful contributions right now:

- review the [architecture](docs/05-architecture.md), [requirements](docs/04-requirements.md) and [roadmap](docs/07-roadmap.md) and open issues for mistakes or gaps;
- verify facts in the [research](docs/02-research.md) against official sources;
- contribute real-world Traefik label sets and Compose files for the compatibility suite (open a *Migration / compatibility gap* issue);
- open a *Design proposal* for changes to the config model, label grammar or security model.

## Ways to contribute

| Contribution | Start with |
|---|---|
| Bug | *Bug report* issue form |
| Traefik / NGINX / Caddy migration gap | *Migration / compatibility gap* issue form |
| New feature | *Feature request* issue form; check the requirements and roadmap first |
| Architecture or public-API change | *Design proposal* issue form → ADR in `docs/decisions/` |
| Documentation fix | Small fixes: open a PR directly. Larger changes: *Documentation* issue form |
| Question | [Discussions → Q&A](https://github.com/Docker-Hunterpedia/ReverseDock/discussions) |
| Security problem | [SECURITY.md](SECURITY.md), never a public issue |

Comment on an issue before starting larger work so nobody duplicates effort. Issues labelled `good first issue` and `help wanted` are ready to pick up.

## Development setup

From M0 on, the workspace needs:

- **Rust** via [rustup](https://rustup.rs); the exact toolchain is pinned in `rust-toolchain.toml`.
- **just** for the dev recipes (`just ci`, `just e2e`, `just dashboard`).
- **Node 24 + pnpm** for the dashboard in `apps/dashboard`.
- **Docker** for end-to-end tests (Pebble ACME, toxiproxy, Docker provider).
- Optional: [Graphify](docs/06-repo-layout.md#6-code-graph-tooling-graphify) to explore the code as a graph. Keep its Claude Code hooks in `.claude/settings.local.json`, not in a committed file.

Using an AI coding assistant? It should follow [CLAUDE.md](CLAUDE.md) (also available as `AGENTS.md`). You remain responsible for every line you submit, and your DCO sign-off covers AI-assisted changes too.

Conventions for crates, errors, logging, features and tests are in [docs/06-repo-layout.md](docs/06-repo-layout.md).

## Branches and commits

- Work on a branch in your fork (or a topic branch if you are a maintainer): `feat/docker-network-selection`, `fix/acme-ari-retry`, `docs/roadmap-typo`.
- Commit messages and **PR titles** follow [Conventional Commits](https://www.conventionalcommits.org): `type(scope): summary`.
  - Types: `feat`, `fix`, `docs`, `perf`, `refactor`, `test`, `build`, `ci`, `chore`, `revert`, `security`. Add `!` for breaking changes: `feat(config)!: rename listeners.tls`.
  - Scopes are crate or area names without the `rdock-` prefix: `proxy`, `rules`, `config`, `tls`, `acme`, `balancer`, `middleware`, `docker`, `swarm`, `kubernetes`, `cloudflare`, `admin`, `dashboard`, `observability`, `adr`, `repo`.
- **Sign off every commit** (Developer Certificate of Origin, no CLA): `git commit -s`. This adds `Signed-off-by: Your Name <you@example.com>`, certifying the [DCO](https://developercertificate.org/). Forgot it? `git rebase --signoff main` and force-push your branch.

## Pull requests

`main` is protected: nobody can push to it directly, and every change is merged as a **squash commit** through a pull request. A PR can be merged when:

1. The `docs`, `dco` and `pr-title` checks pass (heavier Rust and dashboard checks join from M0).
2. The branch is up to date with `main`.
3. A code owner approved the latest push, and every review conversation is resolved.

Keep PRs focused on one change; under ~400 changed lines is easiest to review. Fill in the PR template: link the issue (`Closes #123`) and the requirement ID it implements (`B-NET-04`). The PR title becomes the commit message on `main`, so make it a good Conventional Commit.

## Documentation rules

- The feature matrix in `docs/03-feature-matrix.md` is **generated**: edit the workbook in `docs/research/` and run `python3 -I scripts/xlsx2md.py docs/research/feature-parity-matrix-2026-10-26.xlsx /tmp/tables.md`, then replace the generated section. CI fails when they drift.
- Requirement IDs in `docs/04-requirements.md` are stable: never reuse or renumber an ID; strike it through and point to its replacement.
- Every ID is scheduled in `docs/07-roadmap.md` or listed as unscheduled there.
- Architecture decisions are ADRs (`docs/decisions/0000-template.md`), one decision per file, never rewritten after acceptance except to mark them superseded.
- Relative links must resolve; CI checks them.

## Labels

| Prefix | Meaning | Examples |
|---|---|---|
| `type/` | What kind of change | `type/bug`, `type/feature`, `type/docs`, `type/compat`, `type/proposal`, `type/security`, `type/performance`, `type/chore`, `type/question` |
| `area/` | Which part of the system | `area/proxy`, `area/tls`, `area/docker`, `area/kubernetes`, `area/dashboard` … |
| `priority/` | Roadmap phase | `priority/P0` … `priority/P3` |
| `status/` | Triage state | `status/needs-triage`, `status/needs-info`, `status/needs-discussion`, `status/accepted`, `status/blocked` |
| — | Release notes and onboarding | `breaking-change`, `skip-changelog`, `good first issue`, `help wanted`, `dependencies` |

Milestones mirror the roadmap: `M0` … `v1.0`.

## License

ReverseDock is licensed under [Apache-2.0](LICENSE). By contributing, you agree that your contributions are licensed under the same terms (inbound = outbound), as certified by your DCO sign-off.
