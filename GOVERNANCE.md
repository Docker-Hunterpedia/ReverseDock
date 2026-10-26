# Governance

ReverseDock is a 100 % free, Apache-2.0 project ([ADR-0005](docs/decisions/0005-license-apache2-dco.md)): no CLA, no open-core split, no paid features.

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| **Users** | Anyone running ReverseDock | Report bugs, ask questions, share configs and feedback |
| **Contributors** | Anyone with a merged PR, review, triage or docs work | Follow [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) |
| **Maintainers** | Listed below | Review and merge PRs, triage, cut releases, enforce the Code of Conduct, own the roadmap |
| **Project lead** | Oday Bakkour ([@Docker-Hunterpedia](https://github.com/Docker-Hunterpedia)) | Final say when maintainers cannot reach consensus |

### Maintainers

- Oday Bakkour — [@Docker-Hunterpedia](https://github.com/Docker-Hunterpedia) (project lead)

## How decisions are made

1. **Day-to-day changes** (bug fixes, features already on the roadmap, docs): a pull request approved by one maintainer who is not the author, with all required checks green. While the project has a single maintainer, the maintainer may merge their own PRs, but only through a PR (no direct pushes; see *Branch rules*).
2. **Significant changes** (architecture, config model, label grammar, public API, security model, licensing, new dependencies with a large footprint): a *Design proposal* issue first, then an ADR in `docs/decisions/` merged by PR. Proposals stay open for at least 7 days for comment.
3. **Disagreements**: maintainers seek consensus in the issue or PR. If none is reached, the project lead decides and records the reasoning in the ADR or PR.
4. **Roadmap**: [`docs/07-roadmap.md`](docs/07-roadmap.md) is changed by PR like any other document; GitHub milestones mirror it.

## Branch rules

- `main` is protected by a repository ruleset: no direct pushes, no force pushes, no deletion, linear history, squash merges only.
- Every change lands through a pull request with green `docs`, `dco` and `pr-title` checks, an up-to-date branch, resolved conversations, and a code-owner approval of the latest push. Repository admins may bypass the review requirement **only through a pull request**, never by pushing.
- Release tags `v*` can only be created by admins and can never be moved or deleted.

## Becoming a maintainer

Contributors with a sustained record of high-quality contributions and reviews can be nominated by any maintainer. The nomination is accepted when no maintainer objects within 7 days. Maintainers who are inactive for 12 months move to emeritus status and can return by asking.

## Changing this document

Changes to governance require a PR approved by the project lead and, once there are several maintainers, by a majority of them.
