# ReverseDock documentation

Reading order:

| # | Document | What it answers |
|---|---|---|
| 01 | [Vision](01-vision.md) | Why, for whom, principles, non-goals, naming, definition of done |
| 02 | [Research](02-research.md) | Verified facts (2026-10-26): Pingora 0.9 reality, competitors, ACME/K8s/Docker ecosystem, crates, risks |
| 03 | [Feature matrix](03-feature-matrix.md) | 171 capabilities vs NGINX/Traefik/Caddy/HAProxy/Envoy/Pingap/Pingora, phases, modules (generated from the workbook) |
| 04 | [Requirements](04-requirements.md) | Checklists: Basics · Medium traffic · High traffic · Features · Works with (IDs used by the roadmap) |
| 05 | [Architecture](05-architecture.md) | The main plan: layers, crates, config model, providers/merge, request lifecycle, TLS/ACME, Docker labels, admin, security, failure modes |
| 06 | [Repo layout & conventions](06-repo-layout.md) | Tree, crate rules, dashboard rules, git/release, testing, Graphify |
| 07 | [Roadmap](07-roadmap.md) | Milestones M0 → v1.0 with acceptance criteria |
| 08 | [Design system](08-design-system.md) | Harbor UI: tokens, layout, pages, components, a11y/RTL |
| — | [Decisions (ADRs)](decisions/README.md) | Why we chose what we chose |
| — | [research/](research/) | Original idea, notes, matrix summary and the source workbook |
| — | [design/](design/) | Dashboard mock (HTML) |
| — | [assets/](assets/) | Logo (SVG/PNG), README banner (HTML source + PNG) |

Regenerate the matrix tables after editing the workbook: `python3 -I scripts/xlsx2md.py docs/research/feature-parity-matrix-2026-10-26.xlsx /tmp/tables.md` and replace the generated section of `03-feature-matrix.md`.
