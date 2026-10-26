# ADR-0017: The public website and docs are built with Astro + Starlight, in this repository

- Status: accepted
- Date: 2026-10-27

## Context
ReverseDock needs a public website at `reversedock.dev`: a landing page plus documentation for installation, usage, migration and reference (F-MGMT-05). The roadmap had the docs site starting with v0.3 ([07-roadmap](../07-roadmap.md)). We want it before v0.2, so each later milestone ships with its docs.

We compared two candidates (versions from the npm registry, 2026-10-27):

| | Astro 7.4 + Starlight 0.42 | TanStack Start 1.169 |
|---|---|---|
| Built for | content and documentation sites; static by default | full-stack React applications (SSR, server functions) |
| Docs features | sidebar, search (Pagefind), table of contents, MDX, code blocks (Expressive Code), "edit this page", dark mode — built in | none built in ([TanStack Start overview](https://tanstack.com/start/latest/docs/framework/react/overview), read 2026-10-27); we would build or adopt them |
| i18n / RTL | per-locale `dir: 'rtl'`, untranslated pages fall back to English with a notice ([Starlight i18n guide](https://starlight.astro.build/guides/i18n/), read 2026-10-27) | do it ourselves |
| Plugins we need | `starlight-links-validator` 0.27, `starlight-versions` 0.10, `starlight-llms-txt` 0.12, `starlight-openapi` 0.27, `starlight-blog` 0.30 | — |
| JavaScript shipped | none on content pages, except search and the theme toggle; React only in interactive "islands" | a React app on every page |
| Stewardship | MIT; Cloudflare acquired the Astro company on 2026-01-16 and keeps it open source ([Cloudflare press release](https://cloudflare.net/news/news-details/2026/Cloudflare-Acquires-Astro-to-Accelerate-the-Future-of-High-Performance-Web-Development/default.aspx)) | MIT; 1.0 declared stable on 2026-10-13 ([TanStack blog](https://tanstack.com/blog)) |

## Decision
- **Astro + Starlight** for the website and docs, in `apps/website` of this repository (pnpm workspace). Landing and other marketing pages are custom Astro pages. Interactive parts (config playground, label converter) are React islands.
- **Docs live next to the code.** A pull request that changes behaviour also changes its docs page. Reference pages (configuration, CLI, metrics, changelog) are **generated** from the schema, the binary and the repository, never written by hand.
- **Every configuration snippet in the docs is checked.** CI extracts each `yaml` block marked as rdock configuration and runs `rdock validate --strict` on it.
- **Status badges.** Every feature page says when the feature became available ("since v0.1") or when it is planned ("planned for v0.3"), using the same milestones as `gate.rs`. The docs never present planned features as shipped.
- **Hosting** on Cloudflare Workers static assets, deployed by Cloudflare's Git integration (no deploy token in GitHub Actions). `main` is published to a preview host; release tags are published to `reversedock.dev`.
- **Design.** The website uses the Harbor UI tokens ([08-design-system](../08-design-system.md)) from a shared token package, the same one the dashboard will use, with the same amber accent and light, dark and RTL support.
- TanStack Start is not used for the website. The dashboard stays a Vite SPA ([ADR-0004](0004-embedded-spa-dashboard.md)).

## Consequences
- The repository gains a Node toolchain (Node 22.23+, pnpm) for `apps/website`, and a `website` CI job: build, type check, link check, snippet validation and accessibility checks. The job becomes required once it is stable.
- Docs can drift from the code only in hand-written prose. Reference pages are regenerated and snippets are validated in CI.
- The website depends on Astro's direction under Cloudflare. Content is plain MDX, so moving to another framework would mean rewriting the theme, not the content.
