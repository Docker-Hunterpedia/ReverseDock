# ReverseDock — Website and documentation plan

The public site, later at `reversedock.dev`: a landing page and complete documentation for installing, using, migrating to and operating ReverseDock. The stack and the rules come from [ADR-0017](decisions/0017-website-astro-starlight.md): Astro + Starlight in `apps/website`, generated reference pages, validated snippets and status badges. Requirement: F-MGMT-05 ([04-requirements](04-requirements.md)).

## 1. Goals

1. **A reader can go from nothing to a working proxy in 5 minutes.** The Quickstart is tested in CI.
2. **Every feature has a page that answers three questions:** what it does, how to use it (a complete, valid example) and since when it is available.
3. **Moving from NGINX, Traefik, Caddy or Nginx Proxy Manager is a guided, reversible procedure,** not guesswork.
4. **Nothing is out of date.** Reference pages are generated, snippets are validated and links are checked.
5. **Fast and accessible.** Lighthouse ≥ 95 in every category, WCAG 2.2 AA, no JavaScript on content pages except search and the theme toggle, light/dark/RTL.
6. **Honest.** Planned features carry "planned for vX.Y" badges. Comparisons with other proxies cite their sources.

## 2. Repository layout

```text
apps/website/
├── astro.config.mjs            # Starlight config: sidebar, locales (en; ar later), plugins
├── src/
│   ├── content/docs/           # MDX pages (the sections in §4)
│   ├── pages/                  # custom pages: index (landing), 404
│   ├── components/             # Hero, FeatureGrid, Compare, InstallTabs, StatusBadge, Terminal …
│   └── styles/                 # Starlight theme mapped onto Harbor UI tokens
├── scripts/
│   ├── gen-config-reference.ts # schema/rdock.v1.json → src/content/docs/reference/config/*.mdx
│   ├── gen-cli-reference.ts    # `rdock --help` for each command → reference/cli.mdx
│   ├── gen-changelog.ts        # CHANGELOG.md → project/changelog.mdx
│   └── check-snippets.ts       # every ```yaml title="rdock.yaml"``` block → `rdock validate --strict`
└── public/                     # logo, favicons, OG images, llms.txt (generated)
packages/harbor-tokens/         # CSS variables of 08-design-system §1, shared with apps/dashboard
pnpm-workspace.yaml · package.json (root, private)
```

## 3. Landing page (`/`)

| Section | Content |
|---|---|
| Hero | The tagline, a one-line value statement, buttons **Get started** and **GitHub**, and an animated terminal: `docker compose up` → first request answered |
| Why ReverseDock | Four pillars: Rust + Pingora performance; Docker-native labels (v0.2); automatic HTTPS (v0.3); reloads with zero dropped requests (shipped) |
| See it | Tabs with a Traefik rule and the same route in `rdock.yaml`; a Compose file with labels (once v0.2 ships) |
| Feature grid | Each feature with a status badge: shipped / next / planned |
| Compare | An honest table against NGINX, Traefik, Caddy and HAProxy, generated from [03-feature-matrix](03-feature-matrix.md), with a link to the full matrix |
| Trust | Apache-2.0 with no open core, signed releases (cosign, SBOM, provenance), the security policy, fuzzing |
| Install | Tabs: Docker · Compose · binary · systemd, each with a copy button |
| Community | Contributing, Discussions, roadmap, and a "star on GitHub" link |

The design uses Harbor UI tokens: amber `#F58F0A` accent, light/dark, logical CSS properties (RTL-ready) and the logo from `docs/assets/`.

## 4. Documentation map (Diátaxis)

The sidebar groups pages by what the reader wants to do. Pages for features that have not shipped yet are added with the milestone that ships them.

**Get started**
- What is ReverseDock (in one page) · Quickstart (Docker Compose, 5 minutes) · Tour of the concepts (listeners, routes, services, middlewares, certificates)

**Install**
- Docker · Docker Compose · Linux binary (x86-64, ARM64) · macOS (for development) · systemd · Build from source
- Verify a download (checksums, `cosign verify-blob`, `gh attestation verify`, image signatures) · Upgrade · Uninstall
- Later: Kubernetes/Helm (v0.7), Swarm (v0.6)

**Guides** (one task per page, each with a complete validated config)
- Route a domain to an app · Several sites on one server · Path-based routing · Your own TLS certificate (SNI, wildcard, default) · HTTP→HTTPS and HSTS
- Redirects and rewrites · Basic auth (with `rdock hash`) · Forward auth with Authelia / Authentik · IP allow/deny · Rate limiting · CORS · Compression · Custom error pages and maintenance mode
- WebSockets, SSE and gRPC · Backends over HTTPS, h2c or Unix sockets · Behind Cloudflare or another proxy (trusted proxies) · Secrets with `${file:}` and `${env:}`
- Reloads with zero dropped requests and last-known-good · Logs and Prometheus metrics (with a Grafana dashboard) · Production hardening checklist
- v0.2: Docker labels, networks, socket proxy, Dokploy/Coolify/Portainer · v0.3: automatic HTTPS, DNS-01, Cloudflare Tunnel

**Migrate** (every guide has the same shape)
1. Concept map table (their term → our term)
2. Side-by-side configurations for the five most common setups
3. Differences and gotchas (from [ADR-0014](decisions/0014-http-semantics-v0-1.md) for Traefik)
4. Cutover procedure: run in parallel on another port, compare responses, switch, roll back
5. Checklist

Guides: **from NGINX** (directives → keys, `location` matching → rules) · **from Traefik** (file provider now; labels with `rdock migrate traefik` in v0.2) · **from Caddy** (Caddyfile → YAML) · **from Nginx Proxy Manager** (UI hosts → YAML) · later from HAProxy.

**Reference** (generated pages are marked ⚙)
- ⚙ Configuration: one page per top-level section, with types, defaults, examples and "since vX.Y"
- ⚙ CLI: every command and flag, exit codes
- Rule grammar (matchers, priority, path normalisation) · Middlewares (every option) · HTTP behaviour (limits, timeouts, headers added/removed)
- ⚙ Metrics · Access-log fields · Environment variables · Files and directories (`/etc/rdock`, `/var/lib/rdock`) · Admin API (⚙ OpenAPI from v0.5)
- v0.2: ⚙ Docker labels, and the Traefik label support table

**Concepts**
- Architecture (on Pingora) · Request lifecycle · Routing and priorities · Reload model, history and last-known-good · Security model and trust boundaries · How ReverseDock compares

**Operations**
- Monitoring and alerts · Troubleshooting, by symptom (404, 502, 504, TLS errors, reload refused) · FAQ

**Project**
- Roadmap (from [07-roadmap](07-roadmap.md)) · ⚙ Changelog · Contributing · Governance · Security policy · Brand assets
- Blog: release notes and deep dives (`starlight-blog`)

## 5. Quality gates (`website` CI job)

| Check | Tool |
|---|---|
| Build and type check | `astro check`, `astro build` |
| Internal links and anchors | `starlight-links-validator` |
| Config snippets are valid | `scripts/check-snippets.ts` with the `rdock` binary built in CI |
| Generated pages are up to date | regenerate, then `git diff --exit-code` |
| Accessibility | Playwright + axe on the landing page, one page from each section, light and dark |
| Performance budget | Lighthouse CI on the landing page and one docs page (≥ 95) |
| Prose | Vale with a small style guide (sentence-case headings, product names, no "simply/just") |

Other outputs: a sitemap, OG images per page, `llms.txt` for AI assistants, "Edit this page" links to GitHub, "last updated" dates from git, and a 404 page with search.

## 6. Versions and languages

- **Before 1.0**, the site documents the latest release, with status badges for anything newer. `main` deploys to a preview host for reviewing docs that are not released yet.
- **From 1.0**, `starlight-versions` keeps one version per minor release.
- **English** is the source language. **Arabic** comes next (Starlight RTL), starting with the landing page, Quickstart and Install. Untranslated pages fall back to English with a notice.

## 7. Phases

| Phase | Ships with | Scope |
|---|---|---|
| **W0 — Launch** | before v0.2 | Workspace, tokens package, Starlight theme · landing page (approved design first, §9) · Get started, Install (all v0.1 methods + verification) · ⚙ config, ⚙ CLI, rules, middlewares, HTTP behaviour reference · v0.1 guides · migrate from NGINX and Traefik (file config) · troubleshooting · ⚙ changelog · CI job · Cloudflare deploy on its `workers.dev` address |
| **W1** | v0.2 | Docker labels guides and ⚙ reference · Traefik labels migration with `rdock migrate traefik` · Compose examples (Dokploy, Coolify, Portainer) · migrate from Caddy and Nginx Proxy Manager |
| **W2** | v0.3 | Automatic HTTPS, DNS-01 and Cloudflare guides · Arabic for core pages · blog with release posts |
| **W3** | v0.5 → v1.0 | Config playground (CodeMirror + JSON Schema in the browser; `rdock-config` compiled to WebAssembly for exact diagnostics, after a spike) · ⚙ admin API (OpenAPI) · benchmark pages · versioned docs from 1.0 |

## 8. Open decisions for the maintainer

1. **Analytics:** none, or Cloudflare Web Analytics (cookie-free, no consent banner). The vision promises no telemetry in the product; the website is a separate question.
2. **Hosting account:** which Cloudflare account owns the site.
3. **The domain comes last.** The site runs on its Cloudflare `workers.dev` address until everything else is done; registering `reversedock.dev` ([01-vision](01-vision.md) lists it as "to be registered") and moving the schema `$id` and the Kubernetes controller name to it is the final step.

## 9. Design

The look is approved on a design before any code: the home page is drawn in Claude Design with the ReverseDock design system (the Harbor UI tokens of [08-design-system](08-design-system.md), plus a proposed website type scale), reviewed, and only then built in `apps/website`.
