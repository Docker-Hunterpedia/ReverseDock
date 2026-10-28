# apps/website

The public website and documentation: Astro + Starlight ([ADR-0017](../../docs/decisions/0017-website-astro-starlight.md), plan in [docs/09-website.md](../../docs/09-website.md)).

```sh
pnpm install                         # at the repository root
cargo build -p rdock                 # the checks run the real binary
cd apps/website
pnpm dev                             # http://localhost:4321
pnpm gen                             # regenerate the reference pages (config, CLI, changelog)
pnpm check:snippets                  # every ```yaml title="rdock.yaml" block passes rdock validate --strict
pnpm check:status                    # status badges agree with what rdock refuses
pnpm build && pnpm check:a11y        # build (links checked) and axe in light and dark
```

## Writing pages

- Pages are MDX under `src/content/docs/docs/<section>/`. The sidebar follows the folders; `sidebar.order` sorts them.
- A complete configuration is a block titled `rdock.yaml`; an excerpt gets another title, such as `rdock.yaml (excerpt)`. Use `example.com` names and the paths `scripts/lib.ts` knows (`/etc/rdock/certs/*.pem|.key`, `/run/secrets/*`, `/etc/rdock/*.htpasswd`).
- Mark availability with `<Status since="v0.1" />` or `<Status planned="v0.3" />`. Settings that `rdock` refuses as "planned" are listed in `src/data/status.json`, which `check:status` proves against the binary.
- Never edit `reference/configuration/`, `reference/cli.mdx` or `project/changelog.md` by hand: `pnpm gen` writes them from `schema/rdock.v1.json`, `rdock --help` and `CHANGELOG.md`.

## Deploying

Cloudflare Workers static assets, connected through Cloudflare's Git integration (no deploy token in GitHub). Settings: root directory `apps/website`, build command `pnpm install --frozen-lockfile && pnpm build`, deploy command `npx wrangler deploy`, build variables `SITE_URL=https://reversedock.oday-bakkour.com` and `NODE_VERSION=24`. The Worker `reversedock-website` serves the custom domain **https://reversedock.oday-bakkour.com**; every push to `main` redeploys it. The Worker has no `workers.dev` address and no preview URLs (`wrangler.jsonc`), and preview builds for other branches are off in Workers Builds; pull requests are built by the `website` check in GitHub CI instead. The project's own domain (`reversedock.dev`) replaces it as the last step (docs/09-website.md).
