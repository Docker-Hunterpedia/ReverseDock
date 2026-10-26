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

Cloudflare Workers static assets, connected through Cloudflare's Git integration (no deploy token in GitHub). Settings: root directory `apps/website`, build command `pnpm install --frozen-lockfile && pnpm build`, deploy command `npx wrangler deploy`, environment variable `SITE_URL` = the public address (the `workers.dev` address until the domain is registered). Pull requests get preview URLs from the same integration.
