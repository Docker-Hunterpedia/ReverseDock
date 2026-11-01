# Dashboard

The ReverseDock dashboard ([ADR-0024](../../docs/decisions/0024-management-api-and-dashboard.md), [design system](../../docs/08-design-system.md)): Vite, React 19, TypeScript, Tailwind v4 with the Harbor tokens, TanStack Query and Router. English only; it calls only `/api/v1` on its own origin and loads nothing from the internet.

```sh
pnpm install
pnpm --dir apps/dashboard build      # dist/ with .br/.gz siblings
cargo build -p rdock                 # embeds dist/ (crates/rdock-admin/src/dashboard.rs)
```

Without a build, `rdock` still compiles and the admin listener explains how to add the dashboard.

For development, run rdock (admin on `127.0.0.1:2080`) and `pnpm --dir apps/dashboard dev`; Vite proxies `/api` to it. Open the Vite address on `localhost` so the `Secure` session cookie is kept.

## Checks

After `pnpm build` and then `cargo build -p rdock` (the binary embeds `dist/`, so build it after the dashboard), or with `RDOCK_BIN` pointing at a binary:

| Command | What it checks |
|---|---|
| `pnpm check:budget` | First load at most 300 KB gzipped, later chunks at most 250 KB |
| `pnpm check:licenses` | Production npm packages have an allowed licence |
| `pnpm check:pages` | Against a real rdock, every page in both themes at 400, 768, 1024 and 1440 px: axe WCAG 2.2 AA, no sideways scrolling, no script errors, no 5xx or 429, no request leaving the admin origin. Screenshots go to `e2e/screenshots/` |
| `pnpm check:lighthouse` | Performance, accessibility and best practices at least 95 on the logged-in Overview |

The `dashboard` job in CI runs them all and keeps the screenshots for 14 days.
