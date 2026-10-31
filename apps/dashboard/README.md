# Dashboard

The ReverseDock dashboard ([ADR-0024](../../docs/decisions/0024-management-api-and-dashboard.md), [design system](../../docs/08-design-system.md)): Vite, React 19, TypeScript, Tailwind v4 with the Harbor tokens, TanStack Query and Router. English only; it calls only `/api/v1` on its own origin and loads nothing from the internet.

```sh
pnpm install
pnpm --dir apps/dashboard build      # dist/ with .br/.gz siblings
cargo build -p rdock                 # embeds dist/ (crates/rdock-admin/src/dashboard.rs)
```

Without a build, `rdock` still compiles and the admin listener explains how to add the dashboard.

For development, run rdock (admin on `127.0.0.1:2080`) and `pnpm --dir apps/dashboard dev`; Vite proxies `/api` to it. Open the Vite address on `localhost` so the `Secure` session cookie is kept.
