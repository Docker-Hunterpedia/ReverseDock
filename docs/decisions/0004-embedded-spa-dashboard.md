# ADR-0004: Dashboard is a static SPA embedded in the binary

- Status: accepted · Date: 2026-10-26

## Context
The original notes proposed Next.js. A self-hosted proxy must stay a single binary with no Node runtime, work offline/air-gapped, and never put the UI on the request path.

## Decision
`apps/dashboard` is a Vite + React + TypeScript SPA (Tailwind v4, shadcn/ui). `pnpm build` output is embedded via `rust-embed` into `rdock-admin` and served from the admin listener. The SPA only calls `/api/v1` and loads no external assets. `RDOCK_SKIP_DASHBOARD=1` builds without it.

## Consequences
- One artifact to ship; the dashboard version always matches the API version.
- No SSR; fine for an authenticated ops tool. Deep links work via client routing.
- Bundle-size budget enforced in CI.
