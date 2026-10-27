# ReverseDock — Dashboard and design system ("Harbor UI")

The dashboard follows the **structure** of the Cloudflare dashboard (left navigation, hairline cards, stat tiles, tabbed page headers, dense data tables, status pills, side drawers for editing) with ReverseDock's own brand: an **amber accent on warm neutrals**. Cloudflare's orange (`#ff5e1f`/`#f6821f`) and its typeface are not used.

Goals: scan-and-operate (not read), summary before detail, every state visible, works at 400 px and 1440 px, light/dark, **RTL-ready**, keyboard-first, no external requests.

## 1. Tokens

### Colour (light → dark)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--rd-bg` | `#FAFAF9` | `#0C0A09` | page canvas (warm stone) |
| `--rd-surface` | `#FFFFFF` | `#1C1917` | cards, tables, drawers |
| `--rd-surface-2` | `#F5F5F4` | `#292524` | table headers, code, hover rows |
| `--rd-border` | `#E7E5E4` | `#2E2A27` | hairlines (1 px), the main structural device |
| `--rd-text` | `#1C1917` | `#FAFAF9` | primary text |
| `--rd-text-2` | `#57534E` | `#A8A29E` | secondary text, labels |
| `--rd-text-3` | `#78716C` | `#8A847E` | muted, placeholders (4.5:1 on light canvas, 4.9:1 on dark surface) |
| `--rd-accent` | `#F58F0A` | `#FFA826` | brand amber: primary actions, active nav, focus ring |
| `--rd-accent-hover` | `#D47400` | `#FFB84D` | hover state |
| `--rd-accent-soft` | `#FFF4E0` | `#3A2A10` | selected row, active nav background, callouts |
| `--rd-accent-ink` | `#1C1917` | `#1C1917` | text **on** accent (ink on amber ≈ 7.3:1 light, 9:1 dark) |
| `--rd-link` | `#1D4ED8` | `#7DB0FF` | links (blue, like Cloudflare: orange acts, blue links) |
| `--rd-ok` | `#15803D` | `#4ADE80` | healthy, valid, applied |
| `--rd-warn` | `#B45309` | `#FBBF24` | degraded, expiring, shadowed |
| `--rd-danger` | `#B91C1C` | `#F87171` | down, failed, rejected |
| `--rd-info` | `#1D4ED8` | `#60A5FA` | informational |
| `--rd-focus` | `#A85A00` | `#FFA826` | 2 px outline, 2 px offset (accent-700 in light mode: amber-500 on the canvas is only 2.3:1, below the 3:1 non-text minimum) |

Accent scale (for charts and gradients): `50 #FFF7E6 · 100 #FFECC2 · 200 #FFD98A · 300 #FFC14D · 400 #FFA826 · 500 #F58F0A · 600 #D47400 · 700 #A85A00 · 800 #7A4100 · 900 #4D2900`.
Semantic colours never double as the accent; charts use a categorical ramp (`amber, blue, teal, violet, rose, slate`) chosen for ≥ 3:1 contrast on both canvases.

### Typography
- UI: **Inter** (variable, self-hosted, OFL) — `--rd-font-sans`. Arabic: **IBM Plex Sans Arabic** as the `ar` fallback in the same stack.
- Data/code: **JetBrains Mono** (OFL) — `--rd-font-mono`, used for hosts, paths, IPs, YAML, logs, metrics.
- Scale (px / line-height / weight): `display 28/34/600 · h1 22/28/600 · h2 18/24/600 · h3 15/22/600 · body 14/20/400 · small 13/18/400 · caption 12/16/500 (uppercase labels get 0.04em tracking) · mono 13/20/400`.
- Numbers in tables and tiles use `font-variant-numeric: tabular-nums`.

### Spacing, radius, elevation
- 4 px base: `1=4 · 2=8 · 3=12 · 4=16 · 5=20 · 6=24 · 8=32 · 10=40 · 12=48`.
- Radius: inputs/buttons `6`, cards/tables `8`, drawers `12`, pills `999`.
- Elevation: none on cards (hairline borders do the work); drawers/menus `0 8px 24px rgba(0,0,0,.12)`; dark mode uses border-brightening instead of shadows.
- Motion: 120 ms ease-out for hover/press, 200 ms for drawers; all disabled under `prefers-reduced-motion`.

## 2. Layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ▣ ReverseDock   [instance: vps-1 ▾]        ⌘K Search   ⟳ Applied 12s ago  ☾  ⚙ oday ▾ │  56 px top bar
├──────────────┬───────────────────────────────────────────────────────────┤
│ Overview     │  Breadcrumb ›                                             │
│ Routes       │  Page title                           [secondary] [Primary]│  page header
│ Services     │  Tabs: Overview · Health · Settings                        │
│ Middlewares  ├───────────────────────────────────────────────────────────┤
│ Certificates │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐               │
│ Listeners    │  │ tile   │ │ tile   │ │ tile   │ │ tile   │  stat tiles   │
│ Providers    │  └────────┘ └────────┘ └────────┘ └────────┘               │
│ Security     │  ┌──────────────────────────────────────────┐             │
│ ─────────    │  │ card: chart / table                      │             │
│ Logs         │  └──────────────────────────────────────────┘             │
│ Metrics      │                                                            │
│ Config       │                                                            │
│ ─────────    │                                                            │
│ Settings     │                                                            │
│ 240 px       │  content max-width 1280, padding 24                        │
└──────────────┴───────────────────────────────────────────────────────────┘
```

- Sidebar collapses to icons at < 1024 px and to a sheet at < 768 px. In RTL the sidebar sits on the right; icons that imply direction (chevrons, back) flip; charts keep LTR time axes.
- Page header carries: breadcrumb, title (+ owner badge: `file`, `docker`, `kubernetes`, `api`), actions (one primary), tabs.
- Edit flows open a **right-side drawer** (480–640 px) over the list, never a new page; the list stays visible. Destructive actions confirm inline inside the drawer.
- The top bar's **apply state** is global: `Applied · gen 142 · 12 s ago` / `Applying…` / `Rejected (3 diagnostics)` → click opens the diagnostics panel.

## 3. Information architecture and pages

| Page | What it shows | Primary actions |
|---|---|---|
| **Overview** | tiles: requests/s, error rate, p95, active connections, backends healthy/total, certs inside their ARI window or with < 25 % lifetime left, providers state; 15-min traffic chart (req/s by status class); top routes table; recent events | Open diagnostics; Add route |
| **Routes** | table: name · owner · match (mono) · listeners · service · middlewares · TLS (auto/manual/off + cert state) · status (active/shadowed/rejected); filters by owner/listener/status; search | New route (drawer) · Edit (api-owned only) · Disable · Test match (enter URL → which route wins and why) |
| **Services** | table: name · owner · backends (n healthy/total with dots) · policy · p95 · error % · circuit state; detail: backend list with health history sparkline, drain/undrain | New service · Drain backend · Trigger health check |
| **Middlewares** | table by type with "used by N routes"; typed forms per type | New middleware · Duplicate |
| **Certificates** | table: name/SANs · issuer · profile · not after (relative + absolute) · ARI window · state (valid/renew due/failed) · used by; detail: chain, last error, logs | Renew now · Upload manual cert · Set default |
| **Listeners** | address · protocol · TLS policy · routes count · http3 flag; changing the listener set needs a restart (ADR-0008) → explained inline before applying | Add listener |
| **Providers** | cards per provider: state, last sync, objects count, diagnostics list (e.g. unsupported Traefik labels with the container name) | Reconnect · Full reconcile |
| **Security** | trusted proxies (with Cloudflare sync status + range count), limits, admin users/tokens, audit log | Add token · Rotate |
| **Logs** | live stream (SSE) with pause, filters (route, status, client IP, text), row expand shows the full JSON line; export current filter | Pause · Clear · Download |
| **Metrics** | prebuilt charts (RPS, latency percentiles, status classes, upstream health, TLS, certs) from the ring buffer; link to Prometheus/Grafana | Time range |
| **Config** | YAML editor (CodeMirror 6, schema completion) for the API-owned snapshot; effective config viewer (read-only, with owner annotations per line); history list with diff viewer; validate → preview diff → apply; rollback | Validate · Apply · Rollback |
| **Settings** | instance name, theme, language (en/ar), observability endpoints, ACME account, updates | Save |

Empty states always explain the next step with one action (e.g. Routes empty: "No routes yet. Add a label `rdock.host=app.example.com` to a container, or create one here.").

## 4. Components (shadcn/ui base + Harbor additions)

| Component | Spec |
|---|---|
| **Button** | primary: accent bg + ink text; secondary: surface + hairline; ghost; danger (danger text, hairline, filled on hover). Height 36 (32 in tables). Never two primaries on one header |
| **StatTile** | label (caption, uppercase), value (display, tabular), delta pill, 48 px sparkline; status stripe on the inline-start edge (ok/warn/danger) when thresholded |
| **StatusPill** | dot + text, pill radius, semantic colour on `soft` background; states: `healthy · degraded · down · pending · shadowed · rejected · valid · expiring · failed` |
| **HealthDots** | n small dots per backend (ok/warn/danger/grey), tooltip with address + last check |
| **DataTable** | TanStack Table; sticky header; column chooser; density toggle; row hover `surface-2`; selected row `accent-soft`; bulk action bar; keyboard row navigation; virtualised over 200 rows |
| **Drawer** | right side (inline-end in RTL), 480/640, header with title + owner badge + close; footer with Cancel / Save; unsaved-changes guard |
| **OwnerBadge** | monochrome badge `file · docker · swarm · k8s · api` with tooltip showing the source ref (file path / container / namespace) |
| **DiagnosticsPanel** | list of `error/warn/info` with source, message, hint, "copy" and deep link to the object |
| **DiffViewer** | side-by-side/inline YAML diff (added/removed lines on ok/danger soft backgrounds) |
| **CodeEditor** | CodeMirror 6, YAML mode, JSON-Schema completion, inline error markers from `/config/validate` |
| **Chart** | uPlot for time series (1 s updates, 15-min window), faint grid, area fill at 12 % alpha, emphasised last point; legend as toggles; accessible table fallback |
| **CommandPalette** | ⌘K: jump to any object, actions (Reload, Validate, Renew cert), theme, language |
| **Toast** | bottom-end, 4 s, with undo where reversible (e.g. disable route) |
| **Tabs** | underline style; active tab accent underline 2 px |
| **Form fields** | 36 px inputs, hairline border, 2 px accent focus ring, inline validation, mono for hosts/paths/IPs, unit suffixes (`s`, `KiB`), duration and size pickers |

## 5. States and feedback

- Every object shows **where it came from** (owner badge) and **whether it is live** (`applied gen N` vs `pending`).
- Rejected config never silently disappears: the top bar turns `warn`, the object row shows `rejected`, the drawer shows the diagnostics inline at the field.
- Live data degrades gracefully: when SSE drops, charts freeze with a "reconnecting" pill rather than showing zeros.
- Danger zone pattern for destructive settings (delete route, rotate tokens): outlined danger card with typed confirmation.

## 6. Accessibility and internationalisation

- WCAG 2.2 AA: text contrast ≥ 4.5:1 (accent text on canvas uses `accent-700` in light mode), focus visible everywhere, no colour-only status (pill text + icon), skip links, landmarks, `aria-live` for apply state and toasts, reduced motion respected.
- Keyboard: `g r` go to routes, `n` new, `/` search, `?` shortcuts help, drawers trap focus.
- i18n: ICU messages; `en` source, `ar` first; logical CSS properties (`margin-inline-start`) throughout; numerals follow locale but hosts/paths/logs stay LTR in `bdi` wrappers; date-times with absolute + relative.
- Theme: light/dark/system; the SPA sets `data-theme` and `color-scheme`; tokens defined once on `:root` and overridden under `[data-theme="dark"]` and `prefers-color-scheme`.

## 7. Technical stack

Vite · React 19 · TypeScript · Tailwind v4 (tokens as CSS variables) · shadcn/ui · TanStack Query + Table · React Router · CodeMirror 6 · uPlot · lucide icons · Playwright/Vitest. Build output is embedded in the `rdock` binary; the UI calls only `/api/v1` and never loads anything from the internet.

## 8. Visual reference

- **Logo (Berth):** a container moored in a dock bay. An amber `#F58F0A` rounded tile (radius 23 %) with a bay cut into its right side and an ink `#1C1917` box inside it; on dark backgrounds the box is amber. Wordmark: Inter Display SemiBold, outlined. [`assets/logo.svg`](assets/logo.svg) is the cropped symbol (PNG 512 in `assets/logo.png`); every version, the small-size cut and the usage rules are in [`assets/logo/`](assets/logo/README.md).
- **README banner / social preview (2:1):** [`assets/banner.html`](assets/banner.html) is the source; `scripts/render-assets.sh` renders `assets/banner.png` (2560×1280) with headless Chrome. Editable canvas: https://claude.ai/artifact/Kg8V5vPCPyYbokXwYEH8iu

An interactive mock of the Overview and Routes pages lives in [`design/dashboard-mock.html`](design/dashboard-mock.html) (published at https://claude.ai/artifact/Svy4mzFgfqoWie4aGmHrxB). Use it as the reference when implementing M-ADM-03 / F-UI.
