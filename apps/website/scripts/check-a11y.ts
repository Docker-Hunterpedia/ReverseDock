// Accessibility gate (docs/09-website.md §5): axe-core (WCAG 2.2 AA rules) on the landing page and
// one page from each docs section, in light and dark. Run after `pnpm build`.
import { spawn } from 'node:child_process';
import AxeBuilder from '@axe-core/playwright';
import { chromium } from 'playwright';
import { SITE } from './lib.ts';

const PORT = 4329;
const PAGES = [
  '/',
  '/docs/start/quickstart/',
  '/docs/install/docker/',
  '/docs/guides/route-a-domain/',
  '/docs/migrate/from-traefik/',
  '/docs/reference/configuration/routes/',
  '/docs/concepts/architecture/',
  '/docs/operations/troubleshooting/',
];

// Its own process group, so stopping it also stops the node process behind the astro wrapper;
// --ignore-lock keeps it independent of a preview server you may have running.
const server = spawn('pnpm', ['exec', 'astro', 'preview', '--port', String(PORT), '--ignore-lock'], { cwd: SITE, stdio: 'ignore', detached: true });
const base = `http://localhost:${PORT}`;
for (let i = 0; ; i++) {
  try {
    if ((await fetch(base)).ok) break;
  } catch {
    if (i > 100) throw new Error('astro preview did not start');
  }
  await new Promise((r) => setTimeout(r, 200));
}

const browser = await chromium.launch();
const failures: string[] = [];
try {
  for (const theme of ['light', 'dark']) {
    const context = await browser.newContext();
    await context.addInitScript((t) => localStorage.setItem('starlight-theme', t), theme);
    const page = await context.newPage();
    for (const path of PAGES) {
      await page.goto(base + path);
      const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
      for (const v of result.violations) {
        failures.push(`${theme} ${path}: ${v.id} (${v.impact}) ${v.help}\n  ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join('\n  ')}`);
      }
    }
    await context.close();
  }
} finally {
  await browser.close();
  process.kill(-server.pid!);
}
if (failures.length > 0) {
  console.error(`${failures.length} accessibility violation(s):\n\n${failures.join('\n\n')}`);
  process.exit(1);
}
console.log(`a11y ok: ${PAGES.length} pages × 2 themes, no WCAG 2.2 AA violations`);
