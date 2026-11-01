// The configuration playground (F-MGMT-05) checks a document with the bundled JSON Schema, offers
// completion, and never talks to the network. Run after `pnpm build`.
import { spawn } from 'node:child_process';
import { chromium, type Page } from 'playwright';
import { SITE } from './lib.ts';

const PORT = 4330;
const base = `http://localhost:${PORT}`;
const server = spawn('pnpm', ['exec', 'astro', 'preview', '--port', String(PORT), '--ignore-lock'], { cwd: SITE, stdio: 'ignore', detached: true });
for (let i = 0; ; i++) {
  try {
    if ((await fetch(base)).ok) break;
  } catch {
    if (i > 100) throw new Error('astro preview did not start');
  }
  await new Promise((r) => setTimeout(r, 200));
}

const status = (page: Page) => page.locator('#playground-status');

async function write(page: Page, text: string) {
  await page.locator('.cm-content').click();
  await page.keyboard.press('ControlOrMeta+a');
  await page.keyboard.press('Delete');
  await page.keyboard.insertText(text);
}

async function expectStatus(page: Page, pattern: RegExp, what: string) {
  await page.waitForFunction(
    (source) => new RegExp(source).test(document.getElementById('playground-status')?.textContent ?? ''),
    pattern.source,
    { timeout: 10_000 },
  ).catch(async () => {
    throw new Error(`${what}: the status says "${await status(page).textContent()}"`);
  });
}

const browser = await chromium.launch();
// The site's web fonts load with every page; nothing else may leave it, and nothing at all may be
// requested once the page has loaded, because that is when a configuration exists to leak.
const FONTS = ['https://fonts.googleapis.com/', 'https://fonts.gstatic.com/'];
const foreign: string[] = [];
const whileEditing: string[] = [];
try {
  const page = await browser.newPage();
  let loaded = false;
  page.on('request', (request) => {
    const url = request.url();
    if (url.startsWith('data:')) return;
    if (loaded) whileEditing.push(url);
    if (!url.startsWith(base) && !FONTS.some((font) => url.startsWith(font))) foreign.push(url);
  });
  await page.goto(`${base}/docs/reference/playground/`, { waitUntil: 'networkidle' });
  loaded = true;

  await expectStatus(page, /^No problems found$/, 'the starter document');
  await write(page, 'listeners:\n  web: { address: ":80" }\nroutez: {}\n');
  await expectStatus(page, /^\d+ problems? found$/, 'an unknown field');
  await write(page, 'listeners: {\n');
  await expectStatus(page, /^\d+ problems? found$/, 'broken YAML');
  await write(page, 'listeners:\n  web: { address: ":80" }\n');
  await expectStatus(page, /^No problems found$/, 'a corrected document');

  await write(page, 'rou');
  await page.keyboard.press('Control+Space');
  await page.locator('.cm-tooltip-autocomplete').getByText('routes').first().waitFor({ timeout: 5_000 });

  await page.locator('#playground-reset').click();
  await expectStatus(page, /^No problems found$/, 'starting over');
  if (foreign.length > 0) throw new Error(`requests left the site:\n${foreign.join('\n')}`);
  if (whileEditing.length > 0) throw new Error(`requests while editing:\n${whileEditing.join('\n')}`);
  console.log('playground ok: checks, completion, no requests while editing');
} finally {
  await browser.close();
  if (server.pid) process.kill(-server.pid);
}
