// Every page, in the light and the dark theme, from 400 to 1440 px wide (F-UI-01): a screenshot,
// axe's WCAG 2.2 AA rules, no sideways scrolling, no script errors, and no request that leaves the
// admin origin. Needs `pnpm build` and a built rdock; screenshots go to e2e/screenshots/.
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { startLab } from "./rdock.ts";

const PAGES = ["/", "/routes", "/services", "/middlewares", "/certificates", "/listeners", "/providers", "/security", "/logs", "/traffic", "/config", "/settings"];
const WIDTHS = [400, 768, 1024, 1440];
const SHOTS = join(import.meta.dirname, "screenshots");
mkdirSync(SHOTS, { recursive: true });

const lab = await startLab();
const failures: string[] = [];
let checked = 0;
try {
  for (const theme of ["light", "dark"] as const) {
    const context = await lab.loggedIn(theme);
    const page = await context.newPage();
    let where = "";
    page.on("pageerror", (error) => failures.push(`${where}: script error: ${error.message}`));
    page.on("console", (message) => {
      if (message.type() === "error" && message.text().includes("Content Security Policy")) failures.push(`${where}: ${message.text()}`);
    });
    page.on("request", (request) => {
      const url = request.url();
      if (!url.startsWith(lab.base) && !url.startsWith("data:") && !url.startsWith("blob:")) failures.push(`${where}: request left the admin origin: ${url}`);
    });
    page.on("response", (response) => {
      if (response.status() >= 500 || response.status() === 429) failures.push(`${where}: ${response.status()} from ${response.url()}`);
    });
    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: 900 });
      for (const path of PAGES) {
        where = `${theme} ${width}px ${path}`;
        await page.goto(lab.base + path);
        await page.getByRole("heading", { level: 1 }).first().waitFor();
        await page.waitForTimeout(400);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        if (overflow > 0) failures.push(`${where}: scrolls sideways by ${overflow}px`);
        const name = path === "/" ? "overview" : path.slice(1);
        await page.screenshot({ path: join(SHOTS, `${name}-${theme}-${width}.png`), fullPage: true });
        const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
        for (const v of result.violations) {
          failures.push(`${where}: ${v.id} (${v.impact}) ${v.help}\n  ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join("\n  ")}`);
        }
        checked++;
      }
    }
    await context.close();
  }
} finally {
  await lab.stop();
}
if (failures.length > 0) {
  console.error(`${failures.length} problem(s):\n\n${failures.join("\n\n")}`);
  process.exit(1);
}
console.log(`pages ok: ${checked} page views, ${PAGES.length} pages × 2 themes × ${WIDTHS.length} widths`);
