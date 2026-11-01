// Lighthouse on the Overview page, logged in: performance, accessibility and best practices must
// each score at least 95 (F-UI-01). Needs `pnpm build` and a built rdock.
import lighthouse from "lighthouse";
import desktop from "lighthouse/core/config/desktop-config.js";
import { startLab } from "./rdock.ts";

const PORT = 9333;
const MINIMUM = 95;
const lab = await startLab([`--remote-debugging-port=${PORT}`]);
let failed = false;
try {
  const run = await lighthouse(
    `${lab.base}/`,
    { port: PORT, output: "json", logLevel: "error", extraHeaders: { Cookie: lab.cookie }, onlyCategories: ["performance", "accessibility", "best-practices"] },
    desktop,
  );
  // A login page would also score well, so make sure this was the logged-in Overview.
  const requests = run?.lhr.audits["network-requests"]?.details as { items?: { url: string; statusCode: number }[] } | undefined;
  if (!requests?.items?.some((item) => item.url.endsWith("/api/v1/status") && item.statusCode === 200)) {
    throw new Error("Lighthouse did not reach the logged-in page: no successful GET /api/v1/status");
  }
  for (const category of Object.values(run?.lhr.categories ?? {})) {
    const score = Math.round((category.score ?? 0) * 100);
    console.log(`${category.title}: ${score}`);
    if (score < MINIMUM) {
      failed = true;
      for (const ref of category.auditRefs.filter((r) => r.weight > 0)) {
        const audit = run?.lhr.audits[ref.id];
        if (audit && audit.score !== null && audit.score < 0.9) console.log(`  ${audit.title}: ${audit.displayValue ?? audit.score}`);
      }
    }
  }
} finally {
  await lab.stop();
}
if (failed) process.exit(1);
