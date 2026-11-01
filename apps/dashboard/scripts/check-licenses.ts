// Production npm dependencies of the dashboard, which ship inside the rdock binary, must have one
// of these licences (F-UI-01).
import { execFileSync } from "node:child_process";

const ALLOWED = new Set(["MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "MIT-0", "Unlicense", "OFL-1.1"]);
// Checked by hand: its metadata names no licence, its LICENSE file is the MIT text.
const EXCEPTIONS = new Set(["valid-url"]);
const output = execFileSync("pnpm", ["licenses", "list", "--prod", "--json"], { cwd: import.meta.dirname, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
const byLicense: Record<string, { name: string }[]> = JSON.parse(output);
let count = 0;
const refused: string[] = [];
for (const [license, packages] of Object.entries(byLicense)) {
  count += packages.length;
  const parts = license.replace(/[()]/g, "").split(/\s+OR\s+/);
  const names = packages.map((p) => p.name).filter((name) => !EXCEPTIONS.has(name));
  if (names.length > 0 && !parts.some((p) => ALLOWED.has(p.trim()))) refused.push(`${license}: ${names.join(", ")}`);
}
if (refused.length > 0) {
  console.error(`licences outside the allow-list:\n${refused.join("\n")}`);
  process.exit(1);
}
console.log(`licences ok: ${count} production packages`);
