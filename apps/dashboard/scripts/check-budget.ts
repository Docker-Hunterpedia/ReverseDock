// Bundle budget (F-UI-01): what the first page needs is at most 300 KB gzipped, every chunk loaded
// later at most 250 KB. Run after `pnpm build`.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const DIST = join(import.meta.dirname, "../dist");
const INITIAL_LIMIT = 300 * 1024;
const LAZY_LIMIT = 250 * 1024;
const gzipped = (file: string) => gzipSync(readFileSync(join(DIST, file)), { level: 9 }).length;
const kb = (bytes: number) => `${(bytes / 1024).toFixed(1)} KB`;

const html = readFileSync(join(DIST, "index.html"), "utf8");
const initial = new Set([...html.matchAll(/(?:src|href)="\/?(assets\/[^"]+\.(?:js|css))"/g)].flatMap((m) => m[1] ?? []));
const assets = readdirSync(join(DIST, "assets")).filter((f) => /\.(js|css)$/.test(f)).map((f) => `assets/${f}`);
if (initial.size === 0) throw new Error("index.html names no assets; has its format changed?");

const initialSize = gzipSync(readFileSync(join(DIST, "index.html"))).length + [...initial].reduce((sum, f) => sum + gzipped(f), 0);
const problems: string[] = [];
if (initialSize > INITIAL_LIMIT) problems.push(`initial load is ${kb(initialSize)}, over ${kb(INITIAL_LIMIT)}`);
let largest = 0;
for (const file of assets.filter((f) => !initial.has(f))) {
  const size = gzipped(file);
  largest = Math.max(largest, size);
  if (size > LAZY_LIMIT) problems.push(`${file} is ${kb(size)}, over ${kb(LAZY_LIMIT)}`);
}
if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`budget ok: initial ${kb(initialSize)} of ${kb(INITIAL_LIMIT)}, largest lazy chunk ${kb(largest)} of ${kb(LAZY_LIMIT)}`);
