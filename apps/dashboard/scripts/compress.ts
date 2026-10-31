// Writes Brotli and gzip siblings next to every compressible file in dist/, which the admin
// listener serves when the browser accepts them (ADR-0024). Node's zlib only: no dependency.
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const COMPRESSIBLE = /\.(html|js|css|svg|json|txt|woff2?)$/;

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

for (const file of walk("dist")) {
  if (!COMPRESSIBLE.test(file) || file.endsWith(".woff2")) continue;
  const data = readFileSync(file);
  if (data.length < 512) continue;
  const br = brotliCompressSync(data, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } });
  const gz = gzipSync(data, { level: 9 });
  if (br.length < data.length) writeFileSync(`${file}.br`, br);
  if (gz.length < data.length) writeFileSync(`${file}.gz`, gz);
}
