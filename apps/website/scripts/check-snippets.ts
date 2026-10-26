// Every complete configuration in the docs (a ```yaml block titled "rdock.yaml") must pass
// `rdock validate --strict`. Excerpts carry another title, e.g. title="rdock.yaml (excerpt)".
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { SITE, scratch, validate } from './lib.ts';

const CONTENT = join(SITE, 'src/content/docs');
// Fences may be indented (inside <Steps> lists); the indent is removed before validating.
const FENCE = /^( *)```ya?ml([^\n]*)\n([\s\S]*?)^\1```$/gm;

function pages(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return pages(path);
    return /\.mdx?$/.test(entry.name) ? [path] : [];
  });
}

const env = scratch();
const failures: string[] = [];
let checked = 0;
let excerpts = 0;
for (const page of pages(CONTENT)) {
  const text = readFileSync(page, 'utf8');
  for (const block of text.matchAll(FENCE)) {
    const [, indent, meta, body] = block;
    if (!/title="rdock\.yaml"/.test(meta)) {
      excerpts += 1;
      continue;
    }
    checked += 1;
    const line = text.slice(0, block.index).split('\n').length;
    const config = body.split('\n').map((l) => l.slice(indent.length)).join('\n');
    const result = validate(env.localize(config), join(env.dir, 'rdock.yaml'));
    if (!result.ok) failures.push(`${relative(SITE, page)}:${line}\n${result.output}`);
  }
}
if (failures.length > 0) {
  console.error(`${failures.length} configuration snippet(s) fail rdock validate --strict:\n\n${failures.join('\n\n')}`);
  process.exit(1);
}
console.log(`snippets ok: ${checked} complete configurations valid, ${excerpts} excerpts skipped`);
