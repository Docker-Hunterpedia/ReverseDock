// Proves src/data/status.json against the binary: each fixture must validate with exactly the
// warning "planned for <milestone>" at its path, so no page can show a wrong status badge.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SITE, scratch, validate } from './lib.ts';

interface Entry { path: string; planned: string; what: string; value: boolean; fixture: string }

const entries: Entry[] = JSON.parse(readFileSync(join(SITE, 'src/data/status.json'), 'utf8'));
const env = scratch();
const failures: string[] = [];
for (const entry of entries) {
  const result = validate(env.localize(entry.fixture), join(env.dir, 'status.yaml'), false);
  const path = new RegExp(`^warning: ${entry.path.replaceAll('.', '\\.').replaceAll('<name>', '[^.:]+')}\\b.*planned for ${entry.planned.replace('.', '\\.')}\\)`, 'm');
  if (!result.ok || !path.test(result.output)) {
    failures.push(`${entry.path} (planned for ${entry.planned}):\n${result.output}`);
  }
}
if (failures.length > 0) {
  console.error(`status.json disagrees with rdock:\n\n${failures.join('\n\n')}`);
  process.exit(1);
}
console.log(`status ok: ${entries.length} planned settings confirmed by rdock`);
