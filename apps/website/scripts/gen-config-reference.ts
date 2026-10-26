// src/content/docs/docs/reference/configuration/*.mdx from schema/rdock.v1.json (`just schema`),
// with the "planned for" badges of src/data/status.json (proved by check-status.ts).
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, SITE } from './lib.ts';

type Schema = {
  $ref?: string;
  type?: string | string[];
  description?: string;
  default?: unknown;
  examples?: unknown[];
  pattern?: string;
  const?: string;
  properties?: Record<string, Schema>;
  required?: string[];
  additionalProperties?: Schema | boolean;
  items?: Schema;
  anyOf?: Schema[];
  oneOf?: Schema[];
  minimum?: number;
};
interface Status { path: string; planned: string; what: string; value: boolean }

const schema: Schema & { $defs: Record<string, Schema> } = JSON.parse(readFileSync(join(ROOT, 'schema/rdock.v1.json'), 'utf8'));
const defs = schema.$defs;
const statuses: Status[] = JSON.parse(readFileSync(join(SITE, 'src/data/status.json'), 'utf8'));
const OUT = join(SITE, 'src/content/docs/docs/reference/configuration');
const BASE = '/docs/reference/configuration/';

const defName = (s: Schema) => s.$ref?.replace('#/$defs/', '');
const resolve = (s: Schema): Schema => (s.$ref ? { ...defs[defName(s)!], description: s.description ?? defs[defName(s)!].description } : s);
const withoutNull = (s: Schema): Schema[] => (s.anyOf ?? [s]).filter((v) => v.type !== 'null');
const isObject = (s: Schema) => Boolean(resolve(s).properties);
const isMap = (s: Schema) => typeof resolve(s).additionalProperties === 'object';
const isUnionOfObjects = (s: Schema) => (resolve(s).oneOf ?? []).some((v) => v.properties);
const consts = (s: Schema) => (resolve(s).oneOf ?? []).filter((v) => v.const !== undefined);

/** Named scalar types (Duration, ByteSize…) get one entry on the index page instead of being repeated. */
const valueTypes = new Set(
  Object.entries(defs)
    .filter(([, d]) => !d.properties && !d.additionalProperties && !(d.oneOf ?? []).some((v) => v.properties) && consts(d).length === 0)
    .map(([name]) => name),
);
const anchor = (name: string) => name.toLowerCase();

function typeLabel(s: Schema): string {
  const variants = withoutNull(s);
  if (variants.length > 1) return variants.map(typeLabel).join(' or ');
  const v = variants[0];
  const name = defName(v);
  if (name && valueTypes.has(name)) return `[\`${name}\`](${BASE}#${anchor(name)})`;
  const r = resolve(v);
  if (consts(r).length > 0) return consts(r).map((c) => `\`${c.const}\``).join(' · ');
  if (isUnionOfObjects(r)) return 'object, selected by `type`';
  if (r.properties) return 'object';
  if (typeof r.additionalProperties === 'object') return `map of names to ${typeLabel(r.additionalProperties)}`;
  const types = (Array.isArray(r.type) ? r.type : [r.type]).filter((t) => t && t !== 'null');
  if (types[0] === 'array' && r.items) return `list of ${typeLabel(r.items)}`;
  return types.map((t) => `\`${t === 'integer' ? 'integer' : t}\``).join(' or ') || '`any`';
}

function defaultLabel(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (Array.isArray(value) && value.length === 0) return undefined;
  if (typeof value === 'object' && Object.keys(value as object).length === 0) return undefined;
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return text.length > 90 ? 'see the fields below' : `\`${text}\``;
}

function statusFor(path: string) {
  return statuses.find((s) => s.path === path);
}

/** MDX-safe prose from a schema description: braces and angle brackets outside code are escaped. */
function prose(text = ''): string {
  return text
    .split(/(`+[^`]*`+)/)
    .map((part, i) => (i % 2 === 1 ? part : part.replace(/[{}<>]/g, (c) => `\\${c}`)))
    .join('')
    .replace(/\n(?!\n)/g, ' ');
}

function field(lines: string[], path: string, s: Schema, required: boolean, level: number) {
  const status = statusFor(path);
  const badge = status && !status.value ? ` <Status planned="${status.planned}" />` : '';
  lines.push(`${'#'.repeat(level)} \`${path}\`${badge}`, '');
  const facts = [`**Type:** ${typeLabel(s)}`];
  if (required) facts.push('**Required**');
  const def = defaultLabel(s.default ?? resolve(s).default);
  if (def) facts.push(`**Default:** ${def}`);
  lines.push(facts.join(' · '), '');
  if (s.description) lines.push(prose(s.description), '');
  const r = resolve(withoutNull(s).find((v) => isObject(v) || isMap(v) || consts(v).length > 0) ?? withoutNull(s)[0]);
  const values = consts(r);
  if (values.length > 0) {
    lines.push(...values.map((c) => `- \`${c.const}\`: ${prose(c.description ?? '')}`), '');
  }
  if (status?.value) lines.push(`:::note[Planned for ${status.planned}]`, `${prose(status.what)}: accepted by \`rdock validate\` with a warning, refused by \`rdock run\` until ${status.planned}.`, ':::', '');
}

function walk(lines: string[], path: string, s: Schema, level: number) {
  for (const variant of withoutNull(s)) {
    const r = resolve(variant);
    if (r.properties) {
      for (const [key, child] of Object.entries(r.properties)) {
        const childPath = `${path}.${key}`;
        field(lines, childPath, child, (r.required ?? []).includes(key), level);
        walk(lines, childPath, child, Math.min(level + 1, 4));
      }
    } else if (typeof r.additionalProperties === 'object' && (isObject(r.additionalProperties) || isUnionOfObjects(r.additionalProperties))) {
      walk(lines, `${path}.<name>`, r.additionalProperties, level);
    } else if (r.items && isObject(r.items)) {
      walk(lines, `${path}[]`, r.items, level);
    } else if (isUnionOfObjects(r)) {
      for (const option of r.oneOf ?? []) {
        const kind = option.properties?.type?.const;
        lines.push(`${'#'.repeat(level)} \`type: ${kind}\``, '', prose(option.description), '');
        const { type: _type, ...rest } = option.properties ?? {};
        walk(lines, path, { ...option, properties: rest }, Math.min(level + 1, 4));
      }
    }
  }
}

const header = (title: string, description: string, order: number) => `---
title: ${title}
description: ${JSON.stringify(description)}
sidebar:
  order: ${order}
---

import Status from '../../../../../components/Status.astro';

{/* Generated by scripts/gen-config-reference.ts from schema/rdock.v1.json. Do not edit by hand. */}
`;

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const sections = Object.entries(schema.properties ?? {}).filter(([key]) => key !== '$schema');
sections.forEach(([key, s], i) => {
  const lines: string[] = [header(key, (s.description ?? key).replace(/\n/g, ' '), i + 1), prose(s.description), ''];
  const status = statusFor(key);
  if (status && !status.value) lines.push(`<Status planned="${status.planned}" />`, '');
  const value = withoutNull(s)[0];
  if (isObject(value) || isMap(value) || isUnionOfObjects(value)) walk(lines, key, s, 2);
  else field(lines, key, s, false, 2);
  writeFileSync(join(OUT, `${key.replaceAll('_', '-')}.mdx`), `${lines.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd()}\n`);
});

const types = [...valueTypes].sort().map((name) => {
  const d = defs[name];
  const examples = (d.examples ?? []).map((e) => `\`${typeof e === 'string' ? e : JSON.stringify(e)}\``).join(', ');
  return `### ${name}\n\n${prose(d.description)}${examples ? `\n\nExamples: ${examples}` : ''}`;
});
writeFileSync(join(OUT, 'index.mdx'), `---
title: Configuration
description: Every key of rdock.yaml, generated from the JSON Schema.
sidebar:
  order: 0
---

{/* Generated by scripts/gen-config-reference.ts from schema/rdock.v1.json. Do not edit by hand. */}

ReverseDock reads one YAML or JSON file, \`/etc/rdock/rdock.yaml\` by default (\`--config\` or \`RDOCK_CONFIG\` choose another). Every section is optional. Listeners, routes, services, middlewares and certificates are maps: the key is the object's name, and other objects refer to it by that name.

- Unknown keys are errors, so a typo never goes unnoticed. Keys that start with \`x-\` are ignored, which is handy for YAML anchors.
- \`\${NAME}\`, \`\${env:NAME}\` and \`\${file:/path}\` insert environment variables and file contents; secret fields keep the reference instead of the value.
- Add \`# yaml-language-server: $schema=https://raw.githubusercontent.com/Docker-Hunterpedia/ReverseDock/main/schema/rdock.v1.json\` at the top of the file for completion and checks in your editor.
- Settings marked **planned** are accepted by \`rdock validate\` with a warning and refused by \`rdock run\` until their release.

## Sections

${sections.map(([key, s]) => `- [\`${key}\`](${BASE}${key.replaceAll('_', '-')}/): ${prose((s.description ?? '').split('\n')[0])}`).join('\n')}

## Value types

${types.join('\n\n')}
`);
console.log(`config reference: ${sections.length} sections, ${valueTypes.size} value types`);
