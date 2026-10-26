// Shared helpers for the website's checks: run the real `rdock` binary against configuration
// written in the docs, with throw-away files standing in for the paths the docs use.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

export const ROOT = resolve(import.meta.dirname, '../../..');
export const SITE = resolve(import.meta.dirname, '..');
export const RDOCK = process.env.RDOCK_BIN ?? join(ROOT, 'target/debug/rdock');

export interface Validation {
  ok: boolean;
  output: string;
}

/**
 * A scratch directory holding a certificate for example.com and *.example.com, a secret and an
 * htpasswd file. `localize` points the docs' absolute paths at them:
 *   /etc/rdock/certs/<name>.pem|.crt → the certificate   /etc/rdock/certs/<name>.key → the key
 *   /run/secrets/<name>               → a secret          /etc/rdock/*.htpasswd       → users
 */
export function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'rdock-docs-'));
  const cert = join(dir, 'example.pem');
  const key = join(dir, 'example.key');
  execFileSync('openssl', ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key], { stdio: 'ignore' });
  execFileSync('openssl', ['req', '-new', '-x509', '-key', key, '-out', cert, '-days', '30', '-subj', '/CN=example.com',
    '-addext', 'subjectAltName=DNS:example.com,DNS:*.example.com'], { stdio: 'ignore' });
  const secret = join(dir, 'secret');
  writeFileSync(secret, 'not-a-real-secret\n');
  const users = join(dir, 'users.htpasswd');
  writeFileSync(users, `${hash('alice', 'example-password')}\n`);
  return {
    dir,
    localize(text: string): string {
      return text
        .replace(/\/etc\/rdock\/certs\/[\w.-]+\.(pem|crt)/g, cert)
        .replace(/\/etc\/rdock\/certs\/[\w.-]+\.key/g, key)
        .replace(/\/run\/secrets\/[\w.-]+/g, secret)
        .replace(/\/etc\/rdock\/[\w.-]+\.htpasswd/g, users);
    },
  };
}

function hash(user: string, password: string): string {
  return execFileSync(RDOCK, ['hash', '--user', user], { input: `${password}\n` }).toString().trim();
}

/** `rdock validate --strict` (or without --strict) on one configuration text. */
export function validate(config: string, file: string, strict = true): Validation {
  writeFileSync(file, config);
  const args = ['validate', ...(strict ? ['--strict'] : []), file];
  const run = spawnSync(RDOCK, args, { encoding: 'utf8', env: { ...process.env, CF_API_TOKEN: 'example' } });
  return { ok: run.status === 0, output: `${run.stdout}${run.stderr}`.trim() };
}
