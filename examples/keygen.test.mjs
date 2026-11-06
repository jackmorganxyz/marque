import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verify } from '@jackmorgan/marque';

test('key setup protects its file, never prints the secret, and works with the sender', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'marque-key-test-'));
  const keygen = fileURLToPath(new URL('./keygen.mjs', import.meta.url));
  try {
    const output = execFileSync(process.execPath, [keygen], { cwd, encoding: 'utf8' });
    const saved = readFileSync(join(cwd, '.env.local'), 'utf8');
    const env = Object.fromEntries(saved.trim().split('\n').map(line => line.split('=')));
    assert.match(env.MARQUE_PRIVATE_KEY, /^0x[0-9a-f]{64}$/);
    assert.equal(output.includes(env.MARQUE_PRIVATE_KEY), false);
    assert.equal(output.includes(env.TRUSTED_ADDRESSES), true);
    assert.equal(statSync(join(cwd, '.env.local')).mode & 0o777, 0o600);
    assert.throws(() => execFileSync(process.execPath, [keygen], { cwd, stdio: 'pipe' }));
    assert.equal(readFileSync(join(cwd, '.env.local'), 'utf8'), saved);
    const message = JSON.parse(execFileSync(process.execPath, [fileURLToPath(new URL('./send.mjs', import.meta.url))], {
      env: { ...process.env, ...env, MARQUE_AUDIENCE: 'key-test' }, encoding: 'utf8',
    }));
    assert.equal(message.signer, env.TRUSTED_ADDRESSES);
    assert.equal((await verify(message, { aud: 'key-test', consumeNonce: () => true })).ok, true);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});
