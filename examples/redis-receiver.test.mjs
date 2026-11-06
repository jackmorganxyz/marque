import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import { createECDH, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createClient } from 'redis';
import { sign } from '@jackmorganxyz/marque';

assert.ok(process.env.REDIS_URL, 'Set REDIS_URL to a running Redis server');
const key = createECDH('secp256k1');
key.generateKeys();
const privateKey = `0x${key.getPrivateKey('hex').padStart(64, '0')}`;
const aud = `marque-test-${randomUUID()}`;
const payload = () => ({ id: randomUUID(), task: 'summarize', text: 'Hello' });
const receiver = fileURLToPath(new URL('./redis-receiver.mjs', import.meta.url));

function receive(message, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [receiver], {
      env: { ...process.env, MARQUE_AUDIENCE: aud, TRUSTED_ADDRESSES: message.signer, ...env },
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000,
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.stdin.on('error', reject);
    child.on('close', code => resolve({ code, stdout, stderr }));
    child.stdin.end(typeof message === 'string' ? message : JSON.stringify(message));
  });
}

test('one receiver wins concurrent delivery; new processes still reject replays', async () => {
  const message = await sign(payload(), { privateKey, aud });
  const attempts = await Promise.all(Array.from({ length: 6 }, () => receive(message)));
  assert.equal(attempts.filter(result => result.code === 0).length, 1);
  assert.equal(attempts.filter(result => result.stderr.includes('Rejected: replay')).length, 5);
  const accepted = JSON.parse(attempts.find(result => result.code === 0).stdout);
  assert.equal(accepted.payload.id, message.payload.id);
  assert.match((await receive(message)).stderr, /Rejected: replay/);
  const redis = createClient({ url: process.env.REDIS_URL });
  redis.on('error', () => {});
  try {
    await redis.connect();
    const nonceKey = `marque:nonce:${JSON.stringify([aud, message.signer.toLowerCase(), message.nonce])}`;
    assert.equal(await redis.get(nonceKey), '1');
    assert.equal(await redis.sendCommand(['EXPIRETIME', nonceKey]), message.exp);
  } finally { if (redis.isOpen) redis.destroy(); }
});

test('the receiver rejects tampering, wrong recipients, unknown addresses and unsupported actions', async () => {
  const message = await sign(payload(), { privateKey, aud });
  assert.match((await receive({ ...message, payload: { ...message.payload, text: 'Changed' } })).stderr, /signer mismatch/);
  assert.match((await receive(message, { MARQUE_AUDIENCE: 'wrong-inbox' })).stderr, /wrong audience/);
  assert.match((await receive(message, { TRUSTED_ADDRESSES: `0x${'00'.repeat(20)}` })).stderr, /untrusted sender/);
  const invalid = await sign({ ...payload(), task: 'execute' }, { privateKey, aud });
  assert.match((await receive(invalid)).stderr, /invalid payload/);
});

test('request limits and unavailable storage fail closed', async () => {
  const env = { TRUSTED_ADDRESSES: `0x${'00'.repeat(20)}` };
  assert.match((await receive('{', env)).stderr, /invalid JSON/);
  assert.match((await receive(' '.repeat(17000), env)).stderr, /message too large/);
  assert.match((await receive('['.repeat(34) + '0' + ']'.repeat(34), env)).stderr, /message too deep/);
  const message = await sign(payload(), { privateKey, aud });
  const failed = await receive(message, { REDIS_URL: 'redis://127.0.0.1:1' });
  assert.equal(failed.code, 1);
  assert.match(failed.stderr, /nonce store failed/);
  assert.equal(failed.stdout, '');
  const misconfigured = await receive(message, { REDIS_URL: 'invalid-url-with-secret' });
  assert.equal(misconfigured.code, 1);
  assert.match(misconfigured.stderr, /nonce store failed/);
  assert.equal(misconfigured.stderr.includes('invalid-url-with-secret'), false);
});
