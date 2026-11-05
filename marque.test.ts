import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as marque from './marque.js';
import { sign, verify, type Signed, type Hex } from './marque.js';
import { privateKeyToAddress, signMessage } from './eth.js';

// Public test keys, never use for real messages or funds.
const PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const OTHER_KEY = ('0x' + '01'.repeat(32)) as Hex;
const ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const AUD = 'bob-inbox';
const NOW = 1751371200;
const opts = { privateKey: PRIVATE_KEY, aud: AUD } as const;

function nonceStore() {
  const seen = new Set<string>();
  return (key: string, _expiresAt: number) => {
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  };
}

// Literal canonical key order, independent of the library's serializer.
function fixture(changes: Partial<Omit<Signed, 'sig'>> = {}, privateKey: Hex = PRIVATE_KEY): Signed {
  const message = {
    aud: AUD, exp: NOW + 300, nonce: '0x9f3c1a7be44d0521c0a8f2e6' as Hex,
    payload: 42, signer: privateKeyToAddress(privateKey), ts: NOW, v: 2 as const,
    ...changes,
  };
  return { ...message, sig: signMessage('marque/v2\n' + JSON.stringify(message), privateKey) };
}

const context = () => ({ aud: AUD, consumeNonce: nonceStore(), now: NOW });

test('the public runtime API is only sign and verify', () => {
  assert.deepEqual(Object.keys(marque).sort(), ['sign', 'verify']);
});

test('sign and verify round-trip JSON without domain or identity services', async t => {
  const fetch = t.mock.method(globalThis, 'fetch', () => { throw new Error('unexpected network request'); });
  const payload = { task: 'summarize', text: 'Hello 🌍', options: [null, true, 1.25] };
  const message = await sign(payload, opts);
  assert.equal(message.v, 2);
  assert.equal(message.signer, ADDRESS);
  assert.equal(message.exp, message.ts + 300);
  assert.match(message.nonce, /^0x[0-9a-f]{24}$/);
  assert.match(message.sig, /^0x[0-9a-f]{130}$/);
  assert.deepEqual(Object.keys(message).sort(), ['aud', 'exp', 'nonce', 'payload', 'sig', 'signer', 'ts', 'v']);
  assert.deepEqual(await verify(JSON.parse(JSON.stringify(message)), { ...context(), now: message.ts }), {
    ok: true, signer: ADDRESS,
  });
  assert.equal(fetch.mock.callCount(), 0);
});

test('JSON object key order does not change a signature; array order does', async () => {
  const message = await sign({ z: [1, 2], a: { b: 'x', a: 'y' } }, opts);
  const ctx = { ...context(), now: message.ts };
  assert.equal((await verify({ ...message, payload: { a: { a: 'y', b: 'x' }, z: [1, 2] } }, ctx)).ok, true);
  assert.equal((await verify({ ...message, payload: { a: { a: 'y', b: 'x' }, z: [2, 1] } }, ctx)).ok, false);
});

test('sign validates audience, key and lifetime', async () => {
  for (const aud of ['', null, 42])
    await assert.rejects(sign(null, { ...opts, aud: aud as string }), /audience/);
  for (const ttl of [0, -1, 1.5, 301, NaN, Infinity, '60'])
    await assert.rejects(sign(null, { ...opts, ttl: ttl as number }), /ttl/);
  for (const privateKey of ['bad', '0x01', '0x' + '00'.repeat(32), '0x' + 'ff'.repeat(32)])
    await assert.rejects(sign(null, { ...opts, privateKey: privateKey as Hex }));
  const short = await sign(null, { ...opts, ttl: 1 });
  assert.equal(short.exp, short.ts + 1);
});

test('unsafe payloads fail at signing and verification', async () => {
  const bad = [undefined, NaN, Infinity, -Infinity, 2 ** 60, 10n, () => 1, Symbol('x'),
    new Date(0), new Map(), new Set(), new Number(1), [1, , 3], { nested: undefined },
    { toJSON: () => 'different' }];
  for (const payload of bad) {
    await assert.rejects(sign(payload, opts), /not JSON-safe/);
    assert.equal((await verify({ ...fixture(), payload }, context())).ok, false);
  }
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  await assert.rejects(sign(cyclic, opts));
  assert.equal((await verify({ ...fixture(), payload: cyclic }, context())).ok, false);
});

test('a valid signature from any address verifies; trust is the caller decision', async () => {
  const message = fixture({}, OTHER_KEY);
  const result = await verify(message, context());
  assert.deepEqual(result, { ok: true, signer: privateKeyToAddress(OTHER_KEY) });
  const trusted = new Set([ADDRESS.toLowerCase()]);
  assert.equal(result.ok && trusted.has(result.signer.toLowerCase()), false);
});

test('every message field is bound by the signature', async () => {
  const message = fixture();
  const changes = [
    { payload: 43 }, { aud: 'carol-inbox' }, { ts: NOW + 1 }, { exp: NOW + 299 },
    { nonce: '0x000000000000000000000000' }, { signer: privateKeyToAddress(OTHER_KEY) },
    { sig: fixture({}, OTHER_KEY).sig },
  ];
  for (const change of changes) {
    let consumed = false;
    const tampered = { ...message, ...change };
    const result = await verify(tampered, {
      ...context(), aud: tampered.aud, consumeNonce: () => { consumed = true; return true; },
    });
    assert.equal(result.ok, false, JSON.stringify(change));
    assert.equal(consumed, false);
  }
});

test('a genuine message addressed elsewhere is rejected', async () => {
  assert.equal((await verify(fixture(), { ...context(), aud: 'carol-inbox' })).reason, 'wrong audience');
  assert.equal((await verify(fixture(), { ...context(), aud: 'BOB-INBOX' })).reason, 'wrong audience');
});

test('expiry, clock skew and maximum lifetime are enforced on signed input', async () => {
  assert.equal((await verify(fixture(), { ...context(), now: NOW + 300 })).reason, 'expired');
  assert.equal((await verify(fixture(), { ...context(), now: NOW - 301 })).reason, 'clock skew');
  assert.equal((await verify(fixture(), { ...context(), now: NOW - 300 })).ok, true);
  assert.equal((await verify(fixture(), { ...context(), now: NOW + 299 })).ok, true);
  for (const changes of [{ exp: NOW }, { exp: NOW + 301 }, { ts: NOW + 0.5 }, { exp: NOW + 1.5 }])
    assert.equal((await verify(fixture(changes), context())).ok, false);
});

test('malformed or extended envelopes return a failure without throwing', async () => {
  const message = fixture();
  const noPayload: Partial<Signed> = { ...message };
  delete noPayload.payload;
  const throwing = new Proxy({}, { ownKeys() { throw new Error('hostile object'); } });
  const bad = [null, undefined, 'text', 42, [], {}, noPayload, throwing,
    { ...message, v: 1 }, { ...message, origin: 'eve.example.com' },
    { ...message, sig: 'nope' }, { ...message, sig: message.sig.slice(0, -2) },
    { ...message, sig: message.sig.slice(0, -2) + 'ff' },
    { ...message, signer: 'not-an-address' }, { ...message, nonce: '' },
    { ...message, nonce: 42 }, { ...message, aud: null },
    { ...message, ts: 'soon' }, { ...message, ts: -1 }, { ...message, exp: Infinity }];
  for (const input of bad) assert.equal((await verify(input, context())).ok, false);
});

test('missing or invalid verification context cannot disable checks', async () => {
  const bad = [undefined, null, {}, { ...context(), aud: '' }, { ...context(), now: NaN },
    { ...context(), now: NOW + 0.5 }, { ...context(), consumeNonce: undefined }];
  for (const ctx of bad) assert.equal((await verify(fixture(), ctx as Parameters<typeof verify>[1])).ok, false);
});

test('replays are rejected and forged messages do not consume a genuine nonce', async () => {
  const message = fixture();
  const ctx = context();
  assert.equal((await verify({ ...message, payload: 'forged' }, ctx)).ok, false);
  assert.equal((await verify(message, ctx)).ok, true);
  assert.equal((await verify(message, ctx)).reason, 'replay');
});

test('nonce storage receives the signed expiry and separates senders and audiences', async () => {
  const records: [string, number][] = [];
  const store = nonceStore();
  const ctx = { ...context(), consumeNonce: (key: string, expiry: number) => {
    records.push([key, expiry]);
    return store(key, expiry);
  } };
  assert.equal((await verify(fixture(), ctx)).ok, true);
  assert.equal((await verify(fixture({}, OTHER_KEY), ctx)).ok, true);
  assert.equal((await verify(fixture({ aud: 'carol-inbox' }), { ...ctx, aud: 'carol-inbox' })).ok, true);
  assert.equal(new Set(records.map(([key]) => key)).size, 3);
  assert.ok(records.every(([, expiry]) => expiry === NOW + 300));
});

test('nonce casing cannot bypass replay detection', async () => {
  const ctx = context();
  assert.equal((await verify(fixture(), ctx)).ok, true);
  const upper = fixture({ nonce: '0x9F3C1A7BE44D0521C0A8F2E6', signer: ADDRESS.toLowerCase() as Hex });
  assert.equal((await verify(upper, ctx)).reason, 'replay');
});

test('concurrent verifications work with an async atomic replay store', async () => {
  const store = nonceStore();
  const ctx = { ...context(), consumeNonce: async (key: string, expiry: number) => {
    await Promise.resolve();
    return store(key, expiry);
  } };
  const results = await Promise.all(Array.from({ length: 8 }, () => verify(fixture(), ctx)));
  assert.equal(results.filter(r => r.ok).length, 1);
  assert.ok(results.filter(r => !r.ok).every(r => r.reason === 'replay'));
});

test('storage failures are distinct from invalid messages and genuine replays', async () => {
  const callbacks = [
    () => { throw new Error('store unavailable'); },
    async () => { throw new Error('store unavailable'); },
    () => undefined, () => 'OK', () => 1,
  ];
  for (const callback of callbacks)
    assert.equal((await verify(fixture(), {
      ...context(), consumeNonce: callback as Parameters<typeof verify>[1]['consumeNonce'],
    })).reason, 'nonce store failed');
  assert.equal((await verify(fixture(), { ...context(), consumeNonce: () => false })).reason, 'replay');
  assert.equal((await verify({ ...fixture(), sig: '0x' + '00'.repeat(65) }, context())).reason, 'verification failed');
});

test('nonce remains recorded until expiry when the receiver clock trails the sender', async () => {
  let now = NOW - 300;
  const seen = new Map<string, number>();
  const consumeNonce = (key: string, expiry: number) => {
    for (const [k, t] of seen) if (t <= now) seen.delete(k);
    if (seen.has(key)) return false;
    seen.set(key, expiry);
    return true;
  };
  assert.equal((await verify(fixture(), { aud: AUD, consumeNonce, now })).ok, true);
  now = NOW + 299;
  assert.equal((await verify(fixture(), { aud: AUD, consumeNonce, now })).reason, 'replay');
});

test('the v2 signature prefix cannot be replaced by v1 or raw personal_sign', async () => {
  const { sig, ...message } = fixture();
  for (const prefix of ['marque/v1\n', '']) {
    const forged = { ...message, sig: signMessage(prefix + JSON.stringify(message), PRIVATE_KEY) };
    assert.equal((await verify(forged, context())).ok, false);
  }
});

test('frozen v2 vector verifies and preserves EIP-191 signature bytes', async () => {
  const payload = { task: 'summarize', url: 'https://x.com/thread/1' };
  const message = fixture({ payload });
  assert.equal(message.sig, '0x46cf7c13e9d89bbc4145a64cb6600723b9c16db787c540255c78417ce41b7f2c4364005216c6bda359f33ce0425a40604d76a8de8ddc7727cc45f9fb09582fca1b');
  assert.deepEqual(await verify(message, context()), { ok: true, signer: ADDRESS });
});
