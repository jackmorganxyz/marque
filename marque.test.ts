// marque.test.ts — self-checks + frozen regression vector.
// Run: npm test   (node --import tsx --test marque.test.ts)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { privateKeyToAddress, signMessage, isAddressEqual } from './eth.js';
import {
  canon, payloadHash, sign, verify, generateAgent, httpsResolver, cached, SKEW,
  type Signed, type ResolveKeys,
} from './marque.js';

const EVE = 'eve.example.com';
const BOB = 'bob.example.com';

// ---- 2. canon + payloadHash ----
test('canon sorts keys and stays compact', () => {
  assert.equal(canon({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canon([3, 1]), '[3,1]');
  assert.equal(canon('x'), '"x"');
  assert.equal(canon(null), 'null');
});

test('key order does not change the hash', () => {
  assert.equal(payloadHash({ a: 1, b: { c: 2, d: 3 } }), payloadHash({ b: { d: 3, c: 2 }, a: 1 }));
});

test('isAddressEqual is case-insensitive and rejects non-addresses', () => {
  const A = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
  assert.equal(isAddressEqual(A, A.toLowerCase()), true);
  assert.throws(() => isAddressEqual('junk', A), /bad address/);
});

test('canon refuses values whose canon form differs from the JSON wire', () => {
  assert.throws(() => canon(() => 1), /not JSON-safe/);        // function
  assert.throws(() => canon(10n as any), /not JSON-safe/);     // bigint
  assert.throws(() => canon(Symbol('x') as any), /not JSON-safe/);
  assert.throws(() => canon(new Date(0)), /not JSON-safe/);    // toJSON differs
  assert.throws(() => canon({ a: new Date(0) }), /not JSON-safe/);
});

// ---- 3. payload safety (assertJsonSafe fires at sign time) ----
const signOpts = { privateKey:
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const,
  origin: EVE, aud: BOB };

test('sign rejects unsafe numbers, accepts safe payloads', async () => {
  await assert.rejects(sign({ n: 1.5e308 }, signOpts), /unsafe number/);
  await assert.rejects(sign({ n: 2 ** 60 }, signOpts), /unsafe number/);
  await assert.rejects(sign({ n: Infinity }, signOpts), /unsafe number/);
  await sign({ n: 42, s: 'hi', nested: { a: [1, 2, 3] } }, signOpts); // does not throw
});

// ---- 4. generateAgent ----
test('generateAgent returns a matching checksummed address + well-known', () => {
  const g = generateAgent(EVE);
  assert.equal(privateKeyToAddress(g.privateKey), g.address);
  assert.match(g.address, /^0x[0-9a-fA-F]{40}$/);
  assert.notEqual(g.address, g.address.toLowerCase());        // EIP-55 mixed-case
  assert.deepEqual(g.wellKnown, { v: 1, keys: [g.address] });
});

// ---- 5. sign shape ----
test('sign produces the full envelope', async () => {
  const s = await sign({ hello: 'world' }, signOpts);
  assert.equal(Object.keys(s).length, 12);                    // 10 core + sig + payload
  assert.equal(s.sig.length, 132);                            // 0x + 65 bytes
  assert.equal(s.nonce.length, 26);                           // 0x + 12 bytes
  assert.equal(s.exp, s.ts + SKEW);
  assert.equal(s.signer, s.agent_id);
  assert.equal(s.scope, '');
  assert.equal(s.v, 1);
});

test('sign caps ttl at SKEW (longer exp cannot outlive the skew check anyway)', async () => {
  const s = await sign({ x: 1 }, { ...signOpts, ttl: 9999 });
  assert.equal(s.exp, s.ts + SKEW);
});

// ---- 6. httpsResolver SSRF guard + cached ----
test('httpsResolver rejects non-public / malformed origins', async () => {
  for (const bad of ['localhost', '10.0.0.1', 'x.internal', 'a.com:8080', 'a.com/b', 'nodot']) {
    await assert.rejects(httpsResolver(bad), /marque:/, `expected reject for ${bad}`);
  }
});

test('httpsResolver reads keys on 200, empty on non-200; cached hits once', async () => {
  const A = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
  const orig = globalThis.fetch;
  try {
    const hdrs = { get: () => null };   // real fetch always exposes a Headers; stub the content-length lookup
    globalThis.fetch = (async () => ({ ok: true, headers: hdrs, text: async () => JSON.stringify({ v: 1, keys: [A] }) })) as any;
    assert.deepEqual(await httpsResolver(EVE), [A]);
    globalThis.fetch = (async () => ({ ok: false, headers: hdrs, text: async () => '' })) as any;
    assert.deepEqual(await httpsResolver(EVE), []);

    let calls = 0;
    const counting: ResolveKeys = async () => { calls++; return [A]; };
    const c = cached(counting, 60_000);
    await c(EVE); await c(EVE);
    assert.equal(calls, 1);                                    // second call served from cache
  } finally { globalThis.fetch = orig; }
});

// ---- regression: SSRF guard catches shorthand / octal / userinfo IPv4 ----
test('httpsResolver rejects non-canonical IPv4 + userinfo bypasses', async () => {
  for (const bad of ['127.1', '10.1', '0177.0.0.1', '0x7f.0.0.1', '192.168.1',
                     '2130706433', 'user@127.0.0.1', 'a.com?x=1', 'a.com#f']) {
    await assert.rejects(httpsResolver(bad), /marque:/, `expected reject for ${bad}`);
  }
});

// ---- 7 + 8. verify ordered checks (offline resolver) ----
const only = (addr: string): ResolveKeys => async () => [addr as `0x${string}`];

async function baseline() {
  const s = await sign({ task: 'summarize' }, signOpts);
  const ok = { selfOrigin: BOB, resolveKeys: only(s.signer), now: s.ts, seen: new Map<string, number>() };
  return { s, ok };
}

test('verify happy path', async () => {
  const { s, ok } = await baseline();
  const r = await verify(s, ok);
  assert.deepEqual(r, { ok: true, identity: `https:${EVE}`, signer: s.signer });
});

test('verify rejects tampered payload', async () => {
  const { s, ok } = await baseline();
  const r = await verify({ ...s, payload: { task: 'DELETE' } }, ok);
  assert.equal(r.reason, 'payload mismatch');
});

test('verify rejects wrong audience', async () => {
  const { s, ok } = await baseline();
  const r = await verify(s, { ...ok, selfOrigin: 'carol.example.com' });
  assert.equal(r.reason, 'wrong audience');
});

test('verify rejects expired', async () => {
  const { s, ok } = await baseline();
  const r = await verify(s, { ...ok, now: s.exp + 1 });
  assert.equal(r.reason, 'expired');
});

test('verify rejects clock skew', async () => {
  const { s, ok } = await baseline();
  const r = await verify(s, { ...ok, now: s.ts - (SKEW + 100) }); // fresh exp, stale ts
  assert.equal(r.reason, 'clock skew');
});

test('verify rejects replay (same nonce twice)', async () => {
  const { s, ok } = await baseline();
  assert.equal((await verify(s, ok)).ok, true);
  assert.equal((await verify(s, ok)).reason, 'replay');
});

test('verify rejects key not published at origin', async () => {
  const { s, ok } = await baseline();
  const r = await verify(s, { ...ok, resolveKeys: async () => [] });
  assert.equal(r.reason, 'key not published at origin');
});

test('verify rejects a spliced (wrong) signature', async () => {
  const { s, ok } = await baseline();
  const other = await sign({ task: 'other' }, signOpts); // valid sig over a different core
  const r = await verify({ ...s, sig: other.sig }, ok);
  assert.equal(r.reason, 'signer mismatch');
});

// ---- regression: verify RETURNS {ok:false}, never throws, on hostile input ----
test('verify never throws on malformed envelopes', async () => {
  const { s, ok } = await baseline();
  const bad: [string, any][] = [
    ['null msg', null],
    ['non-object', 'not-an-envelope'],
    ['truncated sig', { ...s, sig: s.sig.slice(0, 130) }],
    ['non-hex sig', { ...s, sig: 'nope' }],
    ['numeric sig', { ...s, sig: 12345 }],
    ['bad signer address', { ...s, signer: 'not-an-address' }],
    ['bad agent_id address', { ...s, agent_id: 'not-an-address' }],
    ['non-numeric ts', { ...s, ts: 'soon' }],
    ['missing payload', (() => { const { payload, ...rest } = s; return rest; })()],
  ];
  for (const [name, m] of bad) {
    const r = await verify(m, ok);              // must resolve, not reject
    assert.equal(r.ok, false, `${name} should be ok:false`);
  }
});

// ---- regression: nonce retained across the whole freshness window under skew ----
// sign() clamps ttl, but a forger doesn't — hand-craft a long-exp envelope directly.
test('replay blocked even when receiver clock trails the sender', async () => {
  const addr = privateKeyToAddress(signOpts.privateKey);
  const ts = 1751371200;
  const c = {
    v: 1 as const, origin: EVE, signer: addr, agent_id: addr, scope: '', aud: BOB,
    ts, exp: ts + 1000, nonce: '0x9f3c1a7be44d0521c0a8f2e6' as const,   // exp > ts + SKEW
    payload_hash: payloadHash({ x: 1 }),
  };
  const s: Signed = { ...c, sig: signMessage('marque/v1\n' + canon(c), signOpts.privateKey), payload: { x: 1 } };
  const seen = new Map<string, number>();
  const ctx = { selfOrigin: BOB, resolveKeys: only(addr), seen };
  assert.equal((await verify(s, { ...ctx, now: s.ts })).ok, true);           // first receipt at ts
  const replay = await verify(s, { ...ctx, now: s.ts + SKEW });              // still fresh (exp>now)
  assert.equal(replay.reason, 'replay');        // pre-fix this pruned the nonce and returned ok:true
});

// ---- identity label is canonicalized (case-insensitive host, trailing dot) ----
test('verify returns a lowercased, dot-stripped identity', async () => {
  const s = await sign({ x: 1 }, { ...signOpts, origin: 'EVE.Example.com.' });
  const r = await verify(s, { selfOrigin: BOB, resolveKeys: only(s.signer), seen: new Map(), now: s.ts });
  assert.deepEqual(r, { ok: true, identity: 'https:eve.example.com', signer: s.signer });
});

// ---- regression: reserved scope must be empty in v1 ----
test('verify rejects a non-empty scope', async () => {
  const s = await sign({ x: 1 }, signOpts);
  const r = await verify({ ...s, scope: 'admin' }, { selfOrigin: BOB, resolveKeys: only(s.signer), seen: new Map(), now: s.ts });
  assert.equal(r.reason, 'scope not supported');   // note: tampering scope also breaks the sig, but this check fires first
});

// ---- regression: concurrent copies of one envelope can't both pass ----
test('concurrent replay: exactly one of two identical verifies succeeds', async () => {
  const s = await sign({ x: 1 }, signOpts);
  const ctx = { selfOrigin: BOB, resolveKeys: only(s.signer), seen: new Map<string, number>(), now: s.ts };
  const [a, b] = await Promise.all([verify(s, ctx), verify(s, ctx)]);
  assert.equal([a, b].filter(r => r.ok).length, 1);
  assert.equal([a, b].find(r => !r.ok)!.reason, 'replay');
});

// ---- round trip: sign -> verify across both functions ----
test('round trip ok, cross-audience fails', async () => {
  const s = await sign({ ping: 1 }, signOpts);
  const good = await verify(s, { selfOrigin: BOB, resolveKeys: only(s.signer), seen: new Map() });
  assert.equal(good.ok, true);
  const bad = await verify(s, { selfOrigin: 'carol.example.com', resolveKeys: only(s.signer), seen: new Map() });
  assert.equal(bad.reason, 'wrong audience');
});

// ---- FROZEN TEST VECTOR (regression anchor). ----
// Fixed {privateKey, payload, ts, exp, nonce} -> exact {payload_hash, signingString, sig, address}.
// A refactor that changes any signed byte must break this test.
test('frozen vector byte-compatibility', () => {
  const pk = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
  const address = privateKeyToAddress(pk);
  const payload = { task: 'summarize', url: 'https://x.com/thread/1' };

  const V = {
    address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    payload_hash: '0x4721dc6fbe58a0fe2e9dee3ff4925194ebac7dd00fe23a0afba4bb9e382f2701',
    signingString:
      'marque/v1\n{"agent_id":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","aud":"bob.example.com","exp":1751371500,"nonce":"0x9f3c1a7be44d0521c0a8f2e6","origin":"eve.example.com","payload_hash":"0x4721dc6fbe58a0fe2e9dee3ff4925194ebac7dd00fe23a0afba4bb9e382f2701","scope":"","signer":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","ts":1751371200,"v":1}',
    sig: '0xb0b1d272bd1ab5d5902136ffd96e996f57331bf9837a117a9438cdf2bbdcf9925241b1f39ff4450496055222c2ad707f0f5ae0aa02fffc4871fe6d85bea940a41b',
  };

  assert.equal(address, V.address);
  assert.equal(payloadHash(payload), V.payload_hash);

  const c = {
    v: 1 as const, origin: EVE, signer: address, agent_id: address,
    scope: '', aud: BOB, ts: 1751371200, exp: 1751371500,
    nonce: '0x9f3c1a7be44d0521c0a8f2e6' as `0x${string}`,
    payload_hash: V.payload_hash as `0x${string}`,
  };
  assert.equal('marque/v1\n' + canon(c), V.signingString);
  // Deterministic RFC 6979 signing must reproduce the frozen (viem-era) signature bit-for-bit.
  assert.equal(signMessage(V.signingString, pk), V.sig);
});

// verify() accepts a hand-built envelope carrying the frozen signature.
test('frozen vector verifies end to end', async () => {
  const msg: Signed = {
    v: 1, origin: EVE, signer: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    agent_id: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', scope: '', aud: BOB,
    ts: 1751371200, exp: 1751371500, nonce: '0x9f3c1a7be44d0521c0a8f2e6',
    payload_hash: '0x4721dc6fbe58a0fe2e9dee3ff4925194ebac7dd00fe23a0afba4bb9e382f2701',
    sig: '0xb0b1d272bd1ab5d5902136ffd96e996f57331bf9837a117a9438cdf2bbdcf9925241b1f39ff4450496055222c2ad707f0f5ae0aa02fffc4871fe6d85bea940a41b',
    payload: { task: 'summarize', url: 'https://x.com/thread/1' },
  };
  const r = await verify(msg, {
    selfOrigin: BOB, now: 1751371300, seen: new Map(),
    resolveKeys: async () => ['0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'],
  });
  assert.deepEqual(r, { ok: true, identity: `https:${EVE}`, signer: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' });
});
