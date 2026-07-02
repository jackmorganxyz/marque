// x.test.ts — checks for the optional X handle verification module (x.ts).
// Run: npm test   (node --import tsx --test marque.test.ts x.test.ts)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { privateKeyToAddress, recoverMessageAddress, generatePrivateKey } from './eth.js';
import { linkX, verifyX, xProofStatement } from './x.js';

const PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
const ADDR = privateKeyToAddress(PK);
const EVE = 'eve.example.com';

const PROOF = 'https://x.com/eve/status/1234567890';
const wellKnown = (x: unknown) => ({ v: 1, keys: [ADDR], x });
const oembed = (tweet: string, author = 'eve') =>
  ({ author_url: `https://twitter.com/${author}`, html: `<blockquote><p>${tweet}</p></blockquote>` });

// Stub fetch to return the given JSON bodies in call order: [marque.json, oEmbed]
// (same globalThis.fetch stubbing pattern as the httpsResolver tests).
function stubFetch(bodies: any[]) {
  const orig = globalThis.fetch;
  let i = 0;
  globalThis.fetch = (async () => ({
    ok: true, headers: { get: () => null },
    text: async () => JSON.stringify(bodies[i++]),
  })) as any;
  return () => { globalThis.fetch = orig; };
}

test('linkX normalizes the handle and its tweet signature binds handle to address', () => {
  const l = linkX('@Eve', PK);
  assert.equal(l.handle, 'eve');
  assert.equal(l.address, ADDR);
  const sig = /sig:(0x[0-9a-fA-F]{130})/.exec(l.tweet)![1];
  assert.equal(recoverMessageAddress(xProofStatement('eve', ADDR), sig), ADDR);
  assert.throws(() => linkX('way-too-long-handle!', PK), /bad x handle/);
});

// Frozen vector: a refactor that changes any signed byte of the proof must break this.
test('frozen x-proof vector byte-compatibility', () => {
  assert.equal(xProofStatement('eve', ADDR),
    'marque/x-proof/v1\nx:@eve\n0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266');
  const l = linkX('eve', PK);
  assert.equal(/sig:(0x[0-9a-fA-F]{130})/.exec(l.tweet)![1],
    '0xed91d23a0d315c4ab31157d25d8300676a4ca3d0ee6e82d18ee37deec393fd6a66d6d1cbe2a447462db95fd60ea4c08f0f4673cbbdc2164745ee46923bb23b861b');
});

test('verifyX happy path', async () => {
  const l = linkX('eve', PK);
  const restore = stubFetch([wellKnown({ handle: 'eve', proof: PROOF }), oembed(l.tweet)]);
  try {
    assert.deepEqual(await verifyX(EVE, ADDR), { ok: true, identity: 'x:@eve', handle: 'eve' });
  } finally { restore(); }
});

test('verifyX rejects a tweet posted by someone else', async () => {
  const l = linkX('eve', PK);
  const restore = stubFetch([wellKnown({ handle: 'eve', proof: PROOF }), oembed(l.tweet, 'mallory')]);
  try {
    assert.equal((await verifyX(EVE, ADDR)).reason, 'tweet author mismatch');
  } finally { restore(); }
});

test('verifyX rejects a proof signed by a different key', async () => {
  const other = linkX('eve', generatePrivateKey());   // valid proof, wrong key
  const restore = stubFetch([wellKnown({ handle: 'eve', proof: PROOF }), oembed(other.tweet)]);
  try {
    assert.equal((await verifyX(EVE, ADDR)).reason, 'proof signer mismatch');
  } finally { restore(); }
});

test('verifyX rejects non-tweet proof urls before fetching them', async () => {
  for (const bad of ['https://evil.com/eve/status/1', 'http://x.com/eve/status/1',
                     'https://x.com/eve/likes', 'https://x.com.evil.com/eve/status/1', 'junk']) {
    const restore = stubFetch([wellKnown({ handle: 'eve', proof: bad })]);
    try {
      assert.equal((await verifyX(EVE, ADDR)).reason, 'bad proof url', `expected reject for ${bad}`);
    } finally { restore(); }
  }
});

test('verifyX returns {ok:false}, never throws, on hostile or missing input', async () => {
  assert.equal((await verifyX('localhost', ADDR)).reason, 'bad origin');
  const cases: [any, string][] = [
    [wellKnown(undefined), 'no x entry at origin'],
    [wellKnown({ handle: 'not a handle!', proof: PROOF }), 'no x entry at origin'],
    [wellKnown({ handle: 'eve' }), 'bad proof url'],
    [null, 'no x entry at origin'],                       // well-known fetch failed
  ];
  for (const [wk, reason] of cases) {
    const restore = stubFetch([wk]);
    try { assert.equal((await verifyX(EVE, ADDR)).reason, reason); }
    finally { restore(); }
  }
  // oEmbed body with no signature in the tweet text
  const restore = stubFetch([wellKnown({ handle: 'eve', proof: PROOF }), oembed('gm')]);
  try { assert.equal((await verifyX(EVE, ADDR)).reason, 'no signature in tweet'); }
  finally { restore(); }
});
