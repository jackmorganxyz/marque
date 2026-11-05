import assert from 'node:assert/strict';
import { createECDH } from 'node:crypto';
import { sign, verify } from '@jackmorganxyz/marque';

// Ephemeral demo key. Production keys belong in your application's secret store.
const key = createECDH('secp256k1');
key.generateKeys();
const privateKey = `0x${key.getPrivateKey('hex').padStart(64, '0')}`;
const message = await sign({ task: 'summarize', text: 'Hello' }, {
  privateKey, aud: 'bob-inbox',
});

// This demo trusts the key it just created. Never enroll keys from incoming messages.
const trustedAddresses = new Set([message.signer.toLowerCase()]);
// shortcut: process-local replay storage, replace with an atomic durable store before deployment.
const seen = new Map();
const consumeNonce = (key, expiresAt) => {
  const now = Math.floor(Date.now() / 1000);
  for (const [k, expiry] of seen) if (expiry <= now) seen.delete(k);
  if (seen.has(key)) return false;
  seen.set(key, expiresAt);
  return true;
};

const received = JSON.parse(JSON.stringify(message));
const context = { aud: 'bob-inbox', consumeNonce };
const result = await verify(received, context);
assert.equal(result.ok, true);
assert.equal(trustedAddresses.has(result.signer.toLowerCase()), true);
console.log('✓ Message verified from', result.signer);
assert.equal((await verify({ ...received, payload: 'tampered' }, context)).ok, false);
console.log('✓ Tampered message rejected');
assert.equal((await verify(received, context)).reason, 'replay');
console.log('✓ Replayed message rejected');
