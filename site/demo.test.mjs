import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDemo } from './demo.mjs';

test('the playground uses real signatures, audience checks and one-time nonces', async () => {
  const demo = createDemo();
  const message = await demo.sign({ task: 'summarize', text: 'Hello' }, 'bob-inbox');
  assert.equal((await demo.verify({ ...message, payload: { text: 'Changed' } }, 'bob-inbox')).ok, false);
  assert.equal((await demo.verify(message, 'alice-inbox')).reason, 'wrong audience');
  const attempts = await Promise.all(Array.from({ length: 8 }, () => demo.verify(message, 'bob-inbox')));
  assert.equal(attempts.filter(result => result.ok).length, 1);
  assert.equal(attempts.filter(result => result.reason === 'replay').length, 7);
  const fresh = await demo.sign(message.payload, 'bob-inbox');
  assert.equal(fresh.signer, message.signer);
  assert.notEqual(fresh.nonce, message.nonce);
  assert.equal((await demo.verify(fresh, 'bob-inbox')).ok, true);
  assert.notEqual((await createDemo().sign(null, 'bob-inbox')).signer, message.signer);
});
