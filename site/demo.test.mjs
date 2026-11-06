import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
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

test('playground controls separate signing, verification, edits, trust and reset', async (t) => {
  const html = await readFile(new URL('./dist/index.html', import.meta.url), 'utf8');
  const element = () => ({
    textContent: '', dataset: {}, disabled: true, listeners: {},
    addEventListener(type, callback) { this.listeners[type] = callback; },
    focus() { this.focused = true; },
    async fire(type = 'click') {
      if (type === 'click') assert.equal(this.disabled, false);
      await this.listeners[type]();
    },
  });
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(([, id]) => [id, element()]));
  const get = id => { assert.ok(elements.has(id), `Missing #${id}`); return elements.get(id); };
  const buttons = [...html.matchAll(/data-demo="([^"]+)"/g)].map(([, action]) => ({ ...element(), dataset: { demo: action } }));
  const button = action => buttons.find(item => item.dataset.demo === action);
  const payload = get('demo-payload');
  const audience = get('demo-audience');
  const trust = get('demo-trust');
  payload.value = payload.defaultValue = html.match(/<textarea id="demo-payload"[^>]*>([\s\S]*?)<\/textarea>/)[1];
  audience.value = audience.defaultValue = html.match(/<input id="demo-audience" value="([^"]+)"/)[1];
  trust.checked = true;
  assert.equal(globalThis.document, undefined);
  globalThis.document = {
    getElementById: get,
    querySelectorAll: selector => { assert.equal(selector, '[data-demo]'); return buttons; },
  };
  t.after(() => { delete globalThis.document; });
  await import('./playground.js');
  const envelope = () => JSON.parse(get('demo-envelope').textContent);
  const status = () => get('demo-proof').textContent;
  const original = envelope();
  assert.match(html, /<details class="technical demo-envelope" open>/);
  assert.equal(status(), 'Signed · ready to verify');
  assert.equal(button('replay').disabled, true);

  await button('verify').fire();
  assert.equal(status(), 'Verified · message unchanged');
  assert.equal(get('demo-policy').textContent, 'Sender allowed by this app');
  trust.checked = false;
  await trust.fire('change');
  assert.equal(status(), 'Verified · message unchanged');
  assert.equal(get('demo-policy').textContent, 'Sender blocked by this app');
  assert.match(button('verify').textContent, /replay/);
  get('demo-proof').focused = false;
  await button('replay').fire();
  assert.equal(status(), 'Rejected · already received');
  assert.equal(get('demo-proof').focused, true);

  await button('tamper').fire();
  assert.equal(status(), 'Rejected · message changed');
  assert.equal(envelope().sig, original.sig);
  assert.notDeepEqual(envelope().payload, original.payload);
  await button('recipient').fire();
  assert.equal(status(), 'Rejected · wrong receiver');
  assert.equal(envelope().aud, original.aud);
  assert.notEqual(audience.value, original.aud);

  await button('reset').fire();
  assert.equal(status(), 'Signed · ready to verify');
  assert.notEqual(envelope().nonce, original.nonce);
  assert.equal(envelope().signer, original.signer);
  assert.equal(button('replay').disabled, true);
  assert.equal(trust.checked, true);
  payload.value = '"edited"';
  await payload.fire('input');
  assert.equal(envelope().payload, 'edited');
  assert.equal(status(), 'Edited · not verified');
  await button('verify').fire();
  assert.equal(status(), 'Rejected · message changed');
  await button('sign').fire();
  assert.equal(status(), 'Signed · ready to verify');
  await button('verify').fire();
  assert.equal(status(), 'Verified · message unchanged');

  payload.value = '{';
  await payload.fire('input');
  await button('sign').fire();
  assert.equal(status(), 'Check your input');
  audience.value = '   ';
  await audience.fire('input');
  await button('verify').fire();
  assert.equal(status(), 'Check your input');
  await button('reset').fire();
  assert.equal(status(), 'Signed · ready to verify');
  assert.equal(audience.value, audience.defaultValue);
  assert.equal(payload.value, payload.defaultValue);
  await button('verify').fire();
  assert.equal(status(), 'Verified · message unchanged');
});
