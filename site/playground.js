import { createDemo } from './demo.mjs';

const payload = document.getElementById('demo-payload');
const audience = document.getElementById('demo-audience');
const trust = document.getElementById('demo-trust');
const proof = document.getElementById('demo-proof');
const policy = document.getElementById('demo-policy');
const detail = document.getElementById('demo-detail');
const envelopeView = document.getElementById('demo-envelope');
const envelopeNote = document.getElementById('demo-envelope-note');
const buttons = [...document.querySelectorAll('[data-demo]')];
const verifyButton = buttons.find(button => button.dataset.demo === 'verify');
let demo, envelope, result, demoAddress;
let consumed = false;

function showTrust() {
  const allowed = result?.ok && trust.checked && result.signer === demoAddress;
  policy.textContent = !result ? 'Waiting for verification' : !result.ok ? 'Not checked · message rejected'
    : allowed ? 'Sender allowed by this app' : 'Sender blocked by this app';
  policy.dataset.state = !result?.ok ? '' : allowed ? 'success' : 'rejected';
}

function setStatus(title, explanation, state = '') {
  proof.textContent = title;
  proof.dataset.state = state;
  detail.textContent = explanation;
  showTrust();
}

function showEnvelope(message, note) {
  envelopeView.textContent = JSON.stringify(message, null, 2);
  envelopeNote.textContent = note;
}

function enableButtons() {
  for (const button of buttons) {
    button.disabled = !demo || !envelope || (button.dataset.demo === 'replay' && !consumed);
  }
}

async function signMessage() {
  if (!audience.value.trim()) throw new Error('Enter a receiver ID, such as bob-inbox.');
  envelope = await demo.sign(JSON.parse(payload.value), audience.value);
  demoAddress = envelope.signer;
  consumed = false;
  result = undefined;
  document.getElementById('demo-address').textContent = demoAddress;
  verifyButton.textContent = 'Verify message';
  showEnvelope(envelope, 'Signed envelope. Verification has not used its one-time ID yet.');
  setStatus('Signed · ready to verify', 'The signature is created. Click “Verify message” to check the signature, receiver, expiry, and one-time ID.');
}

function render(message, verified) {
  result = verified;
  consumed ||= result.ok;
  showEnvelope(message, `Envelope just checked against receiver “${audience.value}”. Its signed recipient is “${message.aud}”.`);
  verifyButton.textContent = result.ok || result.reason === 'replay' ? 'Verify again (replay)' : 'Verify message';
  const explanations = {
    'signer mismatch': ['Rejected · message changed', 'The payload changed, but the signature stayed the same. This is the expected protection against tampering. Sign a fresh message to approve your edits.'],
    'wrong audience': ['Rejected · wrong receiver', `This envelope is addressed to “${message.aud}”, but you checked it at “${audience.value}”. The intended receiver must match.`],
    replay: ['Rejected · already received', 'This exact envelope already passed verification. Its one-time ID (nonce) has been used, so a second delivery is rejected. Sign a fresh message to try again.'],
    expired: ['Rejected · message expired', 'The five-minute lifetime ended. Sign a fresh message to start a new five-minute window.'],
  };
  const [title, explanation] = result.ok
    ? ['Verified · message unchanged', 'The signature matches, the receiver is correct, and the message is still valid. Its one-time ID is now used. Send it again to see replay protection.']
    : explanations[result.reason] ?? ['Verification failed', 'Sign a fresh message to start again.'];
  setStatus(title, explanation, result.ok ? 'success' : 'rejected');
}

for (const button of buttons) button.addEventListener('click', async () => {
  buttons.forEach(button => { button.disabled = true; });
  try {
    const action = button.dataset.demo;
    if (action === 'reset') {
      payload.value = payload.defaultValue;
      audience.value = audience.defaultValue;
      trust.checked = true;
    }
    if (action === 'sign' || action === 'reset') {
      await signMessage();
      return;
    }
    if (action === 'tamper') {
      audience.value = envelope.aud;
      payload.value = JSON.stringify({ original: envelope.payload, changed: true }, null, 2);
    } else if (action === 'recipient' || action === 'replay') {
      payload.value = JSON.stringify(envelope.payload, null, 2);
      audience.value = action === 'recipient' ? `${envelope.aud}-other` : envelope.aud;
    }
    if (!audience.value.trim()) throw new Error('Enter a receiver ID, such as bob-inbox.');
    const message = { ...envelope, payload: JSON.parse(payload.value) };
    render(message, await demo.verify(message, audience.value));
  } catch (error) {
    result = undefined;
    setStatus('Check your input', error instanceof SyntaxError ? 'The message must be valid JSON. Fix it, or click “Reset example” to start again.' : error.message, 'rejected');
  } finally {
    enableButtons();
    proof.focus();
  }
});

for (const input of [payload, audience]) input.addEventListener('input', () => {
  if (!envelope) return;
  result = undefined;
  verifyButton.textContent = 'Verify edits';
  setStatus('Edited · not verified', 'Your edits do not create a new signature. Verify them against the existing signature, or sign a fresh message.');
  try {
    showEnvelope({ ...envelope, payload: JSON.parse(payload.value) }, `Current payload with the original signature. Receiver to check: “${audience.value}”; signed recipient: “${envelope.aud}”.`);
  } catch {
    envelopeView.textContent = 'The edited message is not valid JSON. Fix it or reset the example to see the envelope.';
    envelopeNote.textContent = 'The original signature is kept. No verification has run for these edits.';
  }
});
trust.addEventListener('change', showTrust);

try {
  demo = createDemo();
  await signMessage();
  enableButtons();
} catch {
  setStatus('Demo unavailable', 'The example could not be signed. Reload in a browser with secure random generation, using localhost or HTTPS.', 'rejected');
}
