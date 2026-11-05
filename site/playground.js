import { createDemo } from './demo.mjs';

const payload = document.getElementById('demo-payload');
const audience = document.getElementById('demo-audience');
const trust = document.getElementById('demo-trust');
const proof = document.getElementById('demo-proof');
const policy = document.getElementById('demo-policy');
const detail = document.getElementById('demo-detail');
const envelopeView = document.getElementById('demo-envelope');
const buttons = [...document.querySelectorAll('[data-demo]')];
let demo, envelope, result, demoAddress;

function showTrust() {
  policy.textContent = !result?.ok ? 'Not evaluated'
    : trust.checked && result.signer === demoAddress ? 'Address allowed' : 'Address not allowed';
  policy.dataset.state = !result?.ok ? '' : trust.checked ? 'success' : 'rejected';
}

function render(message, verified) {
  result = verified;
  envelopeView.textContent = JSON.stringify(message, null, 2);
  proof.textContent = result.ok ? 'Verified' : `Rejected · ${result.reason}`;
  proof.dataset.state = result.ok ? 'success' : 'rejected';
  const explanations = {
    'signer mismatch': 'The message changed after signing. The signature no longer matches this address.',
    'wrong audience': 'The receiver’s configured ID does not match the signed recipient.',
    replay: 'This envelope was already verified. Sign a new message to get a fresh nonce.',
    expired: 'The five-minute lifetime ended. Sign a new message.',
  };
  detail.textContent = result.ok ? 'Signature, recipient, expiry, and one-time nonce checked. Application permissions still apply.'
    : explanations[result.reason] ?? 'Verification failed. Sign a new message to start again.';
  showTrust();
}

for (const button of buttons) button.addEventListener('click', async () => {
  buttons.forEach(button => { button.disabled = true; });
  try {
    if (!audience.value.length) throw new Error('Enter the receiver’s configured ID.');
    let message;
    if (button.dataset.demo === 'sign') {
      const value = JSON.parse(payload.value);
      envelope = await demo.sign(value, audience.value);
      demoAddress = envelope.signer;
      document.getElementById('demo-address').textContent = demoAddress;
      message = envelope;
    } else if (button.dataset.demo === 'tamper') {
      audience.value = envelope.aud;
      payload.value = JSON.stringify({ original: envelope.payload, changed: true }, null, 2);
      message = { ...envelope, payload: JSON.parse(payload.value) };
    } else if (button.dataset.demo === 'recipient') {
      payload.value = JSON.stringify(envelope.payload, null, 2);
      audience.value = `${envelope.aud}-other`;
      message = envelope;
    } else if (button.dataset.demo === 'replay') {
      payload.value = JSON.stringify(envelope.payload, null, 2);
      audience.value = envelope.aud;
      message = envelope;
    } else {
      message = { ...envelope, payload: JSON.parse(payload.value) };
    }
    render(message, await demo.verify(message, audience.value));
  } catch (error) {
    result = undefined;
    proof.textContent = 'Check your input';
    proof.dataset.state = 'rejected';
    detail.textContent = error instanceof SyntaxError ? 'Enter valid JSON, then try again.' : error.message;
    showTrust();
  } finally {
    buttons.forEach(button => { button.disabled = !envelope && button.dataset.demo !== 'sign'; });
  }
});

for (const input of [payload, audience]) input.addEventListener('input', () => {
  result = undefined;
  proof.textContent = 'Edits not verified';
  proof.dataset.state = '';
  detail.textContent = 'Verify your edits against the existing signature, or sign a fresh message.';
  showTrust();
});
trust.addEventListener('change', showTrust);

try {
  demo = createDemo();
  buttons.find(button => button.dataset.demo === 'sign').disabled = false;
  detail.textContent = 'Sign a message, then try changing it or verifying it twice.';
} catch {
  detail.textContent = 'This demo needs a browser with secure random generation. Try localhost or HTTPS.';
}
