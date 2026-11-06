import { createClient } from 'redis';
import { verify } from '@jackmorgan/marque';

const { REDIS_URL, MARQUE_AUDIENCE, TRUSTED_ADDRESSES } = process.env;
const addresses = TRUSTED_ADDRESSES?.split(',').map(address => address.trim().toLowerCase());
if (!REDIS_URL || !MARQUE_AUDIENCE || !addresses?.length ||
    addresses.some(address => !/^0x[0-9a-f]{40}$/.test(address))) {
  throw new Error('Set REDIS_URL, MARQUE_AUDIENCE and comma-separated TRUSTED_ADDRESSES');
}
const trustedAddresses = new Set(addresses);
let redis;

async function readMessage() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 16384) throw new Error('message too large');
    chunks.push(chunk);
  }
  const message = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  function checkDepth(value, remaining) {
    if (remaining < 0) throw new Error('message too deep');
    if (value && typeof value === 'object')
      for (const child of Object.values(value)) checkDepth(child, remaining - 1);
  }
  checkDepth(message, 32);
  return message;
}

try {
  const message = await readMessage();
  try {
    redis = createClient({
      url: REDIS_URL, disableOfflineQueue: true,
      socket: { connectTimeout: 3000, reconnectStrategy: false },
    });
    // Required by node-redis; promise failures below reject without logging connection secrets.
    redis.on('error', () => {});
    await redis.connect();
  } catch { throw new Error('nonce store failed'); }
  const result = await verify(message, {
    aud: MARQUE_AUDIENCE,
    consumeNonce: async (key, expiresAt) => {
      const reply = await redis.withCommandOptions({ abortSignal: AbortSignal.timeout(3000) }).set(
        `marque:nonce:${key}`, '1', { condition: 'NX', expiration: { type: 'EXAT', value: expiresAt } },
      );
      if (reply !== 'OK' && reply !== null) throw new Error('unexpected nonce store response');
      return reply === 'OK';
    },
  });
  if (!result.ok) throw new Error(result.reason);
  if (!trustedAddresses.has(result.signer.toLowerCase())) throw new Error('untrusted sender');
  const payload = message.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
      Object.keys(payload).length !== 3 ||
      typeof payload.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(payload.id) ||
      payload.task !== 'summarize' || typeof payload.text !== 'string' ||
      payload.text.length < 1 || payload.text.length > 2000) throw new Error('invalid payload');
  // Dispatch here only after persisting operation status by signer + payload.id for idempotent retries.
  process.stdout.write(JSON.stringify({ signer: result.signer, payload }) + '\n');
} catch (error) {
  console.error('Rejected:', error instanceof SyntaxError ? 'invalid JSON' : error.message);
  process.exitCode = 1;
} finally {
  if (redis?.isOpen) redis.destroy();
}
