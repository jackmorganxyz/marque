import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { sign, verify } from '../marque.ts';

export function createDemo() {
  const privateKey = `0x${bytesToHex(secp256k1.utils.randomPrivateKey())}`;
  // shortcut: browser-local replay storage, use shared durable storage in deployed receivers.
  const seen = new Map();
  return {
    sign: (payload, aud) => sign(payload, { privateKey, aud }),
    verify: (message, aud) => verify(message, {
      aud,
      consumeNonce: (key, expiresAt) => {
        const now = Math.floor(Date.now() / 1000);
        for (const [key, expiry] of seen) if (expiry <= now) seen.delete(key);
        if (seen.has(key)) return false;
        seen.set(key, expiresAt);
        return true;
      },
    }),
  };
}
