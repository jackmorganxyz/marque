import {
  privateKeyToAddress, signMessage, recoverMessageAddress,
  isAddressEqual, randomHex, type Hex, type Address,
} from './eth.js';

export type { Hex, Address };

const WINDOW = 300;
const DOMAIN = 'marque/v2\n';

export interface Signed {
  v: 2;
  signer: Address;
  aud: string;
  ts: number;
  exp: number;
  nonce: Hex;
  payload: unknown;
  sig: Hex;
}

export type VerifyFailure =
  | 'invalid verification context' | 'malformed envelope' | 'bad version'
  | 'wrong audience' | 'expired' | 'clock skew' | 'signer mismatch'
  | 'replay' | 'nonce store failed' | 'verification failed';

export type VerifyResult =
  | { ok: true; signer: Address; reason?: undefined }
  | { ok: false; reason: VerifyFailure; signer?: undefined };

// Sorted-key JSON; reject values that change or disappear during JSON transport.
function canon(v: any): string {
  const t = typeof v;
  if (v === null || t === 'string' || t === 'boolean') return JSON.stringify(v);
  if (t === 'number' && Number.isFinite(v) && (!Number.isInteger(v) || Number.isSafeInteger(v)))
    return JSON.stringify(v);
  if (t === 'object' && typeof v.toJSON !== 'function') {
    // Array.from visits holes so sparse arrays cannot silently turn into nulls.
    if (Array.isArray(v)) return '[' + Array.from(v, x => canon(x)).join(',') + ']';
    if (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null)
      return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  throw new Error('marque: value not JSON-safe');
}

export async function sign(
  payload: unknown,
  opts: { privateKey: Hex; aud: string; ttl?: number },
): Promise<Signed> {
  const ttl = opts.ttl ?? WINDOW;
  if (typeof opts.aud !== 'string' || !opts.aud.length)
    throw new Error('marque: audience required');
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > WINDOW)
    throw new Error('marque: ttl must be an integer from 1 to 300 seconds');
  const ts = Math.floor(Date.now() / 1000);
  const message = {
    v: 2 as const, signer: privateKeyToAddress(opts.privateKey), aud: opts.aud,
    ts, exp: ts + ttl, nonce: randomHex(12), payload,
  };
  return { ...message, sig: signMessage(DOMAIN + canon(message), opts.privateKey) };
}

export async function verify(
  msg: unknown,
  ctx: {
    aud: string;
    // Atomically record key until expiresAt (Unix seconds); true only for the first use.
    consumeNonce: (key: string, expiresAt: number) => boolean | Promise<boolean>;
    now?: number;
  },
): Promise<VerifyResult> {
  try {
    const now = ctx.now ?? Math.floor(Date.now() / 1000);
    if (typeof ctx.aud !== 'string' || !ctx.aud.length ||
        typeof ctx.consumeNonce !== 'function' || !Number.isSafeInteger(now))
      return { ok: false, reason: 'invalid verification context' };
    if (!msg || typeof msg !== 'object' || Array.isArray(msg))
      return { ok: false, reason: 'malformed envelope' };
    const { sig, ...message } = msg as Signed;
    if (message.v !== 2) return { ok: false, reason: 'bad version' };
    if (Object.keys(message).length !== 7 || !Object.hasOwn(message, 'payload') ||
        typeof message.aud !== 'string' || !message.aud.length ||
        typeof message.signer !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(message.signer) ||
        typeof message.nonce !== 'string' || !/^0x[0-9a-fA-F]{24}$/.test(message.nonce) ||
        typeof sig !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(sig) ||
        !Number.isSafeInteger(message.ts) || message.ts < 0 ||
        !Number.isSafeInteger(message.exp) || message.exp <= message.ts || message.exp - message.ts > WINDOW)
      return { ok: false, reason: 'malformed envelope' };
    if (message.aud !== ctx.aud) return { ok: false, reason: 'wrong audience' };
    if (message.exp <= now) return { ok: false, reason: 'expired' };
    if (Math.abs(now - message.ts) > WINDOW) return { ok: false, reason: 'clock skew' };

    const signer = recoverMessageAddress(DOMAIN + canon(message), sig);
    if (!isAddressEqual(signer, message.signer)) return { ok: false, reason: 'signer mismatch' };

    // Only authenticated messages reach storage; separate senders cannot burn each other's nonces.
    const key = JSON.stringify([message.aud, signer.toLowerCase(), message.nonce.toLowerCase()]);
    let consumed: unknown;
    try {
      consumed = await ctx.consumeNonce(key, message.exp);
    } catch {
      return { ok: false, reason: 'nonce store failed' };
    }
    if (typeof consumed !== 'boolean') return { ok: false, reason: 'nonce store failed' };
    if (!consumed) return { ok: false, reason: 'replay' };
    return { ok: true, signer };
  } catch {
    // Malformed input fails closed without exposing parser or crypto internals.
    return { ok: false, reason: 'verification failed' };
  }
}
