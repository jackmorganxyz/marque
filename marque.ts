// marque.ts — Marque core. Deps: @noble/curves + @noble/hashes (via eth.ts). Node 18+/Vercel.
//
// Sign an outbound agent message with a secp256k1 wallet key; verify which
// https origin sent it, with no shared secret. Trust is anchored in the
// sender's TLS control of https://<origin>/.well-known/marque.json.
//
// SECURITY: read the warnings in README.md before using. In particular:
//   - use a DEDICATED signing key (never reuse for SIWE / wallet-connect),
//   - supply a SHARED nonce store in multi-instance deployments,
//   - act ONLY on { ok: true } and check identity against your allowlist.
import {
  generatePrivateKey, privateKeyToAddress, signMessage, recoverMessageAddress,
  keccak256, isAddressEqual, randomHex, type Hex, type Address,
} from './eth.js';
import { isIP } from 'node:net';

export type { Hex, Address };

export const SKEW = 300;            // seconds — max clock-skew window
const DOMAIN = 'marque/v1\n';       // domain separator (red-team mitigation)

export interface Core {
  v: 1; origin: string; signer: Address; agent_id: Address; scope: string;
  aud: string; ts: number; exp: number; nonce: Hex; payload_hash: Hex;
}
export interface Signed extends Core { sig: Hex; payload: unknown; }

// Deterministic sorted-key compact JSON. NOT full RFC 8785: payloads
// must be JSON-safe primitives (see assertJsonSafe + README).
export function canon(v: any): string {
  // Refuse anything canon can't reproduce byte-for-byte against JSON.stringify on
  // the wire, so distinct values can't collide to one payload_hash:
  //   - undefined / NaN / ±Infinity → JSON emits "null" (collision),
  //   - function / symbol → JSON drops them (canon-vs-wire mismatch),
  //   - bigint → JSON.stringify throws,
  //   - anything with toJSON (Date, moment, …) serializes to its own keys here but
  //     to toJSON()'s output on the wire.
  const t = typeof v;
  if (v === undefined || t === 'function' || t === 'symbol' || t === 'bigint' ||
      (t === 'number' && !Number.isFinite(v)) ||
      (t === 'object' && v !== null && typeof v.toJSON === 'function'))
    throw new Error('marque: value not JSON-safe in canon');
  if (v === null || t !== 'object') return JSON.stringify(v);
  // Array.from visits holes as undefined (map/forEach skip them) → canon throws, no collision.
  if (Array.isArray(v)) return '[' + Array.from(v, (x) => canon(x)).join(',') + ']';
  return '{' + Object.keys(v).sort()
    .map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

// Reject payloads that canonicalize ambiguously across runtimes.
function assertJsonSafe(v: any): void {
  if (v === undefined) throw new Error('marque: undefined not JSON-safe');
  if (typeof v === 'number' &&
      (!Number.isFinite(v) || (Number.isInteger(v) && Math.abs(v) > Number.MAX_SAFE_INTEGER)))
    throw new Error('marque: unsafe number in payload');
  // iterate arrays by index so holes ([1,,3]) surface as undefined and are rejected
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) assertJsonSafe(v[i]); return; }
  if (v && typeof v === 'object') for (const k of Object.keys(v)) assertJsonSafe(v[k]);
}

// Hash of the UTF-8 BYTES of canon(p). Exported so interop implementations and
// tests can reproduce payload_hash without signing.
export const payloadHash = (p: unknown): Hex => keccak256(canon(p));
const core = (c: Core): string => DOMAIN + canon(c);

export function generateAgent(origin: string) {
  const privateKey = generatePrivateKey();
  const address = privateKeyToAddress(privateKey);
  return { privateKey, address, origin,
    wellKnown: { v: 1, keys: [address] } };   // serve at /.well-known/marque.json
}

export async function sign(
  payload: unknown,
  opts: { privateKey: Hex; origin: string; aud: string; ttl?: number },
): Promise<Signed> {
  assertJsonSafe(payload);
  const address = privateKeyToAddress(opts.privateKey);
  const now = Math.floor(Date.now() / 1000);
  const c: Core = {
    v: 1, origin: opts.origin, signer: address, agent_id: address,
    scope: '', aud: opts.aud, ts: now,
    // ttl is capped at SKEW: verify rejects |now - ts| > SKEW regardless, so a
    // longer exp would only pretend to extend freshness it can't deliver.
    exp: now + Math.min(opts.ttl ?? SKEW, SKEW),
    nonce: randomHex(12), payload_hash: payloadHash(payload),
  };
  return { ...c, sig: signMessage(core(c), opts.privateKey), payload }; // EIP-191
}

// ---- Identity resolution (injectable). Default: HTTPS .well-known only. ----

// SSRF guard (red-team must-fix): origin must be a public https hostname.
function assertPublicHost(origin: string): void {
  // no scheme/port/path/userinfo/query/fragment/whitespace (IPv6 has colons → also rejected here)
  if (origin === '' || /[:/\\@?#\s]/.test(origin)) throw new Error('marque: bad origin');
  let host: string;
  try { host = new URL('https://' + origin).hostname; }
  catch { throw new Error('marque: bad origin'); }
  // URL normalizes shorthand/octal/hex IPv4 (127.1 → 127.0.0.1); isIP rejects EVERY
  // IP literal form — a strict dotted-quad regex would miss the short forms.
  if (isIP(host)) throw new Error('marque: ip origin not allowed');
  const h = host.replace(/\.$/, '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') ||
      h.endsWith('.local') || !h.includes('.'))
    throw new Error('marque: non-public origin');
}

export type ResolveKeys = (origin: string) => Promise<Address[]>;

export const httpsResolver: ResolveKeys = async (origin) => {
  assertPublicHost(origin);
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 3000);          // timeout
  try {
    const r = await fetch(`https://${origin}/.well-known/marque.json`, {
      redirect: 'error',                                  // no cross-origin redirect follow
      signal: ac.signal,
      headers: { accept: 'application/json' },
    });
    if (!r.ok) return [];
    if (Number(r.headers.get('content-length')) > 64 * 1024) return [];  // reject honest-huge bodies
    const text = (await r.text()).slice(0, 64 * 1024);    // chunked/no-length bodies still bounded by the 3s timeout
    const j = JSON.parse(text);
    return Array.isArray(j?.keys) ? (j.keys as Address[]) : [];
  } catch { return []; }
  finally { clearTimeout(t); }
};

// Small verify-side cache to cut latency + liveness dependency on the sender's host.
export function cached(resolver: ResolveKeys, ttlMs = 60_000): ResolveKeys {
  const m = new Map<string, { at: number; keys: Address[] }>();
  return async (origin) => {
    const hit = m.get(origin);
    if (hit && Date.now() - hit.at < ttlMs) return hit.keys;
    const keys = await resolver(origin);
    if (keys.length) {                                         // don't cache empties
      if (m.size >= 1000) m.delete(m.keys().next().value!);    // bound memory: evict oldest
      m.set(origin, { at: Date.now(), keys });
    }
    return keys;
  };
}

// One shared cache for the default path — building it per verify() call (as
// `?? cached(httpsResolver)` did) meant the cache never actually hit.
const defaultResolver = cached(httpsResolver);

// ---- verify ----

// Discriminated union: `if (r.ok)` narrows to { identity, signer } with no undefined-checks.
// The never-set fields are declared `?: undefined` so `r.reason` also reads without narrowing.
export type VerifyResult =
  | { ok: true; identity: string; signer: Address; reason?: undefined }
  | { ok: false; reason: string; identity?: undefined; signer?: undefined };

export async function verify(
  msg: Signed,
  ctx: {
    selfOrigin: string;                 // this verifier's own origin — checked against aud
    seen?: Map<string, number>;         // nonce -> expiry epoch s (injectable shared store)
    resolveKeys?: ResolveKeys;          // default: cached(httpsResolver)
    now?: number;
  },
): Promise<VerifyResult> {
  const now = ctx.now ?? Math.floor(Date.now() / 1000);
  // msg is untrusted JSON at runtime (req.body / stdin) despite the Signed type.
  // Every path below must RETURN {ok:false}, never throw — a throw out of verify
  // is an unauthenticated DoS and breaks the "act only on {ok:true}" contract.
  if (!msg || typeof msg !== 'object') return { ok: false, reason: 'malformed envelope' };
  const { sig, payload, ...c } = msg;
  const seen = ctx.seen;
  const resolve = ctx.resolveKeys ?? defaultResolver;

  if (c.v !== 1) return { ok: false, reason: 'bad version' };
  if (typeof c.origin !== 'string' || typeof c.aud !== 'string' ||
      typeof c.signer !== 'string' || typeof c.agent_id !== 'string' ||
      typeof c.scope !== 'string' || typeof c.nonce !== 'string' ||
      typeof sig !== 'string' || !Number.isFinite(c.ts) || !Number.isFinite(c.exp))
    return { ok: false, reason: 'malformed envelope' };
  if (c.scope !== '') return { ok: false, reason: 'scope not supported' };   // reserved slot; must be empty in v1
  if (c.aud !== ctx.selfOrigin) return { ok: false, reason: 'wrong audience' };
  if (!(c.exp > now)) return { ok: false, reason: 'expired' };
  if (Math.abs(now - c.ts) > SKEW) return { ok: false, reason: 'clock skew' };
  if (seen) {
    for (const [k, t] of seen) if (t <= now) seen.delete(k);      // prune
    if (seen.has(c.nonce)) return { ok: false, reason: 'replay' };
  }
  let ph: Hex;
  try { ph = payloadHash(payload); }                        // canon throws on non-JSON-safe payload
  catch { return { ok: false, reason: 'unsafe payload' }; }
  if (ph !== c.payload_hash) return { ok: false, reason: 'payload mismatch' };

  let recovered: Address;
  try {
    recovered = recoverMessageAddress(core(c as Core), sig);
    if (!isAddressEqual(recovered, c.signer)) return { ok: false, reason: 'signer mismatch' };
    if (!isAddressEqual(c.agent_id, c.signer)) return { ok: false, reason: 'agent/signer split not supported' };
  } catch { return { ok: false, reason: 'bad signature' }; }  // malformed sig / signer / agent_id

  // Reserve the nonce now: authenticated, and synchronously before the resolve
  // await, so two concurrent copies of the same envelope can't both pass. Retain
  // to the message's OWN freshness horizon (ts + SKEW), not receipt time, else a
  // clock-skewed receiver prunes it while the envelope is still fresh.
  if (seen) {
    if (seen.has(c.nonce)) return { ok: false, reason: 'replay' };
    seen.set(c.nonce, c.ts + SKEW + 1);
  }
  let keys: Address[];
  try { keys = await resolve(c.origin); }                    // assertPublicHost throws on bad/internal origin
  catch { seen?.delete(c.nonce); return { ok: false, reason: 'origin resolve failed' }; }
  if (!keys.some(k => { try { return isAddressEqual(k, recovered); } catch { return false; } })) {
    seen?.delete(c.nonce);                                    // release so a real retry isn't burned
    return { ok: false, reason: 'key not published at origin' };
  }
  // Canonicalize the identity label (case-insensitive host, trailing dot = same host)
  // so an exact-string allowlist can't be split by casing. Percent/IDN normalization
  // + homograph checks remain the caller's job (README #3). The "https:" prefix (no
  // slashes — it's a label, not a URL) namespaces the assurance backend, so future
  // "dns:…" / "x:…" identities can't collide with TLS-anchored ones in an allowlist.
  return { ok: true, identity: `https:${c.origin.replace(/\.$/, '').toLowerCase()}`, signer: recovered };
}
