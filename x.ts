// x.ts — optional X (Twitter) handle verification for Marque. Zero new deps.
//
// Same trick as the core well-known: an owner-controlled public surface IS the
// registry. The agent key signs a statement binding itself to an X handle; that
// signature is posted as a tweet (only the handle's owner can do that); the
// sender advertises the tweet next to its keys in marque.json. A receiver
// re-verifies both directions — tweet authorship proves the handle vouches for
// the key, the signature proves the key consented to the handle — with one
// keyless fetch to X's public oEmbed endpoint. No X API key, no smart contract,
// no attestor, and nothing here runs unless the receiver opts in: the core
// verify() path never touches this module.
//
// This is an ADDITIONAL factor on top of the TLS identity, not a replacement:
// handles are mutable and recyclable, and X account compromise transfers the
// handle (not the key). Treat `x:@handle` as lower assurance than `https:origin`.
import {
  privateKeyToAddress, signMessage, recoverMessageAddress, isAddressEqual,
  type Hex, type Address,
} from './eth.js';
import { assertPublicHost } from './marque.js';

const X_DOMAIN = 'marque/x-proof/v1\n';                 // domain separator, like core's marque/v1
const OEMBED = 'https://publish.twitter.com/oembed';    // official, keyless, host is pinned here

// X handles: 1–15 chars of [A-Za-z0-9_]; case-insensitive, so normalize to lowercase.
function normHandle(h: unknown): string {
  const s = String(h ?? '').replace(/^@/, '').toLowerCase();
  if (!/^[a-z0-9_]{1,15}$/.test(s)) throw new Error('marque: bad x handle');
  return s;
}

/** The exact statement the agent key signs to claim a handle. Exported so interop
 *  implementations and tests can reproduce proofs byte-for-byte (like payloadHash). */
export const xProofStatement = (handle: string, address: Address): string =>
  `${X_DOMAIN}x:@${normHandle(handle)}\n${address.toLowerCase()}`;

/** Sender side, once: build the proof tweet and the marque.json `x` entry.
 *  Post `tweet` from the handle, then publish `x` (with the real tweet URL) in
 *  the same well-known file that already serves `keys`. */
export function linkX(handle: string, privateKey: Hex) {
  const h = normHandle(handle);
  const address = privateKeyToAddress(privateKey);
  const sig = signMessage(xProofStatement(h, address), privateKey);
  return {
    handle: h, address,
    tweet: `Verifying my marque agent ${address} sig:${sig}`,
    x: { handle: h, proof: `https://x.com/${h}/status/<tweet-id>` },
  };
}

// Discriminated union, same shape contract as core VerifyResult.
export type XVerifyResult =
  | { ok: true; identity: string; handle: string; reason?: undefined }
  | { ok: false; reason: string; identity?: undefined; handle?: undefined };

// Bounded JSON fetch mirroring httpsResolver's guards: 3s timeout, no redirect
// follow, 64KB cap, null on any failure (fail closed).
async function boundedJson(url: string): Promise<any> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 3000);
  try {
    const r = await fetch(url, {
      redirect: 'error', signal: ac.signal, headers: { accept: 'application/json' },
    });
    if (!r.ok) return null;
    if (Number(r.headers.get('content-length')) > 64 * 1024) return null;
    return JSON.parse((await r.text()).slice(0, 64 * 1024));
  } catch { return null; }
  finally { clearTimeout(t); }
}

/**
 * Verify that `signer` (the address `verify()` returned) belongs to the X handle
 * advertised at https://<origin>/.well-known/marque.json. Run it AFTER a
 * successful verify(), per peer — not per message. Total like verify(): every
 * failure returns { ok: false }, never a throw.
 */
export async function verifyX(origin: string, signer: Address): Promise<XVerifyResult> {
  try { assertPublicHost(origin); } catch { return { ok: false, reason: 'bad origin' }; }
  // ponytail: refetches marque.json (the core resolver keeps only `keys`); wrap in a
  // cached()-style layer like marque.ts's defaultResolver if this ever runs hot.
  const wk = await boundedJson(`https://${origin}/.well-known/marque.json`);
  let handle: string;
  try { handle = normHandle(wk?.x?.handle); }
  catch { return { ok: false, reason: 'no x entry at origin' }; }
  let proof: URL;
  try { proof = new URL(String(wk?.x?.proof)); }
  catch { return { ok: false, reason: 'bad proof url' }; }
  // Only a tweet URL ever reaches oEmbed; the fetched host itself is pinned above.
  if (proof.protocol !== 'https:' || !/^(www\.)?(x|twitter)\.com$/.test(proof.hostname) ||
      !/^\/[A-Za-z0-9_]{1,15}\/status\/\d+$/.test(proof.pathname))
    return { ok: false, reason: 'bad proof url' };
  const o = await boundedJson(`${OEMBED}?url=${encodeURIComponent(proof.href)}&omit_script=1&dnt=1`);
  if (!o) return { ok: false, reason: 'proof fetch failed' };
  // author_url comes from X's TLS response, not from the sender — it is the
  // authorship truth no matter whose handle appears in the proof URL path.
  let author: string;
  try { author = normHandle(new URL(String(o.author_url)).pathname.slice(1)); }
  catch { return { ok: false, reason: 'proof fetch failed' }; }
  if (author !== handle) return { ok: false, reason: 'tweet author mismatch' };
  const m = /sig:(0x[0-9a-fA-F]{130})/.exec(String(o.html ?? ''));
  if (!m) return { ok: false, reason: 'no signature in tweet' };
  try {
    if (!isAddressEqual(recoverMessageAddress(xProofStatement(handle, signer), m[1]), signer))
      return { ok: false, reason: 'proof signer mismatch' };
  } catch { return { ok: false, reason: 'bad proof signature' }; }
  return { ok: true, identity: `x:@${handle}`, handle };
}
