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
import { assertPublicHost, boundedJson } from './net.js';

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
    tweet: `Verifying my marque agent ${address} sig:${sig}`,
    x: { handle: h, proof: `https://x.com/${h}/status/<tweet-id>` },
  };
}

// Discriminated union, same shape contract as core VerifyResult.
// The identity label is derivable as `x:@${handle}` — one field, no invariant.
export type XVerifyResult =
  | { ok: true; handle: string; reason?: undefined }
  | { ok: false; reason: string; handle?: undefined };

/**
 * Verify that `signer` (the address `verify()` returned) belongs to the X handle
 * advertised at https://<origin>/.well-known/marque.json. Run it AFTER a
 * successful verify(), per peer — not per message. Total like verify(): every
 * failure returns { ok: false }, never a throw.
 *
 * fetchJson is injectable like core's resolveKeys — for offline tests, or to
 * supply a cached layer (the default refetches marque.json, since the core
 * resolver keeps only `keys`).
 */
export async function verifyX(
  origin: string, signer: Address,
  opts: { fetchJson?: (url: string) => Promise<any> } = {},
): Promise<XVerifyResult> {
  const fetchJson = opts.fetchJson ?? boundedJson;
  try { assertPublicHost(origin); } catch { return { ok: false, reason: 'bad origin' }; }
  const wk = await fetchJson(`https://${origin}/.well-known/marque.json`);
  let handle: string;
  try { handle = normHandle(wk?.x?.handle); }
  catch { return { ok: false, reason: 'no x entry at origin' }; }
  let proof: URL;
  try { proof = new URL(String(wk?.x?.proof)); }
  catch { return { ok: false, reason: 'bad proof url' }; }
  // Only a tweet permalink ever reaches oEmbed; the fetched host itself is pinned
  // above. The path's handle segment is untrusted cosmetics (authorship truth is
  // oEmbed's author_url below), so don't re-encode handle grammar here.
  if (proof.protocol !== 'https:' || !/^(www\.)?(x|twitter)\.com$/.test(proof.hostname) ||
      !/^\/[^/]+\/status\/\d+$/.test(proof.pathname))
    return { ok: false, reason: 'bad proof url' };
  const o = await fetchJson(`${OEMBED}?url=${encodeURIComponent(proof.href)}&omit_script=1&dnt=1`);
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
  return { ok: true, handle };
}
