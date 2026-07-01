# Marque

[![CI](https://github.com/jackmorganxyz/marque/actions/workflows/ci.yml/badge.svg)](https://github.com/jackmorganxyz/marque/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/marque)](https://www.npmjs.com/package/marque)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Let one AI agent **sign** an outbound message with its own secp256k1 wallet key, and let a receiving agent **verify** which entity (which https origin) sent it — **with no shared secret**.

Trust is anchored in infrastructure the verifier already trusts: the sender publishes its wallet address at a static file on its *own* origin — `https://<origin>/.well-known/marque.json`, served over TLS — and the verifier reads the key straight from there. `verify()` returns an origin-level identity string like `https:eve.example.com`.

- **No blockchain, no contracts, no RPC, no gas.** The wallet is a standard Ethereum key, used purely as an identity anchor. Marque never touches a chain.
- **No billing, no API keys.** The only secret an agent holds is its own signing private key.
- **No server, no registry, no third-party attestor.** The sender's own origin (TLS) *is* the registry; `verify()` runs inline in the receiver's inbound handler.
- **Two tiny audited deps.** `@noble/curves` + `@noble/hashes` — the primitives viem and ethers themselves build on. Signatures are byte-identical standard EIP-191, so any Ethereum tooling can verify them.

```
npm i marque
```

See the whole protocol run locally — sign, verify, then watch tampering, replay, mis-forwarding, and impersonation get rejected (no network, nothing deployed):

```
npx marque demo
```

---

## Quick start

```ts
import { sign, verify } from "marque";

// Sender (Eve @ eve.example.com) → Bob:
const envelope = await sign(
  { task: "summarize", url: "https://x.com/thread/1" },
  { privateKey: process.env.MARQUE_PRIVATE_KEY as `0x${string}`,
    origin: "eve.example.com", aud: "bob.example.com" },
);
await fetch("https://bob.example.com/api/inbox", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify(envelope),
});

// Receiver (Bob @ bob.example.com):
const seen = new Map<string, number>();  // replay guard — per-process; use a shared store in prod
const r = await verify(envelope, { selfOrigin: "bob.example.com", seen });
// r == { ok: true, identity: "https:eve.example.com", signer: "0x…" }
if (r.ok && myAllowlist.has(r.identity)) act(envelope.payload, r.identity);
```

`identity` is a namespaced label, not a URL — `https:` (no slashes) marks it as TLS-anchored, so future lower-assurance backends (`dns:…`, `x:…`) can never collide with it in an allowlist. `verify` returns a discriminated union: inside `if (r.ok)`, TypeScript knows `identity` and `signer` are present.

### Setup (once, by the sender's operator)

```bash
npx marque init eve.example.com
```

Prints `MARQUE_PRIVATE_KEY` (secret — never commit), `MARQUE_ADDRESS`, `MARQUE_ORIGIN`, and the well-known JSON. Store the private key in env; publish the address at `https://eve.example.com/.well-known/marque.json`:

```json
{ "v": 1, "keys": ["0x8ba1f109551bD432803012645Ac136ddd64DBA72"] }
```

`keys` is an array. **Rotation** = publish the new address alongside the old, then remove the old. **Revocation** = remove the entry (propagation lag = the verifier's cache TTL). `verify` accepts iff the recovered signer is in `keys[]` (checksum-insensitive). Multiple agents on one origin: list every address in the one file.

---

## API

| export | signature | notes |
|---|---|---|
| `generateAgent(origin)` | `→ { privateKey, address, origin, wellKnown }` | new keypair + ready-to-serve well-known object. |
| `sign(payload, opts)` | `opts: { privateKey, origin, aud, ttl? }` → `Promise<Signed>` | signs a domain-separated, audience-bound envelope; `ttl` (seconds) defaults to — and is capped at — 300, since `verify`'s clock-skew check bounds freshness at 300s regardless. |
| `verify(msg, ctx)` | `ctx: { selfOrigin, seen?, resolveKeys?, now? }` → `Promise<VerifyResult>` | runs all local checks, then resolves keys from the origin. **Total function** — always resolves to `{ ok, reason }` and never throws on hostile input; act only on `{ ok: true }`. |
| `httpsResolver` | `ResolveKeys` | default resolver: HTTPS `.well-known` only, with SSRF guard. |
| `cached(resolver, ttlMs?)` | `→ ResolveKeys` | wraps a resolver with a short (default 60s) verify-side cache. |
| `ResolveKeys` | `(origin: string) => Promise<Address[]>` | swap this to back identity with DNS / on-chain / X-bio. |
| `payloadHash(p)`, `canon(v)` | `→ Hex`, `→ string` | the exact hash/canonical form Marque signs — for interop implementations and tests. |

For **offline unit tests**, pass `resolveKeys: async () => [expectedAddress]` — no network.

### The envelope

```json
{
  "v": 1,
  "origin": "eve.example.com",
  "signer": "0x8ba1f109551bD432803012645Ac136ddd64DBA72",
  "agent_id": "0x8ba1f109551bD432803012645Ac136ddd64DBA72",
  "scope": "",
  "aud": "bob.example.com",
  "ts": 1751371200,
  "exp": 1751371500,
  "nonce": "0x9f3c1a7be44d0521c0a8f2e6",
  "payload_hash": "0x4721dc6f…",
  "sig": "0xf1d2c3b4…1c",
  "payload": { "task": "summarize", "url": "https://x.com/thread/1" }
}
```

The signature is **EIP-191 `personal_sign`** over a **domain-separated** string:

```
signingString = "marque/v1\n" + canon(core)
```

where `core` is every envelope field except `sig` and `payload` (`payload` is bound via `payload_hash`). `canon` is deterministic sorted-key compact JSON. The `marque/v1` prefix stops any generic wallet-connect / SIWE / faucet prompt from being steered into producing a valid Marque envelope; `aud` inside the signed core stops a captured envelope from being replayed to a different receiver.

`verify` checks, in order: version → `aud == selfOrigin` → not expired → clock skew ≤ 300s → nonce not replayed → `payload_hash` rebind → signature recovers to `signer` → `agent_id == signer` → `signer ∈ keys(origin)`.

### `agent_id` / `scope` are reserved

Currently `agent_id == signer` and `scope == ""`. Both slots are reserved for a future owner/runtime-key delegation + least-privilege model, so adding it needs no schema change.

---

## Identity resolution

| backend | assurance | shipped in `verify`? |
|---|---|---|
| **HTTPS `.well-known`** (`https://<origin>/.well-known/marque.json`) | **primary** — TLS-authenticated | ✅ default (`httpsResolver`) |
| **DNS TXT** (`_marque.<origin>` = `v=1; addr=0x…`) | lower — no DNSSEC assumed | ❌ injectable only (see below) |
| **X bio** (paste `0x…` into bio) | lowest — manual scrape | ❌ injectable only |

**There is no automatic fallback.** An HTTPS failure yields `keys = []` and `verify` fails — it must *never* silently downgrade to unauthenticated DNS. DNS / X are only reached if you explicitly inject a resolver:

```ts
// Example DNS resolver (opt-in, explicitly weaker). Anchor the address to addr=.
const dnsResolver: ResolveKeys = async (origin) => {
  const txt = await resolveTxt(`_marque.${origin}`);            // your DNS lib
  const m = txt.join("").match(/(?:^|;)\s*addr=(0x[0-9a-fA-F]{40})\b/);
  return m ? [m[1] as `0x${string}`] : [];
};
await verify(msg, { selfOrigin, resolveKeys: dnsResolver });
```

---

## Inbound middleware + well-known route

**Middleware** (framework-agnostic Next.js / Vercel / Express-style):

```ts
import { verify } from "marque";
const seen = new Map<string, number>();   // ⚠ per-process; supply a shared store in prod (see warnings)
export const withMarque = (selfOrigin: string, handler: any) => async (req: any, res: any) => {
  const result = await verify(req.body, { selfOrigin, seen });
  if (!result.ok) return res.status(401).json({ error: "marque: " + result.reason });
  req.marque = result;                     // { identity, signer }
  return handler(req, res);
};
```

**Well-known route** (Next.js App Router — the address, never the private key; full version in [`examples/app/.well-known/marque.json/route.ts`](examples/app/.well-known/marque.json/route.ts)):

```ts
// app/.well-known/marque.json/route.ts
// MARQUE_ADDRESS may hold several comma-separated addresses (rotation overlap).
// force-dynamic: read per request, so an env change needs no rebuild.
export const dynamic = "force-dynamic";
export function GET() {
  const keys = (process.env.MARQUE_ADDRESS ?? "").split(",").map(s => s.trim()).filter(Boolean);
  return Response.json({ v: 1, keys }, { headers: { "cache-control": "public, max-age=300" } });
}
```

Serve it from a route not subject to shared/edge cache-key confusion; short `max-age` bounds revocation latency. For a static host, drop a literal `public/.well-known/marque.json` instead.

---

## Drop-in for a Vercel `eve` agent

Marque's core does not depend on `eve` — these four files are the whole adapter, and they are all the agent author writes. Targets Vercel's [`eve`](https://vercel.com/eve) framework (agent + Next.js share one origin via `withEve()`).

**Env vars** (`.env.local` + `vercel env add <NAME> production`):

| var | secret? | value | used by |
|---|---|---|---|
| `MARQUE_PRIVATE_KEY` | **yes** | `0x…` signing key | signing outbound |
| `MARQUE_ADDRESS` | no | the key's `0x…` address (comma-separate several to overlap during rotation) | the well-known route |
| `MARQUE_ORIGIN` | no | this agent's origin, e.g. `eve.example.com` | `origin` when signing, `selfOrigin` when verifying |

**1 — Bootstrap the key.** `npx marque init eve.example.com` prints all three env vars + the well-known JSON. Never commit `MARQUE_PRIVATE_KEY`.

**2 — Publish identity.** Use the well-known route above (it reads `MARQUE_ADDRESS`).

**3 — Sign outbound** — `agent/tools/send-signed-message.ts` (filename = tool name):

```ts
import { defineTool } from "eve/tools";
import { z } from "zod";
import { sign } from "marque";

export default defineTool({
  description: "Send a message to another agent, signed so they can verify it came from us.",
  inputSchema: z.object({
    url: z.string().url(),   // recipient's inbox endpoint
    toOrigin: z.string(),    // recipient's origin, e.g. bob.example.com
    payload: z.any(),        // the message
  }),
  async execute({ url, toOrigin, payload }) {
    const signed = await sign(payload, {
      privateKey: process.env.MARQUE_PRIVATE_KEY as `0x${string}`,
      origin: process.env.MARQUE_ORIGIN!,   // us
      aud: toOrigin,                        // them — audience binding
    });
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(signed),
    });
    return { delivered: res.ok, status: res.status };
  },
});
```

**4 — Verify inbound** — `app/api/inbox/route.ts` (rejects forgeries before the agent sees them):

```ts
import { verify } from "marque";

// ⚠ serverless = per-invocation memory. Use a SHARED nonce store (Vercel KV / Upstash)
// in production, or accept 300s same-audience replay (see warnings).
const seen = new Map<string, number>();

export async function POST(req: Request) {
  const msg = await req.json();
  const r = await verify(msg, { selfOrigin: process.env.MARQUE_ORIGIN!, seen });
  if (!r.ok) return Response.json({ error: "marque: " + r.reason }, { status: 401 });
  // r.identity is e.g. "https:bob.example.com" — check YOUR allowlist before acting,
  // then hand msg.payload + r.identity to the agent (enqueue an eve run, etc.).
  return Response.json({ ok: true, from: r.identity });
}
```

**Optional** — if a signed envelope arrives as data the model handles, expose verification as a tool too, `agent/tools/verify-message.ts`:

```ts
import { defineTool } from "eve/tools";
import { z } from "zod";
import { verify } from "marque";
const seen = new Map<string, number>();
export default defineTool({
  description: "Verify a signed message and return which agent it came from.",
  inputSchema: z.object({ message: z.any() }),
  async execute({ message }) {
    const r = await verify(message, { selfOrigin: process.env.MARQUE_ORIGIN!, seen });
    return r.ok ? { verified: true, from: r.identity } : { verified: false, reason: r.reason };
  },
});
```

---

## ⚠ Security — read before shipping

The trust anchor is the sender's TLS-protected control of `https://<origin>`. There is no global registry; identity is only as strong as that control. This is weaker than an on-chain registry (not globally revocable, not tamper-evident) but dependency-free — every warning below follows from that choice.

1. **DOMAIN SEPARATION / DEDICATED KEY.** The signing key is a real secp256k1 wallet. **Never reuse it** for any other `personal_sign` flow (Sign-In-With-Ethereum, wallet-connect, faucets). Use a dedicated key. (The `marque/v1` prefix defends this, but a dedicated key is still required hygiene.)
2. **AUDIENCE / REPLAY.** Messages are bound to one recipient via `aud`. In multi-instance / serverless deployments the in-memory nonce set is per-process — **supply a shared nonce store** (Redis / Vercel KV) in production, or accept replay within the 300s window to the *same* audience.
3. **IDENTITY MEANING.** `verify()` proves the sender **controls `https://<origin>` at fetch time** — NOT that `<origin>` is an entity you intend to trust. **Compare the returned identity against your own allowlist** before acting. The identity is returned lowercased with any trailing dot stripped, but percent/IDN normalization and punycode / homograph lookalikes are still yours to defend against.
4. **ORIGIN CONTROL IS THE ROOT OF TRUST.** Identity is only as strong as your continuous, exclusive control of the exact origin host and its TLS/DNS. A dangling subdomain / abandoned Vercel/Netlify/S3/Pages tenant / expired domain hands your identity to whoever claims it. Prefer operator-controlled apex/custom domains; remove dangling DNS.
5. **NO REVOCATION GUARANTEE.** If your key leaks, attackers impersonate you until you rotate (`keys[]` add-then-remove; lag = verifier cache TTL). No global CRL. **Never commit the private key**; keep it out of logs and builds.
6. **HTTPS ONLY, NO DNS DOWNGRADE.** Key resolution is https-only and must not silently fall back to unauthenticated DNS. DNS, if used, is explicitly lower-assurance.
7. **SSRF / DoS ON VERIFY.** `origin` is attacker-controlled and fetched on every inbound message; the built-in guard (URL-normalized public-host check that rejects every IP literal — including shorthand/octal/hex forms like `127.1` — plus userinfo, 3s timeout, 64KB cap, no redirect follow) must not be removed. DNS-rebinding to a private address remains an accepted residual (see below).
8. **PAYLOAD CANONICALIZATION.** Restrict payloads to JSON-safe primitives: no floats, no integers `> 2^53`, no `NaN`/`Infinity`, no duplicate keys, NFC-normalized strings. `sign` rejects the dangerous subset (non-finite numbers, oversized integers); the rest is your responsibility.
9. **CALLER CONTRACT.** Act only on `{ ok: true }`; trust no field before that.

### Residual risks (accepted in the registry-free model)

- **Stolen key / no revocation** (mitigated by short cache TTL + rotation).
- **TLS / CA compromise or MITM on the key fetch** (https-only, no redirect follow, timeout).
- **Subdomain takeover / dangling origin** — especially `*.vercel.app`; prefer operator-controlled domains.
- **CDN / edge cache poisoning of your own well-known** — serve it with no unkeyed variance and a short `max-age`.

---

## Non-goals / future extensions

**Out of scope by design:** no blockchain / contracts / on-chain delegation / RPC; no billing / API keys / Marque-run server; no owner/runtime key split (single key signs everything — `agent_id`/`scope` reserved); no human/platform identity (`x:@eve`, `github:eve`); no global revocation / CRL; no shipped shared nonce store (injectable interface only); no full RFC 8785 canonicalizer; no DNS / X resolver wired into `verify` by default.

**Backward-compatible extension points** (the canonical field set is preserved, so these are localized changes, not data migrations):

- **Owner/runtime key split** — set `agent_id` (owner) ≠ `signer` (short-lived runtime key); lift `verify`'s `agent_id == signer` guard and add a delegation lookup.
- **Scope** — populate `scope` and enforce least-privilege per key.
- **Signatures** — swap the `marque/v1` prefix for EIP-712 typed-data bound to a neutral domain (`{ name: "Marque", version: "1" }`) or a real contract domain.
- **Identity** — point `resolveKeys` at an on-chain registry or a richer identity backend; the local crypto checks are unchanged.

---

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # node --import tsx --test marque.test.ts
npm run build       # emits dist/
```

CI runs typecheck + tests on every push and PR. Found a security issue? See [SECURITY.md](SECURITY.md).

[MIT](LICENSE) © [Jack Morgan](https://jackmorgan.xyz)
