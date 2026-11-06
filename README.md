# Marque

Sign a JSON message. Verify which address signed it.

Marque proves key possession and message integrity. Your application decides who an address belongs to, whether it is trusted and what it may do. The core exports only `sign` and `verify`, with two runtime dependencies: `@noble/curves` and `@noble/hashes`.

## One-minute quickstart

In this checkout:

```sh
npm ci
npm run example
```

The complete [example](https://github.com/jackmorganxyz/marque/blob/main/examples/round-trip.mjs) creates an ephemeral key, verifies a message, then rejects tampering and replay. It never prints the private key.

```text
✓ Message verified from 0x…
✓ Tampered message rejected
✓ Replayed message rejected
```

## Install

Node.js 18+ and ESM. The package is `@jackmorganxyz/marque`; core v2 is prepared but not published yet. For now, install a local checkout:

```sh
npm install /absolute/path/to/marque
```

After release, install with `npm install @jackmorganxyz/marque`. The unscoped `marque` package is an unrelated project.

## Use

```ts
import { sign, verify } from '@jackmorganxyz/marque';

const message = await sign({ task: 'summarize', text: 'Hello' }, {
  privateKey,        // Dedicated secp256k1 key from your secret store.
  aud: 'bob-inbox',  // Recipient ID agreed by both applications.
});

// Deliver JSON.stringify(message) through your existing transport.
const result = await verify(message, { aud: 'bob-inbox', consumeNonce });
if (result.ok && trustedAddresses.has(result.signer.toLowerCase())) {
  // Apply your action permissions, then use message.payload.
}
```

`privateKey`, `consumeNonce` and `trustedAddresses` are supplied by your application. `consumeNonce(key, expiresAt)` must atomically record an unused key until its Unix-seconds expiry and return `true` only once; all receiver instances share that storage. It may return a promise. Storage errors fail verification. See the [integration guide](https://github.com/jackmorganxyz/marque/blob/main/docs/integration.md) for setup and failure handling.

For a receiver with key setup, allowlisting and shared replay storage, use the [Redis recipe](https://github.com/jackmorganxyz/marque/blob/main/docs/integration.md#run-the-redis-recipe).

## API

| Operation | Arguments | Result |
| --- | --- | --- |
| `sign(payload, { privateKey, aud, ttl? })` | Plain JSON, a `0x`-prefixed 32-byte secp256k1 key, recipient ID, lifetime of 1–300 seconds (default 300). | `Promise<Signed>`; throws on invalid input. |
| `verify(message, { aud, consumeNonce, now? })` | Untrusted message, expected recipient, atomic nonce callback, optional Unix-seconds clock override. | `Promise<{ ok: true, signer } \| { ok: false, reason }>`; fails closed. |

TypeScript exports: `Hex`, `Address`, `Signed`, `VerifyFailure`, `VerifyResult`. Narrow on `result.ok`; failure reasons are a typed union. `nonce store failed` means the callback threw or returned a non-boolean value; `replay` means it returned `false`. See the [failure guide](https://github.com/jackmorganxyz/marque/blob/main/docs/integration.md#handle-failures) for every reason and next step.

Returned addresses use EIP-55 checksum casing; compare them case-insensitively. `aud` is a non-empty, case-sensitive ID. Supply the receiver's configured ID rather than copying it from an incoming message.

## Message format

The v2 envelope has eight fields: `v`, `signer`, `aud`, `ts`, `exp`, `nonce`, `payload`, `sig`. A 12-byte random nonce identifies the message. The EIP-191 signature covers `"marque/v2\n"` plus the canonical JSON of every field except `sig`: recursively sorted object keys, compact JSON primitives and preserved array order. The payload is signed directly; extra envelope fields are rejected.

Verification checks structure, recipient, expiry, a five-minute lifetime and clock-skew window, the recovered signer, then nonce consumption. There are no built-in network requests. V1 envelopes and domain-based APIs are intentionally unsupported in v2.

## Security boundaries

- A signature does not prove a person's identity, approval or safe content. Apply your own address trust and action permissions.
- Keep dedicated keys outside prompts, logs and public bundles. Your application owns enrollment, rotation and revocation.
- Signatures do not encrypt messages. Use a secure transport.
- Use plain JSON. Unsupported values include `undefined`, bigint, functions, symbols, sparse arrays, custom objects, cycles, non-finite numbers and unsafe integers. Set input size/depth limits. This is not a full RFC 8785 canonicalizer.
- Replay protection depends on shared, durable, atomic storage and synchronized clocks. Verification consumes a nonce before returning success; use application idempotency for retries.

## Guides

- [Integrate with an agent or service](https://github.com/jackmorganxyz/marque/blob/main/docs/integration.md)
- [Instructions for coding agents](https://github.com/jackmorganxyz/marque/blob/main/docs/agent.md)
- [Developer page and browser playground](https://github.com/jackmorganxyz/marque/blob/main/site/README.md)
- [Use cases](https://github.com/jackmorganxyz/marque/blob/main/docs/USE_CASES.md)
- [Agent login](https://github.com/jackmorganxyz/marque/blob/main/docs/authentication.md)
- [Contribute and release](https://github.com/jackmorganxyz/marque/blob/main/CONTRIBUTING.md)

Runtime notes: [eve](https://github.com/jackmorganxyz/marque/blob/main/docs/eve.md), [Flue](https://github.com/jackmorganxyz/marque/blob/main/docs/flue.md), [OpenClaw](https://github.com/jackmorganxyz/marque/blob/main/docs/openclaw.md), and [managed agents](https://github.com/jackmorganxyz/marque/blob/main/docs/managed-agents.md). Each points to the same v2 integration contract and preserves a link to its v1 guide.

Run `npm run check` before contributing. See [SECURITY.md](SECURITY.md) to report vulnerabilities. [MIT](LICENSE).
