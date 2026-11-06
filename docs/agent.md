# Build with Marque — core v2.0.0

Install core v2 with `npm install @jackmorgan/marque`. Node.js 18+, ESM. The only runtime exports are `sign` and `verify`.

## API

- `await sign(payload, { privateKey, aud, ttl? })` returns a v2 `Signed` envelope. Supply plain JSON, a dedicated `0x`-prefixed 32-byte secp256k1 key, and a nonempty recipient ID. Lifetime is 1–300 seconds, default 300. Invalid input throws.
- `await verify(message, { aud, consumeNonce, now? })` returns `{ ok: true, signer }` or `{ ok: false, reason }`. Use the receiver’s configured audience, never an incoming value. Leave `now` unset outside tests; it is Unix seconds.
- `consumeNonce(key, expiresAt)` must atomically retain a new key until its Unix-seconds expiry, shared across all receivers and restarts. Return exactly `true` once, `false` for repeats; throw on storage errors. Verification returns `nonce store failed` on errors or non-boolean results.
- Types: `Hex`, `Address`, `Signed`, `VerifyFailure`, `VerifyResult`. Failure reasons: `invalid verification context`, `malformed envelope`, `bad version`, `wrong audience`, `expired`, `clock skew`, `signer mismatch`, `replay`, `nonce store failed`, `verification failed`.

## Application responsibilities

Keep keys outside prompts, logs and public bundles. Enroll public addresses through a trusted channel; compare lowercase addresses. A signature proves control of a key, not identity, permission or safe content. Never enroll an incoming sender automatically.

Limit request size and JSON depth before verification. After verification, check the address allowlist, action permissions and payload schema. Deliver the complete envelope over secure transport. No domain setup, identity service or blockchain is required.

Verification consumes a nonce before your handler runs. Use a signed operation ID and durable application idempotency for retries. A fresh signature is not proof that an operation is new. Reject on storage failure; never fall back to accepting messages or an in-memory cache.

The runnable Redis recipe is `examples/redis-receiver.mjs`; setup is in `docs/integration.md`. Keep Redis records until expiry, including through restarts, eviction pressure and failover. Use `examples/keygen.mjs` for local key setup. These are examples, not additional core APIs.

## Check your integration

Run `npm ci` and `npm run check` in the Marque checkout. With Redis running, set `REDIS_URL` and run `npm run test:redis`. Test valid messages, tampering, unknown senders, wrong audience, expiry, unavailable storage, concurrent replay and receiver restarts. Exactly one verification of an envelope may succeed. Never claim production readiness based only on the browser demo.

## Complete local example

Run `npm run example` in this checkout. The complete source is [examples/round-trip.mjs](../examples/round-trip.mjs); with Marque installed, save it as `quickstart.mjs` and run `node quickstart.mjs`. Its key and replay cache are deliberately temporary. The website's copy button includes the full file.
