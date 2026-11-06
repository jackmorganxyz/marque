# Integrate with an agent or service

Marque needs a signing key and an agreed recipient ID. Your application owns delivery, trusted addresses, permissions and replay storage. Start with the complete [round-trip example](../examples/round-trip.mjs); the recipe below adds a shared Redis store.

## Run the Redis recipe

From this checkout, with Redis 7+ running locally:

```sh
npm ci
node examples/keygen.mjs
set -a
. ./.env.local
set +a
export MARQUE_AUDIENCE=bob-inbox
export REDIS_URL=redis://127.0.0.1:6379
node examples/send.mjs | node examples/redis-receiver.mjs
```

[Key setup](../examples/keygen.mjs) creates `.env.local` with mode `0600`, refuses to overwrite it, and prints only the public address. Keep `.env*` out of Git. This local walkthrough enrolls the key it just created. In production, keep the private key in the sender's secret store; configure the receiver separately with approved public addresses. It never needs the private key.

The [sender](../examples/send.mjs) signs a `summarize` request with a unique operation ID. The [receiver](../examples/redis-receiver.mjs) reads JSON from stdin, enforces 16 KiB and depth-32 limits, verifies it, checks the address allowlist, and validates the action schema. It prints accepted work; connect your own handler after those checks. It allows only `summarize`, a UUID v4 operation ID and text of 1–2,000 characters.

For an existing project, install [Marque](../README.md#install) and `redis@5`, then copy the example files. Redis and the browser bundler are development dependencies of this repository, not Marque runtime dependencies.

| Variable | Used by | Value |
| --- | --- | --- |
| `MARQUE_PRIVATE_KEY` | Sender | Dedicated `0x`-prefixed 32-byte secp256k1 secret. |
| `MARQUE_AUDIENCE` | Both | Exact, case-sensitive recipient ID, set in configuration. |
| `TRUSTED_ADDRESSES` | Receiver | Comma-separated approved public addresses; normalized to lowercase. |
| `REDIS_URL` | Receiver | Shared Redis connection; use TLS and authentication for a remote store. |

## Keep trust in your application

Exchange public addresses through a channel you already trust. Never enroll an address from an incoming request just because its signature verifies. Apply action permissions and schema validation after verification. A signature proves control of a key, not identity, human approval or safe instructions.

Keep private keys outside prompts, logs and browser bundles. Put signing behind a trusted tool your agent can call. Rotate by enrolling the replacement public address and removing the old one. Deliver the complete envelope over secure transport; signatures do not encrypt payloads.

Use the receiver's configured `aud`, not the incoming envelope's value. Leave `now` unset outside tests. Synchronize receiver and Redis clocks and enforce transport timeouts and rate limits before cryptography or storage.

## Replay storage

`consumeNonce(key, expiresAt)` atomically records an unused key until the supplied Unix-seconds expiry. Return exactly `true` for a new key, `false` if already used, and throw on storage failure. All receiver instances must share the store.

The recipe uses node-redis 5 and one `SET … NX EXAT …` operation:

```js
consumeNonce: async (key, expiresAt) => {
  const reply = await redis.withCommandOptions({ abortSignal: AbortSignal.timeout(3000) }).set(
    `marque:nonce:${key}`, '1', { condition: 'NX', expiration: { type: 'EXAT', value: expiresAt } },
  );
  if (reply !== 'OK' && reply !== null) throw new Error('unexpected nonce store response');
  return reply === 'OK';
}
```

The client disables offline command queuing and automatic reconnection for this one-shot receiver. Connection and command failures reject the message. A long-lived service can manage reconnection itself while still rejecting verification whenever storage is unavailable.

**Retain every consumed nonce until expiry.** Use Redis persistence and a failover policy that preserve acknowledged writes, with `maxmemory-policy noeviction`. Losing or evicting records allows replay; a fresh in-memory fallback does too. A default, disposable local Redis is for development. Verify your deployment's durability guarantees before relying on it.

Verification consumes a nonce before your handler runs. Persist operation status keyed by the signing address and signed `payload.id` to make work idempotent. Re-signing creates a fresh nonce, so it can repeat an action without that application check. The receiver deliberately prints accepted work; it does not implement your business operation or exactly-once delivery.

## Handle failures

`VerifyResult` narrows on `ok`. Its `reason` is the exported `VerifyFailure` string union; every failure means reject. Signing throws on invalid local input.

| Failure | Next step |
| --- | --- |
| `wrong audience` | Match both applications' configured recipient IDs exactly. |
| `expired` / `clock skew` | Check clocks and delivery time; inspect operation status before retrying. |
| `replay` | The envelope was consumed. Look up the application operation ID. |
| `nonce store failed` | Restore storage or fix the callback's return type. Keep rejecting messages. |
| `bad version` / `malformed envelope` | Deliver a complete v2 envelope from `sign`. |
| `signer mismatch` / `verification failed` | Check for tampering, malformed signatures or unsupported JSON. |
| `invalid verification context` | Supply a nonempty configured audience, a nonce callback and a valid clock. |

## Check the integration

```sh
npm run check
REDIS_URL=redis://127.0.0.1:6379 npm run test:redis
```

The Redis tests send one envelope concurrently to separate receiver processes, check that exactly one succeeds, check the recorded expiry, and retry in a new process. They also reject unknown addresses, tampering, wrong recipients, unsupported actions, oversized/deep JSON and unavailable storage. Tests use unique audience IDs and let their keys expire; they never flush Redis.

Also test your actual handler's permissions and idempotency, expiry, and replay retention through your Redis restart/failover procedure. The supplied integration test restarts receivers, not your Redis deployment.
