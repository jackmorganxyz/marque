# Agent login

An agent can prove control of an address to a service that explicitly integrates Marque. The service owns account linking, challenges and sessions; this is not an OAuth or OIDC replacement.

## Enroll the address

Link a signing address to an account through an authenticated account or trusted operator. Normalize addresses to lowercase. A signed claim containing an email, account ID or role does not establish ownership of that account. Agents sharing one private key are indistinguishable.

## Sign a challenge

The service generates a random challenge, stores it with the intended address and a short expiry (for example 60 seconds), and returns it to the agent. Use cryptographically random bytes, such as Node's `randomBytes(32)`. The requested address is still unverified and grants no access.

```ts
import { sign, type Hex } from '@jackmorgan/marque';

const message = await sign({ action: 'login', challenge }, {
  privateKey: process.env.MARQUE_PRIVATE_KEY as Hex,
  aud: 'my-service:login',
  ttl: 60,
});
```

Deliver the envelope over HTTPS to the service. Use a separate login audience and check the action so an ordinary signed message cannot become a login request.

## Verify and issue a session

The service performs these steps in order:

1. Call `verify(message, { aud: 'my-service:login', consumeNonce })` with shared atomic replay storage; reject failures.
2. Validate that the payload has `action: 'login'` and the expected challenge format.
3. Find an active account already linked to `result.signer.toLowerCase()`.
4. Atomically consume the stored challenge only if its address matches the verified signer and it has not expired. Commit this before creating a session.
5. Issue the service's normal session with that account's permissions.

The challenge and envelope nonce are separate. A second signature over the same challenge has a new nonce; consuming the challenge prevents a second login. Both stores must fail closed and work across all service instances.

Rate-limit both endpoints and limit request size/depth. For browser login, bind the challenge to the initiating session and use the service's normal CSRF protections. If session creation fails after challenge consumption, start a new login flow.

## Check and revoke

Check wrong audiences/actions, unknown addresses, expired challenges, challenges issued to another address, a newly signed reuse of a consumed challenge, and concurrent logins. Only one consumption of a challenge may succeed.

Removing a trusted address blocks future logins, not existing sessions. Store the signing address with sessions so your application can revoke both when a key is compromised. If your API verifies each request directly, you do not need this session flow.

See [integration](integration.md) for key setup and replay storage, and [security](../SECURITY.md) for the caller's responsibilities.
