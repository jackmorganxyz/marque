# Use cases

Marque answers one question: **which address signed this message?** The receiver supplies the trust policy.

| Use case | What Marque provides | What your application supplies |
| --- | --- | --- |
| Messages between agents | Proof of the signing address and unchanged payload. | Trusted contacts, permitted actions and delivery. |
| Webhooks or service requests | One signing key; receivers hold only its public address. | Address enrollment, rotation, rate limits and operation idempotency. |
| Agent login | A signed response to a service's challenge. | Account linking, challenge storage, permissions and sessions. |

Start with the [integration guide](integration.md). Use the [login guide](authentication.md) only if you need sessions; an API can verify each request directly.

Marque does not identify people, prevent prompt injection, encrypt messages or prove that a person approved an agent's action. Messages expire within five minutes and are bound to one recipient, so this core is not an archival-signature or unrestricted-forwarding system.
