# Marque with managed agents

Use the [v2 integration guide](integration.md) to add signing and verification around your agent. A trusted host-side tool can hold the private key and sign outbound requests. Verify incoming envelopes and apply address trust, permissions and payload validation before passing work to the agent. Keep the key outside the model’s context.

Start with the [complete quickstart](../examples/round-trip.mjs), then connect the [Redis receiver](../examples/redis-receiver.mjs) to your application. The receiving service owns the configured audience, durable nonce storage and operation idempotency.

For implementation context, give your coding agent [the v2 brief](agent.md). The previous Claude Managed Agents deployment walkthrough is preserved in the [v1 source](https://github.com/jackmorganxyz/marque/blob/905d5be/docs/managed-agents.md); its CLI and envelope format are not compatible with v2.
