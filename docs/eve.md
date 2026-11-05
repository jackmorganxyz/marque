# Marque with eve

Use the [v2 integration guide](integration.md) to add signing and verification around your agent. Keep the private key in your server-side signing tool, and verify incoming envelopes before invoking the agent. Enrollment, address allowlisting and action permissions belong to your application.

Start with the [complete quickstart](../examples/round-trip.mjs), then connect the [shared replay-store recipe](../examples/redis-receiver.mjs) to your receiver. Every receiver instance must use the same atomic, durable nonce store.

For implementation context, give your coding agent [the v2 brief](agent.md). The previous domain-based deployment walkthrough is preserved in the [v1 source](https://github.com/jackmorganxyz/marque/blob/905d5be/docs/eve.md); its CLI and envelope format are not compatible with v2.
