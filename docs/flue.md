# Marque with Flue

Use the [v2 integration guide](integration.md) to add signing and verification around your agent. Keep signing keys in the application’s secret storage, and verify incoming envelopes before invoking the agent. Marque does not require a domain or a well-known route.

Start with the [complete quickstart](../examples/round-trip.mjs). Supply an atomic, durable nonce store shared by your deployed receivers; the [Redis recipe](../examples/redis-receiver.mjs) demonstrates the required callback contract. A cache local to one worker or request does not provide that guarantee.

For implementation context, give your coding agent [the v2 brief](agent.md). The previous domain-based deployment walkthrough is preserved in the [v1 source](https://github.com/jackmorganxyz/marque/blob/905d5be/docs/flue.md); its CLI and envelope format are not compatible with v2.
