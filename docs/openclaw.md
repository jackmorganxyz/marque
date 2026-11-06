# Marque with OpenClaw

Use the [v2 integration guide](integration.md) to add signing and verification around your agent. Keep signing in trusted application code and verify external envelopes before they reach the agent. The application must also check the sender’s address, allowed actions and payload schema.

Start with the [complete quickstart](../examples/round-trip.mjs), then adapt the [Redis receiver](../examples/redis-receiver.mjs) to your inbox. Preserve nonce records across process restarts and use a signed operation ID for idempotent work.

For implementation context, give your coding agent [the v2 brief](agent.md). The previous domain-based plugin walkthrough is preserved in the [v1 source](https://github.com/jackmorganxyz/marque/blob/905d5be/docs/openclaw.md); its CLI and envelope format are not compatible with v2.
