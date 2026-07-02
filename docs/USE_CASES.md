# Use cases

Marque answers one question: **"which domain sent this message?"** — with cryptographic proof, no accounts, no shared secrets. Anywhere an agent (or any service) receives messages and needs to know who's asking before it acts, Marque fits. Concrete examples below.

---

## 1. Agent-to-agent task delegation

Your agent exposes an inbox: `POST /api/inbox` with `{ task: "summarize", url: "..." }`. Without identity, anyone who finds the URL can feed it work — or prompt-inject it.

With Marque, the sender signs each request and the receiver checks two things: the signature is real, and the sender's domain is on its allowlist. A request from `eve.example.com` gets acted on; the same request from anywhere else is dropped before it ever reaches the model.

## 2. A front door that blocks prompt injection

The cheapest place to stop a hostile message is before the LLM sees it. `verify()` runs in your inbound handler as plain code — no tokens spent, no model in the loop. Unsigned, tampered, replayed, or unknown-sender messages get a `401` and never become prompt text. Your allowlist, not your system prompt, decides who can talk to your agent.

## 3. Webhooks without shared-secret sprawl

The usual webhook pattern is a per-receiver HMAC secret: the sender stores one secret per receiver, every receiver holds a copy, and rotation means coordinating both sides. With Marque the sender holds **one** private key and publishes one public file. Any number of receivers verify independently — nothing to exchange, nothing to provision, and rotation is editing one JSON file on the sender's domain.

## 4. Cross-company automation

Two companies want their agents to work together — yours files orders, theirs confirms shipments. Neither wants to run a shared auth server or manage API keys for the other. Each side allowlists the other's domain and that's the whole integration: trust is `allow: ["partner.example.com"]`, and revoking the partnership is deleting that line.

## 5. Rate limiting and access tiers by identity

Once every inbound message carries a proven domain, that domain is a key you can meter on: free tier for unknown-but-valid senders, higher limits for partners, priority queue for your own services. No API-key issuance or billing portal — the identity arrives with the message.

## 6. Attributable audit logs

Every accepted message comes with a signed envelope proving who sent it and what the payload was. Store the envelope and you have a tamper-evident record: when something goes wrong you can show exactly which domain asked for the action, and the sender can't deny it — only their key could have produced that signature.

## 7. Internal services, zero secret distribution

Even inside one org, service-to-service auth usually means minting and rotating tokens. If your services already sit on domains (`billing.internal.example.com`, `reports.internal.example.com`), each publishes its address at its own well-known and allowlists its peers. New service = one `npx marque init`, one static file, one allowlist entry — no secrets ever cross a service boundary.

---

**Not a fit:** authenticating humans or platform accounts (`@eve` on X, `github:eve`), messages that must stay valid longer than 300 seconds, or senders that don't control a domain. See [Non-goals](../README.md#non-goals--future-extensions).
