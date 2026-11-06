# Marque developer page

A static guide and playground for the v2 core. System fonts, no framework, and no external requests from the demo. Signing and verification run locally with a temporary key.

From the repository root:

```sh
npm run build:site
python3 -m http.server 8080 --directory site/dist
```

Open `http://localhost:8080`. Run `npm ci` first if dependencies are not installed. The system font stack uses San Francisco on Apple platforms.

Edit `dist/index.html`, `dist/styles.css` and `dist/main.js` directly. The build bundles `playground.js` and `demo.mjs` with the actual `marque.ts` implementation using esbuild, and syncs the quickstart, Redis recipe and agent instructions from `examples/` and `docs/agent.md`. Leave the generated HTML marker blocks and `dist/playground.js` to the build. Keep other API examples and release status in sync with the core README.

The build also versions CSS and script URLs by their contents so returning visitors load matching assets after an update.

The demo creates a key in memory, uses a page-local nonce cache, and never accepts production private keys. Reloading clears that state. Its allowlist checkbox demonstrates application trust separately from verification; it does not add trust policy to Marque.

The playground opens with a signed, unverified example and its envelope visible. Signing and verification are separate actions; successful verification consumes the nonce and unlocks the replay example. Edits keep the original signature until the user signs again. Reset restores the sample inputs and signs a fresh envelope.

`npm run check` tests the demo logic and control transitions with a minimal DOM fixture, and builds all assets. Before publishing, check desktop/mobile layouts, tampering, wrong recipients, replay, the trust toggle, and copy buttons in a browser.

`.openai/hosting.json` identifies the private Sites preview. The same `dist/` directory can be served by any static host. It is excluded from the npm package by the package's existing file allowlist.
