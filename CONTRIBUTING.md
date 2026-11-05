# Contributing

Marque is an MIT-licensed signing and verification library. Keep changes focused on those two operations; identity, trust policy, transport and storage integrations belong in applications or examples.

```sh
npm ci
npm run check
```

`check` runs a clean TypeScript build, core/demo/key-setup tests, the complete example, and the static page build. With Redis 7+ running, also run `REDIS_URL=redis://127.0.0.1:6379 npm run test:redis`. CI runs both checks and a package preview on Node 18, 22 and 24. Include a regression test for changes to signed bytes, validation or replay handling. Report vulnerabilities through [SECURITY.md](SECURITY.md).

Website instructions live in [site/README.md](site/README.md). Its build copies canonical examples and the coding-agent brief into the page, so update those sources instead of generated copies. Redis and esbuild stay development-only; the published core still has two runtime dependencies and two runtime exports.

## Package and release

```sh
npm pack --dry-run
npm pack
```

The tarball contains compiled ESM, TypeScript declarations, README, security guidance, package metadata and the license. Guides, examples and tests remain in the repository. Test the tarball in a separate consumer with `npm install /absolute/path/to/jackmorganxyz-marque-2.0.0.tgz` before releasing.

The package name is `@jackmorganxyz/marque`, with public access configured in `package.json`. Publishing requires an npm account with access to that scope.

To release after checking the tarball:

1. Sign in with `npm login`, and confirm account access using `npm whoami`.
2. Confirm the version is unused on the registry and the repository changes are committed.
3. Run `npm publish --access public`; the `prepublishOnly` hook runs `npm run check` again. Follow npm's account/2FA requirements.
4. Verify the registry release and update the README to make `npm install @jackmorganxyz/marque` the default installation command.

See npm's [publishing guide](https://docs.npmjs.com/creating-and-publishing-scoped-public-packages/) and [lifecycle documentation](https://docs.npmjs.com/cli/v11/using-npm/scripts/). Publication is a separate action from building or packing. There is no automatic publishing workflow.
