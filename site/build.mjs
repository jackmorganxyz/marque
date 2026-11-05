import { readFile, writeFile, copyFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = new URL('../', import.meta.url);
const file = path => new URL(path, root);
const read = path => readFile(file(path), 'utf8');
const escape = text => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const quickstart = await read('examples/round-trip.mjs');
const brief = await read('docs/agent.md');
const agent = `${brief}\n\x60\x60\x60js\n${quickstart}\x60\x60\x60\n`;
const receiver = await read('examples/redis-receiver.mjs');
let html = await read('site/dist/index.html');
for (const [name, content] of Object.entries({ quickstart, agent, receiver })) {
  const marker = new RegExp(`<!-- ${name}:start -->[\\s\\S]*?<!-- ${name}:end -->`);
  if (!marker.test(html)) throw new Error(`Missing ${name} content marker`);
  html = html.replace(marker, () => `<!-- ${name}:start --><pre><code id="${name}-code">${escape(content)}</code></pre><!-- ${name}:end -->`);
}
await writeFile(file('site/dist/index.html'), html);
await writeFile(file('site/dist/agent.md'), agent);
await writeFile(file('site/dist/quickstart.mjs'), quickstart);
for (const name of ['keygen.mjs', 'send.mjs', 'redis-receiver.mjs'])
  await copyFile(file(`examples/${name}`), file(`site/dist/${name}`));
await build({
  entryPoints: [fileURLToPath(file('site/playground.js'))], outfile: fileURLToPath(file('site/dist/playground.js')),
  bundle: true, minify: true, platform: 'browser', format: 'esm', target: 'es2022',
  legalComments: 'eof',
});
const licenses = await Promise.all(['curves', 'hashes'].map(async name =>
  `@noble/${name}\n\n${await read(`node_modules/@noble/${name}/LICENSE`)}\n`));
await writeFile(file('site/dist/THIRD_PARTY_LICENSES.txt'), licenses.join('\n'));
console.log('Built the playground and synced examples, agent instructions and licenses.');
