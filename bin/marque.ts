#!/usr/bin/env node
// Marque CLI — for humans/scripts, not the hot path. Commands: init|demo|keygen|sign|verify.
import { generateAgent, sign, verify } from '../marque.js';

const [cmd, ...a] = process.argv.slice(2);
const read = async () => {                       // read JSON from stdin (Node stream)
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};
const need = (v: string | undefined, what: string): string => {
  if (!v) { console.error(`marque: missing ${what}`); process.exit(1); }
  return v;
};

if (cmd === 'keygen') {                       // marque keygen <origin>
  const { privateKey, address, wellKnown } = generateAgent(need(a[0], '<origin>'));
  console.log(JSON.stringify({ privateKey, address, wellKnown }, null, 2));
} else if (cmd === 'sign') {                   // echo <payload-json> | marque sign <origin> <aud>
  console.log(JSON.stringify(await sign(await read(),
    { privateKey: process.env.MARQUE_PRIVATE_KEY as `0x${string}`,
      origin: need(a[0], '<origin>'), aud: need(a[1], '<aud>') })));
} else if (cmd === 'verify') {                 // echo <signed-json> | marque verify <selfOrigin>
  console.log(JSON.stringify(await verify(await read(),
    { selfOrigin: need(a[0], '<selfOrigin>'), seen: new Map() })));
} else if (cmd === 'init') {                   // marque init <origin> — bootstrap env + well-known
  const origin = need(a[0], '<origin>');
  const { privateKey, address } = generateAgent(origin);
  console.log([
    `MARQUE_PRIVATE_KEY=${privateKey}   # secret — never commit`,
    `MARQUE_ADDRESS=${address}`,
    `MARQUE_ORIGIN=${origin}`,
    `# serve this at https://${origin}/.well-known/marque.json :`,
    JSON.stringify({ v: 1, keys: [address] }),
  ].join('\n'));
} else if (cmd === 'demo') {                   // marque demo — the whole protocol, in-process, no network
  const eve = generateAgent('eve.example.com');
  const mallory = generateAgent('eve.example.com');            // mallory CLAIMS eve's origin
  const resolveKeys = async (origin: string) => origin === 'eve.example.com' ? [eve.address] : [];
  const bob = { selfOrigin: 'bob.example.com', seen: new Map<string, number>(), resolveKeys };

  const payload = { task: 'summarize', url: 'https://x.com/thread/1' };
  const msg = await sign(payload, { privateKey: eve.privateKey, origin: eve.origin, aud: 'bob.example.com' });
  console.log(`eve.example.com signs ${JSON.stringify(payload)}`);
  console.log(`  → envelope: sig ${msg.sig.slice(0, 18)}…, nonce ${msg.nonce}, aud ${msg.aud}\n`);

  const show = async (label: string, p: ReturnType<typeof verify>) => {
    const r = await p;
    console.log(`${label}\n  → ${r.ok ? `✓ accepted — identity ${r.identity}` : `✗ rejected — ${r.reason}`}\n`);
  };
  await show('mallory intercepts and tampers with the payload',
    verify({ ...msg, payload: { task: 'DELETE EVERYTHING' } }, bob));
  await show('bob verifies the genuine envelope', verify(msg, bob));
  await show('mallory replays the same envelope to bob', verify(msg, bob));
  await show('mallory forwards it to carol.example.com instead',
    verify(msg, { ...bob, selfOrigin: 'carol.example.com', seen: new Map() }));
  await show("mallory signs with her own key, claiming eve's origin",
    verify(await sign(payload, { privateKey: mallory.privateKey, origin: 'eve.example.com', aud: 'bob.example.com' }), bob));
  console.log('every check ran locally — real deployments fetch keys from https://<origin>/.well-known/marque.json');
  console.log('next: npx marque init <your-origin>');
} else {
  console.error([
    'usage: marque <command>',
    '  init <origin>          bootstrap an agent: prints env vars + well-known JSON',
    '  demo                   two-agent sign/verify story, in-process, no network',
    '  keygen <origin>        new keypair as JSON',
    '  sign <origin> <aud>    sign stdin JSON with $MARQUE_PRIVATE_KEY',
    '  verify <selfOrigin>    verify a signed envelope from stdin',
  ].join('\n'));
  process.exit(1);
}