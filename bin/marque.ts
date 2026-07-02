#!/usr/bin/env node
// Marque CLI — for humans/scripts, not the hot path. Commands: init|keygen|sign|verify.
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

if (cmd === 'keygen') {                       // marque keygen
  const { privateKey, address, wellKnown } = generateAgent();
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
  const { privateKey, address } = generateAgent();
  console.log([
    `MARQUE_PRIVATE_KEY=${privateKey}   # secret — never commit`,
    `MARQUE_ADDRESS=${address}`,
    `MARQUE_ORIGIN=${origin}`,
    `# serve this at https://${origin}/.well-known/marque.json :`,
    JSON.stringify({ v: 1, keys: [address] }),
  ].join('\n'));
} else {
  console.error([
    'usage: marque <command>',
    '  init <origin>          bootstrap an agent: prints env vars + well-known JSON',
    '  keygen                 new keypair as JSON',
    '  sign <origin> <aud>    sign stdin JSON with $MARQUE_PRIVATE_KEY',
    '  verify <selfOrigin>    verify a signed envelope from stdin',
  ].join('\n'));
  process.exit(1);
}