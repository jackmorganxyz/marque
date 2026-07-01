#!/usr/bin/env node
// Marque CLI — for humans/scripts, not the hot path. Commands: init|keygen|sign|verify.
import { generateAgent, sign, verify } from '../marque.js';

const [cmd, ...a] = process.argv.slice(2);
const read = async () => {                       // read JSON from stdin (Node stream)
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};

if (cmd === 'keygen') {                       // marque keygen <origin>
  const { privateKey, address, wellKnown } = generateAgent(a[0]);
  console.log(JSON.stringify({ privateKey, address, wellKnown }, null, 2));
} else if (cmd === 'sign') {                   // echo <payload-json> | marque sign <origin> <aud>
  console.log(JSON.stringify(await sign(await read(),
    { privateKey: process.env.MARQUE_PRIVATE_KEY as `0x${string}`, origin: a[0], aud: a[1] })));
} else if (cmd === 'verify') {                 // echo <signed-json> | marque verify <selfOrigin>
  console.log(JSON.stringify(await verify(await read(), { selfOrigin: a[0], seen: new Map() })));
} else if (cmd === 'init') {                   // marque init <origin> — bootstrap env + well-known
  const { privateKey, address } = generateAgent(a[0]);
  console.log([
    `MARQUE_PRIVATE_KEY=${privateKey}   # secret — never commit`,
    `MARQUE_ADDRESS=${address}`,
    `MARQUE_ORIGIN=${a[0]}`,
    `# serve this at https://${a[0]}/.well-known/marque.json :`,
    JSON.stringify({ v: 1, keys: [address] }),
  ].join('\n'));
} else { console.error('usage: init|keygen|sign|verify'); process.exit(1); }
