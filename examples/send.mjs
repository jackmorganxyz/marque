import { randomUUID } from 'node:crypto';
import { sign } from '@jackmorganxyz/marque';

if (!process.env.MARQUE_AUDIENCE) throw new Error('Set MARQUE_AUDIENCE to the receiver’s configured ID');
const message = await sign({ id: randomUUID(), task: 'summarize', text: 'Hello from my agent.' }, {
  privateKey: process.env.MARQUE_PRIVATE_KEY,
  aud: process.env.MARQUE_AUDIENCE,
});
process.stdout.write(JSON.stringify(message) + '\n');
