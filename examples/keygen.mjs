import { createECDH } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { sign } from '@jackmorganxyz/marque';

const key = createECDH('secp256k1');
key.generateKeys();
const privateKey = `0x${key.getPrivateKey('hex').padStart(64, '0')}`;
const { signer } = await sign(null, { privateKey, aud: 'key-setup' });
writeFileSync('.env.local', `MARQUE_PRIVATE_KEY=${privateKey}\nTRUSTED_ADDRESSES=${signer}\n`, {
  flag: 'wx', mode: 0o600,
});
console.log('Saved a new key to .env.local. Public address:', signer);
