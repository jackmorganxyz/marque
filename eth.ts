// eth.ts — minimal Ethereum-style signing kit for Marque. Deps: @noble/curves,
// @noble/hashes (the audited primitives viem itself builds on — byte-identical
// signatures, ~2% of the install size).
//
// Scope is exactly what Marque needs, nothing more: keygen, EIP-55 address,
// EIP-191 personal_sign, address recovery, keccak256. No ABI, no RPC, no chain.
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils';

export type Hex = `0x${string}`;
export type Address = `0x${string}`;

/** keccak256 of the UTF-8 bytes of a string, as 0x-hex. */
export function keccak256(data: string): Hex {
  return ('0x' + bytesToHex(keccak_256(utf8ToBytes(data)))) as Hex;
}

export const randomHex = (bytes: number): Hex => ('0x' + bytesToHex(randomBytes(bytes))) as Hex;

/** EIP-55 mixed-case checksum of a 20-byte hex address. */
function checksumAddress(address: string): Address {
  const a = address.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error('eth: bad address');
  const h = bytesToHex(keccak_256(utf8ToBytes(a)));
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out as Address;
}

/** Case-insensitive address equality. Throws if either side is not a 0x…40-hex address. */
export function isAddressEqual(a: string, b: string): boolean {
  const re = /^0x[0-9a-fA-F]{40}$/;
  if (!re.test(a) || !re.test(b)) throw new Error('eth: bad address');
  return a.toLowerCase() === b.toLowerCase();
}

const pubToAddress = (uncompressedPub: Uint8Array): Address =>
  // address = last 20 bytes of keccak256(pubkey minus the 0x04 prefix byte)
  checksumAddress('0x' + bytesToHex(keccak_256(uncompressedPub.subarray(1)).subarray(12)));

export const generatePrivateKey = (): Hex =>
  ('0x' + bytesToHex(secp256k1.utils.randomPrivateKey())) as Hex;

export function privateKeyToAddress(privateKey: Hex): Address {
  return pubToAddress(secp256k1.getPublicKey(strip0x(privateKey), false));
}

function strip0x(h: string): string {
  if (!/^0x[0-9a-fA-F]+$/.test(h)) throw new Error('eth: bad hex');
  return h.slice(2);
}

// EIP-191 personal_sign digest: keccak256("\x19Ethereum Signed Message:\n" + len + msg),
// where len is the DECIMAL BYTE length of the UTF-8 message.
function personalDigest(message: string): Uint8Array {
  const m = utf8ToBytes(message);
  return keccak_256(concatBytes(utf8ToBytes('\x19Ethereum Signed Message:\n' + m.length), m));
}

/** EIP-191 personal_sign. Deterministic (RFC 6979, low-s). Returns 65-byte r‖s‖v hex, v ∈ {27,28}. */
export function signMessage(message: string, privateKey: Hex): Hex {
  const sig = secp256k1.sign(personalDigest(message), strip0x(privateKey));
  return ('0x' + sig.toCompactHex() + (27 + sig.recovery).toString(16).padStart(2, '0')) as Hex;
}

/** Recover the signing address of an EIP-191 personal_sign signature. Throws on malformed input. */
export function recoverMessageAddress(message: string, signature: string): Address {
  const bytes = hexToBytes(strip0x(signature));
  if (bytes.length !== 65) throw new Error('eth: bad signature length');
  const v = bytes[64] >= 27 ? bytes[64] - 27 : bytes[64];
  if (v !== 0 && v !== 1) throw new Error('eth: bad recovery id');
  const sig = secp256k1.Signature.fromCompact(bytes.subarray(0, 64)).addRecoveryBit(v);
  return pubToAddress(sig.recoverPublicKey(personalDigest(message)).toRawBytes(false));
}
