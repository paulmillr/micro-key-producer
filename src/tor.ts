import * as ed25519 from '@noble/ed25519';
import { sha3_256 } from '@noble/hashes/sha3';
import { utf8, base32, base64 } from '@scure/base';
import { concatBytes } from 'micro-packed';

const ADDRESS_VERSION = new Uint8Array([0x03]);

export async function formatPublicKey(pubBytes: Uint8Array) {
  // checksum = H(".onion checksum" || pubkey || version)
  const checksum = sha3_256(concatBytes(utf8.decode('.onion checksum'), pubBytes, ADDRESS_VERSION));
  // onion_address = base32(pubkey || checksum || version);
  return `${base32
    .encode(concatBytes(pubBytes, checksum.slice(0, 2), ADDRESS_VERSION))
    .toLowerCase()}.onion`;
}

export async function parseAddress(address: string) {
  let addr = base32.decode(address.replace('.onion', '').toUpperCase());
  // skip last 3 bytes
  addr = addr.slice(0, addr.length - 3);
  const key = await formatPublicKey(addr);
  if (key !== address) throw new Error('Invalid checksum');
  return addr;
}

export async function getKeys(seed: Uint8Array) {
  const { head, prefix, pointBytes } = await ed25519.utils.getExtendedPublicKey(seed);
  const bytes = concatBytes(head, prefix);
  return {
    publicKey: await formatPublicKey(pointBytes),
    privateKey: `ED25519-V3:${base64.encode(bytes)}`,
  };
}

export default getKeys;
